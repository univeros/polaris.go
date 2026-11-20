package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/identity"
	"github.com/univeros/polaris-go/plugins/admin"
	"github.com/univeros/polaris-go/plugins/anonymous"
	"github.com/univeros/polaris-go/plugins/audit"
	"github.com/univeros/polaris-go/plugins/mcp"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/wiring"
)

// grantedBy is what the CLI records as the author of a grant or key, as upstream.
const grantedBy = "cli"

// pluginOf builds the instance and finds the plugin id on it.
func pluginOf[T any](ctx context.Context, a *app, id string, of func(*wiring.Graph) *T) (*T, *polaris.Polaris, error) {
	p, err := a.src.instance(ctx)
	if err != nil {
		return nil, nil, err
	}
	plugin := of(p.Graph())
	if plugin == nil {
		return nil, nil, fail(fmt.Sprintf("the %s plugin is not enabled", id), fmt.Sprintf("pass --plugins=…,%s (or POLARIS_PLUGINS), or register it in your binary's polaris.Config", id))
	}
	return plugin, p, nil
}

func auditPrune(a *app, _ *flag.FlagSet) runFunc {
	return func(ctx context.Context) (report, error) {
		plugin, _, err := pluginOf(ctx, a, audit.ID, audit.Of)
		if err != nil {
			return report{}, err
		}
		n, err := plugin.Prune(ctx)
		if err != nil {
			return report{}, fail(err.Error(), "check the database connection and run it again; pruning is idempotent")
		}
		return report{text: fmt.Sprintf("Pruned %d audit event(s).\n", n), data: map[string]any{"pruned": n}}, nil
	}
}

func auditVerify(a *app, _ *flag.FlagSet) runFunc {
	return func(ctx context.Context) (report, error) {
		plugin, _, err := pluginOf(ctx, a, audit.ID, audit.Of)
		if err != nil {
			return report{}, err
		}
		r, err := plugin.Verify(ctx)
		if err != nil {
			return report{}, fail(err.Error(), "check the database connection and run it again")
		}
		var b strings.Builder
		for _, br := range r.Breaks {
			b.WriteString(br + "\n")
		}
		state := "Chain intact"
		if !r.Intact() {
			state = "Chain broken"
		}
		fmt.Fprintf(&b, "%s: %d event(s) checked, %d break(s).\n", state, r.Rows, len(r.Breaks))
		rep := report{text: b.String(), data: map[string]any{"intact": r.Intact(), "rows": r.Rows, "breaks": nonNil(r.Breaks)}}
		if !r.Intact() {
			return rep, fail(fmt.Sprintf("the audit hash chain has %d break(s)", len(r.Breaks)), "the rows listed were altered or deleted outside Polaris: investigate them; the chain cannot be repaired in place")
		}
		return rep, nil
	}
}

func roleArg(s string) (admin.Role, error) {
	role, ok := admin.ParseRole(s)
	if !ok {
		return "", usage(fmt.Sprintf("unknown role %q", s), "the role is viewer, support, admin or owner")
	}
	return role, nil
}

func expiresFlag(v string) (*time.Time, error) {
	if v == "" {
		return nil, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, v); err == nil {
			return &t, nil
		}
	}
	return nil, usage(fmt.Sprintf("--expires %q is not an ISO 8601 date", v), "use e.g. --expires=2027-01-31T00:00:00Z or --expires=2027-01-31")
}

func adminGrant(a *app, fs *flag.FlagSet) runFunc {
	scope := fs.String("scope", admin.ScopeInstance, "instance, or an organization id")
	expires := fs.String("expires", "", "an ISO 8601 date after which the grant lapses")
	return func(ctx context.Context) (report, error) {
		role, err := roleArg(a.args[1])
		if err != nil {
			return report{}, err
		}
		until, err := expiresFlag(*expires)
		if err != nil {
			return report{}, err
		}
		plugin, p, err := pluginOf(ctx, a, admin.ID, admin.Of)
		if err != nil {
			return report{}, err
		}
		email := identity.NormalizeEmail(a.args[0])
		user, err := p.Graph().Repos().Users.ByEmail(ctx, email)
		if errors.Is(err, repository.ErrNotFound) {
			return report{}, fail(fmt.Sprintf("no user has the email address %q", email), "register the user first (POST /auth/register), then grant again")
		}
		if err != nil {
			return report{}, fail(err.Error(), "check the database connection and run it again")
		}
		g, err := plugin.Grants().Grant(ctx, admin.Grant{UserID: user.ID, Role: role, Scope: *scope, GrantedBy: grantedBy, ExpiresAt: until})
		if err != nil {
			return report{}, fail(err.Error(), "check the arguments and run it again; a user's grant is replaced, never duplicated")
		}
		data := g.Map()
		data["email"] = user.Email
		return report{text: fmt.Sprintf("Granted %s to %s (scope %s, grant %s).\n", g.Role, user.Email, g.Scope, g.ID), data: data}, nil
	}
}

func adminKey(a *app, fs *flag.FlagSet) runFunc {
	scope := fs.String("scope", admin.ScopeInstance, "instance, or an organization id")
	allow := fs.String("allow", "", "comma-separated addresses or CIDR blocks the key may be used from")
	expires := fs.String("expires", "", "an ISO 8601 date after which the key stops working")
	return func(ctx context.Context) (report, error) {
		name := a.args[0]
		role, err := roleArg(a.args[1])
		if err != nil {
			return report{}, err
		}
		allowlist := []string{}
		for entry := range strings.SplitSeq(*allow, ",") {
			if entry = strings.TrimSpace(entry); entry == "" {
				continue
			}
			if !admin.ValidAllowlistEntry(entry) {
				return report{}, usage(fmt.Sprintf("%q is not an address or a CIDR block", entry), "use e.g. --allow=10.0.0.0/8,203.0.113.7")
			}
			allowlist = append(allowlist, entry)
		}
		until, err := expiresFlag(*expires)
		if err != nil {
			return report{}, err
		}
		plugin, _, err := pluginOf(ctx, a, admin.ID, admin.Of)
		if err != nil {
			return report{}, err
		}
		// Idempotent: a retried command must not leave a second live key behind.
		keys, err := plugin.Keys().All(ctx)
		if err != nil {
			return report{}, fail(err.Error(), "check the database connection and run it again")
		}
		if i := slices.IndexFunc(keys, func(k admin.Key) bool { return k.Name == name }); i >= 0 {
			return report{data: map[string]any{"key": keys[i].Map()}}, fail(fmt.Sprintf("an admin key named %q already exists (%s); its secret was shown once, when it was created", name, keys[i].ID), "use another name, or delete it first (DELETE /admin/keys/"+keys[i].ID+")")
		}
		key, secret, err := plugin.Keys().Create(ctx, admin.Key{Name: name, Role: role, Scope: *scope, IPAllowlist: allowlist, ExpiresAt: until, CreatedBy: grantedBy})
		if err != nil {
			return report{}, fail(err.Error(), "check the arguments: the name is 1 to 120 characters")
		}
		text := fmt.Sprintf("Created key %s (%s, %s, scope %s).\nThe key is shown once; store it now:\n%s\n", key.ID, key.Name, key.Role, key.Scope, secret)
		return report{text: text, data: map[string]any{"key": key.Map(), "secret": secret}}, nil
	}
}

func anonymousPrune(a *app, _ *flag.FlagSet) runFunc {
	return func(ctx context.Context) (report, error) {
		plugin, _, err := pluginOf(ctx, a, anonymous.ID, anonymous.Of)
		if err != nil {
			return report{}, err
		}
		n, err := plugin.Prune(ctx)
		if err != nil {
			return report{}, fail(err.Error(), "check the database connection and run it again; pruning is idempotent")
		}
		return report{text: fmt.Sprintf("Pruned %d guest(s).\n", n), data: map[string]any{"pruned": n}}, nil
	}
}

func mcpCommand(a *app, fs *flag.FlagSet) runFunc {
	credential := fs.String("token", "", "the credential to act as (or "+mcp.StdioEnv+"): a session token, an API key, an OAuth access token or an operator key; none serves the public tools")
	return func(ctx context.Context) (report, error) {
		_, p, err := pluginOf(ctx, a, mcp.ID, mcp.Of)
		if err != nil {
			return report{}, err
		}
		cred := *credential
		if cred == "" {
			cred, _ = a.src.getenv(mcp.StdioEnv)
		}
		// stdout is the protocol stream: nothing else is printed on success.
		if err := mcp.ServeStdio(ctx, p, mcp.StdioOptions{Credential: cred, In: a.stdinOf(), Out: a.stdout, Tools: a.cliTools()}); err != nil {
			return report{}, fail(err.Error(), "pass --token (or set "+mcp.StdioEnv+") to a valid credential")
		}
		return report{}, nil
	}
}

// cliTools are the read-only commands as MCP tools (stdio only, as upstream): their flags are the
// arguments, their text output the result, a non-zero exit an error.
func (a *app) cliTools() []wiring.Tool {
	var tools []wiring.Tool
	for _, name := range []string{"schema:export", "schema:diff", "manifest", "doctor"} {
		cmd, _ := find(name)
		nested := &app{src: a.src, nested: true}
		fs := nested.flagSet(name)
		cmd.setup(nested, fs)
		properties := map[string]any{}
		fs.VisitAll(func(f *flag.Flag) {
			typ := "string"
			if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
				typ = "boolean"
			}
			properties[f.Name] = map[string]any{"type": typ, "description": f.Usage}
		})
		tools = append(tools, wiring.Tool{
			Name:        "polaris." + strings.ReplaceAll(name, ":", "."),
			Description: cmd.summary + " (polaris " + name + ")",
			InputSchema: map[string]any{"type": "object", "properties": properties},
			ReadOnly:    true,
			Call: func(ctx context.Context, arguments map[string]any) (wiring.ToolResult, error) {
				argv := []string{name}
				for _, k := range slices.Sorted(maps.Keys(arguments)) {
					switch v := arguments[k].(type) {
					case bool:
						if v {
							argv = append(argv, "--"+k)
						}
					case nil:
					default:
						argv = append(argv, fmt.Sprintf("--%s=%v", k, v))
					}
				}
				var out bytes.Buffer
				status := 200
				if run(ctx, &app{src: a.src, nested: true, stdout: &out, stderr: &out}, argv) != exitOK {
					status = 500
				}
				return wiring.ToolResult{Status: status, Body: out.String()}, nil
			},
		})
	}
	return tools
}
