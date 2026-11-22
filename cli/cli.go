// Package cli is the polaris command line as a library: schema export, creation, diff and drop,
// migrations, the manifest, a doctor, key generation, `.env` scaffolding, the MCP stdio server and
// the plugins' maintenance commands (audit, admin, anonymous).
//
// A host builds its own binary over its own instance, so the commands see its plugins, tables and
// permissions:
//
//	func main() {
//		p, err := polaris.New(cfg) // the host's Config, plugins included
//		if err != nil {
//			log.Fatal(err)
//		}
//		os.Exit(cli.Run(context.Background(), p, os.Args[1:], os.Stdout, os.Stderr))
//	}
//
// cmd/polaris is the standalone binary ([Main]): it builds the instance from the environment and
// `.env`, the database from DATABASE_URL or --dsn, and the plugins named by --plugins.
//
// Every command is idempotent, takes --json (one JSON object on stdout) and exits non-zero on
// failure, naming the remedy: 1 when the work failed, 2 when the command line is wrong.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	polaris "github.com/univeros/polaris.go"
)

// Exit codes.
const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

// cliError is a failure with its remedy and exit code.
type cliError struct {
	code   int
	msg    string
	remedy string
}

func (e *cliError) Error() string { return e.msg }

func fail(msg, remedy string) error  { return &cliError{exitFail, msg, remedy} }
func usage(msg, remedy string) error { return &cliError{exitUsage, msg, remedy} }

// report is what a command prints: text by default, data with --json.
type report struct {
	text string
	data any
}

// runFunc does a command's work once its flags are parsed.
type runFunc func(ctx context.Context) (report, error)

type command struct {
	name    string
	args    []string // positional arguments, in order
	summary string
	// setup registers the command's flags on fs and returns its work.
	setup func(a *app, fs *flag.FlagSet) runFunc
}

// commands is a function, not a var: mcp's tools refer back to the list.
func commands() []command {
	return []command{
		{name: "init", summary: "Writes APP_KEY, a fresh RS256 key pair and AUTH_ISSUER to .env (never replacing a value without --force) and prints the quickstart for the plugins.", setup: initCommand},
		{name: "keys:generate", summary: "Prints a fresh APP_KEY and JWT key pair as environment lines.", setup: keysGenerate},
		{name: "schema:export", summary: "Prints the Polaris schema as DDL for a database dialect.", setup: schemaExport},
		{name: "schema:create", summary: "Same as migrate.", setup: migrate},
		{name: "migrate", summary: "Creates the missing Polaris tables, adds the missing columns and indexes, and seeds the permission catalog and the system roles.", setup: migrate},
		{name: "schema:diff", summary: "Compares the Polaris schema with a live database.", setup: schemaDiff},
		{name: "schema:drop", summary: "Drops the Polaris tables (requires --force).", setup: schemaDrop},
		{name: "manifest", summary: "Validates the endpoint specs and prints the manifest as JSON or OpenAPI 3.1.", setup: manifestCommand},
		{name: "doctor", summary: "Checks configuration, keys, manifest, database connectivity and schema.", setup: doctor},
		{name: "mcp", summary: "Serves Polaris as an MCP server over stdio (needs the mcp plugin).", setup: mcpCommand},
		{name: "audit:prune", summary: "Deletes the audit events the retention policy no longer keeps.", setup: auditPrune},
		{name: "audit:verify", summary: "Verifies the audit hash chain.", setup: auditVerify},
		{name: "admin:grant", args: []string{"email", "role"}, summary: "Grants an admin role (viewer, support, admin, owner) to a user, by email.", setup: adminGrant},
		{name: "admin:key", args: []string{"name", "role"}, summary: "Creates an admin API key and prints it once.", setup: adminKey},
		{name: "anonymous:prune", summary: "Deletes the unconverted guests older than the policy.", setup: anonymousPrune},
	}
}

func find(name string) (command, bool) {
	cmds := commands()
	i := slices.IndexFunc(cmds, func(c command) bool { return c.name == name })
	if i < 0 {
		return command{}, false
	}
	return cmds[i], true
}

// app is one invocation: where the instance comes from, the streams and the parsed common flags.
type app struct {
	src    *source
	stdin  io.Reader // nil: os.Stdin
	stdout io.Writer
	stderr io.Writer
	nested bool // run as an MCP tool: no source flags

	json bool
	args []string // positional arguments
}

// Run runs the command line args (without the program name) against the host's instance p and
// returns the exit code.
func Run(ctx context.Context, p *polaris.Polaris, args []string, stdout, stderr io.Writer) int {
	if p == nil {
		fmt.Fprintln(stderr, "error: cli.Run needs a *polaris.Polaris\nremedy: build one with polaris.New, or use cli.Main")
		return exitUsage
	}
	return run(ctx, &app{src: &source{host: p, stderr: stderr}, stdout: stdout, stderr: stderr}, args)
}

// Main runs the standalone command line (cmd/polaris): the instance is built from the environment
// and the .env file (--env-file; the environment wins), the database from --dsn or DATABASE_URL
// (postgres://…, mysql://…, sqlite:path), the plugins from --plugins or POLARIS_PLUGINS
// (audit, admin, apikeys, oauth, agents, mcp, anonymous; none by default).
func Main(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	src := &source{envFile: ".env", stderr: stderr}
	defer src.close()
	return run(ctx, &app{src: src, stdout: stdout, stderr: stderr}, args)
}

func run(ctx context.Context, a *app, args []string) int {
	if len(args) == 0 {
		a.help(a.stderr)
		return exitUsage
	}
	name, rest := args[0], args[1:]
	if name == "help" || name == "-h" || name == "--help" {
		a.json = slices.Contains(rest, "--json")
		if a.json {
			return a.finish(report{data: a.helpData()}, nil)
		}
		a.help(a.stdout)
		return exitOK
	}
	cmd, ok := find(name)
	if !ok {
		a.json = slices.Contains(rest, "--json")
		return a.finish(report{}, usage(fmt.Sprintf("unknown command %q", name), "run `polaris help` for the commands"))
	}
	fs := a.flagSet(name)
	work := cmd.setup(a, fs)
	positional, err := parse(fs, rest)
	if errors.Is(err, flag.ErrHelp) {
		commandHelp(a.stdout, cmd, fs)
		return exitOK
	}
	if err == nil && len(positional) != len(cmd.args) {
		err = fmt.Errorf("%s takes %d argument(s), got %d", name, len(cmd.args), len(positional))
	}
	if err != nil {
		return a.finish(report{}, usage(err.Error(), fmt.Sprintf("run `polaris %s -h` for its usage", name)))
	}
	a.args = positional
	if err := a.src.prepare(); err != nil {
		return a.finish(report{}, err)
	}
	rep, err := work(ctx)
	return a.finish(rep, err)
}

// flagSet registers the common flags: --json, and the source flags of the standalone binary.
func (a *app) flagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&a.json, "json", false, "print one JSON object on stdout")
	if a.src.host == nil && !a.nested {
		fs.StringVar(&a.src.dsn, "dsn", "", "database URL (or DATABASE_URL): postgres://…, mysql://user:pass@host:3306/db, sqlite:path/to/polaris.db")
		fs.StringVar(&a.src.pluginNames, "plugins", "", "comma-separated plugins (or POLARIS_PLUGINS): "+strings.Join(pluginNames(), ","))
		fs.StringVar(&a.src.envFile, "env-file", a.src.envFile, "the .env file read for the environment (the process environment wins) and written by init")
	}
	return fs
}

// parse parses flags anywhere among the positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		positional, args = append(positional, args[0]), args[1:]
	}
}

// finish prints the report (and the failure with its remedy) and returns the exit code.
func (a *app) finish(rep report, err error) int {
	var ce *cliError
	if err != nil && !errors.As(err, &ce) {
		ce = &cliError{exitFail, err.Error(), "run `polaris doctor` to see what is misconfigured"}
	}
	if a.json {
		data := rep.data
		if ce != nil {
			m, ok := data.(map[string]any)
			if !ok {
				m = map[string]any{}
			}
			m["error"], m["remedy"] = ce.msg, ce.remedy
			data = m
		}
		if data != nil {
			enc := json.NewEncoder(a.stdout)
			enc.SetEscapeHTML(false)
			enc.SetIndent("", "  ")
			if encErr := enc.Encode(data); encErr != nil {
				fmt.Fprintf(a.stderr, "error: %v\n", encErr)
				return exitFail
			}
		}
	} else {
		_, _ = io.WriteString(a.stdout, rep.text)
		if ce != nil {
			fmt.Fprintf(a.stderr, "error: %s\n", ce.msg)
			if ce.remedy != "" {
				fmt.Fprintf(a.stderr, "remedy: %s\n", ce.remedy)
			}
		}
	}
	if ce != nil {
		return ce.code
	}
	return exitOK
}

func (a *app) help(w io.Writer) {
	fmt.Fprintln(w, "usage: polaris <command> [flags] [arguments]   (polaris <command> -h for its flags)")
	fmt.Fprintln(w, "\ncommands:")
	for _, c := range commands() {
		fmt.Fprintf(w, "  %-16s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(w, "\nevery command takes --json and exits 1 on failure, 2 on a usage error, naming the remedy.")
}

func (a *app) helpData() map[string]any {
	list := []map[string]any{}
	for _, c := range commands() {
		list = append(list, map[string]any{"name": c.name, "arguments": append([]string{}, c.args...), "summary": c.summary})
	}
	return map[string]any{"commands": list}
}

func commandHelp(w io.Writer, c command, fs *flag.FlagSet) {
	args := ""
	for _, arg := range c.args {
		args += " <" + arg + ">"
	}
	fmt.Fprintf(w, "usage: polaris %s [flags]%s\n\n%s\n\nflags:\n", c.name, args, c.summary)
	fs.SetOutput(w)
	fs.PrintDefaults()
	fs.SetOutput(io.Discard)
}

// stdinOf is the reader the mcp command serves.
func (a *app) stdinOf() io.Reader {
	if a.stdin == nil {
		return os.Stdin
	}
	return a.stdin
}
