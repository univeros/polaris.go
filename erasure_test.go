package polaris_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/agents"
	"github.com/univeros/polaris.go/plugins/anonymous"
	"github.com/univeros/polaris.go/plugins/apikeys"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/mcp"
	"github.com/univeros/polaris.go/plugins/messaging"
	"github.com/univeros/polaris.go/plugins/multisession"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/plugins/passkey"
	"github.com/univeros/polaris.go/plugins/passwordless"
	"github.com/univeros/polaris.go/plugins/scim"
	"github.com/univeros/polaris.go/plugins/sentinel"
	"github.com/univeros/polaris.go/plugins/social"
	"github.com/univeros/polaris.go/plugins/sso"
	"github.com/univeros/polaris.go/plugins/ui"
	"github.com/univeros/polaris.go/plugins/username"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/wiring"
)

// retainedOnErasure are the plugin columns that name a user and stay when the user is erased,
// each with the reason. Every other such column must lose the user's rows on erasure.
var retainedOnErasure = map[string]string{
	// Attribution: who configured or approved something. The id names the anonymized tombstone,
	// as the audit trail does; the object belongs to the organization or the agent, not the user.
	"polaris_admin_grant.granted_by":             "attribution",
	"polaris_admin_key.created_by":               "attribution",
	"polaris_agent_grant.granted_by":             "attribution",
	"polaris_agent_approval.decided_by":          "attribution",
	"polaris_oauth_client.created_by":            "attribution",
	"polaris_scim_connection.created_by":         "attribution",
	"polaris_sso_provider.created_by":            "attribution",
	"polaris_sentinel_ip_rule.created_by":        "attribution",
	"polaris_audit_drain.created_by":             "attribution",
	"polaris_audit_event.subject_id":             "the audit trail outlives the account (decision 21)",
	"polaris_audit_event.actor_id":               "the audit trail outlives the account (decision 21)",
	"polaris_audit_chain.locked_by":              "not a user column: the id of the audit event holding the chain's lock",
	"polaris_anonymous.converted_user_id":        "the guest's row goes by its own user_id; the account it became keeps its rows",
	"polaris_scim_resource.local_id":             "covered with kind=user below",
	"polaris_agent_receipt.agent_id":             "not a user column",
	"polaris_passwordless_secret.user_id":        "",
	"polaris_multi_session_device.user_id":       "",
	"polaris_sentinel_device.user_id":            "",
	"polaris_username.user_id":                   "",
	"polaris_passwordless_phone.user_id":         "",
	"polaris_audit_activity.user_id":             "",
	"polaris_scim_membership_provenance.user_id": "",
	"polaris_scim_user_name.user_id":             "",
	"polaris_sso_account.user_id":                "",
	"polaris_admin_grant.user_id":                "",
	"polaris_oauth_code.user_id":                 "",
	"polaris_oauth_device_code.user_id":          "",
	"polaris_oauth_ciba_request.user_id":         "",
	"polaris_oauth_consent.user_id":              "",
	"polaris_oauth_token.user_id":                "",
	"polaris_passkey.user_id":                    "",
	"polaris_social_account.user_id":             "",
	"polaris_api_key.owner_id":                   "",
	"polaris_api_key.created_by":                 "",
	"polaris_agent.owner_id":                     "",
	"polaris_agent.created_by":                   "",
	"polaris_agent_host.owner_id":                "",
	"polaris_agent_host.created_by":              "",
	"polaris_anonymous.user_id":                  "",
	"polaris_scim_resource.local_id(user)":       "",
}

// userColumn reports whether a column names a user: *user_id, *_by, owner_id, subject_id,
// actor_id, local_id.
func userColumn(c string) bool {
	switch c {
	case "owner_id", "subject_id", "actor_id", "local_id":
		return true
	}
	return strings.HasSuffix(c, "user_id") || strings.HasSuffix(c, "_by")
}

// allPlugins is every plugin, configured just enough to boot.
func allPlugins() []polaris.Plugin {
	return []polaris.Plugin{
		audit.New(audit.Config{}), admin.New(admin.Config{}), apikeys.New(apikeys.Config{}), oauth.New(oauth.Config{}),
		agents.New(agents.Config{}), mcp.New(mcp.Config{BaseURL: "https://app.example.com/auth"}), anonymous.New(anonymous.Config{}),
		username.New(username.Config{}), multisession.New(multisession.Config{}),
		passwordless.New(passwordless.Config{}), messaging.New(messaging.Config{}), sentinel.New(sentinel.Config{}),
		sso.New(sso.Config{}), scim.New(scim.Config{}), ui.New(ui.Config{}),
		passkey.New(passkey.Config{Origins: []string{"https://app.example.com"}, RPName: "App"}),
		social.New(social.Config{BaseURL: "https://app.example.com/auth", RedirectURIs: []string{"https://app.example.com/in"}, Providers: map[string]social.Provider{
			"google": {ClientID: "c", ClientSecret: "s"},
		}}),
	}
}

// Erasing a user removes every plugin row keyed to it: a row naming the user is seeded in every
// plugin table with a user column, the user is erased, and only the retained columns may still
// name it. A new plugin table with a user column fails here until erasure covers it or it is
// listed in retainedOnErasure with its reason.
func TestErasureRemovesEveryPluginRowOfTheUser(t *testing.T) {
	srv := polaristest.New(t, polaristest.WithPlugins(allPlugins()...))
	ctx := context.Background()
	victim, err := srv.Users().Create(ctx, polaris.NewUser{Email: "gone@example.com", EmailVerified: true})
	ok(t, err)
	db := srv.Graph().DB()

	type seeded struct{ table, column, key string }
	var rows []seeded
	for _, plug := range srv.Graph().Plugins() {
		sp, isSchema := plug.(wiring.SchemaProvider)
		if !isSchema {
			continue
		}
		for _, m := range sp.Schema() {
			for _, f := range m.Fields {
				if !userColumn(f.Column) {
					continue
				}
				key := m.Table + "." + f.Column
				extra := store.Row{}
				switch f.Column {
				case "owner_id":
					extra["owner_type"] = "user"
				case "local_id":
					extra["kind"], key = scim.KindUser, key+"(user)"
				}
				reason, listed := retainedOnErasure[key]
				if !listed {
					t.Errorf("%s names a user: erase its rows on event.UserDeleted, or list it in retainedOnErasure with the reason", key)
					continue
				}
				if reason != "" {
					continue
				}
				row := sampleRow(m, f.Column, victim.ID, extra)
				if err := db.Insert(ctx, m.Table, row); err != nil {
					t.Fatalf("seed %s: %v", key, err)
				}
				rows = append(rows, seeded{m.Table, f.Column, key})
			}
		}
	}
	declared := map[string]bool{}
	for _, r := range rows {
		declared[r.key] = true
	}
	for key, reason := range retainedOnErasure {
		if reason == "" && !declared[key] {
			t.Errorf("%s is listed but no plugin declares it", key)
		}
	}

	ok(t, srv.Users().Delete(ctx, victim.ID))
	for _, r := range rows {
		n, err := db.Count(ctx, r.table, store.Criteria{r.column: victim.ID})
		ok(t, err)
		if n != 0 {
			t.Errorf("%s: %d row(s) of the erased user remain", r.key, n)
		}
	}
}

// sampleRow is a row of m whose column names userID and every other column holds a value of its
// type (strings random, so unique indexes hold).
func sampleRow(m schema.Model, column, userID string, extra store.Row) store.Row {
	row := store.Row{}
	for _, f := range m.Fields {
		switch {
		case f.Column == column:
			row[f.Column] = userID
		case extra[f.Column] != nil:
			row[f.Column] = extra[f.Column]
		case f.Type == schema.String:
			row[f.Column] = randomText(f.Length)
		case f.Type == schema.Text:
			row[f.Column] = randomText(16)
		case f.Type == schema.Int:
			row[f.Column] = 0
		case f.Type == schema.Bool:
			row[f.Column] = false
		case f.Type == schema.DateTime:
			row[f.Column] = time.Now().UTC().Truncate(time.Second)
		case f.Type == schema.JSON:
			row[f.Column] = "{}"
		}
	}
	return row
}

func randomText(length int) string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	s := hex.EncodeToString(b)
	return s[:min(length, len(s))]
}
