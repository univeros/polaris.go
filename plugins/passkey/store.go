package passkey

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
)

// TablePasskeys is the table the plugin owns. Challenges live in the cache.
const TablePasskeys = "polaris_passkey"

// Models returns polaris_passkey; its columns are the schema existing databases hold.
func Models() []schema.Model {
	return []schema.Model{
		schema.Table(TablePasskeys,
			schema.StringField("id", 36).AsPrimary(),
			schema.StringField("userId", 36),
			// ASCII: base64url, case-sensitive; on MySQL a utf8mb4 VARCHAR(1024) is too long to index.
			schema.StringField("credentialId", 1024).AsASCII(),
			schema.TextField("publicKey"),
			schema.IntField("counter").WithDefault(0),
			schema.StringField("aaguid", 36),
			schema.JSONField("transports"),
			schema.BoolField("backupEligible").WithDefault(false),
			schema.BoolField("backedUp").WithDefault(false),
			schema.StringField("name", 80),
			schema.StringField("factorId", 36).AsNullable(),
			schema.DateTimeField("lastUsedAt").AsNullable(),
			schema.DateTimeField("createdAt"),
		).
			Unique([]string{"credential_id"}, "polaris_passkey_credential_unique").
			Index([]string{"user_id"}, "polaris_passkey_user_index").
			Index([]string{"factor_id"}, "polaris_passkey_factor_index"),
	}
}

// record is a row of polaris_passkey: the credential id and COSE public key as the authenticator
// presented them (base64url), the signature counter, the backup flags, and the factor it backs.
type record struct {
	ID, UserID, CredentialID, PublicKey string
	Counter                             int64
	AAGUID                              string
	Transports                          []string
	BackupEligible, BackedUp            bool
	Name                                string
	FactorID                            string // "" is NULL
	LastUsedAt                          *time.Time
	CreatedAt                           time.Time
}

// wire is the passkey as the client sees it.
func (r record) wire() map[string]any {
	var factorID, lastUsed any
	if r.FactorID != "" {
		factorID = r.FactorID
	}
	if r.LastUsedAt != nil {
		lastUsed = r.LastUsedAt.UTC().Format(time.RFC3339)
	}
	return map[string]any{"id": r.ID, "name": r.Name, "aaguid": r.AAGUID, "transports": r.Transports, "backed_up": r.BackedUp,
		"factor_id": factorID, "last_used_at": lastUsed, "created_at": r.CreatedAt.UTC().Format(time.RFC3339)}
}

func (p *Plugin) now() time.Time { return p.g.Clock().Now().UTC().Truncate(time.Second) }

func (p *Plugin) insert(ctx context.Context, r record) error {
	transports, err := store.JSONValue(r.Transports)
	if err != nil {
		return err
	}
	var factorID any
	if r.FactorID != "" {
		factorID = r.FactorID
	}
	err = p.g.DB().Insert(ctx, TablePasskeys, store.Row{
		"id": r.ID, "user_id": r.UserID, "credential_id": r.CredentialID, "public_key": r.PublicKey, "counter": r.Counter,
		"aaguid": r.AAGUID, "transports": transports, "backup_eligible": r.BackupEligible, "backed_up": r.BackedUp,
		"name": r.Name, "factor_id": factorID, "last_used_at": nil, "created_at": r.CreatedAt,
	})
	if errors.Is(err, store.ErrDuplicate) {
		return errInvalid("this credential is already registered")
	}
	return err
}

func (p *Plugin) find(ctx context.Context, c store.Criteria) (*record, error) {
	row, err := p.g.DB().FindOne(ctx, TablePasskeys, c)
	if err != nil || row == nil {
		return nil, err
	}
	r := hydrate(row)
	return &r, nil
}

func (p *Plugin) forUser(ctx context.Context, userID string) ([]record, error) {
	rows, err := p.g.DB().FindMany(ctx, TablePasskeys, store.Criteria{"user_id": userID}, store.Query{OrderBy: []store.Order{{Column: "id"}}})
	if err != nil {
		return nil, err
	}
	out := make([]record, len(rows))
	for i, row := range rows {
		out[i] = hydrate(row)
	}
	return out, nil
}

// used records an assertion: the new counter and backup state, the time. It is conditional on the
// counter the assertion was checked against, so two concurrent assertions cannot both move it.
func (p *Plugin) used(ctx context.Context, r record, a asserted) error {
	n, err := p.g.DB().Update(ctx, TablePasskeys, store.Criteria{"id": r.ID, "counter": r.Counter},
		store.Data{"counter": int64(a.counter), "backed_up": a.backedUp, "last_used_at": p.now()})
	if err == nil && n != 1 {
		return errInvalid("the passkey was used concurrently")
	}
	return err
}

func (p *Plugin) detachFactor(ctx context.Context, factorID string) error {
	_, err := p.g.DB().Update(ctx, TablePasskeys, store.Criteria{"factor_id": factorID}, store.Data{"factor_id": nil})
	return err
}

func (p *Plugin) deleteForUser(ctx context.Context, userID string) error {
	_, err := p.g.DB().Delete(ctx, TablePasskeys, store.Criteria{"user_id": userID})
	return err
}

func hydrate(row store.Row) record {
	r := record{ID: row.String("id"), UserID: row.String("user_id"), CredentialID: row.String("credential_id"), PublicKey: row.String("public_key"),
		Counter: row.Int("counter"), AAGUID: row.String("aaguid"), BackupEligible: row.Bool("backup_eligible"), BackedUp: row.Bool("backed_up"),
		Name: row.String("name"), FactorID: row.String("factor_id"), LastUsedAt: row.TimePtr("last_used_at"), Transports: []string{}}
	r.CreatedAt, _ = row.Time("created_at")
	var transports []any
	if row.JSON("transports", &transports) == nil {
		for _, t := range transports {
			if s, ok := t.(string); ok {
				r.Transports = append(r.Transports, s)
			}
		}
	}
	return r
}

// kind names why a passkey step could not proceed; it is the problem type passkey/<kind>.
type kind string

const (
	kindInvalidInput         kind = "invalid_input"
	kindOriginMismatch       kind = "origin_mismatch"
	kindChallengeInvalid     kind = "challenge_invalid"
	kindCredentialInvalid    kind = "credential_invalid"
	kindAccountDisabled      kind = "account_disabled"
	kindEmailUnverified      kind = "email_unverified"
	kindUserVerificationReqd kind = "user_verification_required"
	kindNotFound             kind = "not_found"
	kindLastFactor           kind = "last_factor"
)

// refusal is a refused step; detail is what the caller may read (credential_invalid's stays
// server-side: the client reads the fixed sentence).
type refusal struct {
	kind   kind
	detail string
}

func (r *refusal) Error() string { return "passkey: " + string(r.kind) + ": " + r.detail }

// errInvalid is a credential that does not verify.
func errInvalid(detail string) error { return &refusal{kindCredentialInvalid, detail} }

func asRefusal(err error) (*refusal, bool) {
	var r *refusal
	return r, errors.As(err, &r)
}

var problems = map[kind]struct {
	status int
	title  string
	detail string // "" means the refusal's own detail
}{
	kindOriginMismatch:       {http.StatusForbidden, "Origin mismatch", ""},
	kindChallengeInvalid:     {http.StatusUnprocessableEntity, "Invalid challenge", "The challenge is unknown, used or expired."},
	kindCredentialInvalid:    {http.StatusUnprocessableEntity, "Invalid credential", "The credential could not be verified."},
	kindAccountDisabled:      {http.StatusForbidden, "Account disabled", "This account is disabled."},
	kindEmailUnverified:      {http.StatusForbidden, "Email not verified", ""},
	kindUserVerificationReqd: {http.StatusForbidden, "User verification required", ""},
	kindNotFound:             {http.StatusNotFound, "Passkey not found", "No such passkey."},
	kindLastFactor:           {http.StatusConflict, "Last factor", ""},
}
