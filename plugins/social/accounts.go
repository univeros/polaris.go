package social

import (
	"context"
	"errors"
	"time"

	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/security"
	"github.com/univeros/polaris-go/store"
)

// TableAccounts is the table the plugin owns. The OAuth state lives in the cache.
const TableAccounts = "polaris_social_account"

// Models returns polaris_social_account as upstream declares it.
func Models() []schema.Model {
	return []schema.Model{
		schema.Table(TableAccounts,
			schema.StringField("id", 36).AsPrimary(),
			schema.StringField("userId", 36),
			schema.StringField("provider", 40),
			schema.StringField("providerAccountId", 255),
			schema.StringField("email", 320).AsNullable(),
			schema.BoolField("emailVerified").WithDefault(false),
			schema.JSONField("scopes"),
			schema.JSONField("profile"),
			schema.TextField("accessTokenEnc").AsNullable(),
			schema.TextField("refreshTokenEnc").AsNullable(),
			schema.DateTimeField("expiresAt").AsNullable(),
			schema.DateTimeField("createdAt"),
			schema.DateTimeField("updatedAt"),
		).
			Unique([]string{"provider", "provider_account_id"}, "polaris_social_account_unique").
			Unique([]string{"user_id", "provider"}, "polaris_social_account_user_provider_unique"),
	}
}

// dateAtom is PHP's DATE_ATOM: UTC is written "+00:00".
const dateAtom = "2006-01-02T15:04:05-07:00"

// account is a row of polaris_social_account; the tokens stay sealed (core's encrypter).
type account struct {
	ID, UserID, Provider, ProviderAccountID string
	Email                                   string // "" is NULL
	EmailVerified                           bool
	Scopes                                  []string
	Profile                                 map[string]any
	AccessTokenEnc, RefreshTokenEnc         string // "" is NULL
	ExpiresAt                               *time.Time
	CreatedAt, UpdatedAt                    time.Time
}

// wire is the account as the client sees it: never its tokens.
func (a account) wire() map[string]any {
	var email any
	if a.Email != "" {
		email = a.Email
	}
	return map[string]any{
		"id": a.ID, "provider": a.Provider, "provider_account_id": a.ProviderAccountID, "email": email,
		"email_verified": a.EmailVerified, "scopes": a.Scopes, "profile": a.Profile,
		"created_at": a.CreatedAt.Format(dateAtom), "updated_at": a.UpdatedAt.Format(dateAtom),
	}
}

func (p *Plugin) now() time.Time { return p.g.Clock.Now().UTC().Truncate(time.Second) }

func (p *Plugin) findAccount(ctx context.Context, c store.Criteria) (*account, error) {
	r, err := p.g.DB.FindOne(ctx, TableAccounts, c)
	if err != nil || r == nil {
		return nil, err
	}
	a := hydrate(r)
	return &a, nil
}

func (p *Plugin) accountsOf(ctx context.Context, userID string) ([]account, error) {
	rows, err := p.g.DB.FindMany(ctx, TableAccounts, store.Criteria{"user_id": userID}, store.Query{OrderBy: []store.Order{{Column: "id"}}})
	if err != nil {
		return nil, err
	}
	out := make([]account, len(rows))
	for i, r := range rows {
		out[i] = hydrate(r)
	}
	return out, nil
}

// link stores a new provider account for userID. A clash on either unique index (the provider
// account linked meanwhile, or the user already holding one of this provider) is account_linked.
func (p *Plugin) link(ctx context.Context, userID, providerID string, prof Profile, t tokens) (account, error) {
	now := p.now()
	a := account{ID: repository.NewID(), UserID: userID, Provider: providerID, ProviderAccountID: prof.Subject, CreatedAt: now}
	a, err := p.apply(a, prof, t, now)
	if err != nil {
		return account{}, err
	}
	row, err := columns(a)
	if err != nil {
		return account{}, err
	}
	row["id"], row["user_id"], row["provider"], row["provider_account_id"], row["created_at"] = a.ID, userID, providerID, prof.Subject, now
	if err := p.g.DB.Insert(ctx, TableAccounts, store.Row(row)); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			return account{}, refuse(kindAccountLinked, "This "+providerID+" account, or another "+providerID+" account of this user, is already linked.")
		}
		return account{}, err
	}
	return a, nil
}

// refreshAccount records what a sign-in reported and its tokens.
func (p *Plugin) refreshAccount(ctx context.Context, a account, prof Profile, t tokens) (account, error) {
	a, err := p.apply(a, prof, t, p.now())
	if err != nil {
		return account{}, err
	}
	return a, p.write(ctx, a)
}

// storeTokens records refreshed tokens (a refresh that answers no refresh token keeps the old).
func (p *Plugin) storeTokens(ctx context.Context, a account, t tokens) (account, error) {
	now := p.now()
	sealed, err := p.g.Encrypter.Encrypt(t.access)
	if err != nil {
		return account{}, err
	}
	a.AccessTokenEnc = sealed
	if t.refresh != "" {
		if a.RefreshTokenEnc, err = p.g.Encrypter.Encrypt(t.refresh); err != nil {
			return account{}, err
		}
	}
	a.ExpiresAt = expiry(t, now)
	a.UpdatedAt = now
	return a, p.write(ctx, a)
}

func (p *Plugin) write(ctx context.Context, a account) error {
	row, err := columns(a)
	if err != nil {
		return err
	}
	_, err = p.g.DB.Update(ctx, TableAccounts, store.Criteria{"id": a.ID}, store.Data(row))
	return err
}

// apply takes the profile and, unless the sign-in carried none (One Tap: an id_token only), the
// tokens, sealed.
func (p *Plugin) apply(a account, prof Profile, t tokens, now time.Time) (account, error) {
	a.Email, a.EmailVerified, a.Scopes, a.Profile = prof.Email, prof.EmailVerified, t.scopes, prof.fields()
	if a.Scopes == nil {
		a.Scopes = []string{}
	}
	var err error
	if t.access != "" {
		if a.AccessTokenEnc, err = p.g.Encrypter.Encrypt(t.access); err != nil {
			return a, err
		}
		a.ExpiresAt = expiry(t, now)
	}
	if t.refresh != "" {
		if a.RefreshTokenEnc, err = p.g.Encrypter.Encrypt(t.refresh); err != nil {
			return a, err
		}
	}
	a.UpdatedAt = now
	return a, nil
}

func expiry(t tokens, now time.Time) *time.Time {
	if t.expiresIn == nil {
		return nil
	}
	at := now.Add(time.Duration(*t.expiresIn) * time.Second)
	return &at
}

func (p *Plugin) unlinkAccount(ctx context.Context, a account) error {
	_, err := p.g.DB.Delete(ctx, TableAccounts, store.Criteria{"id": a.ID})
	return err
}

func (p *Plugin) unlinkAll(ctx context.Context, userID string) error {
	_, err := p.g.DB.Delete(ctx, TableAccounts, store.Criteria{"user_id": userID})
	return err
}

// open decrypts a sealed token; "" when absent or unreadable (a rotated APP_KEY).
func (p *Plugin) open(sealed string) (string, error) {
	if sealed == "" {
		return "", nil
	}
	plain, err := p.g.Encrypter.Decrypt(sealed)
	if errors.Is(err, security.ErrDecrypt) {
		return "", nil
	}
	return plain, err
}

func columns(a account) (map[string]any, error) {
	scopes, err := store.JSONValue(a.Scopes)
	if err != nil {
		return nil, err
	}
	profile, err := store.JSONValue(a.Profile)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"email": nullable(a.Email), "email_verified": a.EmailVerified, "scopes": scopes, "profile": profile,
		"access_token_enc": nullable(a.AccessTokenEnc), "refresh_token_enc": nullable(a.RefreshTokenEnc),
		"expires_at": store.Nullable(a.ExpiresAt), "updated_at": a.UpdatedAt,
	}, nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func hydrate(r store.Row) account {
	a := account{
		ID: r.String("id"), UserID: r.String("user_id"), Provider: r.String("provider"), ProviderAccountID: r.String("provider_account_id"),
		Email: r.String("email"), EmailVerified: r.Bool("email_verified"), AccessTokenEnc: r.String("access_token_enc"),
		RefreshTokenEnc: r.String("refresh_token_enc"), ExpiresAt: r.TimePtr("expires_at"), Scopes: []string{}, Profile: map[string]any{},
	}
	a.CreatedAt, _ = r.Time("created_at")
	a.UpdatedAt, _ = r.Time("updated_at")
	var scopes []any
	if r.JSON("scopes", &scopes) == nil {
		for _, s := range scopes {
			if v, ok := s.(string); ok {
				a.Scopes = append(a.Scopes, v)
			}
		}
	}
	var profile map[string]any
	if r.JSON("profile", &profile) == nil && profile != nil {
		a.Profile = profile
	}
	return a
}
