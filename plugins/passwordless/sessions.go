package passwordless

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/identity"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/token"
	"github.com/univeros/polaris-go/wiring"
)

// handOffTTL is how long a magic link's hand-off code lives.
const handOffTTL = time.Minute

// service runs the four methods. It is safe for concurrent use: every single-use step is a
// conditional write (database) or an atomic add (cache).
type service struct {
	g       *wiring.Graph
	s       settings
	secrets *secrets
}

// envelope is the data of core's login envelope, or of its mfa_required answer.
type envelope = map[string]any

func (v *service) now() time.Time { return v.g.Clock.Now().UTC().Truncate(time.Second) }

// user is the account with id; ok is false when there is none.
func (v *service) user(ctx context.Context, id string) (model.User, bool, error) {
	u, err := v.g.Repos.Users.Get(ctx, id)
	if errors.Is(err, repository.ErrNotFound) {
		return model.User{}, false, nil
	}
	return u, err == nil, err
}

// byEmail is the account of a normalized address; ok is false when there is none.
func (v *service) byEmail(ctx context.Context, email string) (model.User, bool, error) {
	u, err := v.g.Repos.Users.ByEmail(ctx, email)
	if errors.Is(err, repository.ErrNotFound) {
		return model.User{}, false, nil
	}
	return u, err == nil, err
}

// forEmail is the account that owns a proven address: created verified and without a password
// when nobody does and sign-up is on; an unverified owner becomes verified and loses a password
// nobody proved the mailbox for (account pre-hijacking).
func (v *service) forEmail(ctx context.Context, email string) (model.User, error) {
	email = identity.NormalizeEmail(email)
	u, found, err := v.byEmail(ctx, email)
	if err != nil {
		return model.User{}, err
	}
	now := v.now()
	if !found {
		if !v.s.signUp {
			return model.User{}, errCodeInvalid
		}
		u = model.User{ID: repository.NewID(), Email: email, EmailVerifiedAt: &now, Status: model.UserStatusActive, CreatedAt: now, UpdatedAt: now}
		err := v.g.Repos.Users.Insert(ctx, u)
		if errors.Is(err, store.ErrDuplicate) { // a concurrent sign-up of the same address won
			return v.forEmail(ctx, email)
		}
		return u, err
	}
	if u.EmailVerifiedAt != nil {
		return u, nil
	}
	// Whoever registered the address never proved it: a password they set is not the mailbox
	// owner's, so it goes (the owner can set one by reset). Conditional, so one sign-in verifies.
	verified, err := v.g.DB.Update(ctx, "auth_users", store.Criteria{"id": u.ID, "email_verified_at": nil}, store.Data{
		"email_verified_at": now, "password_hash": nil, "failed_login_count": 0, "failed_login_at": nil,
		"locked_until": nil, "updated_at": now,
	})
	if err != nil {
		return model.User{}, err
	}
	if verified == 1 {
		v.g.Events.Dispatch(ctx, event.UserEmailVerified{UserID: u.ID, Email: u.Email})
	}
	u.EmailVerifiedAt, u.PasswordHash = &now, nil
	return u, nil
}

// facts are how a session authenticated; a one-time token carries its generating session's.
type facts struct {
	amr            []string
	gate           bool // core's MFA gate applies
	organizationID string
	mfa            bool
	authTime       *int64
}

// open opens a session for a user who just proved a factor: core's mfa_required answer when the
// user has a confirmed second factor and the gate applies, the login envelope otherwise.
func (v *service) open(ctx context.Context, u model.User, f facts) (envelope, error) {
	if u.Status == model.UserStatusDisabled {
		return nil, errDisabled
	}
	if f.gate && v.s.respectMFA {
		factors, err := v.g.MFA.ConfirmedFactors(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		if len(factors) > 0 {
			ch, err := v.g.MFA.BeginLogin(u.ID, factors)
			if err != nil {
				return nil, err
			}
			return envelope{"mfa_required": true, "mfa_token": ch.MFAToken, "factors": ch.Factors}, nil
		}
	}
	now := v.now()
	principal, err := v.g.Principals.Resolve(ctx, u.ID, f.organizationID)
	if err != nil {
		return nil, err
	}
	authTime := now.Unix()
	if f.authTime != nil {
		authTime = *f.authTime
	}
	principal.EmailVerified, principal.MFA, principal.AMR, principal.AuthTime = u.EmailVerifiedAt != nil, f.mfa, f.amr, &authTime
	client := endpoint.Client(ctx)
	var tokens token.IssuedTokens
	err = v.g.DB.Tx(ctx, func(ctx context.Context) error {
		if _, err := v.g.DB.Update(ctx, "auth_users", store.Criteria{"id": u.ID}, store.Data{"last_login_at": now, "updated_at": now}); err != nil {
			return err
		}
		var err error
		tokens, err = v.g.Sessions.Issue(ctx, principal, client)
		return err
	})
	if err != nil {
		return nil, err
	}
	v.g.Events.Dispatch(ctx, event.UserLoggedIn{UserID: u.ID, SessionID: tokens.SessionID, IP: optional(client.IP), UserAgent: optional(client.UserAgent), AMR: f.amr})
	return envelope{
		"access_token": tokens.AccessToken, "token_type": "Bearer", "expires_in": tokens.AccessExpiresIn,
		"refresh_token": tokens.RefreshToken,
		"user":          map[string]any{"id": u.ID, "email": u.Email, "email_verified": u.EmailVerifiedAt != nil},
	}, nil
}

func handOffKey(code string) string {
	sum := sha256.Sum256([]byte(code))
	return "polaris.passwordless.code." + hex.EncodeToString(sum[:])
}

// handOff keeps an envelope behind a one-minute, one-use code; the code.
func (v *service) handOff(ctx context.Context, e envelope) (string, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	code := newToken()
	return code, v.g.Cache.Set(ctx, handOffKey(code), b, handOffTTL)
}

// exchange is the envelope a hand-off code stands for, once: the first caller to add the code's
// spent marker wins (cache.Cache.Add is atomic), so two concurrent exchanges cannot both get it.
func (v *service) exchange(ctx context.Context, code string) (envelope, error) {
	key := handOffKey(code)
	b, found, err := v.g.Cache.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errTokenInvalid
	}
	won, err := v.g.Cache.Add(ctx, key+".spent", []byte("1"), handOffTTL)
	if err != nil {
		return nil, err
	}
	if !won {
		return nil, errTokenInvalid
	}
	if err := v.g.Cache.Delete(ctx, key); err != nil {
		v.g.Logger.WarnContext(ctx, "polaris passwordless: spent hand-off code not deleted", "error", err)
	}
	var e envelope
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("passwordless: hand-off: %w", err)
	}
	return e, nil
}

// optional maps "" (no value) to nil, as upstream's nullable strings.
func optional(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}
