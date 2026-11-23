package anonymous

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
	"github.com/univeros/polaris.go/wiring"
)

// Guest constants.
const (
	// AMR is the authentication method of a guest session.
	AMR = "anonymous"
	// EmailDomain is the placeholder domain of a guest's email (RFC 2606: it receives nothing).
	EmailDomain = "anonymous.invalid"
	// ActorSystem is the actor of the event.UserDeleted a prune dispatches.
	ActorSystem = "system"
)

// userTables are core's rows keyed by user_id, deleted with a pruned guest.
var userTables = []string{"auth_refresh_tokens", "auth_mfa_factors", "auth_otp_challenges", "auth_recovery_codes", "auth_email_verifications", "auth_password_resets"}

// errConverted aborts a prune transaction for a guest converted meanwhile.
var errConverted = errors.New("anonymous: converted meanwhile")

// Guests signs guests in, converts them and prunes the unconverted ones. Safe for concurrent use:
// a conversion and a prune both claim the guest row with a conditional write, so a guest is
// converted once and never deleted once converted.
type Guests struct {
	g          *wiring.Graph
	onConvert  func(ctx context.Context, guestID, userID string) error
	pruneAfter time.Duration
}

// SignIn creates a guest and opens its session (amr ["anonymous"], no organization): the user, the
// guest row and the session in one transaction.
func (s *Guests) SignIn(ctx context.Context, client token.ClientContext) (token.IssuedTokens, model.User, error) {
	now := s.g.Clock().Now()
	id := repository.NewID()
	user := model.User{ID: id, Email: id + "@" + EmailDomain, Status: model.UserStatusActive, LastLoginAt: &now, CreatedAt: now, UpdatedAt: now}
	authTime := now.Unix()
	var tokens token.IssuedTokens
	err := s.g.DB().Tx(ctx, func(ctx context.Context) error {
		if err := s.g.Identity().InsertUser(ctx, user); err != nil {
			return err
		}
		if err := s.g.DB().Insert(ctx, TableGuests, store.Row{"user_id": id, "created_at": now, "converted_at": nil, "converted_user_id": nil}); err != nil {
			return err
		}
		var err error
		tokens, err = s.g.Sessions().Issue(ctx, token.SessionPrincipal{UserID: id, AMR: []string{AMR}, AuthTime: &authTime}, client)
		return err
	})
	if err != nil {
		return token.IssuedTokens{}, model.User{}, fmt.Errorf("anonymous: sign-in: %w", err)
	}
	s.g.Events().Dispatch(ctx, event.UserLoggedIn{UserID: id, SessionID: tokens.SessionID, IP: optional(client.IP), UserAgent: optional(client.UserAgent), AMR: []string{AMR}})
	return tokens, user, nil
}

// IsGuest reports whether userID is a guest (converted or not).
func (s *Guests) IsGuest(ctx context.Context, userID string) (bool, error) {
	n, err := s.g.DB().Count(ctx, TableGuests, store.Criteria{"user_id": userID})
	return n > 0, err
}

// Convert converts guestID into the account whose access token is accessToken and returns that
// account's id. It is one transaction: the guest row is claimed (so two concurrent conversions
// cannot both run the hook), the hook runs with the transaction in its ctx, the guest is disabled
// and its sessions end. Any failure, the hook's included, rolls all of it back: the guest keeps its
// sessions and can retry, and a guest is never reported converted while its sessions live.
// ErrNotAGuest: guestID is not a guest waiting;
// ErrTokenInvalid: accessToken is not a live session of another, real account.
func (s *Guests) Convert(ctx context.Context, guestID, accessToken string) (string, error) {
	guest, err := s.g.DB().FindOne(ctx, TableGuests, store.Criteria{"user_id": guestID})
	if err != nil {
		return "", fmt.Errorf("anonymous: convert: %w", err)
	}
	if guest == nil || guest["converted_at"] != nil {
		return "", ErrNotAGuest
	}
	userID, err := s.liveSubject(ctx, accessToken)
	if err != nil {
		return "", err
	}
	if userID == guestID {
		return "", ErrTokenInvalid
	}
	isGuest, err := s.IsGuest(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("anonymous: convert: %w", err)
	}
	if isGuest {
		return "", ErrTokenInvalid
	}
	now := s.g.Clock().Now()
	err = s.g.DB().Tx(ctx, func(ctx context.Context) error {
		// The user before the user's rows, the order a session and Prune lock them in.
		if _, err := s.g.DB().Update(ctx, "auth_users", store.Criteria{"id": guestID}, store.Data{"id": guestID}); err != nil {
			return err
		}
		claimed, err := s.g.DB().Update(ctx, TableGuests, store.Criteria{"user_id": guestID, "converted_at": nil},
			store.Data{"converted_at": now, "converted_user_id": userID})
		if err != nil {
			return err
		}
		if claimed != 1 {
			return ErrNotAGuest
		}
		if s.onConvert != nil {
			if err := s.onConvert(ctx, guestID, userID); err != nil {
				return fmt.Errorf("OnConvert: %w", err)
			}
		}
		if _, err := s.g.DB().Update(ctx, "auth_users", store.Criteria{"id": guestID}, store.Data{"status": model.UserStatusDisabled, "updated_at": now}); err != nil {
			return err
		}
		// Last: it also watermarks the denylist, which a rollback cannot undo.
		_, err = s.g.Sessions().RevokeAll(ctx, guestID, model.RevokedLogout)
		return err
	})
	switch {
	case errors.Is(err, ErrNotAGuest):
		return "", ErrNotAGuest
	case err != nil:
		return "", fmt.Errorf("anonymous: convert: %w", err)
	}
	return userID, nil
}

// liveSubject is the subject of a valid access token whose session is still live.
func (s *Guests) liveSubject(ctx context.Context, accessToken string) (string, error) {
	tok, err := s.g.Tokens().Parse(accessToken)
	if err != nil {
		return "", ErrTokenInvalid
	}
	subject := tok.Subject()
	sid, _ := tok.Claim("sid").(string)
	if subject == "" || sid == "" {
		return "", ErrTokenInvalid
	}
	live, err := s.g.DB().FindOne(ctx, "auth_refresh_tokens", store.Criteria{"family_id": sid, "user_id": subject, "revoked_at": nil,
		"expires_at": store.Gt(s.g.Clock().Now())})
	if err != nil {
		return "", fmt.Errorf("anonymous: convert: %w", err)
	}
	if live == nil {
		return "", ErrTokenInvalid
	}
	return subject, nil
}

// Prune deletes the unconverted guests older than the policy with their core rows (sessions,
// factors, challenges, recovery codes, verifications, resets, the user), one transaction per
// guest, and dispatches event.UserDeleted (actor ActorSystem) for each so the host drops what it
// kept. It returns how many it deleted. A guest converted while the prune runs is kept.
func (s *Guests) Prune(ctx context.Context) (int, error) {
	before := s.g.Clock().Now().Add(-s.pruneAfter)
	rows, err := s.g.DB().FindMany(ctx, TableGuests, store.Criteria{"converted_at": nil, "created_at": store.Lt(before)}, store.Query{})
	if err != nil {
		return 0, fmt.Errorf("anonymous: prune: %w", err)
	}
	pruned := 0
	for _, row := range rows {
		guestID := row.String("user_id")
		err := s.g.DB().Tx(ctx, func(ctx context.Context) error {
			// The user before the user's rows, the order a session locks them in.
			if _, err := s.g.DB().Update(ctx, "auth_users", store.Criteria{"id": guestID}, store.Data{"id": guestID}); err != nil {
				return err
			}
			n, err := s.g.DB().Delete(ctx, TableGuests, store.Criteria{"user_id": guestID, "converted_at": nil})
			if err != nil {
				return err
			}
			if n != 1 {
				return errConverted
			}
			for _, table := range userTables {
				if _, err := s.g.DB().Delete(ctx, table, store.Criteria{"user_id": guestID}); err != nil {
					return err
				}
			}
			if err := s.g.Identity().OnUserDeleted(ctx, guestID); err != nil { // before the row: host rows may reference it
				return err
			}
			_, err = s.g.DB().Delete(ctx, "auth_users", store.Criteria{"id": guestID})
			return err
		})
		if errors.Is(err, errConverted) {
			continue
		}
		if err != nil {
			return pruned, fmt.Errorf("anonymous: prune %s: %w", guestID, err)
		}
		s.g.Events().Dispatch(ctx, event.UserDeleted{UserID: guestID, ActorUserID: ActorSystem})
		pruned++
	}
	return pruned, nil
}

// optional maps "" (no value) to nil, so an absent string is written as null.
func optional(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}
