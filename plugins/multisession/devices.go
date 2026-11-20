package multisession

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/univeros/polaris.go/wiring"
	"slices"
	"strings"
	"time"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

// Refusals; each names a problem type multi-session/<name>.
var (
	errDeviceUnknown   = errors.New("This session is not signed in on a known device.")
	errSessionNotFound = errors.New("No live session of this device has this id.")
)

// dateAtom is PHP's DATE_ATOM: UTC is written "+00:00".
const dateAtom = "2006-01-02T15:04:05-07:00"

const tableSessions = "auth_refresh_tokens"

// devices holds the accounts signed in on each device. Only the SHA-256 of a device id is stored.
type devices struct {
	db         store.Adapter
	repos      *repository.Repos
	sessions   wiring.Sessions
	principals wiring.Principals
	clock      clock.Clock
}

// mint returns a new device id: 256 random bits, hex.
func mint() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // never fails (crypto/rand panics on an unusable source)
	return hex.EncodeToString(b)
}

func hash(deviceID string) string {
	sum := sha256.Sum256([]byte(deviceID))
	return hex.EncodeToString(sum[:])
}

func (d *devices) now() time.Time { return d.clock.Now().UTC().Truncate(time.Second) }

// known reports whether the server minted deviceID (some account is on it).
func (d *devices) known(ctx context.Context, deviceID string) (bool, error) {
	n, err := d.db.Count(ctx, TableDevices, store.Criteria{"device_id": hash(deviceID)})
	return n > 0, err
}

// record notes that the device holds this session of the account and returns the device id to
// answer. A session the account did not have on the device is a sign-in: its method becomes the
// device's last one, and a device that already had accounts gets a new id (device fixation); a
// refresh or a switch keeps it. One transaction, so a concurrent sign-in cannot interleave the
// rotation with the write.
func (d *devices) record(ctx context.Context, deviceID, userID, sessionID string, amr []string) (string, error) {
	err := d.db.Tx(ctx, func(ctx context.Context) error {
		now, h := d.now(), hash(deviceID)
		row, err := d.db.FindOne(ctx, TableDevices, store.Criteria{"device_id": h, "user_id": userID})
		if err != nil {
			return err
		}
		if row != nil && row.String("session_id") == sessionID {
			_, err = d.db.Update(ctx, TableDevices, store.Criteria{"id": row.String("id")}, store.Data{"last_seen": now})
			return err
		}
		n, err := d.db.Count(ctx, TableDevices, store.Criteria{"device_id": h})
		if err != nil {
			return err
		}
		if n > 0 {
			deviceID = mint()
			if _, err = d.db.Update(ctx, TableDevices, store.Criteria{"device_id": h}, store.Data{"device_id": hash(deviceID)}); err != nil {
				return err
			}
			h = hash(deviceID)
		}
		method := "pwd"
		if len(amr) > 0 {
			method = amr[0]
		}
		signIn := store.Data{"device_id": h, "session_id": sessionID, "last_method": method,
			"sign_in_id": repository.NewID(), "signed_in_at": now, "last_seen": now}
		if row != nil {
			_, err = d.db.Update(ctx, TableDevices, store.Criteria{"id": row.String("id")}, signIn)
			return err
		}
		signIn["id"], signIn["user_id"] = repository.NewID(), userID
		return d.db.Insert(ctx, TableDevices, store.Row(signIn))
	})
	if err != nil {
		return "", fmt.Errorf("multisession: record: %w", err)
	}
	return deviceID, nil
}

// lastMethod is the method of the device's most recent sign-in; nil for an unknown device.
func (d *devices) lastMethod(ctx context.Context, deviceID string) (*string, error) {
	if deviceID == "" {
		return nil, nil
	}
	rows, err := d.db.FindMany(ctx, TableDevices, store.Criteria{"device_id": hash(deviceID)},
		store.Query{OrderBy: []store.Order{{Column: "sign_in_id", Desc: true}}, Limit: 1})
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	m := rows[0].String("last_method")
	return &m, nil
}

// list is the device's live sessions, the most recent sign-in first.
func (d *devices) list(ctx context.Context, deviceID, currentSessionID string) ([]map[string]any, error) {
	rows, err := d.live(ctx, deviceID, currentSessionID)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		u, err := d.repos.Users.Get(ctx, row.String("user_id"))
		if errors.Is(err, repository.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		signedIn, _ := row.Time("signed_in_at")
		seen, _ := row.Time("last_seen")
		out = append(out, map[string]any{
			"session_id":   row.String("session_id"),
			"user":         map[string]any{"id": u.ID, "email": u.Email, "display_name": u.DisplayName},
			"last_method":  row.String("last_method"),
			"signed_in_at": signedIn.UTC().Format(dateAtom),
			"last_seen":    seen.UTC().Format(dateAtom),
			"current":      row.String("session_id") == currentSessionID,
		})
	}
	return out, nil
}

// switchTo opens a fresh session for the account behind another live session of the device, with
// the authentication facts core stored on that session (amr, mfa, auth_time, organization), and
// ends the old one. The old session is claimed by a conditional update in the same transaction as
// the new one is opened, so two concurrent switches cannot both mint from it.
func (d *devices) switchTo(ctx context.Context, deviceID, currentSessionID, sessionID string, client token.ClientContext) (token.IssuedTokens, model.User, error) {
	row, err := d.liveRow(ctx, deviceID, currentSessionID, sessionID)
	if err != nil {
		return token.IssuedTokens{}, model.User{}, err
	}
	old, err := d.repos.RefreshTokens.ActiveInFamily(ctx, sessionID)
	if errors.Is(err, repository.ErrNotFound) {
		return token.IssuedTokens{}, model.User{}, errSessionNotFound
	}
	if err != nil {
		return token.IssuedTokens{}, model.User{}, err
	}
	u, err := d.repos.Users.Get(ctx, row.String("user_id"))
	if errors.Is(err, repository.ErrNotFound) || (err == nil && u.Status == model.UserStatusDisabled) {
		return token.IssuedTokens{}, model.User{}, errSessionNotFound
	}
	if err != nil {
		return token.IssuedTokens{}, model.User{}, err
	}
	org := ""
	if old.OrganizationID != nil {
		org = *old.OrganizationID
	}
	p, err := d.principals.Resolve(ctx, u.ID, org)
	if err != nil {
		return token.IssuedTokens{}, model.User{}, err
	}
	p.UserID, p.OrganizationID, p.EmailVerified, p.MFA, p.AuthTime = u.ID, org, u.EmailVerifiedAt != nil, old.MFA, old.AuthTime
	p.AMR = []string{"pwd"}
	if old.AMR != nil {
		if amr := slices.DeleteFunc(strings.Split(*old.AMR, ","), func(m string) bool { return m == "" }); len(amr) > 0 {
			p.AMR = amr
		}
	}
	var issued token.IssuedTokens
	err = d.db.Tx(ctx, func(ctx context.Context) error {
		now := d.now()
		claimed, err := d.db.Update(ctx, tableSessions, store.Criteria{"family_id": sessionID, "revoked_at": nil},
			store.Data{"revoked_at": now, "revoked_reason": model.RevokedRotated})
		if err != nil {
			return err
		}
		if claimed == 0 {
			return errSessionNotFound
		}
		if issued, err = d.sessions.Issue(ctx, p, client); err != nil {
			return err
		}
		_, err = d.db.Update(ctx, TableDevices, store.Criteria{"id": row.String("id")}, store.Data{"session_id": issued.SessionID, "last_seen": now})
		return err
	})
	return issued, u, err
}

// revoke ends one of the device's sessions (the caller's own included) and forgets it.
func (d *devices) revoke(ctx context.Context, deviceID, currentSessionID, sessionID string) error {
	row, err := d.liveRow(ctx, deviceID, currentSessionID, sessionID)
	if err != nil {
		return err
	}
	if err := d.sessions.RevokeFamily(ctx, sessionID, model.RevokedLogout); err != nil {
		return err
	}
	_, err = d.db.Delete(ctx, TableDevices, store.Criteria{"id": row.String("id")})
	return err
}

func (d *devices) liveRow(ctx context.Context, deviceID, currentSessionID, sessionID string) (store.Row, error) {
	rows, err := d.live(ctx, deviceID, currentSessionID)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row.String("session_id") == sessionID {
			return row, nil
		}
	}
	return nil, errSessionNotFound
}

// live is the device's rows whose session is live, newest sign-in first; ended ones are dropped.
// The caller's session must be one of them.
func (d *devices) live(ctx context.Context, deviceID, currentSessionID string) ([]store.Row, error) {
	if deviceID == "" {
		return nil, errDeviceUnknown
	}
	all, err := d.db.FindMany(ctx, TableDevices, store.Criteria{"device_id": hash(deviceID)},
		store.Query{OrderBy: []store.Order{{Column: "sign_in_id", Desc: true}}})
	if err != nil {
		return nil, err
	}
	now := d.now()
	rows := make([]store.Row, 0, len(all))
	current := false
	for _, row := range all {
		live, err := d.db.FindOne(ctx, tableSessions, store.Criteria{"family_id": row.String("session_id"), "revoked_at": nil, "expires_at": store.Gt(now)})
		if err != nil {
			return nil, err
		}
		if live == nil {
			if _, err := d.db.Delete(ctx, TableDevices, store.Criteria{"id": row.String("id")}); err != nil {
				return nil, err
			}
			continue
		}
		current = current || row.String("session_id") == currentSessionID
		rows = append(rows, row)
	}
	if !current {
		return nil, errDeviceUnknown
	}
	return rows, nil
}
