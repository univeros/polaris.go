package oauth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/univeros/polaris-go/clock"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/security"
	"github.com/univeros/polaris-go/store"
)

const (
	devicePepper     = "oauth_device"
	userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"
	userCodeLength   = 8

	statusPending  = "pending"
	statusApproved = "approved"
	statusDenied   = "denied"
	statusUsed     = "used"
)

var nonLetters = regexp.MustCompile(`[^A-Za-z]`)

// pollable is a device code or a backchannel request: who decided, for what, and its state.
type pollable struct {
	ID, ClientID, UserID, OrganizationID string
	Scopes                               []string
	Resource, Status, UserCode           string
	BindingMessage                       string
	AuthTime                             *int64
	LastPolledAt                         *time.Time
	ExpiresAt, CreatedAt                 time.Time
}

func pollableFromRow(r store.Row) pollable {
	p := pollable{
		ID: r.String("id"), ClientID: r.String("client_id"), UserID: r.String("user_id"),
		OrganizationID: r.String("organization_id"), Scopes: stringList(r, "scopes"), Resource: r.String("resource"),
		Status: r.String("status"), UserCode: r.String("user_code"), BindingMessage: r.String("binding_message"),
		AuthTime: intPtr(r, "auth_time"), LastPolledAt: r.TimePtr("last_polled_at"),
	}
	p.ExpiresAt, _ = r.Time("expires_at")
	p.CreatedAt, _ = r.Time("created_at")
	return p
}

// grant is what an approved poll issues tokens for.
func (p pollable) grant() Grant {
	return Grant{UserID: p.UserID, OrganizationID: p.OrganizationID, Scopes: p.Scopes, Resource: p.Resource, AuthTime: p.AuthTime}
}

// poller spends approved requests at the token endpoint, throttling clients that poll too often.
type poller struct {
	db       store.Adapter
	table    string
	interval int
	clock    clock.Clock
	what     string // "device code" or "request", for the messages
}

// poll answers the client's poll: the approved request, spent; or why not yet.
func (p *poller) poll(ctx context.Context, found *pollable, c Client, unknown, expired string) (pollable, error) {
	if found == nil || found.ClientID != c.ClientID {
		return pollable{}, refusal(CodeInvalidGrant, unknown)
	}
	now := p.clock.Now()
	if !found.ExpiresAt.After(now) {
		return pollable{}, refusal(CodeExpiredToken, expired)
	}
	tooSoon := found.LastPolledAt != nil && now.Unix()-found.LastPolledAt.Unix() < int64(p.interval)
	if _, err := p.db.Update(ctx, p.table, store.Criteria{"id": found.ID}, store.Data{"last_polled_at": now}); err != nil {
		return pollable{}, err
	}
	if tooSoon {
		return pollable{}, refusal(CodeSlowDown, fmt.Sprintf("Poll every %d seconds.", p.interval))
	}
	switch found.Status {
	case statusPending:
		return pollable{}, refusal(CodeAuthorizationPending, "The user has not decided yet.")
	case statusDenied:
		return pollable{}, refusal(CodeAccessDenied, "The user refused.")
	case statusApproved:
		n, err := p.db.Update(ctx, p.table, store.Criteria{"id": found.ID, "status": statusApproved}, store.Data{"status": statusUsed})
		if err != nil {
			return pollable{}, err
		}
		if n == 1 {
			spent := *found
			spent.Status = statusUsed
			return spent, nil
		}
	}
	return pollable{}, refusal(CodeInvalidGrant, "The "+p.what+" was already used.")
}

// devices is the device authorization grant (RFC 8628).
type devices struct {
	poller
	pepper    *security.Pepper
	deviceURL string
	ttl       int
}

// DeviceAuthorization is the RFC 8628 §3.2 response.
type DeviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

func (d *devices) start(ctx context.Context, c Client, scopes []string, resource string) (DeviceAuthorization, error) {
	if d.deviceURL == "" {
		return DeviceAuthorization{}, refusal(CodeUnauthorizedClient, "The device flow is not enabled on this server.")
	}
	if !c.AllowsGrant(GrantDeviceCode) {
		return DeviceAuthorization{}, refusal(CodeUnauthorizedClient, "The client may not use the device grant.")
	}
	now := d.clock.Now()
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	deviceCode := b64(buf)
	scopeJSON, err := store.JSONValue(list(scopes))
	if err != nil {
		return DeviceAuthorization{}, err
	}
	var userCode string
	for attempt := 0; ; attempt++ {
		userCode = randomUserCode()
		err = d.db.Insert(ctx, TableDeviceCodes, store.Row{
			"id": repository.NewID(), "device_code_hash": d.pepper.Hash(devicePepper, deviceCode), "user_code": userCode,
			"client_id": c.ClientID, "scopes": scopeJSON, "resource": null(resource), "status": statusPending,
			"user_id": nil, "organization_id": nil, "auth_time": nil, "last_polled_at": nil,
			"expires_at": now.Add(time.Duration(d.ttl) * time.Second), "created_at": now,
		})
		if err == nil || !errors.Is(err, store.ErrDuplicate) || attempt == 3 {
			break
		}
	}
	if err != nil {
		return DeviceAuthorization{}, err
	}
	display := userCode[:4] + "-" + userCode[4:]
	return DeviceAuthorization{
		DeviceCode: deviceCode, UserCode: display, VerificationURI: d.deviceURL,
		VerificationURIComplete: d.deviceURL + "?user_code=" + display, ExpiresIn: d.ttl, Interval: d.interval,
	}, nil
}

func randomUserCode() string {
	var b strings.Builder
	alphabet := big.NewInt(int64(len(userCodeAlphabet)))
	for range userCodeLength {
		n, _ := rand.Int(rand.Reader, alphabet)
		b.WriteByte(userCodeAlphabet[n.Int64()])
	}
	return b.String()
}

// byUserCode is the pending authorization a user code names (dashes and case do not matter).
func (d *devices) byUserCode(ctx context.Context, userCode string) (pollable, error) {
	normalized := strings.ToUpper(nonLetters.ReplaceAllString(userCode, ""))
	var row store.Row
	if len(normalized) == userCodeLength {
		var err error
		if row, err = d.db.FindOne(ctx, TableDeviceCodes, store.Criteria{"user_code": normalized}); err != nil {
			return pollable{}, err
		}
	}
	if row != nil {
		if p := pollableFromRow(row); p.Status == statusPending && p.ExpiresAt.After(d.clock.Now()) {
			return p, nil
		}
	}
	return pollable{}, refusalWith(CodeInvalidGrant, "The code is unknown, used or expired.", http.StatusNotFound)
}

func (d *devices) decide(ctx context.Context, p pollable, approve bool, userID, organizationID string, authTime *int64) error {
	status := statusDenied
	if approve {
		status = statusApproved
	}
	n, err := d.db.Update(ctx, TableDeviceCodes, store.Criteria{"id": p.ID, "status": statusPending},
		store.Data{"status": status, "user_id": userID, "organization_id": null(organizationID), "auth_time": store.Nullable(authTime)})
	if err != nil {
		return err
	}
	if n != 1 {
		return refusalWith(CodeInvalidGrant, "The code was already decided.", http.StatusConflict)
	}
	return nil
}

func (d *devices) pollCode(ctx context.Context, deviceCode string, c Client) (pollable, error) {
	row, err := d.db.FindOne(ctx, TableDeviceCodes, store.Criteria{"device_code_hash": d.pepper.Hash(devicePepper, deviceCode)})
	if err != nil {
		return pollable{}, err
	}
	var found *pollable
	if row != nil {
		p := pollableFromRow(row)
		found = &p
	}
	return d.poll(ctx, found, c, "The device code is unknown.", "The device code expired; start again.")
}
