package oauth

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/univeros/polaris-go/identity"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/store"
)

var (
	bindingMessageFormat = regexp.MustCompile(`^[\p{L}\p{N}\p{P}\p{Zs}]+$`)
	uuidFormat           = regexp.MustCompile(`^[0-9a-f-]{36}$`)
)

// BackchannelAuthorization is the CIBA §7.3 response.
type BackchannelAuthorization struct {
	AuthReqID string `json:"auth_req_id"`
	ExpiresIn int    `json:"expires_in"`
	Interval  int    `json:"interval"`
}

// ciba is client-initiated backchannel authentication (OpenID CIBA, poll mode).
type ciba struct {
	poller
	repos *repository.Repos
	ttl   int
}

func (b *ciba) view(p pollable) map[string]any {
	return map[string]any{
		"id": p.ID, "client_id": p.ClientID, "scopes": list(p.Scopes), "binding_message": null(p.BindingMessage),
		"status": p.Status, "expires_at": atom(p.ExpiresAt), "created_at": atom(p.CreatedAt),
	}
}

// request asks the user named by loginHint (their email) to approve a sign-in.
func (b *ciba) request(ctx context.Context, c Client, scopes []string, loginHint, bindingMessage, resource string) (BackchannelAuthorization, pollable, error) {
	if !c.AllowsGrant(GrantCIBA) {
		return BackchannelAuthorization{}, pollable{}, refusal(CodeUnauthorizedClient, "The client may not use the backchannel grant.")
	}
	if loginHint == "" {
		return BackchannelAuthorization{}, pollable{}, refusal(CodeInvalidRequest, "login_hint (the user's email) is required.")
	}
	if bindingMessage != "" && (utf8.RuneCountInString(bindingMessage) > 160 || !bindingMessageFormat.MatchString(bindingMessage)) {
		return BackchannelAuthorization{}, pollable{}, refusal(CodeInvalidRequest, "binding_message is short plain text (at most 160 characters).")
	}
	user, err := b.repos.Users.ByEmail(ctx, identity.NormalizeEmail(loginHint))
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return BackchannelAuthorization{}, pollable{}, err
	}
	if err != nil || !active(user) {
		return BackchannelAuthorization{}, pollable{}, refusal(CodeUnknownUserID, "No user answers to that hint.")
	}
	now := b.clock.Now()
	p := pollable{
		ID: repository.NewID(), ClientID: c.ClientID, UserID: user.ID, Scopes: list(scopes),
		BindingMessage: bindingMessage, Resource: resource, Status: statusPending,
		ExpiresAt: now.Add(time.Duration(b.ttl) * time.Second), CreatedAt: now,
	}
	scopeJSON, err := store.JSONValue(p.Scopes)
	if err != nil {
		return BackchannelAuthorization{}, pollable{}, err
	}
	err = b.db.Insert(ctx, TableCIBARequests, store.Row{
		"id": p.ID, "client_id": p.ClientID, "user_id": p.UserID, "organization_id": nil, "scopes": scopeJSON,
		"binding_message": null(bindingMessage), "resource": null(resource), "status": statusPending,
		"auth_time": nil, "last_polled_at": nil, "expires_at": p.ExpiresAt, "created_at": now,
	})
	if err != nil {
		return BackchannelAuthorization{}, pollable{}, err
	}
	return BackchannelAuthorization{AuthReqID: p.ID, ExpiresIn: b.ttl, Interval: b.interval}, p, nil
}

// active reports whether u may sign in.
func active(u model.User) bool { return u.Status == "" || u.Status == model.UserStatusActive }

// pending lists the user's undecided, unexpired requests, newest first.
func (b *ciba) pending(ctx context.Context, userID string) ([]pollable, error) {
	rows, err := b.db.FindMany(ctx, TableCIBARequests, store.Criteria{"user_id": userID, "status": statusPending},
		store.Query{OrderBy: []store.Order{{Column: "id", Desc: true}}})
	if err != nil {
		return nil, err
	}
	now := b.clock.Now()
	out := []pollable{}
	for _, r := range rows {
		if p := pollableFromRow(r); p.ExpiresAt.After(now) {
			out = append(out, p)
		}
	}
	return out, nil
}

// decide records the user's answer to a request addressed to them.
func (b *ciba) decide(ctx context.Context, id, userID string, approve bool, organizationID string, authTime *int64) (pollable, error) {
	row, err := b.db.FindOne(ctx, TableCIBARequests, store.Criteria{"id": id, "user_id": userID})
	if err != nil {
		return pollable{}, err
	}
	if row == nil {
		return pollable{}, refusalWith(CodeNotFound, "No such pending request.", http.StatusNotFound)
	}
	p := pollableFromRow(row)
	if !p.ExpiresAt.After(b.clock.Now()) {
		return pollable{}, refusalWith(CodeNotFound, "No such pending request.", http.StatusNotFound)
	}
	status := statusDenied
	if approve {
		status = statusApproved
	}
	n, err := b.db.Update(ctx, TableCIBARequests, store.Criteria{"id": p.ID, "status": statusPending},
		store.Data{"status": status, "organization_id": null(organizationID), "auth_time": store.Nullable(authTime)})
	if err != nil {
		return pollable{}, err
	}
	if n != 1 {
		return pollable{}, refusalWith(CodeInvalidGrant, "The request was already decided.", http.StatusConflict)
	}
	p.Status, p.OrganizationID, p.AuthTime = status, organizationID, authTime
	return p, nil
}

func (b *ciba) pollRequest(ctx context.Context, authReqID string, c Client) (pollable, error) {
	var found *pollable
	if uuidFormat.MatchString(authReqID) {
		row, err := b.db.FindOne(ctx, TableCIBARequests, store.Criteria{"id": authReqID})
		if err != nil {
			return pollable{}, err
		}
		if row != nil {
			p := pollableFromRow(row)
			found = &p
		}
	}
	return b.poll(ctx, found, c, "The auth_req_id is unknown.", "The request expired; ask again.")
}
