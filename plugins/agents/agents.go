package agents

import (
	"context"
	"errors"
	"github.com/univeros/polaris.go/wiring"
	"log/slog"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

// noGrantScope is the client scope of an agent without a live grant: the provider reads an empty
// list as "any scope", so the agent keeps the harmless profile scope and can mint only a token for
// its own routes.
const noGrantScope = oauth.ScopeProfile

// service holds what every part of the plugin works with. Each method that writes more than one
// row runs in one transaction; events are dispatched after it commits.
type service struct {
	db       store.Adapter
	clock    clock.Clock
	events   event.Dispatcher
	log      *slog.Logger
	oauth    *oauth.Plugin
	resolver wiring.Resolver
	gate     wiring.Gate
	pepper   wiring.Pepper
	codec    *token.Codec
	mfa      interface {
		HasConfirmedFactor(ctx context.Context, userID string) (bool, error)
	}
	stepUpMaxAge time.Duration
	settings     settings
	caps         *capabilities
	jwts         *requestJWTs
}

func (s *service) now() time.Time { return s.clock.Now().UTC().Truncate(time.Second) }

func (s *service) dispatch(ctx context.Context, events ...Event) {
	for _, e := range events {
		s.events.Dispatch(ctx, e)
	}
}

// displayName is an agent's or host's name trimmed (strings.TrimSpace: a label, never looked up),
// ok when it is 1 to 160 characters with no control character: a NUL would reach the store,
// which PostgreSQL refuses.
func displayName(s string) (string, bool) {
	s = strings.TrimSpace(s)
	ok := s != "" && utf8.RuneCountInString(s) <= 160 && !strings.ContainsFunc(s, unicode.IsControl)
	return s, ok
}

// createAgent registers the agent and its OAuth client (no organization: the plugin manages it, so
// the organization's client routes never see it); the secret is returned for client_secret.
func (s *service) createAgent(ctx context.Context, fields map[string]any, owner Agent) (Agent, string, error) {
	name, _ := fields["name"].(string)
	name, validName := displayName(name)
	mode, auth := fields["mode"], fields["auth"]
	if mode == nil {
		mode = ModeDelegated
	}
	if auth == nil {
		auth = AuthPrivateKeyJWT
	}
	if !validName {
		return Agent{}, "", refuse(ErrInvalidInput, "name is required, at most 160 characters.")
	}
	m, _ := mode.(string)
	if !slices.Contains(modes, m) {
		return Agent{}, "", refuse(ErrInvalidInput, "mode is delegated or autonomous.")
	}
	a, _ := auth.(string)
	if !slices.Contains(auths, a) {
		return Agent{}, "", refuse(ErrInvalidInput, "auth is private_key_jwt, client_secret or delegated_token.")
	}
	if a == AuthDelegatedToken && m != ModeDelegated {
		return Agent{}, "", refuse(ErrInvalidInput, "delegated_token authenticates a delegated agent only: an autonomous agent needs a key or a secret.")
	}
	agent := owner
	agent.Name, agent.Mode, agent.Auth, agent.Status = name, m, a, StatusActive
	if a == AuthPrivateKeyJWT {
		jwk, err := publicJWK(fields["jwk"])
		if err != nil {
			return Agent{}, "", err
		}
		agent.PublicJWK = jwk
	}
	agent.CreatedAt = s.now()
	agent.UpdatedAt = agent.CreatedAt
	issued, err := s.oauth.CreateClient(ctx, clientFields(agent), "", agent.CreatedBy, false)
	if err != nil {
		var oe *oauth.Error
		if errors.As(err, &oe) {
			return Agent{}, "", refuse(ErrInvalidInput, "The agent's OAuth client could not be registered: "+oe.Description)
		}
		return Agent{}, "", err
	}
	agent.ID = issued.Client.ClientID
	if err := s.db.Insert(ctx, TableAgents, agent.row()); err != nil {
		return Agent{}, "", err
	}
	return agent, issued.Secret, nil
}

// clientFields is the agent's OAuth client: the mode decides the grant, auth the method.
func clientFields(a Agent) oauth.ClientFields {
	f := oauth.ClientFields{"name": a.Name, "type": oauth.TypeConfidential, "scopes": []any{noGrantScope},
		"grant_types": []any{oauth.GrantTokenExchange}}
	if a.Mode == ModeAutonomous {
		f["grant_types"] = []any{oauth.GrantClientCredentials}
	}
	switch a.Auth {
	case AuthPrivateKeyJWT:
		f["token_endpoint_auth_method"] = oauth.AuthPrivateKeyJWT
		f["jwks"] = map[string]any{"keys": []any{a.PublicJWK}}
	case AuthClientSecret:
		f["token_endpoint_auth_method"] = oauth.AuthSecretBasic
	default:
		f["type"], f["token_endpoint_auth_method"] = oauth.TypePublic, oauth.AuthNone
	}
	return f
}

// agent finds an agent by id; ok is false when there is none.
func (s *service) agent(ctx context.Context, id string) (Agent, bool, error) {
	if id == "" {
		return Agent{}, false, nil
	}
	row, err := s.db.FindOne(ctx, TableAgents, store.Criteria{"id": id})
	if err != nil || row == nil {
		return Agent{}, false, err
	}
	return agentFromRow(row), true, nil
}

func (s *service) agentsWhere(ctx context.Context, c store.Criteria) ([]Agent, error) {
	rows, err := s.db.FindMany(ctx, TableAgents, c, store.Query{OrderBy: []store.Order{{Column: "id"}}})
	if err != nil {
		return nil, err
	}
	out := make([]Agent, 0, len(rows))
	for _, r := range rows {
		out = append(out, agentFromRow(r))
	}
	return out, nil
}

// transition moves an agent from one status to another with a conditional update.
func (s *service) transition(ctx context.Context, a Agent, from, to, otherwise string) (Agent, error) {
	now := s.now()
	n, err := s.db.Update(ctx, TableAgents, store.Criteria{"id": a.ID, "status": from}, store.Data{"status": to, "updated_at": now})
	if err != nil {
		return a, err
	}
	if n != 1 {
		return a, refuse(ErrConflict, otherwise)
	}
	a.Status, a.UpdatedAt = to, now
	return a, nil
}

// revoke is the kill switch, in one transaction: the agent revoked (once), its OAuth client
// disabled and every token of it revoked, its live and pending grants revoked, its pending
// approvals cancelled and its receipt chain sealed. byUserID is the person pulling it ("" for the
// system or an operator key); the agent.revoked and agent.receipt.sealed events follow.
func (s *service) revoke(ctx context.Context, a Agent, byUserID, how string, c client) (Agent, Receipt, error) {
	var sealed Receipt
	var grants int64
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		now := s.now()
		n, err := s.db.Update(ctx, TableAgents, store.Criteria{"id": a.ID, "status": []string{StatusActive, StatusSuspended}},
			store.Data{"status": StatusRevoked, "sealed_at": now, "updated_at": now})
		if err != nil {
			return err
		}
		if n != 1 {
			return refuse(ErrConflict, "The agent is already revoked.")
		}
		a.Status, a.SealedAt, a.UpdatedAt = StatusRevoked, &now, now
		if cl, err := s.oauth.Client(ctx, a.ID); err == nil {
			if _, _, err := s.oauth.UpdateClient(ctx, cl, oauth.ClientFields{"disabled": true}, false); err != nil {
				return err
			}
		} else if !errors.Is(err, oauth.ErrClientNotFound) {
			return err
		}
		if _, err := s.oauth.RevokeClientTokens(ctx, a.ID); err != nil {
			return err
		}
		if grants, err = s.db.Update(ctx, TableGrants, store.Criteria{"agent_id": a.ID, "status": []string{GrantActive, GrantPending}},
			store.Data{"status": GrantRevoked, "updated_at": now}); err != nil {
			return err
		}
		if _, err := s.db.Update(ctx, TableApprovals, store.Criteria{"agent_id": a.ID, "status": ApprovalPending},
			store.Data{"status": ApprovalCancelled, "updated_at": now}); err != nil {
			return err
		}
		sealed, err = s.appendReceipt(ctx, a, nil, "", inputHash(map[string]any{}), OutcomeSealed, nil, nil)
		return err
	})
	if err != nil {
		return a, Receipt{}, err
	}
	data := map[string]any{"name": a.Name, "how": how, "grants_revoked": grants, "sealed_receipt_id": sealed.ID}
	revoked := bySystem(EventRevoked, a, data)
	if byUserID != "" {
		revoked = byUser(EventRevoked, a, byUserID, data, c)
	}
	s.dispatch(ctx, revoked, bySystem(EventReceiptSealed, a, map[string]any{"receipt_id": sealed.ID, "seq": sealed.Seq, "hash": sealed.Hash}))
	return a, sealed, nil
}

// erase leaves nothing of an agent: its client and tokens, grants, approvals and receipts.
func (s *service) erase(ctx context.Context, a Agent) error {
	return s.db.Tx(ctx, func(ctx context.Context) error {
		cl, err := s.oauth.Client(ctx, a.ID)
		switch {
		case err == nil:
			if err := s.oauth.DeleteClient(ctx, cl); err != nil {
				return err
			}
		case !errors.Is(err, oauth.ErrClientNotFound):
			return err
		}
		for _, table := range []string{TableGrants, TableApprovals, TableReceipts} {
			if _, err := s.db.Delete(ctx, table, store.Criteria{"agent_id": a.ID}); err != nil {
				return err
			}
		}
		_, err = s.db.Delete(ctx, TableAgents, store.Criteria{"id": a.ID})
		return err
	})
}

// eraseWhere erases every agent the criteria select.
func (s *service) eraseWhere(ctx context.Context, criteria ...store.Criteria) error {
	for _, c := range criteria {
		list, err := s.agentsWhere(ctx, c)
		if err != nil {
			return err
		}
		for _, a := range list {
			if err := s.erase(ctx, a); err != nil {
				return err
			}
		}
	}
	return nil
}

// revokeForMember: a member who leaves takes the organization's agents they registered with them.
func (s *service) revokeForMember(ctx context.Context, orgID, userID string) error {
	list, err := s.agentsWhere(ctx, store.Criteria{"owner_type": OwnerOrganization, "owner_id": orgID, "created_by": userID})
	if err != nil {
		return err
	}
	var errs []error
	for _, a := range list {
		if a.Status == StatusRevoked {
			continue
		}
		if _, _, err := s.revoke(ctx, a, "", "member_removed", client{}); err != nil {
			if e, ok := asError(err); !ok || e.Type != ErrConflict {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// newID is a UUIDv7.
func newID() string { return repository.NewID() }
