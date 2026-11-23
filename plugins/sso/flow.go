package sso

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/identity"
	"github.com/univeros/polaris.go/manifest"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
	"github.com/univeros/polaris.go/wiring"
)

// AMR is the authentication method of an SSO session.
const AMR = "sso"

const (
	stateTTL     = 10 * time.Minute // a sign-in's state
	codeTTL      = time.Minute      // the hand-off code
	replayDrift  = 3 * time.Minute  // kept beyond an assertion's validity
	defaultRole  = "member"
	logoutRevoke = "sso_logout"
)

// Started is where the browser goes to sign in (POST /sso/sign-in). State and Binding tie the
// sign-in to the browser that started it: the route sets Binding in a cookie named after State
// and the callback requires it back (CompleteOIDC, CompleteSAML). Neither is in the JSON answer.
type Started struct {
	URL        string `json:"url"`
	ProviderID string `json:"provider_id"`
	Type       string `json:"type"`
	State      string `json:"-"`
	Binding    string `json:"-"`
}

// state is what a sign-in keeps in the cache until its callback, encrypted.
type state struct {
	ProviderID  string `json:"provider_id"`
	RedirectURI string `json:"redirect_uri"`
	Nonce       string `json:"nonce,omitempty"`
	Verifier    string `json:"verifier,omitempty"`
	RequestID   string `json:"request_id,omitempty"`
	Binding     string `json:"binding,omitempty"` // the nonce of the browser that started the sign-in
}

// session is what a hand-off code stands for: core's login envelope.
type session struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	User         struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	} `json:"user"`
}

// Start answers where to send the browser: the provider of providerID, or the one a verified
// domain routes email to; redirectURI must be one of the provider's ("" for the first).
func (p *Plugin) Start(ctx context.Context, email, providerID, redirectURI string) (Started, error) {
	prov, found, err := p.routeTo(ctx, email, providerID)
	if err != nil {
		return Started{}, err
	}
	if !found {
		return Started{}, refuse(ReasonProviderNotFound, "no provider for the request")
	}
	if !prov.Enabled {
		return Started{}, refuse(ReasonProviderDisabled, "the provider is disabled")
	}
	if redirectURI, err = redirectOf(prov, redirectURI); err != nil {
		return Started{}, err
	}
	st := state{ProviderID: prov.ID, RedirectURI: redirectURI, Binding: hex.EncodeToString(random(16))}
	key := hex.EncodeToString(random(16))
	var target string
	if prov.Type == TypeOIDC {
		st.Nonce, st.Verifier = hex.EncodeToString(random(16)), b64(random(48))
		challenge := sha256.Sum256([]byte(st.Verifier))
		target, err = p.oidc.AuthorizationURL(ctx, prov, p.sp.ACSURL(prov.ID), key, st.Nonce, b64(challenge[:]))
	} else {
		st.RequestID, target, err = p.saml.AuthnRequest(prov, p.sp, key)
	}
	if err != nil {
		return Started{}, err
	}
	if err := p.keep(ctx, "state."+digest(key), st, stateTTL); err != nil {
		return Started{}, err
	}
	return Started{URL: target, ProviderID: prov.ID, Type: prov.Type, State: key, Binding: st.Binding}, nil
}

func (p *Plugin) routeTo(ctx context.Context, email, providerID string) (Provider, bool, error) {
	if providerID != "" {
		return p.providers.Find(ctx, providerID)
	}
	at := strings.LastIndex(strings.ToLower(strings.TrimSpace(email)), "@")
	if at < 0 {
		return Provider{}, false, refuse(ReasonInvalidInput, "an email or a provider_id is required")
	}
	d, verified, err := p.domains.Verified(ctx, strings.ToLower(strings.TrimSpace(email))[at+1:])
	if err != nil || !verified {
		return Provider{}, false, err
	}
	return p.providers.Find(ctx, d.ProviderID)
}

// redirectOf is the application URL a sign-in ends on: requested when it is one of the
// provider's, else the first.
func redirectOf(prov Provider, requested string) (string, error) {
	if requested == "" {
		if len(prov.RedirectURIs) == 0 {
			return "", refuse(ReasonInvalidInput, "the provider has no redirect_uri; pass one")
		}
		return prov.RedirectURIs[0], nil
	}
	if !slices.Contains(prov.RedirectURIs, requested) {
		return "", refuse(ReasonInvalidInput, "redirect_uri is not one of the provider's")
	}
	return requested, nil
}

// CompleteOIDC is the OIDC callback: the application URL to send the browser to, with the
// hand-off code. binding is what the calling browser holds for the state (Started.Binding; the
// route reads its cookie): a sign-in completes only in the browser that started it, so nobody can
// have another person's browser finish a sign-in they began (login CSRF).
func (p *Plugin) CompleteOIDC(ctx context.Context, providerID, code, stateKey, binding, idpError string, client token.ClientContext) (string, error) {
	prov, err := p.enabled(ctx, providerID, TypeOIDC)
	if err != nil {
		return "", err
	}
	st, err := p.takeState(ctx, prov, stateKey, binding, client)
	if err != nil {
		return "", err
	}
	if idpError != "" {
		return "", p.reject(ctx, prov, "the provider answered "+idpError, client)
	}
	if code == "" {
		return "", p.reject(ctx, prov, "no code in the callback", client)
	}
	secret, err := p.providers.Secret(prov)
	if err != nil {
		return "", err
	}
	id, err := p.oidc.Exchange(ctx, prov, secret, code, p.sp.ACSURL(prov.ID), st.Verifier, st.Nonce)
	if err != nil {
		return "", p.reject(ctx, prov, rejected(err).Detail, client)
	}
	return p.finish(ctx, prov, id, st.RedirectURI, client)
}

// CompleteSAML is the SAML assertion consumer (POST binding): the application URL to send the
// browser to, with the hand-off code. Without a RelayState the response is IdP-initiated, accepted
// only when the provider's idp_initiated is set (no browser started it, so nothing binds it: the
// flag accepts that). binding is as for CompleteOIDC.
func (p *Plugin) CompleteSAML(ctx context.Context, providerID, samlResponse, relayState, binding string, client token.ClientContext) (string, error) {
	prov, err := p.enabled(ctx, providerID, TypeSAML)
	if err != nil {
		return "", err
	}
	if samlResponse == "" {
		return "", p.reject(ctx, prov, "no SAMLResponse in the callback", client)
	}
	var requestID, redirectURI string
	switch {
	case relayState != "":
		st, err := p.takeState(ctx, prov, relayState, binding, client)
		if err != nil {
			return "", err
		}
		requestID, redirectURI = st.RequestID, st.RedirectURI
	case prov.Flag("idp_initiated"):
		if redirectURI, err = redirectOf(prov, ""); err != nil {
			return "", err
		}
	default:
		return "", p.reject(ctx, prov, "unsolicited response and the provider does not allow IdP-initiated sign-in", client)
	}
	id, err := p.saml.Consume(prov, p.sp, samlResponse, requestID)
	if err != nil {
		return "", p.reject(ctx, prov, rejected(err).Detail, client)
	}
	if id.AssertionID != "" {
		ttl := stateTTL
		if !id.NotOnOrAfter.IsZero() {
			ttl = max(time.Second, id.NotOnOrAfter.Sub(p.g.Clock().Now())) + replayDrift
		}
		added, err := p.g.Cache().Add(ctx, cacheKey("assertion", digest(id.AssertionID)), []byte{1}, ttl)
		if err != nil {
			return "", err
		}
		if !added {
			return "", p.reject(ctx, prov, "assertion "+id.AssertionID+" replayed", client)
		}
	}
	return p.finish(ctx, prov, id, redirectURI, client)
}

// Exchange answers the login envelope a hand-off code stands for, once.
func (p *Plugin) Exchange(ctx context.Context, code string) (map[string]any, error) {
	var s session
	ok, err := p.take(ctx, "code."+digest(code), &s, codeTTL)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, refuse(ReasonCodeInvalid, "the code is unknown, used or expired")
	}
	return map[string]any{
		"access_token": s.AccessToken, "token_type": s.TokenType, "expires_in": s.ExpiresIn, "refresh_token": s.RefreshToken,
		"user": map[string]any{"id": s.User.ID, "email": s.User.Email, "email_verified": s.User.EmailVerified},
	}, nil
}

// IdPLogout handles an IdP's LogoutRequest: every session of the named user ends; the answer is
// the IdP's URL for the LogoutResponse, "" when the provider has none.
func (p *Plugin) IdPLogout(ctx context.Context, providerID string, m LogoutMessage, client token.ClientContext) (string, error) {
	prov, err := p.enabled(ctx, providerID, TypeSAML)
	if err != nil {
		return "", err
	}
	req, err := p.saml.ConsumeLogoutRequest(prov, p.sp, m)
	if err != nil {
		return "", p.reject(ctx, prov, rejected(err).Detail, client)
	}
	// An organization's IdP ends the sessions of its own members only: whoever runs the IdP signs
	// its LogoutRequests, and an organization admin can run one.
	revoked, userID := 0, ""
	u, err := p.g.Repos().Users.ByEmail(ctx, strings.ToLower(strings.TrimSpace(req.NameID)))
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return "", err
	}
	if err == nil {
		owned, err := p.owns(ctx, prov.OrganizationID, u)
		if err != nil {
			return "", err
		}
		if owned {
			userID = u.ID
			if revoked, err = p.g.Sessions().RevokeAll(ctx, u.ID, logoutRevoke); err != nil {
				return "", err
			}
		}
	}
	p.record(ctx, Event{Name: AuditSLOCompleted, ActorType: audit.ActorSystem, SubjectID: userID, OrganizationID: prov.OrganizationID,
		Data: map[string]any{"provider_id": prov.ID, "direction": "idp", "sessions_revoked": revoked}}, client)
	return p.saml.LogoutResponseURL(prov, p.sp, req.ID, m.RelayState)
}

// Logout is the application's logout of an SSO user: their sessions end here; the answer is
// where to send the browser so the IdP ends its own, "" when the provider offers no single
// logout. providerID "" is the organization's first provider; postLogoutURI must be one of the
// provider's redirect URIs ("" for the first).
func (p *Plugin) Logout(ctx context.Context, u model.User, organizationID, providerID, postLogoutURI string, client token.ClientContext) (string, error) {
	var prov Provider
	found := false
	var err error
	if providerID != "" {
		prov, found, err = p.providers.Find(ctx, providerID)
	} else {
		var all []Provider
		all, err = p.providers.ForOrganization(ctx, organizationID)
		if len(all) > 0 {
			prov, found = all[0], true
		}
	}
	if err != nil {
		return "", err
	}
	if !found || prov.OrganizationID != organizationID {
		return "", refuse(ReasonProviderNotFound, "no provider for the organization")
	}
	if postLogoutURI != "" {
		if postLogoutURI, err = redirectOf(prov, postLogoutURI); err != nil {
			return "", err
		}
	} else if len(prov.RedirectURIs) > 0 {
		postLogoutURI = prov.RedirectURIs[0]
	}
	revoked, err := p.g.Sessions().RevokeAll(ctx, u.ID, logoutRevoke)
	if err != nil {
		return "", err
	}
	var target string
	if prov.Type == TypeOIDC {
		target = p.oidc.EndSessionURL(ctx, prov, postLogoutURI)
	} else if target, err = p.saml.LogoutURL(prov, p.sp, u.Email, "", hex.EncodeToString(random(8))); err != nil {
		return "", err
	}
	p.record(ctx, Event{Name: AuditSLOCompleted, ActorType: audit.ActorUser, ActorID: u.ID, SubjectID: u.ID, OrganizationID: prov.OrganizationID,
		Data: map[string]any{"provider_id": prov.ID, "direction": "sp", "sessions_revoked": revoked}}, client)
	return target, nil
}

// enabled is the provider of a callback: of the type, and enabled.
func (p *Plugin) enabled(ctx context.Context, providerID, typ string) (Provider, error) {
	prov, found, err := p.providers.Find(ctx, providerID)
	if err != nil {
		return prov, err
	}
	if !found || prov.Type != typ {
		return prov, refuse(ReasonProviderNotFound, "no such provider")
	}
	if !prov.Enabled {
		return prov, refuse(ReasonProviderDisabled, "the provider is disabled")
	}
	return prov, nil
}

// takeState claims a sign-in's state once; an unknown, used, expired or foreign one, or one started
// in another browser (binding is not the state's), is a rejection.
func (p *Plugin) takeState(ctx context.Context, prov Provider, key, binding string, client token.ClientContext) (state, error) {
	var st state
	ok := false
	if key != "" {
		var err error
		if ok, err = p.take(ctx, "state."+digest(key), &st, stateTTL); err != nil {
			return st, err
		}
	}
	if !ok || st.ProviderID != prov.ID {
		return st, p.reject(ctx, prov, "unknown or expired state", client)
	}
	if st.Binding == "" || subtle.ConstantTimeCompare([]byte(binding), []byte(st.Binding)) != 1 {
		return st, p.reject(ctx, prov, "the sign-in was started in another browser", client)
	}
	return st, nil
}

// finish signs the identity in: the user (provisioned when the provider allows), the membership,
// an organization-scoped session (amr sso), handed over through a one-time code.
func (p *Plugin) finish(ctx context.Context, prov Provider, id Identity, redirectURI string, client token.ClientContext) (string, error) {
	u, provisioned, joined, err := p.provision(ctx, prov, id)
	if err != nil {
		return "", p.recorded(ctx, prov, err, client)
	}
	if joined {
		p.g.Events().Dispatch(ctx, event.MemberJoined{OrganizationID: prov.OrganizationID, UserID: u.ID, Email: u.Email})
	}
	now := p.g.Clock().Now().UTC().Truncate(time.Second)
	authTime := now.Unix()
	var issued token.IssuedTokens
	err = p.g.DB().Tx(ctx, func(ctx context.Context) error {
		// The row is written first, so this and whatever ends the organization's hold on the account
		// (its mailbox's first proof, an operator disabling it) queue on it: one that committed since
		// provision is read here, and one that follows revokes the session issued here.
		if _, err := p.g.DB().Update(ctx, "auth_users", store.Criteria{"id": u.ID}, store.Data{"last_login_at": now, "updated_at": now}); err != nil {
			return err
		}
		if u, err = p.g.Repos().Users.Get(ctx, u.ID); err != nil {
			return err
		}
		if u.Status == model.UserStatusDisabled {
			return refuse(ReasonAccountDisabled, "the account is disabled")
		}
		if err := p.mayLink(ctx, prov, u); err != nil {
			return err
		}
		m, err := p.g.Repos().Memberships.ByUserAndOrganization(ctx, u.ID, prov.OrganizationID)
		switch {
		case errors.Is(err, repository.ErrNotFound):
			return refuse(ReasonUserUnknown, "the membership ended")
		case err != nil:
			return err
		case m.Status == model.MembershipStatusSuspended:
			return refuse(ReasonMembershipSuspended, "the membership is suspended")
		}
		principal, err := p.g.Principals().Resolve(ctx, u.ID, prov.OrganizationID)
		if err != nil {
			return err
		}
		if slices.Contains(principal.Roles, authz.RoleSuperadmin) {
			// The platform override is not an organization's to hand out: an operator signs in to
			// the account itself.
			return refuse(ReasonUserUnknown, "a platform superadmin does not sign in through an organization's identity provider")
		}
		principal.EmailVerified, principal.MFA, principal.AMR, principal.AuthTime = u.EmailVerifiedAt != nil, false, []string{AMR}, &authTime
		issued, err = p.g.Sessions().Issue(ctx, principal, client)
		return err
	})
	if err != nil {
		return "", p.recorded(ctx, prov, err, client)
	}
	p.g.Events().Dispatch(ctx, event.UserLoggedIn{UserID: u.ID, SessionID: issued.SessionID, IP: optional(client.IP), UserAgent: optional(client.UserAgent), AMR: []string{AMR}})
	p.record(ctx, Event{Name: AuditSignedIn, ActorType: audit.ActorUser, ActorID: u.ID, SubjectID: u.ID, OrganizationID: prov.OrganizationID,
		Data: map[string]any{"provider_id": prov.ID, "type": prov.Type, "provisioned": provisioned, "joined": joined}}, client)
	s := session{AccessToken: issued.AccessToken, TokenType: "Bearer", ExpiresIn: issued.AccessExpiresIn, RefreshToken: issued.RefreshToken}
	s.User.ID, s.User.Email, s.User.EmailVerified = u.ID, u.Email, u.EmailVerifiedAt != nil
	code := b64(random(32))
	if err := p.keep(ctx, "code."+digest(code), s, codeTTL); err != nil {
		return "", err
	}
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	return redirectURI + sep + "sso_code=" + code, nil
}

// provision is the user behind an identity and their membership in the provider's organization:
// found by email, or created (no password) when the provider provisions; the membership is created
// with the provider's roles. The provider vouches for a mailbox only on a domain its organization
// verified: there a new account is created verified and an unproven one is proven; anywhere else
// the account stays unverified until its mailbox's owner proves it, which ends the organization's
// hold on it (EraseAccess). One transaction; a concurrent sign-in of the same new
// person re-reads the account it created.
func (p *Plugin) provision(ctx context.Context, prov Provider, id Identity) (u model.User, provisioned, joined bool, err error) {
	for attempt := 0; attempt < 2; attempt++ {
		u, provisioned, joined, err = p.provisionOnce(ctx, prov, id)
		if !errors.Is(err, store.ErrDuplicate) {
			return u, provisioned, joined, err
		}
	}
	return u, provisioned, joined, err
}

func (p *Plugin) provisionOnce(ctx context.Context, prov Provider, id Identity) (u model.User, provisioned, joined bool, err error) {
	email := identity.NormalizeEmail(id.Email)
	vouched, err := p.DomainVerified(ctx, prov.OrganizationID, email[strings.LastIndex(email, "@")+1:])
	if err != nil {
		return u, false, false, err
	}
	err = p.g.DB().Tx(ctx, func(ctx context.Context) error {
		existing, err := p.g.Repos().Users.ByEmail(ctx, email)
		switch {
		case err == nil:
			if existing.Status == model.UserStatusDisabled {
				return refuse(ReasonAccountDisabled, "the account is disabled")
			}
			if err := p.mayLink(ctx, prov, existing); err != nil {
				return err
			}
			u = existing
			if vouched {
				// The organization that verified the domain vouches for the mailbox: for an account
				// nobody had proven, this is the first proof.
				if u, _, err = p.g.Identity().ProveEmail(ctx, existing.ID, false); err != nil {
					return err
				}
			}
		case !errors.Is(err, repository.ErrNotFound):
			return err
		case !prov.JIT.Enabled:
			return refuse(ReasonUserUnknown, "no account for "+email+" and the provider does not provision")
		case !manifest.IsEmail(email):
			return refuse(ReasonAssertionInvalid, "the assertion's email is not an email address")
		default:
			now := p.g.Clock().Now().UTC().Truncate(time.Second)
			u = model.User{ID: repository.NewID(), Email: email, Status: model.UserStatusActive, CreatedAt: now, UpdatedAt: now}
			if vouched {
				u.EmailVerifiedAt = &now
			}
			if id.Name != "" {
				name := id.Name
				u.DisplayName = &name
			}
			if err := p.g.Identity().InsertUser(ctx, u); err != nil {
				return err
			}
			if err := p.markProvisioned(ctx, prov.OrganizationID, u.ID, prov.ID); err != nil {
				return err
			}
			provisioned = true
		}
		joined, err = p.join(ctx, prov, u.ID)
		return err
	})
	return u, provisioned, joined, err
}

// mayLink refuses to sign an existing account in through a provider the account's owner never
// chose: an organization admin runs the organization's IdP and could assert anyone's email. The
// organization must own the account (owns); being a member of it is not enough, since joining an
// organization does not hand it the account.
func (p *Plugin) mayLink(ctx context.Context, prov Provider, u model.User) error {
	owned, err := p.owns(ctx, prov.OrganizationID, u)
	if err != nil || owned {
		return err
	}
	return refuse(ReasonUserUnknown, "an account exists for "+u.Email+" that the organization did not provision and its domain is not verified for the organization")
}

// provisionedBy is what the scim plugin answers (found as g.Plugin("scim")): whether a directory
// of the organization created the account.
type provisionedBy interface {
	Provisioned(ctx context.Context, organizationID string, u model.User) (bool, error)
}

// owns reports whether the organization's identity provider may speak for the account: one of
// its providers provisioned it just in time (TableAccounts), one of its directories did (scim),
// or the account's email is on a domain the organization verified.
func (p *Plugin) owns(ctx context.Context, organizationID string, u model.User) (bool, error) {
	row, err := p.g.DB().FindOne(ctx, TableAccounts, store.Criteria{"organization_id": organizationID, "user_id": u.ID})
	if err != nil || row != nil {
		return row != nil, err
	}
	if directory, ok := p.g.Plugin("scim").(provisionedBy); ok {
		if created, err := directory.Provisioned(ctx, organizationID, u); err != nil || created {
			return created, err
		}
	}
	return p.DomainVerified(ctx, organizationID, u.Email[strings.LastIndex(u.Email, "@")+1:])
}

// EraseAccess implements wiring.AccessEraser: the first proof of the account's mailbox ends what
// the organizations whose providers created it hold over it. An organization that verified the
// account's domain keeps signing it in (owns).
func (p *Plugin) EraseAccess(ctx context.Context, userID string) error {
	_, err := p.g.DB().Delete(ctx, TableAccounts, store.Criteria{"user_id": userID})
	return err
}

// Listeners ends the organizations' hold (EraseAccess) on any account that becomes verified: a
// confirmed registration, the one first proof that removes nothing else (Identity.ProveEmail), runs
// no AccessEraser.
func (p *Plugin) Listeners(*wiring.Graph) []event.Listener {
	return []event.Listener{func(ctx context.Context, e event.Event) {
		if v, ok := e.(event.UserEmailVerified); ok {
			if err := p.EraseAccess(ctx, v.UserID); err != nil {
				p.g.Logger().ErrorContext(ctx, "polaris sso: ending the organizations' hold on a verified account failed", "user_id", v.UserID, "error", err)
			}
		}
	}}
}

// MarkProvisioned records that the organization's identity provider provisioned the account, so
// its providers keep signing it in. The just-in-time path records it itself; a host calls it for
// the accounts a provider created before v0.5.1, when the organization cannot verify their
// email domain. Only for accounts the organization created: its identity provider can sign in as
// them.
func (p *Plugin) MarkProvisioned(ctx context.Context, organizationID, userID string) error {
	return p.markProvisioned(ctx, organizationID, userID, "")
}

func (p *Plugin) markProvisioned(ctx context.Context, organizationID, userID, providerID string) error {
	row, err := p.g.DB().FindOne(ctx, TableAccounts, store.Criteria{"organization_id": organizationID, "user_id": userID})
	if err != nil || row != nil {
		return err
	}
	return p.g.DB().Insert(ctx, TableAccounts, store.Row{"id": repository.NewID(), "organization_id": organizationID, "user_id": userID,
		"provider_id": store.Nullable(optional(providerID)), "created_at": p.g.Clock().Now().UTC().Truncate(time.Second)})
}

// join makes the user an active member with the provider's roles; false when they were one.
func (p *Plugin) join(ctx context.Context, prov Provider, userID string) (bool, error) {
	m, err := p.g.Repos().Memberships.ByUserAndOrganization(ctx, userID, prov.OrganizationID)
	if err == nil {
		if m.Status == model.MembershipStatusSuspended {
			return false, refuse(ReasonMembershipSuspended, "the membership is suspended")
		}
		return false, nil
	}
	if !errors.Is(err, repository.ErrNotFound) {
		return false, err
	}
	now := p.g.Clock().Now().UTC().Truncate(time.Second)
	m = model.Membership{ID: repository.NewID(), UserID: userID, OrganizationID: prov.OrganizationID,
		Status: model.MembershipStatusActive, JoinedAt: &now, CreatedAt: now, UpdatedAt: now}
	if err := p.g.Repos().Memberships.Insert(ctx, m); err != nil {
		return false, err
	}
	slugs := prov.JIT.Roles
	if len(slugs) == 0 {
		slugs = []string{defaultRole}
	}
	orgID := prov.OrganizationID
	for _, slug := range slugs {
		role, err := p.g.Repos().Roles.ByOrganizationAndSlug(ctx, &orgID, slug)
		if errors.Is(err, repository.ErrNotFound) {
			continue
		}
		if err != nil {
			return false, err
		}
		if err := p.g.Repos().MembershipRoles.Insert(ctx, model.MembershipRole{MembershipID: m.ID, RoleID: role.ID}); err != nil {
			return false, err
		}
	}
	return true, nil
}

// recorded records err when it refuses the sign-in, and returns it.
func (p *Plugin) recorded(ctx context.Context, prov Provider, err error, client token.ClientContext) error {
	if e, ok := errors.AsType[*Error](err); ok {
		return p.rejectAs(ctx, prov, e.Reason, e.Detail, client)
	}
	return err
}

// reject records a refused assertion with its reason; the caller reads a generic problem.
func (p *Plugin) reject(ctx context.Context, prov Provider, reason string, client token.ClientContext) *Error {
	return p.rejectAs(ctx, prov, ReasonAssertionInvalid, reason, client)
}

// rejectAs is reject answering another reason.
func (p *Plugin) rejectAs(ctx context.Context, prov Provider, as, reason string, client token.ClientContext) *Error {
	p.record(ctx, Event{Name: AuditAssertionRejected, ActorType: audit.ActorSystem, OrganizationID: prov.OrganizationID,
		Data: map[string]any{"provider_id": prov.ID, "reason": reason}}, client)
	return refuse(as, reason)
}

func (p *Plugin) record(ctx context.Context, e Event, client token.ClientContext) {
	e.IP, e.UserAgent = client.IP, client.UserAgent
	p.g.Events().Dispatch(ctx, e)
}

// keep stores v encrypted in the cache under polaris.sso.<name> (it holds a PKCE verifier and a
// nonce, or session tokens).
func (p *Plugin) keep(ctx context.Context, name string, v any, ttl time.Duration) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	sealed, err := p.g.Encrypter().Encrypt(string(raw))
	if err != nil {
		return err
	}
	return p.g.Cache().Set(ctx, cacheKey(name), []byte(sealed), ttl)
}

// take reads what keep stored, once across every process sharing the cache.
func (p *Plugin) take(ctx context.Context, name string, into any, ttl time.Duration) (bool, error) {
	key := cacheKey(name)
	sealed, ok, err := p.g.Cache().Get(ctx, key)
	if err != nil || !ok {
		return false, err
	}
	if won, err := p.g.Cache().Add(ctx, key+".used", []byte{1}, ttl); err != nil || !won {
		return false, err
	}
	if err := p.g.Cache().Delete(ctx, key); err != nil {
		return false, err
	}
	raw, err := p.g.Encrypter().Decrypt(string(sealed))
	if err != nil {
		return false, nil
	}
	return json.Unmarshal([]byte(raw), into) == nil, nil
}

func cacheKey(parts ...string) string { return "polaris.sso." + strings.Join(parts, ".") }

func random(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	return b
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
