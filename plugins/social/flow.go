package social

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/univeros/polaris.go/identity"
	"github.com/univeros/polaris.go/internal/strictjson"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

const (
	proxyContext   = "social:proxy"
	proxySeparator = "."
)

// stateEntry is a started flow, in the cache under its state until the callback takes it.
type stateEntry struct {
	Provider    string `json:"provider"`
	RedirectURI string `json:"redirect_uri"`
	Callback    string `json:"callback"`
	Nonce       string `json:"nonce"`
	LinkUserID  string `json:"link_user_id,omitempty"`
	LinkSession string `json:"link_session,omitempty"` // the session the link was started from
	Verifier    string `json:"verifier,omitempty"`
	Binding     string `json:"binding,omitempty"` // the nonce of the browser that started the flow
}

// linker is who links a provider account, from which session of theirs.
type linker struct{ User, Session string }

// started is where the browser goes and the state the application compares at the end.
type started struct {
	URL   string `json:"url"`
	State string `json:"state"`

	binding string // the nonce the starting browser must present at the callback
}

func (p *Plugin) provider(ctx context.Context, id string) (*provider, error) {
	prov, ok := p.providers[id]
	if !ok {
		return nil, refuse(kindProviderNotFound, fmt.Sprintf("No provider %q is configured.", id))
	}
	return prov.resolved(ctx)
}

// start begins a sign-in (linkUserID "") or a link for linkUserID: the authorization URL with a
// state valid StateTTL, PKCE and a nonce where the provider takes them. Through the proxy, the
// provider is sent to the stable origin and the state carries this deployment's callback, signed.
func (p *Plugin) start(ctx context.Context, providerID, redirectURI string, scopes []string, link *linker) (started, error) {
	prov, err := p.provider(ctx, providerID)
	if err != nil {
		return started{}, err
	}
	if redirectURI, err = p.redirectURI(redirectURI); err != nil {
		return started{}, err
	}
	callback := p.settings.callbackURL(providerID)
	state := hex.EncodeToString(random(16))
	if p.settings.proxied() {
		payload, err := json.Marshal(struct {
			ReturnTo string `json:"return_to"`
			Provider string `json:"provider"`
			Exp      int64  `json:"exp"`
		}{callback, providerID, p.g.Clock().Now().Add(p.settings.stateTTL).Unix()})
		if err != nil {
			return started{}, err
		}
		state += proxySeparator + b64(payload)
		state += proxySeparator + p.proxySignature(state)
		callback = p.settings.proxy + "/social/" + providerID + "/callback"
	}
	entry := stateEntry{Provider: providerID, RedirectURI: redirectURI, Callback: callback, Nonce: hex.EncodeToString(random(16)),
		Binding: hex.EncodeToString(random(16))}
	if link != nil {
		entry.LinkUserID, entry.LinkSession = link.User, link.Session
	}
	challenge := ""
	if !prov.def.NoPKCE {
		entry.Verifier = b64(random(48))
		sum := sha256.Sum256([]byte(entry.Verifier))
		challenge = b64(sum[:])
	}
	if err := p.keep(ctx, "state", state, entry, p.settings.stateTTL); err != nil {
		return started{}, err
	}
	return started{URL: prov.authorizationURL(callback, state, scopes, challenge, entry.Nonce), State: state, binding: entry.Binding}, nil
}

// proxySignature signs random.payload under the pepper the deployments share: the base64url of
// the hex digest, the form every deployment behind the proxy must produce alike. It is verified
// by another deployment (the stable origin), which may run an earlier release during a rollout,
// so its form does not change.
func (p *Plugin) proxySignature(signed string) string {
	return b64([]byte(p.g.Pepper().Hash(proxyContext, signed)))
}

func (p *Plugin) redirectURI(requested string) (string, error) {
	allowed := p.settings.redirectURIs
	if requested == "" {
		if len(allowed) == 0 {
			return "", refuse(kindRedirectNotAllowed, "No redirect_uri is configured; pass one of the allowed ones.")
		}
		return allowed[0], nil
	}
	if !slices.Contains(allowed, requested) {
		return "", refuse(kindRedirectNotAllowed, "redirect_uri is not one of the allowed ones.")
	}
	return requested, nil
}

// callback handles the provider's answer: the URL to send the browser to, the application's
// redirect URI with a one-minute hand-off code and the state; or, on the proxy's stable origin,
// the preview's callback with everything the provider sent. browser is the callback request: the
// flow must have been started in it (bound).
func (p *Plugin) callback(ctx context.Context, providerID string, params map[string]any, browser *http.Request, client token.ClientContext) (string, error) {
	state, _ := params["state"].(string)
	forward, err := p.forwardTo(state, providerID)
	if err != nil {
		return "", err
	}
	if forward != "" {
		return appendQuery(forward, flatten(params).encode()), nil
	}
	entry, err := p.takeState(ctx, providerID, state)
	if err != nil {
		return "", err
	}
	if !p.settings.bound(browser, state, entry) {
		return "", refuse(kindStateInvalid, "The flow was started in another browser.")
	}
	prov, err := p.provider(ctx, providerID)
	if err != nil {
		return "", err
	}
	if e, _ := params["error"].(string); e != "" {
		return "", p.reject(ctx, providerID, "the provider answered "+e, client, kindProviderError)
	}
	code, _ := params["code"].(string)
	if code == "" {
		return "", p.reject(ctx, providerID, "no code in the callback", client, kindProviderError)
	}
	t, err := prov.exchange(ctx, code, entry.Callback, entry.Verifier)
	var prof Profile
	if err == nil {
		prof, err = prov.profile(ctx, t, entry.Nonce, params)
	}
	if r, ok := asRefusal(err); ok {
		return "", p.reject(ctx, providerID, r.detail, client, kindProviderError)
	} else if err != nil {
		return "", err
	}
	var link *linker
	if entry.LinkUserID != "" {
		link = &linker{User: entry.LinkUserID, Session: entry.LinkSession}
	}
	outcome, err := p.finish(ctx, prov, prof, t, link, client)
	if err != nil {
		return "", err
	}
	handoff := b64(random(32))
	if err := p.keep(ctx, "code", handoff, outcome, codeTTL); err != nil {
		return "", err
	}
	// The state goes back too, so the application can check it started this flow (login CSRF).
	return appendQuery(entry.RedirectURI, "code="+handoff+"&state="+url.QueryEscape(state)), nil
}

// flatten is the callback's parameters for the preview: strings as they are, anything else JSON.
func flatten(params map[string]any) query {
	var q query
	for _, k := range slices.Sorted(maps.Keys(params)) {
		v, ok := params[k].(string)
		if !ok {
			raw, _ := json.Marshal(params[k])
			v = string(raw)
		}
		q = append(q, [2]string{k, v})
	}
	return q
}

var proxyCallback = regexp.MustCompile(`^https?://[^/?#]+(?:/[^?#]*)?/social/[^/?#]+/callback$`)

// forwardTo is, on the proxy's stable origin, the preview callback a validly signed state names;
// "" when the state is this deployment's own or carries no proxy payload. A forged, expired or
// misdirected payload is state_invalid, so the stable origin is never an open redirector.
func (p *Plugin) forwardTo(state, providerID string) (string, error) {
	parts := strings.Split(state, proxySeparator)
	if len(parts) != 3 {
		return "", nil
	}
	if !hmac.Equal([]byte(p.proxySignature(parts[0]+proxySeparator+parts[1])), []byte(parts[2])) {
		return "", refuse(kindStateInvalid, "The state is not signed by a deployment of this application.")
	}
	raw, err := unb64(parts[1])
	var payload map[string]any
	if err == nil {
		err = strictjson.Decode(raw, &payload)
	}
	exp, isInt := integer(payload["exp"])
	if err != nil || payload["provider"] != providerID || !isInt || exp < p.g.Clock().Now().Unix() {
		return "", refuse(kindStateInvalid, "The state is for another provider or has expired.")
	}
	returnTo, _ := payload["return_to"].(string)
	if !proxyCallback.MatchString(returnTo) {
		return "", refuse(kindStateInvalid, "The state names no callback.")
	}
	if origin(returnTo) == origin(p.settings.baseURL) {
		return "", nil // the preview's own callback: it completes the flow itself
	}
	return returnTo, nil
}

func integer(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

// takeState consumes the flow's state, once.
func (p *Plugin) takeState(ctx context.Context, providerID, state string) (stateEntry, error) {
	if state == "" {
		return stateEntry{}, refuse(kindStateInvalid, "The callback carries no state.")
	}
	var entry stateEntry
	ok, err := p.take(ctx, "state", state, &entry)
	if err != nil {
		return stateEntry{}, err
	}
	if !ok || entry.Provider != providerID {
		return stateEntry{}, refuse(kindStateInvalid, "The state is unknown, used or expired.")
	}
	return entry, nil
}

// exchange is the outcome a hand-off code stands for, once: the login envelope, or the link.
func (p *Plugin) exchange(ctx context.Context, code string) (map[string]any, error) {
	var outcome map[string]any
	ok, err := p.take(ctx, "code", code, &outcome)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, refuse(kindCodeInvalid, "The code is unknown, used or expired.")
	}
	return outcome, nil
}

// idTokenSignIn signs in with an id_token the client obtained itself (Google One Tap), verified
// offline against the provider's keys, then the same policy as a callback.
func (p *Plugin) idTokenSignIn(ctx context.Context, providerID, idToken string, client token.ClientContext) (map[string]any, error) {
	prov, err := p.provider(ctx, providerID)
	if err != nil {
		return nil, err
	}
	prof, err := prov.verifyIDToken(ctx, idToken, nil)
	if r, ok := asRefusal(err); ok && r.kind != kindInvalidInput {
		return nil, p.reject(ctx, providerID, r.detail, client, kindProviderError)
	} else if err != nil {
		return nil, err
	}
	return p.finish(ctx, prov, prof, tokens{scopes: []string{}, idToken: idToken}, nil, client)
}

// finish applies the linking policy, then opens a session or links.
func (p *Plugin) finish(ctx context.Context, prov *provider, prof Profile, t tokens, link *linker, client token.ClientContext) (map[string]any, error) {
	id := prov.id
	prof = prof.normalized()
	if prof.Subject == "" {
		return nil, p.reject(ctx, id, "the profile carries no subject", client, kindProviderError)
	}
	acct, err := p.findAccount(ctx, accountKey(id, prof.Subject))
	if err != nil {
		return nil, err
	}
	if link != nil {
		return p.linkFromSession(ctx, id, prof, t, *link, acct, client)
	}
	signedIn := func(u model.User, linked bool) Event {
		return p.event(EventSignedIn, u.ID, id, map[string]any{"account_id": prof.Subject, "linked": linked}, client)
	}
	if acct != nil {
		u, err := p.user(ctx, acct.UserID)
		if err != nil {
			return nil, err
		}
		if u == nil {
			return nil, p.reject(ctx, id, "the linked user is gone", client, kindProviderError)
		}
		if _, err := p.refreshAccount(ctx, *acct, prof, t); err != nil {
			return nil, err
		}
		p.g.Events().Dispatch(ctx, signedIn(*u, false))
		return p.openSession(ctx, *u, id, client)
	}
	email := ""
	if prof.Email != "" {
		email = identity.NormalizeEmail(prof.Email)
	}
	var existing *model.User
	if email != "" {
		if existing, err = p.userByEmail(ctx, email); err != nil {
			return nil, err
		}
	}
	if existing != nil {
		return p.linkTrusted(ctx, *existing, id, prof, t, client, signedIn)
	}
	if !p.settings.signUp {
		return nil, p.reject(ctx, id, "no account matches this identity and sign-up is off", client, kindAccountExists)
	}
	if email == "" {
		return nil, refuse(kindEmailRequired, "The provider shared no email address; grant the email scope or use another provider.")
	}
	if !prof.EmailVerified && p.g.Auth().Flows.RequireVerifiedEmail {
		// No session would open, and an account and a link made now would wait, in the address's
		// name, for whoever proves the mailbox later: nothing is created.
		return nil, p.reject(ctx, id, "the provider does not vouch for the email address", client, kindEmailUnverified)
	}
	var u model.User
	err = p.g.DB().Tx(ctx, func(ctx context.Context) error {
		var err error
		if u, err = p.createUser(ctx, email, prof.EmailVerified, prof.Name); err != nil {
			return err
		}
		_, err = p.link(ctx, u.ID, id, prof, t)
		return err
	})
	if err != nil {
		return nil, err
	}
	p.g.Events().Dispatch(ctx, p.event(EventSignedUp, u.ID, id, map[string]any{"account_id": prof.Subject}, client))
	return p.openSession(ctx, u, id, client)
}

// linkTrusted links a trusted provider's verified email to the existing user with it; anything
// else is account_exists. A user nobody had proved the mailbox of becomes the provider's user.
func (p *Plugin) linkTrusted(ctx context.Context, u model.User, id string, prof Profile, t tokens, client token.ClientContext, signedIn func(model.User, bool) Event) (map[string]any, error) {
	if !slices.Contains(p.settings.trusted, id) || !prof.EmailVerified {
		p.g.Events().Dispatch(ctx, p.event(EventRejected, u.ID, id, map[string]any{"reason": "account exists; the provider is not trusted to link it"}, client))
		return nil, refuse(kindAccountExists, "An account with this email exists; sign in and link the provider from your account.")
	}
	err := p.g.DB().Tx(ctx, func(ctx context.Context) error {
		// Whoever registered an unverified address did not prove it; the provider just did: the
		// first proof removes what could sign in before (the other providers' links included).
		proven, _, err := p.g.Identity().ProveEmail(ctx, u.ID, false)
		if err != nil {
			return err
		}
		u = proven
		_, err = p.link(ctx, u.ID, id, prof, t)
		return err
	})
	if err != nil {
		return nil, err
	}
	p.g.Events().Dispatch(ctx, p.event(EventLinked, u.ID, id, map[string]any{"account_id": prof.Subject, "trusted": true}, client))
	p.g.Events().Dispatch(ctx, signedIn(u, true))
	return p.openSession(ctx, u, id, client)
}

// linkFromSession links the provider account to the user who started the flow from a session, while
// that session lives: what ended it since (a logout, a reset, the first proof of the mailbox) ends the
// flow too. The check and the link are one transaction that first locks the user's row.
func (p *Plugin) linkFromSession(ctx context.Context, id string, prof Profile, t tokens, by linker, acct *account, client token.ClientContext) (map[string]any, error) {
	var linked account
	err := p.g.DB().Tx(ctx, func(ctx context.Context) error {
		if _, err := p.g.DB().Update(ctx, "auth_users", store.Criteria{"id": by.User}, store.Data{"id": by.User}); err != nil {
			return err
		}
		u, err := p.user(ctx, by.User)
		if err != nil {
			return err
		}
		if u == nil {
			return refuse(kindTokenInvalid, "The session's user is gone.")
		}
		live, err := p.liveSession(ctx, by)
		if err != nil {
			return err
		}
		if !live {
			return refuse(kindTokenInvalid, "The session the link was started from has ended.")
		}
		if acct != nil {
			if acct.UserID != by.User {
				return refuse(kindAccountLinked, "This "+id+" account is linked to another user.")
			}
			linked, err = p.refreshAccount(ctx, *acct, prof, t)
			return err
		}
		if email := identity.NormalizeEmail(prof.Email); prof.Email != "" && email != u.Email && !slices.Contains(p.settings.allowDifferentEmails, id) {
			return refuse(kindEmailMismatch, "The provider account's email is not the account's; the provider does not allow another.")
		}
		linked, err = p.link(ctx, by.User, id, prof, t)
		return err
	})
	if err != nil {
		return nil, err
	}
	if acct == nil {
		p.g.Events().Dispatch(ctx, p.event(EventLinked, by.User, id, map[string]any{"account_id": prof.Subject, "trusted": false}, client))
	}
	return map[string]any{"status": "linked", "account": linked.wire()}, nil
}

// liveSession reports whether by's session is theirs and neither ended nor expired.
func (p *Plugin) liveSession(ctx context.Context, by linker) (bool, error) {
	t, err := p.g.Repos().RefreshTokens.ActiveInFamily(ctx, by.Session)
	if errors.Is(err, repository.ErrNotFound) {
		return false, nil
	}
	return err == nil && t.UserID == by.User && t.ExpiresAt.After(p.g.Clock().Now()), err
}

// unlink removes the user's account of a provider, unless it is their only way in. The check and
// the delete are one transaction that first locks the user's row (a no-op update), so concurrent
// unlinks, or an unlink and a dropped password, run one after the other and see each other's
// outcome.
func (p *Plugin) unlink(ctx context.Context, userID, providerID string) error {
	var acct *account
	err := p.g.DB().Tx(ctx, func(ctx context.Context) error {
		if _, err := p.g.DB().Update(ctx, "auth_users", store.Criteria{"id": userID}, store.Data{"id": userID}); err != nil {
			return err
		}
		var err error
		if acct, err = p.findAccount(ctx, ownedKey(userID, providerID)); err != nil {
			return err
		}
		if acct == nil {
			return refuse(kindNotLinked, "No "+providerID+" account is linked.")
		}
		u, err := p.user(ctx, userID)
		if err != nil {
			return err
		}
		if u != nil && u.PasswordHash == nil {
			all, err := p.accountsOf(ctx, userID)
			if err != nil {
				return err
			}
			if len(all) == 1 {
				return refuse(kindLastCredential, "This is the only way to sign in to the account; set a password or link another provider first.")
			}
		}
		return p.unlinkAccount(ctx, *acct)
	})
	if err != nil {
		return err
	}
	p.g.Events().Dispatch(ctx, Event{Name: EventUnlinked, UserID: userID, Provider: providerID, Data: map[string]any{"account_id": acct.ProviderAccountID}})
	return nil
}

// providerToken is the user's provider access token, refreshed when it expires within a minute.
func (p *Plugin) providerToken(ctx context.Context, userID, providerID string) (map[string]any, error) {
	acct, err := p.findAccount(ctx, ownedKey(userID, providerID))
	if err != nil {
		return nil, err
	}
	if acct == nil {
		return nil, refuse(kindNotLinked, "No "+providerID+" account is linked.")
	}
	a := *acct
	access, err := p.open(a.AccessTokenEnc)
	if err != nil {
		return nil, err
	}
	expiring := a.ExpiresAt != nil && !a.ExpiresAt.After(p.g.Clock().Now().Add(time.Minute))
	if access == "" || expiring {
		refresh, err := p.open(a.RefreshTokenEnc)
		if err != nil {
			return nil, err
		}
		if refresh == "" {
			return nil, refuse(kindNoRefresh, "The provider token expired and cannot be refreshed; sign in with the provider again.")
		}
		prov, err := p.provider(ctx, providerID)
		if err != nil {
			return nil, err
		}
		t, err := prov.refresh(ctx, refresh)
		if err != nil {
			return nil, err
		}
		if a, err = p.storeTokens(ctx, a, t); err != nil {
			return nil, err
		}
		access = t.access
		p.g.Events().Dispatch(ctx, Event{Name: EventTokenRefreshed, UserID: userID, Provider: providerID})
	}
	var expiresAt any
	if a.ExpiresAt != nil {
		expiresAt = timestamp(*a.ExpiresAt)
	}
	return map[string]any{"access_token": access, "expires_at": expiresAt, "scopes": a.Scopes}, nil
}

// reject records a refused sign-in and returns it as kind.
func (p *Plugin) reject(ctx context.Context, providerID, reason string, client token.ClientContext, k kind) error {
	p.g.Events().Dispatch(ctx, p.event(EventRejected, "", providerID, map[string]any{"reason": reason}, client))
	return refuse(k, reason)
}

func (p *Plugin) event(name, userID, providerID string, data map[string]any, client token.ClientContext) Event {
	return Event{Name: name, UserID: userID, Provider: providerID, Data: data, IP: client.IP, UserAgent: client.UserAgent}
}

func accountKey(providerID, subject string) map[string]any {
	return map[string]any{"provider": providerID, "provider_account_id": subject}
}

func ownedKey(userID, providerID string) map[string]any {
	return map[string]any{"user_id": userID, "provider": providerID}
}

// keep stores v (sealed with core's encrypter: hand-off outcomes hold session tokens) under a
// digest of the secret it is keyed by.
func (p *Plugin) keep(ctx context.Context, kind, secret string, v any, ttl time.Duration) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	sealed, err := p.g.Encrypter().Encrypt(string(raw))
	if err != nil {
		return err
	}
	return p.g.Cache().Set(ctx, cacheKey(kind, secret), []byte(sealed), ttl)
}

// take reads what keep stored, once: of concurrent takes, only the one that claims the entry's
// single-use marker (an atomic Add) gets it.
func (p *Plugin) take(ctx context.Context, kind, secret string, into any) (bool, error) {
	key := cacheKey(kind, secret)
	sealed, ok, err := p.g.Cache().Get(ctx, key)
	if err != nil || !ok {
		return false, err
	}
	won, err := p.g.Cache().Add(ctx, key+".used", []byte{1}, p.settings.stateTTL)
	if err != nil || !won {
		return false, err
	}
	if err := p.g.Cache().Delete(ctx, key); err != nil {
		return false, err
	}
	raw, err := p.g.Encrypter().Decrypt(string(sealed))
	if err != nil {
		return false, nil
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	return dec.Decode(into) == nil, nil
}

func cacheKey(kind, secret string) string { return "polaris.social." + kind + "." + digest(secret) }

func random(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	return b
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}
