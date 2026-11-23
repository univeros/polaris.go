package sso

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// A sign-in's state is bound to the browser that started it (decision 74, as the social plugin's
// flows are since decision 39): POST /sso/sign-in sets a cookie holding a random nonce the state
// keeps, and the callback refuses a state whose browser does not present it. Without it an
// attacker could start a sign-in as themselves and have a victim's browser complete it, leaving
// the victim signed in to the attacker's account (login CSRF).
//
// The cookie is named after the state, so sign-ins in several tabs do not overwrite one another.
// Under an https BaseURL it is __Host- prefixed (a sibling subdomain cannot plant it) and
// SameSite=None, so the SAML POST binding carries it: the nonce is only compared with the state,
// sending it cross-site gives an attacker nothing. Under a plain http BaseURL (local development)
// it is SameSite=Lax. The scheme is BaseURL's, never the connection's: behind a TLS-terminating
// proxy the request arrives without TLS.

const bindingPrefix = "polaris_sso_"

func (sp SP) https() bool { return strings.HasPrefix(sp.BaseURL, "https://") }

// bindingCookie is the name of the cookie that binds state.
func (sp SP) bindingCookie(state string) string {
	sum := sha256.Sum256([]byte(state))
	name := bindingPrefix + hex.EncodeToString(sum[:8])
	if sp.https() {
		return "__Host-" + name
	}
	return name
}

// bindingHeader is the Set-Cookie value that hands the browser a sign-in's nonce for the state's
// lifetime.
func (sp SP) bindingHeader(s Started) string {
	attrs := "HttpOnly; SameSite=Lax"
	if sp.https() {
		attrs = "HttpOnly; Secure; SameSite=None"
	}
	return fmt.Sprintf("%s=%s; Path=/; Max-Age=%d; %s", sp.bindingCookie(s.State), s.Binding, int(stateTTL.Seconds()), attrs)
}

// binding is the nonce r's browser holds for state, "" when none.
func (sp SP) binding(r *http.Request, state string) string {
	if r == nil || state == "" {
		return ""
	}
	c, err := r.Cookie(sp.bindingCookie(state))
	if err != nil {
		return ""
	}
	return c.Value
}
