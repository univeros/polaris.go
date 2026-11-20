package social

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// A flow's state is bound to the browser that started it (decision #39): start sets a cookie
// holding a random nonce the state entry keeps, and the callback refuses a state whose browser
// does not present it. Without it, an attacker could start a flow (sign-in, or a link to their
// own account) and have a victim's browser complete it: the victim signed in as the attacker, or
// the victim's provider identity linked to the attacker's account (login and link CSRF).
//
// The cookie is named after the state, so flows in several tabs do not overwrite one another.
// Under an https BaseURL it is __Host- prefixed (a sibling subdomain cannot plant it) and
// SameSite=None, so form_post callbacks (Apple) carry it: the nonce is only compared with the state,
// sending it cross-site gives an attacker nothing. Under a plain http BaseURL (local development) it
// is SameSite=Lax. The scheme is BaseURL's, as upstream's, never the connection's: behind a
// TLS-terminating proxy the request arrives without TLS.

const bindingPrefix = "polaris_social_"

// bindingCookie is the cookie name that binds state; https is whether BaseURL is https.
func bindingCookie(state string, https bool) string {
	sum := sha256.Sum256([]byte(state))
	name := bindingPrefix + hex.EncodeToString(sum[:8])
	if https {
		return "__Host-" + name
	}
	return name
}

// https reports whether Polaris is mounted at an https BaseURL.
func (s settings) https() bool { return strings.HasPrefix(s.baseURL, "https://") }

// bindingHeader is the Set-Cookie value that hands the browser a flow's nonce for the state's
// lifetime.
func (s settings) bindingHeader(state, nonce string) string {
	attrs := "HttpOnly; SameSite=Lax"
	if s.https() {
		attrs = "HttpOnly; Secure; SameSite=None"
	}
	return fmt.Sprintf("%s=%s; Path=/; Max-Age=%d; %s", bindingCookie(state, s.https()), nonce, int(s.stateTTL.Seconds()), attrs)
}

// bound reports whether r is the browser the state entry was started in.
func (s settings) bound(r *http.Request, state string, entry stateEntry) bool {
	if r == nil || entry.Binding == "" {
		return false
	}
	c, err := r.Cookie(bindingCookie(state, s.https()))
	return err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(entry.Binding)) == 1
}
