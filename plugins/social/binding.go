package social

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)

// A flow's state is bound to the browser that started it (decision #39): start sets a cookie
// holding a random nonce the state entry keeps, and the callback refuses a state whose browser
// does not present it. Without it, an attacker could start a flow (sign-in, or a link to their
// own account) and have a victim's browser complete it: the victim signed in as the attacker, or
// the victim's provider identity linked to the attacker's account (login and link CSRF).
//
// The cookie is named after the state, so flows in several tabs do not overwrite one another.
// Over HTTPS it is __Host- prefixed (a sibling subdomain cannot plant it) and SameSite=None, so
// form_post callbacks (Apple) carry it: the nonce is only compared with the state, sending it
// cross-site gives an attacker nothing. Over plain http (local development) it is SameSite=Lax.

const bindingPrefix = "polaris_social_"

// bindingCookie is the cookie name that binds state; https is whether the request is TLS.
func bindingCookie(state string, https bool) string {
	sum := sha256.Sum256([]byte(state))
	name := bindingPrefix + hex.EncodeToString(sum[:8])
	if https {
		return "__Host-" + name
	}
	return name
}

// bindingHeader is the Set-Cookie value that hands the browser a flow's nonce for ttl.
func bindingHeader(r *http.Request, state, nonce string, ttl time.Duration) string {
	https := r.TLS != nil
	attrs := "HttpOnly; SameSite=Lax"
	if https {
		attrs = "HttpOnly; Secure; SameSite=None"
	}
	return fmt.Sprintf("%s=%s; Path=/; Max-Age=%d; %s", bindingCookie(state, https), nonce, int(ttl.Seconds()), attrs)
}

// bound reports whether r is the browser the state entry was started in.
func bound(r *http.Request, state string, entry stateEntry) bool {
	if r == nil || entry.Binding == "" {
		return false
	}
	c, err := r.Cookie(bindingCookie(state, r.TLS != nil))
	return err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(entry.Binding)) == 1
}
