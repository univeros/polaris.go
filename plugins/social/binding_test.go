package social

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Login and link CSRF (decision #39): a flow an attacker started cannot be completed by a victim's
// browser, which never received the attacker's binding cookie.

func TestAFlowStartedByAnAttackerCannotBeCompletedInAVictimsBrowser(t *testing.T) {
	h := newHarness(t)
	attacker := h.user("mallory@example.com", true)
	for name, link := range map[string]string{"sign-in": "", "link": attacker.ID} {
		s, err := h.p.start(h.ctx, "github", "", nil, link)
		if err != nil {
			t.Fatal(err)
		}
		victim := httptest.NewRequest(http.MethodGet, unitBase+"/social/github/callback", nil)
		_, err = h.p.callback(h.ctx, "github", map[string]any{"code": "good", "state": s.State}, victim, h.client)
		refused(t, err, kindStateInvalid, name+": a browser without the binding cookie")
	}
	if accounts, _ := h.p.accountsOf(h.ctx, attacker.ID); len(accounts) != 0 {
		t.Fatalf("the victim's identity was linked to the attacker: %v", accounts)
	}
}

func TestTheBindingCookieMustBeTheFlowsOwnAndHostOnlyOverHTTPS(t *testing.T) {
	h := newHarness(t)
	s, err := h.p.start(h.ctx, "github", "", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	callback := func(name, value string) error {
		r := httptest.NewRequest(http.MethodGet, unitBase+"/social/github/callback", nil)
		r.AddCookie(&http.Cookie{Name: name, Value: value})
		_, err := h.p.callback(h.ctx, "github", map[string]any{"code": "good", "state": s.State}, r, h.client)
		return err
	}
	// A sibling subdomain can plant a plain cookie, never a __Host- one: over HTTPS only the
	// __Host- name counts.
	refused(t, callback(bindingCookie(s.State, false), s.binding), kindStateInvalid, "a plain-named cookie over https")
	s, _ = h.p.start(h.ctx, "github", "", nil, "")
	refused(t, callback(bindingCookie(s.State, true), strings.Repeat("0", 32)), kindStateInvalid, "another nonce")
	s, _ = h.p.start(h.ctx, "github", "", nil, "")
	h.rec.SetNonce(queryParam(s.URL, "nonce"))
	if err := callback(bindingCookie(s.State, true), s.binding); err != nil {
		t.Fatalf("the starting browser completes its flow: %v", err)
	}

	header := h.p.settings.bindingHeader(s.State, s.binding)
	if !strings.HasPrefix(header, "__Host-polaris_social_") || !strings.Contains(header, "; Path=/;") ||
		!strings.Contains(header, "HttpOnly; Secure; SameSite=None") || strings.Contains(header, "Domain") {
		t.Fatalf("over https: %q", header)
	}
}

// The cookie follows the scheme of BaseURL, as upstream's Binding::https does, never the
// connection: behind a TLS-terminating proxy r.TLS is nil, and a SameSite=Lax cookie would not
// reach Apple's cross-site form_post callback.
func TestTheBindingCookieFollowsTheBaseURLNotTheConnection(t *testing.T) {
	h := newHarness(t)
	s, err := h.p.start(h.ctx, "github", "", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	h.rec.SetNonce(queryParam(s.URL, "nonce"))
	proxied := httptest.NewRequest(http.MethodGet, "/social/github/callback", nil)
	proxied.AddCookie(&http.Cookie{Name: bindingCookie(s.State, true), Value: s.binding})
	if proxied.TLS != nil {
		t.Fatal("the proxied request must arrive without TLS")
	}
	if _, err := h.p.callback(h.ctx, "github", map[string]any{"code": "good", "state": s.State}, proxied, h.client); err != nil {
		t.Fatalf("a proxied browser holding the __Host- cookie completes its flow: %v", err)
	}

	local := settings{baseURL: "http://localhost:8080", stateTTL: h.p.settings.stateTTL}
	if got := local.bindingHeader("state", "nonce"); !strings.HasPrefix(got, "polaris_social_") || !strings.HasSuffix(got, "; Max-Age=600; HttpOnly; SameSite=Lax") {
		t.Fatalf("over plain http: %q", got)
	}
}
