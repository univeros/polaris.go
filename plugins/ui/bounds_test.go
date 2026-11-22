package ui_test

import (
	"net/http"
	"testing"

	"github.com/univeros/polaris.go/plugins/ui"
)

func fetchSite(site string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", site) }
}

// A navigation another site started does not rotate the refresh token (decision 69): the page
// offers a link instead, and following it (a same-origin navigation) renews the session. Two such
// navigations sending the same cookie would otherwise read as a reused token and end the session.
func TestANavigationFromAnotherSiteDoesNotRotateTheRefreshToken(t *testing.T) {
	a := newApp(t, ui.Config{})
	a.account("ada@example.com")
	b := a.browser()
	location(t, b.signIn("ada@example.com"), "/")
	delete(b.jar, "__Host-polaris_session") // the access cookie expired
	before := b.jar["__Secure-polaris_ui_refresh"]

	for _, site := range []string{"cross-site", "same-site"} {
		for range 2 {
			rec := b.get("/auth/ui/refresh?return_to=/dashboard", fetchSite(site))
			expect(t, rec, 200, `href="/auth/ui/refresh?return_to=%2Fdashboard"`)
			if b.jar["__Secure-polaris_ui_refresh"] != before || b.jar["__Host-polaris_session"] != "" {
				t.Fatalf("%s: the refresh token was rotated", site)
			}
		}
	}
	location(t, b.get("/auth/ui/refresh?return_to=/dashboard", fetchSite("same-origin")), "/dashboard")
	if b.jar["__Secure-polaris_ui_refresh"] == before {
		t.Fatal("a same-origin navigation renews the session")
	}
	delete(b.jar, "__Host-polaris_session")
	location(t, b.get("/auth/ui/refresh?return_to=/dashboard", fetchSite("none")), "/dashboard") // typed, a bookmark
	// Without a refresh cookie there is nothing to protect: straight to sign-in.
	location(t, a.browser().get("/auth/ui/refresh?return_to=/dashboard", fetchSite("cross-site")), "/auth/ui/sign-in?return_to=%2Fdashboard")
}
