package social

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/internal/services"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/token"
)

// A link is made while the session that started it lives: what ended it since (the mailbox's first
// proof, a logout, disabling) ends the flow, and the access token left over starts no other.
func TestALinkEndsWithTheSessionThatStartedIt(t *testing.T) {
	for name, end := range map[string]func(h *harness, userID, sessionID string) error{
		"first proof": func(h *harness, userID, _ string) error {
			_, _, err := h.srv.Graph().Identity().ProveEmail(h.ctx, userID, false)
			return err
		},
		"logout": func(h *harness, _, sessionID string) error {
			return h.srv.Graph().Sessions().RevokeFamily(h.ctx, sessionID, model.RevokedLogout)
		},
		"disabled": func(h *harness, userID, _ string) error {
			return services.Of(h.srv.Graph()).Identity.DisableUser(h.ctx, "operator", userID)
		},
		"nothing": nil,
	} {
		t.Run(name, func(t *testing.T) {
			rec := NewRecorded(t)
			p := New(RecordedConfig(t, unitBase, rec))
			srv := polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{}), p),
				polaristest.WithAuth(func(a *config.Auth) { a.Flows.RequireVerifiedEmail = false }))
			h := &harness{t: t, p: p, srv: srv, rec: rec, client: token.ClientContext{IP: "203.0.113.7", UserAgent: "ua/1"}, ctx: context.Background()}
			ada := h.user("ada@example.com", false)
			issued, err := srv.Graph().Sessions().Issue(h.ctx, token.SessionPrincipal{UserID: ada.ID, AMR: []string{"pwd"}}, h.client)
			if err != nil {
				t.Fatal(err)
			}
			do := func(method, path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
				r := httptest.NewRequest(method, path, bytes.NewReader([]byte("{}")))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Authorization", "Bearer "+issued.AccessToken)
				for _, c := range cookies {
					r.AddCookie(c)
				}
				w := httptest.NewRecorder()
				srv.Handler().ServeHTTP(w, r)
				return w
			}
			h.unvouched("ada@example.com")
			link := do(http.MethodPost, "/social/acme/link")
			var doc struct {
				Data struct{ State string } `json:"data"`
			}
			if err := json.Unmarshal(link.Body.Bytes(), &doc); err != nil || link.Code != 200 || doc.Data.State == "" {
				t.Fatalf("link: %d %s", link.Code, link.Body)
			}
			links, again := 0, 401
			if end == nil {
				links, again = 1, 200
			} else if err := end(h, ada.ID, issued.SessionID); err != nil {
				t.Fatal(err)
			}
			if w := do(http.MethodPost, "/social/acme/link"); w.Code != again {
				t.Errorf("another link: %d, want %d", w.Code, again)
			}
			callback := do(http.MethodGet, "/social/acme/callback?code=good&state="+url.QueryEscape(doc.Data.State), link.Result().Cookies()...)
			if n := len(h.accounts(ada.ID)); n != links {
				t.Errorf("callback %d %s: %d links, want %d", callback.Code, callback.Body, n, links)
			}
		})
	}
}
