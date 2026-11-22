package notes_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/store"

	"example.com/notes"
)

func call(t *testing.T, h http.Handler, method, path, bearer, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out struct {
		Data map[string]any `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out.Data
}

func TestAThirdPartyPluginRunsOnThePublicSurface(t *testing.T) {
	ctx := context.Background()
	srv := polaristest.New(t, polaristest.WithPlugins(notes.New()))
	ada, err := srv.Users().Create(ctx, polaris.NewUser{Email: "ada@example.com", Password: "correct horse battery staple", EmailVerified: true})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	if code, _ := call(t, h, "POST", "/notes/sign-in", "", `{"email":"ada@example.com","password":"wrong"}`); code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", code)
	}
	code, data := call(t, h, "POST", "/notes/sign-in", "", `{"email":"Ada@Example.com","password":"correct horse battery staple"}`)
	access, _ := data["access_token"].(string)
	if code != http.StatusOK || access == "" || data["user_id"] != ada.ID {
		t.Fatalf("sign-in: %d %v", code, data)
	}
	if code, data = call(t, h, "POST", "/notes", access, `{"body":"hello"}`); code != http.StatusCreated || data["id"] == "" {
		t.Fatalf("create: %d %v", code, data)
	}
	// A session and the plugin's own credential both reach the route; nobody granted notes.read.
	for _, bearer := range []string{access, "note_" + ada.ID} {
		code, data = call(t, h, "GET", "/notes/whoami", bearer, "")
		if code != http.StatusOK || data["email"] != "ada@example.com" || data["can_read"] != false || data["superadmin"] != false || data["sessions"] != float64(1) {
			t.Fatalf("whoami: %d %v", code, data)
		}
	}

	if err := srv.Users().Delete(ctx, ada.ID); err != nil {
		t.Fatal(err)
	}
	if row, err := srv.DB.FindOne(ctx, "ext_notes", store.Criteria{"user_id": ada.ID}); err != nil || row != nil {
		t.Fatalf("the erased user's note is still there: %v %v", row, err)
	}
}
