package polaristest_test

import (
	"net/http"
	"testing"

	"github.com/univeros/polaris-go/contracttest"
	"github.com/univeros/polaris-go/polaristest"
)

func TestBoots(t *testing.T) {
	srv := polaristest.New(t)
	c := contracttest.NewClient(t, srv.Handler(), nil)
	resp := c.Get("/auth/does-not-exist")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
	resp = c.Get("/auth/me")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("me without token: %d", resp.StatusCode)
	}
}
