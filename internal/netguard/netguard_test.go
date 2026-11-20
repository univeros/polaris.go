package netguard

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestPublicAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8": true, "2606:4700:4700::1111": true,
		"127.0.0.1": false, "10.0.0.1": false, "169.254.169.254": false, "100.64.1.1": false,
		"192.168.1.1": false, "0.0.0.0": false, "::1": false, "fe80::1": false, "fc00::1": false,
		"::ffff:8.8.8.8": false, "203.0.113.9": false, "2001:db8::1": false, "240.0.0.1": false,
	} {
		if got := PublicAddr(netip.MustParseAddr(addr)); got != want {
			t.Errorf("PublicAddr(%s) = %v, want %v", addr, got, want)
		}
	}
	if PublicAddr(netip.Addr{}) {
		t.Error("invalid address")
	}
}

func TestClientRefusesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	if _, err := Client().Get(srv.URL); err == nil {
		t.Fatal("a loopback server must be refused")
	}
	if err := Control("tcp", "nonsense", nil); err == nil {
		t.Fatal("bad address")
	}
}

func TestNoRedirects(t *testing.T) {
	srv := httptest.NewServer(http.RedirectHandler("/elsewhere", http.StatusFound))
	defer srv.Close()
	resp, err := NoRedirects(srv.Client()).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("followed the redirect: %d", resp.StatusCode)
	}
	if NoRedirects(nil).CheckRedirect == nil {
		t.Fatal("nil client")
	}
}
