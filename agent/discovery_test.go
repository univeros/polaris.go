package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

// documents serves each path's document and keeps the paths asked for; an absent one is a 404.
func documents(t *testing.T, docs func(mount string) map[string]any) (mount string, asked *[]string) {
	t.Helper()
	asked = &[]string{}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*asked = append(*asked, r.URL.Path)
		if doc, ok := docs(srv.URL + "/auth")[r.URL.Path]; ok {
			writeJSON(w, 200, doc)
			return
		}
		writeJSON(w, 404, map[string]any{"error": "not_found", "message": "No such endpoint."})
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/auth", asked
}

const (
	wellKnown = "/auth/.well-known/agent-configuration"
	ownPath   = "/auth/agents/configuration"
)

// agentAuthDoc is the Agent Auth Protocol's document, which names none of Polaris's routes.
func agentAuthDoc(mount string) map[string]any {
	return map[string]any{"version": "1.0-draft", "issuer": mount, "algorithms": []string{"Ed25519"},
		"endpoints": map[string]string{"capabilities": "/capability/list", "execute": "/capability/execute"}}
}

// A server whose well-known document is the Agent Auth Protocol's serves Polaris's at
// /agents/configuration: the SDK reads it from there.
func TestDiscoveryFallsBackToThePolarisConfiguration(t *testing.T) {
	mount, asked := documents(t, func(mount string) map[string]any {
		return map[string]any{wellKnown: agentAuthDoc(mount), ownPath: configurationDoc(mount)}
	})
	for _, at := range []string{mount, mount + "/", mount + DiscoveryPath} {
		*asked = nil
		a, err := New(t.Context(), at)
		if err != nil {
			t.Fatalf("%s: %v", at, err)
		}
		if a.Configuration().Mount != mount || a.Configuration().Endpoints["enroll"] == "" || !slices.Equal(*asked, []string{wellKnown, ownPath}) {
			t.Errorf("%s: %+v, asked %v", at, a.Configuration(), *asked)
		}
	}
}

// A document that names enroll is Polaris's: nothing else is asked for, as in v1.0.0.
func TestDiscoveryAsksOnceForAPolarisDocument(t *testing.T) {
	mount, asked := documents(t, func(mount string) map[string]any {
		return map[string]any{wellKnown: configurationDoc(mount), ownPath: configurationDoc(mount)}
	})
	if _, err := Discover(t.Context(), mount, nil); err != nil || !slices.Equal(*asked, []string{wellKnown}) {
		t.Errorf("%v, asked %v", err, *asked)
	}
}

// A document v1.0.0 accepted without enroll is still accepted where there is nothing to fall back to.
func TestDiscoveryKeepsAUsableDocumentWithoutEnroll(t *testing.T) {
	mount, _ := documents(t, func(mount string) map[string]any {
		return map[string]any{wellKnown: map[string]any{"token_endpoint": mount + "/oauth2/token", "endpoints": map[string]string{"execute": mount + "/agents/execute"}}}
	})
	if config, err := Discover(t.Context(), mount, nil); err != nil || config.Mount != mount {
		t.Errorf("%+v %v", config, err)
	}
}

// Neither document is Polaris's: the error says so, and why the second could not be read.
func TestDiscoveryRefusesAServerWithoutAPolarisDocument(t *testing.T) {
	mount, _ := documents(t, func(mount string) map[string]any { return map[string]any{wellKnown: agentAuthDoc(mount)} })
	_, err := Discover(t.Context(), mount, nil)
	var refused *Error
	if !errors.Is(err, ErrNotConfiguration) || !errors.As(err, &refused) || refused.Status != 404 {
		t.Errorf("no second document: %v", err)
	}
	mount, _ = documents(t, func(mount string) map[string]any {
		return map[string]any{wellKnown: agentAuthDoc(mount), ownPath: agentAuthDoc(mount)}
	})
	if _, err := Discover(t.Context(), mount, nil); !errors.Is(err, ErrNotConfiguration) {
		t.Errorf("a second document that is not Polaris's: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Discover(ctx, mount, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled context: %v", err)
	}
}
