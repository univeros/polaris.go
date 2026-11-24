package agents

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/internal/netguard"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/memstore"
)

func withKid(k *testKey, kid string) map[string]any {
	j := k.jwk()
	j["kid"] = kid
	return j
}

func jwkSet(keys ...any) []byte {
	raw, _ := json.Marshal(map[string]any{"keys": keys})
	return raw
}

// §8.12: the contents of a JWKS are validated before any key of it is used.
func TestSection8_12TheContentsOfAKeySet(t *testing.T) {
	good := withKid(newTestKey(AlgEdDSA), "a")
	if keys, err := parseJWKS(jwkSet(good, withKid(newTestKey(AlgES256), "b"), map[string]any{"kty": "RSA", "n": "AQ", "e": "AQAB"})); err != nil || len(keys) != 3 {
		t.Fatalf("a key set: %v %v", keys, err)
	}
	many := make([]any, 21)
	for i := range many {
		many[i] = good
	}
	private := withKid(newTestKey(AlgEdDSA), "a")
	private["d"] = "x"
	for name, raw := range map[string][]byte{
		"not JSON": []byte("<html>"), "trailing data": append(jwkSet(good), '{', '}'), "a list": []byte(`[]`), "null": []byte(`null`),
		"no keys member": []byte(`{}`), "keys is an object": []byte(`{"keys":{"a":{}}}`), "no key": jwkSet(), "21 keys": jwkSet(many...),
		"a string": jwkSet("key"), "null key": jwkSet(nil), "no kty": jwkSet(map[string]any{"crv": "Ed25519", "x": "AQ"}),
		"an unknown kty": jwkSet(map[string]any{"kty": "AKP", "x": "AQ"}), "oct": jwkSet(map[string]any{"kty": "oct", "k": "AQ"}),
		"oct beside a good key": jwkSet(good, map[string]any{"kty": "oct", "k": "AQ"}),
		"an incomplete OKP":     jwkSet(map[string]any{"kty": "OKP", "crv": "Ed25519"}), "an incomplete EC": jwkSet(map[string]any{"kty": "EC", "crv": "P-256", "x": "AQ"}),
		"an incomplete RSA": jwkSet(map[string]any{"kty": "RSA", "n": "AQ"}), "a private key": jwkSet(private),
	} {
		if keys, err := parseJWKS(raw); err == nil {
			t.Errorf("%s: %v", name, keys)
		}
	}
}

// §8.12: where a key set is fetched from.
func TestSection8_12TheURLOfAKeySet(t *testing.T) {
	for _, bad := range []any{"http://keys.example.com/jwks", "https://", "https:///jwks", "https://user:pass@keys.example.com/jwks", "https://keys.example.com/jwks?a=b",
		"https://keys.example.com/jwks#k", "ftp://keys.example.com", "keys.example.com", "", nil, 5, "https://keys.example.com/" + strings.Repeat("a", 500)} {
		if u, err := jwksURL(bad); err == nil {
			t.Errorf("%v: %s", bad, u)
		}
	}
	if u, err := jwksURL("https://keys.example.com:8443/jwks.json"); err != nil || u == "" {
		t.Error(err)
	}
}

// §8.12: only public addresses, no redirect, a bounded answer, a 200; and the reason is not answered.
func TestSection8_12FetchingAKeySet(t *testing.T) {
	var served http.HandlerFunc
	web := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { served(w, r) }))
	defer web.Close()
	clk := clock.System{}
	open := func(client *http.Client) *jwksKeys {
		return &jwksKeys{client: netguard.NoRedirects(client), cache: cache.NewMemory(clk), log: slog.New(slog.DiscardHandler)}
	}
	set := jwkSet(withKid(newTestKey(AlgEdDSA), "a"))
	served = func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(set) }
	if k, err := open(web.Client()).key(t.Context(), web.URL+"/jwks", "a"); err != nil || k["kid"] != "a" {
		t.Fatalf("a key: %v %v", k, err)
	}
	guarded := open(nil)
	if _, err := guarded.client.Get(web.URL); !errors.Is(err, netguard.ErrNonPublicAddress) { //nolint:bodyclose // no response
		t.Errorf("the default client: %v", err)
	}
	if _, err := guarded.key(t.Context(), web.URL+"/jwks", "a"); err == nil || strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), "public") {
		t.Errorf("a private address: %v", err)
	}
	for name, h := range map[string]http.HandlerFunc{
		"a redirect":    func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/elsewhere", http.StatusFound) },
		"an error":      func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500); _, _ = w.Write(set) },
		"too large":     func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(make([]byte, maxJWKSBytes+1)) },
		"not a key set": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{}")) },
	} {
		served = h
		if k, err := open(web.Client()).key(t.Context(), web.URL+"/jwks", "a"); err == nil {
			t.Errorf("%s: %v", name, k)
		}
	}
}

// §8.12, §10.4: a set is cached, and a kid it lacks fetches it again at most once a minute.
func TestAKeySetIsFetchedAtMostOnceAMinute(t *testing.T) {
	var fetches atomic.Int32
	kid := "old"
	web := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		_, _ = w.Write(jwkSet(withKid(newTestKey(AlgEdDSA), kid)))
	}))
	defer web.Close()
	clk := clock.NewFrozen(time.Now())
	j := &jwksKeys{client: netguard.NoRedirects(web.Client()), cache: cache.NewMemory(clk), log: slog.New(slog.DiscardHandler)}
	get := func(id string, wantFetches int32, found bool) {
		t.Helper()
		if _, err := j.key(t.Context(), web.URL, id); (err == nil) != found || fetches.Load() != wantFetches {
			t.Errorf("%s: %v after %d fetches, want %d", id, err, fetches.Load(), wantFetches)
		}
	}
	get("old", 1, true)
	get("old", 1, true)
	kid = "new"
	get("new", 1, false) // a minute has not passed
	clk.Advance(61 * time.Second)
	get("new", 2, true)
	get("old", 2, false)
	clk.Advance(10 * time.Minute)
	get("new", 3, true)
}

// A URL is taken with a proof by a key it publishes (5.9), and the host is known by that key from then on.
func TestAHostsURLIsProven(t *testing.T) {
	key, other := newTestKey(AlgEdDSA), newTestKey(AlgEdDSA)
	fetched := 0
	web := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetched++
		_, _ = w.Write(jwkSet(withKid(key, "1"), withKid(newTestKey(AlgES256), "ec")))
	}))
	defer web.Close()
	p := New(Config{Capabilities: unitCaps(), Discovery: DiscoveryAgentAuth, Strengths: noPasskeys, HTTPClient: web.Client()})
	polaristest.New(t, polaristest.WithPlugins(oauth.New(oauth.Config{BaseURL: unitBase}), p))
	thumb := func(k *testKey) string { s, _ := oauth.Thumbprint(k.jwk()); return s }
	proof := func(k *testKey, kid, sub string) string {
		now := time.Now().Unix()
		return k.jwt(map[string]any{"iss": thumb(k), "sub": sub, "aud": unitBase, "iat": now, "exp": now + 60, "jti": newID()}, map[string]any{"typ": HostLinkJWTType, "kid": kid})
	}
	h, err := p.s.withKey(Host{OwnerType: OwnerUser, OwnerID: "user-1", CreatedBy: "user-1"}, nil, web.URL+"/jwks")
	must(t, err)
	_, err = p.s.proven(t.Context(), h, proof(key, "1", "user-2"))
	_ = wantType(t, err, ErrInvalidInput, "another account's")
	if fetched != 0 {
		t.Error("the URL is fetched for a proof that names another account")
	}
	for name, raw := range map[string]string{"no kid": proof(key, "", "user-1"), "a kid the set lacks": proof(key, "2", "user-1"), "a key that is not in the set": proof(other, "1", "user-1"), "an EC key": proof(key, "ec", "user-1")} {
		_, err = p.s.proven(t.Context(), h, raw)
		_ = wantType(t, err, ErrInvalidInput, name)
	}
	said := wantType(t, err, ErrInvalidInput, "a key set is not described").Detail
	if strings.Contains(said, "kid") || strings.Contains(said, "fetched") {
		t.Errorf("tells what a URL serves: %s", said)
	}
	if h, err = p.s.proven(t.Context(), h, proof(key, "1", "user-1")); err != nil || h.KeyThumbprint != thumb(key) {
		t.Errorf("%+v %v", h, err)
	}
}

// §8.7: a host that publishes its keys signs with any of them; the thumbprint it is known by follows.
// Its delivery mode is fixed, and turning JWKS URLs off refuses it.
func TestSection8_7AHostThatPublishesItsKeys(t *testing.T) {
	first, second := newTestKey(AlgEdDSA), newTestKey(AlgEdDSA)
	set := jwkSet(withKid(first, "1"))
	web := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(set) }))
	defer web.Close()
	p := New(Config{Capabilities: unitCaps(), Discovery: DiscoveryAgentAuth, Strengths: noPasskeys, HTTPClient: web.Client()})
	polaristest.New(t, polaristest.WithPlugins(oauth.New(oauth.Config{BaseURL: unitBase}), p))
	ctx := t.Context()
	h, err := p.s.withKey(Host{OwnerType: OwnerUser, OwnerID: "user-1", CreatedBy: "user-1"}, nil, web.URL+"/jwks")
	must(t, err)
	h, secret, err := p.s.createHost(ctx, h, "Fleet", nil)
	if err != nil || secret != "" {
		t.Fatalf("%q %v", secret, err)
	}
	thumb := func(k *testKey) string { s, _ := oauth.Thumbprint(k.jwk()); return s }
	call := func(k *testKey, kid string, claims map[string]any) (Host, error) {
		now := time.Now().Unix()
		payload := map[string]any{"iss": thumb(k), "aud": unitBase, "iat": now, "exp": now + 60, "jti": newID(), "host_jwks_url": web.URL + "/jwks"}
		for n, v := range claims {
			payload[n] = v
			if v == nil {
				delete(payload, n)
			}
		}
		r := httptest.NewRequest(http.MethodGet, "/agent/status", nil)
		r.Header.Set("Authorization", "Bearer "+k.jwt(payload, map[string]any{"typ": HostJWTType, "kid": kid}))
		got, _, err := p.s.hostOf(r)
		return got, err
	}
	refused := func(what string, k *testKey, kid string, claims map[string]any) {
		t.Helper()
		_, err := call(k, kid, claims)
		_ = wantType(t, err, ErrInvalidJWT, what)
	}
	if got, err := call(first, "1", nil); err != nil || got.ID != h.ID || got.KeyThumbprint != thumb(first) {
		t.Fatalf("first key: %+v %v", got, err)
	}
	refused("no kid (§4.2)", first, "", nil)
	refused("a kid the set lacks", first, "2", nil)
	refused("a key that is not in the set", second, "1", nil)
	refused("an inline key (§8.7)", first, "1", map[string]any{"host_jwks_url": nil, "host_public_key": first.jwk()})
	refused("another URL", first, "1", map[string]any{"host_jwks_url": web.URL + "/other"})

	// The host rotates; its agent may come with the new iss before the host does (§4.5 step 4).
	set = jwkSet(withKid(first, "1"), withKid(second, "2"))
	must(t, p.s.jwks.cache.Delete(ctx, cacheKey(web.URL+"/jwks")))
	must(t, p.s.jwks.cache.Delete(ctx, cacheKey(web.URL+"/jwks")+".fetched"))
	a := Agent{HostID: h.ID}
	must(t, p.s.checkHost(ctx, a, thumb(second), true))
	_ = wantType(t, p.s.checkHost(ctx, a, thumb(newTestKey(AlgEdDSA)), true), ErrInvalidJWT, "a key that is not the host's")
	if got, err := call(second, "2", nil); err != nil || got.KeyThumbprint != thumb(second) {
		t.Fatalf("second key: %+v %v", got, err)
	}
	stored, _, err := p.s.host(ctx, h.ID)
	if err != nil || stored.KeyThumbprint != thumb(second) {
		t.Errorf("stored %+v %v", stored, err)
	}

	// Another host holds the thumbprint already.
	third := newTestKey(AlgEdDSA)
	inline, err := p.s.withKey(Host{OwnerType: OwnerUser, OwnerID: "user-2", CreatedBy: "user-2"}, third.jwk(), nil)
	must(t, err)
	_, _, err = p.s.createHost(ctx, inline, "Other", nil)
	must(t, err)
	_ = wantType(t, p.s.renameHost(ctx, stored, thumb(third)), ErrInvalidJWT, "another host's key")

	// An EC key of the set is no host key.
	ec := newTestKey(AlgES256)
	set = jwkSet(withKid(ec, "ec"))
	must(t, p.s.jwks.cache.Delete(ctx, cacheKey(web.URL+"/jwks")))
	must(t, p.s.jwks.cache.Delete(ctx, cacheKey(web.URL+"/jwks")+".fetched"))
	_, err = p.s.hostKey(ctx, stored, "ec", nil, stored.JWKSURL)
	_ = wantType(t, err, ErrInvalidJWT, "an EC key")

	p.s.settings.jwksURLs = false
	refused("JWKS URLs turned off", second, "2", nil)
	_, err = p.s.withKey(Host{}, nil, "https://keys.example.com/jwks")
	_ = wantType(t, err, ErrInvalidInput, "and not registered")
	if New(Config{Discovery: DiscoveryAgentAuth, DisableJWKSURLs: true}).settings.jwksURLs || New(Config{}).settings.jwksURLs {
		t.Error("on with DiscoveryAgentAuth only, and not when disabled")
	}
	if _, err := p.s.db.Update(ctx, TableHosts, store.Criteria{"id": h.ID}, store.Data{"revoked_at": time.Now()}); err != nil {
		t.Fatal(err)
	}
	_ = wantType(t, p.s.checkHost(ctx, a, nil, false), ErrHostRevoked, "a revoked host's agent")
}

// Nothing a key set holds may panic; what is accepted is 1 to 20 asymmetric public keys.
func FuzzKeySet(f *testing.F) {
	f.Add(jwkSet(withKid(newTestKey(AlgEdDSA), "a")))
	f.Add([]byte(`{"keys":[{"kty":"oct","k":"AQ"}]}`))
	f.Add([]byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","x":5}],"keys":[]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		keys, err := parseJWKS(raw)
		if err != nil {
			return
		}
		if len(keys) < 1 || len(keys) > maxJWKSKeys {
			t.Fatalf("%d keys", len(keys))
		}
		for _, k := range keys {
			if k["kty"] == "oct" || k["d"] != nil || k["k"] != nil {
				t.Fatalf("accepted %v", k)
			}
			_, _ = oauth.Thumbprint(k)
			_, _ = verifierOf(k)
		}
	})
}

// FuzzUnknownHostJWT is FuzzHostJWT for a host the server does not know, whose key is in the JWT: what is
// accepted is signed by the key it presents, which its iss names.
func FuzzUnknownHostJWT(f *testing.F) {
	k := newTestKey(AlgEdDSA)
	thumb, _ := oauth.Thumbprint(k.jwk())
	now := time.Unix(1_800_000_000, 0)
	hj, _ := json.Marshal(map[string]any{"typ": HostJWTType, "alg": AlgEdDSA})
	cj, _ := json.Marshal(map[string]any{"iss": thumb, "aud": unitBase, "iat": now.Unix(), "exp": now.Unix() + 60, "jti": "j1", "host_public_key": k.jwk()})
	f.Add(hj, cj)
	f.Add(hj, []byte(fmt.Sprintf(`{"iss":%q,"aud":%q,"host_public_key":{"kty":"OKP","crv":"Ed25519","x":"AQ"}}`, thumb, unitBase)))
	f.Add([]byte(`{"typ":"host+jwt","alg":"EdDSA"}`), []byte(fmt.Sprintf(`{"iss":%q,"aud":%q,"host_public_key":[]}`, thumb, unitBase)))
	s := &service{db: memstore.New(), settings: settings{dynamicHosts: true}}
	f.Fuzz(func(t *testing.T, header, claims []byte) {
		clk := clock.NewFrozen(now)
		s.issuerJWTs = &requestJWTs{cache: cache.NewMemory(clk), clock: clk, maxAge: 300, audience: unitBase, skew: protocolSkew}
		input := enc(header) + "." + enc(claims)
		jwt := input + "." + enc(ed25519.Sign(k.ed, []byte(input)))
		call := func(unknown bool) (Host, error) {
			r := (&http.Request{Header: http.Header{"Authorization": {"Bearer " + jwt}}}).WithContext(context.Background())
			h, _, err := s.hostCalling(r, unknown)
			return h, err
		}
		if _, err := call(false); err == nil {
			t.Fatalf("an unknown host accepted: %s", claims)
		}
		h, err := call(true)
		if err != nil {
			return
		}
		if h.ID != "" || h.KeyThumbprint != thumb {
			t.Fatalf("accepted as %+v: %s", h, claims)
		}
		if _, err := call(true); err == nil {
			t.Fatal("a host JWT was accepted twice")
		}
	})
}

// FuzzHostJWT signs arbitrary header and claims bytes with a registered host's key, so the fuzzer
// reaches every check behind the signature. Nothing may panic; an accepted JWT names the host and this
// server, and is accepted once.
func FuzzHostJWT(f *testing.F) {
	k := newTestKey(AlgEdDSA)
	thumb, _ := oauth.Thumbprint(k.jwk())
	now := time.Unix(1_800_000_000, 0)
	hj, _ := json.Marshal(map[string]any{"typ": HostJWTType, "alg": AlgEdDSA})
	cj, _ := json.Marshal(map[string]any{"iss": thumb, "aud": unitBase, "iat": now.Unix(), "exp": now.Unix() + 60, "jti": "j1", "host_public_key": k.jwk()})
	f.Add(hj, cj, "")
	f.Add([]byte(`{"typ":"host+jwt","alg":"EdDSA","jwk":{}}`), []byte(`{"iss":5,"aud":[],"host_jwks_url":{}}`), "a.b.c")
	f.Add(hj, []byte(fmt.Sprintf(`{"iss":%q,"aud":%q,"iat":1e400,"exp":-1,"jti":null,"host_public_key":null}`, thumb, unitBase)), "")
	s := &service{db: memstore.New(), settings: settings{}}
	host, err := s.withKey(Host{ID: "host-1", OwnerType: OwnerUser, OwnerID: "user-1", CreatedBy: "user-1", CreatedAt: now}, k.jwk(), nil)
	if err != nil {
		f.Fatal(err)
	}
	if err := s.db.Insert(context.Background(), TableHosts, host.row()); err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, header, claims []byte, raw string) {
		clk := clock.NewFrozen(now)
		s.issuerJWTs = &requestJWTs{cache: cache.NewMemory(clk), clock: clk, maxAge: 300, audience: unitBase, skew: protocolSkew}
		call := func(jwt string) error {
			r := (&http.Request{Header: http.Header{"Authorization": {"Bearer " + jwt}}}).WithContext(context.Background())
			_, _, err := s.hostOf(r)
			return err
		}
		input := enc(header) + "." + enc(claims)
		signed := input + "." + enc(ed25519.Sign(k.ed, []byte(input)))
		if call(signed) == nil {
			var c map[string]any
			if json.Unmarshal(claims, &c) != nil || c["iss"] != thumb || c["aud"] != unitBase || c["jti"] == "" {
				t.Fatalf("accepted %s", claims)
			}
			if call(signed) == nil {
				t.Fatal("a host JWT was accepted twice")
			}
		}
		_ = call(raw)
	})
}
