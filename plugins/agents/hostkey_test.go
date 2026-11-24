package agents

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/polaristest"
)

// One key has one thumbprint: a key of the protocol is taken in its one spelling only, so it cannot be
// two hosts, and a point of small order, for which anyone can make signatures, is not a key.
func TestAProtocolKeyHasOneSpelling(t *testing.T) {
	k := newTestKey(AlgEdDSA)
	if jwk, err := protocolKey(k.jwk()); err != nil || jwk["alg"] != AlgEdDSA {
		t.Fatalf("a key: %v %v", jwk, err)
	}
	raw := []byte(k.ed.Public().(ed25519.PublicKey))
	x := enc(raw)
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	variants := 0
	for _, last := range alphabet {
		other := x[:len(x)-1] + string(last)
		if b, err := base64.RawURLEncoding.DecodeString(other); err == nil && other != x && string(b) == string(raw) {
			variants++
			_, err := protocolKey(map[string]any{"kty": "OKP", "crv": "Ed25519", "x": other})
			_ = wantType(t, err, ErrInvalidInput, "the same key spelled "+other)
		}
	}
	if variants != 3 {
		t.Errorf("%d other spellings", variants)
	}
	for _, other := range []string{x + "=", x + "\n", x[:10] + "\r\n" + x[10:]} {
		_, err := protocolKey(map[string]any{"kty": "OKP", "crv": "Ed25519", "x": other})
		_ = wantType(t, err, ErrInvalidInput, fmt.Sprintf("spelled %q", other))
	}
	_, err := protocolKey(newTestKey(AlgES256).jwk())
	_ = wantType(t, err, ErrUnsupportedAlgorithm, "an EC key")
}

func TestAPointOfSmallOrderIsNoKey(t *testing.T) {
	identity, _ := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")
	for _, point := range []string{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000080",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	} {
		a, _ := hex.DecodeString(point)
		forged := false // without any private key, for some message
		for i := range 200 {
			forged = forged || ed25519.Verify(a, []byte(fmt.Sprint(i)), append(append([]byte{}, identity...), make([]byte, 32)...))
		}
		if !forged {
			t.Errorf("%s is not a point of small order: the test's list is wrong", point)
		}
		_, err := protocolKey(map[string]any{"kty": "OKP", "crv": "Ed25519", "x": enc(a)})
		_ = wantType(t, err, ErrInvalidInput, point)
	}
	for _, point := range []string{ // y not reduced: other spellings of the points with y 0 and 1
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "0100000000000000000000000000000000000000000000000000000000000080",
	} {
		b, _ := hex.DecodeString(point)
		if _, err := protocolKey(map[string]any{"kty": "OKP", "crv": "Ed25519", "x": enc(b)}); err == nil {
			t.Errorf("%s accepted", point)
		}
	}
}

// Every route that takes a key of the protocol takes it so, a key set's key included.
func TestEveryProtocolKeyIsChecked(t *testing.T) {
	k := newTestKey(AlgEdDSA)
	x := enc(k.ed.Public().(ed25519.PublicKey))
	variant := ""
	for _, last := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" {
		other := x[:len(x)-1] + string(last)
		if b, _ := base64.RawURLEncoding.DecodeString(other); other != x && string(b) == string(k.ed.Public().(ed25519.PublicKey)) {
			variant = other
		}
	}
	bad := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": variant, "kid": "a"}
	p := New(Config{Capabilities: unitCaps(), Discovery: DiscoveryAgentAuth})
	polaristest.New(t, polaristest.WithPlugins(oauth.New(oauth.Config{BaseURL: unitBase}), p))
	_, err := p.s.withKey(Host{}, bad, nil)
	_ = wantType(t, err, ErrInvalidInput, "POST /agents/hosts")
	const url = "https://keys.example.com/jwks"
	must(t, p.s.jwks.cache.Set(t.Context(), cacheKey(url), jwkSet(bad), jwksTTL))
	_, err = p.s.hostKey(t.Context(), Host{JWKSURL: url}, "a", nil, url)
	_ = wantType(t, err, ErrInvalidJWT, "a key set")
	thumb, _ := oauth.Thumbprint(bad)
	h, err := p.s.withKey(Host{OwnerType: OwnerUser, OwnerID: "user-1", CreatedBy: "user-1"}, nil, url)
	must(t, err)
	h, _, err = p.s.createHost(t.Context(), h, "Fleet", nil)
	must(t, err)
	_ = wantType(t, p.s.checkHost(t.Context(), Agent{HostID: h.ID}, thumb, true), ErrInvalidJWT, "an agent's iss")
}
