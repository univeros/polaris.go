package agents

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/internal/strictjson"
)

const (
	jwksPrefix   = "polaris.agents.jwks."
	jwksTTL      = 5 * time.Minute
	jwksRefresh  = time.Minute // the least time between two fetches of one URL
	maxJWKSBytes = 64 << 10
	maxJWKSKeys  = 20
	maxJWKSURL   = 500
)

// jwksURL is a host's JWKS URL as it is stored: https, with a host and no credentials, query or
// fragment. Where the name points is the HTTP client's to check, when it connects (§8.12).
func jwksURL(v any) (string, error) {
	raw, _ := v.(string)
	if strings.ContainsFunc(raw, unicode.IsControl) || !utf8.ValidString(raw) {
		return "", refuse(ErrInvalidInput, "jwks_url is an https URL.")
	}
	u, err := url.Parse(raw)
	if err != nil || len(raw) > maxJWKSURL || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || strings.ContainsAny(raw, "?#@ ") {
		return "", refuse(ErrInvalidInput, fmt.Sprintf("jwks_url is an https URL of at most %d characters, without credentials, a query or a fragment.", maxJWKSURL))
	}
	return raw, nil
}

// jwksKeys fetches hosts' key sets (§8.12): through a client that connects to public addresses only
// and follows no redirect, bounded in time and size, cached.
type jwksKeys struct {
	client *http.Client
	cache  cache.Cache
	log    *slog.Logger
}

// key is the key kid names in the set at url; a kid the cached set lacks fetches it again, at most
// once a minute.
func (j *jwksKeys) key(ctx context.Context, url, kid string) (map[string]any, error) {
	keys, err := j.keys(ctx, url, false)
	if err != nil {
		return nil, err
	}
	if k := keyWithID(keys, kid); k != nil {
		return k, nil
	}
	if keys, err = j.keys(ctx, url, true); err != nil {
		return nil, err
	}
	if k := keyWithID(keys, kid); k != nil {
		return k, nil
	}
	return nil, errors.New("the key set has no key of this kid")
}

func keyWithID(keys []map[string]any, kid string) map[string]any {
	for _, k := range keys {
		if k["kid"] == kid {
			return k
		}
	}
	return nil
}

func cacheKey(url string) string {
	sum := sha256.Sum256([]byte(url))
	return jwksPrefix + hex.EncodeToString(sum[:])
}

// keys is the set at url, from the cache unless refresh asks for a new one and the last fetch is a
// minute old.
func (j *jwksKeys) keys(ctx context.Context, url string, refresh bool) ([]map[string]any, error) {
	key := cacheKey(url)
	raw, found, err := j.cache.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if found && !refresh {
		return parseJWKS(raw)
	}
	due, err := j.cache.Add(ctx, key+".fetched", []byte("1"), jwksRefresh)
	if err != nil {
		return nil, err
	}
	if !due {
		if found {
			return parseJWKS(raw)
		}
		return nil, errors.New("the key set could not be fetched; try again in a minute")
	}
	raw, err = j.fetch(ctx, url)
	if err != nil {
		// What failed is logged, not answered: it would tell the caller what this server reaches.
		j.log.WarnContext(ctx, "agents: fetching a host's key set failed", "url", url, "error", err)
		return nil, errors.New("the key set could not be fetched")
	}
	keys, err := parseJWKS(raw)
	if err != nil {
		return nil, err
	}
	return keys, j.cache.Set(ctx, key, raw, jwksTTL)
}

func (j *jwksKeys) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := j.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err == nil && len(raw) > maxJWKSBytes {
		err = fmt.Errorf("more than %d bytes", maxJWKSBytes)
	}
	return raw, err
}

// keyMembers are the members a public key of each type must have; no other type is taken.
var keyMembers = map[string][]string{"RSA": {"n", "e"}, "EC": {"crv", "x", "y"}, "OKP": {"crv", "x"}}

// parseJWKS validates a JWK Set before any of its keys is used (§8.12, RFC 7517 §5): an object whose
// keys are 1 to 20 asymmetric public keys, each with the members its type needs.
func parseJWKS(raw []byte) ([]map[string]any, error) {
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if strictjson.Decode(raw, &set) != nil {
		return nil, errors.New("the key set is not a JWK Set")
	}
	if len(set.Keys) == 0 || len(set.Keys) > maxJWKSKeys {
		return nil, fmt.Errorf("the key set holds 1 to %d keys", maxJWKSKeys)
	}
	keys := make([]map[string]any, len(set.Keys))
	for i, raw := range set.Keys {
		var k map[string]any
		if strictjson.Decode(raw, &k) != nil || k == nil {
			return nil, errors.New("the key set holds something that is not a key")
		}
		kty, _ := k["kty"].(string)
		members, known := keyMembers[kty]
		if !known {
			return nil, errors.New("the key set holds a key that is not RSA, EC or OKP")
		}
		for _, m := range members {
			if s, ok := k[m].(string); !ok || s == "" {
				return nil, fmt.Errorf("the key set holds an incomplete %s key", kty)
			}
		}
		for _, m := range privateMembers {
			if k[m] != nil {
				return nil, errors.New("the key set holds a private key")
			}
		}
		keys[i] = k
	}
	return keys, nil
}
