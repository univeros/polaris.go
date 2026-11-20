package security

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

const breachPassword = "password123"

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func hibpWith(f roundTripFunc) HIBP {
	return HIBP{
		Client: &http.Client{Transport: f},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func textResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}
}

func TestHIBPMatchingSuffixIsBreachedAndOnlyThePrefixLeaves(t *testing.T) {
	sum := sha1.Sum([]byte(breachPassword))
	hash := strings.ToUpper(hex.EncodeToString(sum[:]))
	var sent *http.Request
	check := hibpWith(func(r *http.Request) (*http.Response, error) {
		sent = r
		return textResponse(200, "AAAAA1234567890AAAAA1234567890AAAAA:3\r\n"+hash[5:]+":42\r\nBBBBB:1"), nil
	})
	if !check.IsBreached(context.Background(), breachPassword) {
		t.Fatal("matching suffix not reported")
	}
	if got := sent.URL.String(); got != "https://api.pwnedpasswords.com/range/"+hash[:5] {
		t.Fatalf("sent %s", got)
	}
	if sent.Header.Get("Add-Padding") != "true" {
		t.Fatal("Add-Padding header missing")
	}
}

func TestHIBPAbsentOrZeroCountSuffixIsNotBreached(t *testing.T) {
	sum := sha1.Sum([]byte(breachPassword))
	suffix := strings.ToUpper(hex.EncodeToString(sum[:]))[5:]
	for _, body := range []string{
		"AAAAA1234567890AAAAA1234567890AAAAA:3\r\nBBBBB:1",
		suffix + ":0",   // padding row
		suffix,          // no count
		suffix + ":abc", // (int) "abc" is 0
	} {
		check := hibpWith(func(*http.Request) (*http.Response, error) { return textResponse(200, body), nil })
		if check.IsBreached(context.Background(), breachPassword) {
			t.Errorf("body %q reported breached", body)
		}
	}
}

func TestHIBPFailsOpen(t *testing.T) {
	for name, f := range map[string]roundTripFunc{
		"non-200":   func(*http.Request) (*http.Response, error) { return textResponse(429, "slow down"), nil },
		"transport": func(*http.Request) (*http.Response, error) { return nil, errors.New("connection refused") },
	} {
		if hibpWith(f).IsBreached(context.Background(), breachPassword) {
			t.Errorf("%s: not fail-open", name)
		}
	}
}

func TestHIBPLogsWithoutTheHashPrefix(t *testing.T) {
	var buf bytes.Buffer
	check := HIBP{
		Client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("connection refused")
		})},
		Logger: slog.New(slog.NewTextHandler(&buf, nil)),
	}
	check.IsBreached(context.Background(), breachPassword)
	sum := sha1.Sum([]byte(breachPassword))
	prefix := strings.ToUpper(hex.EncodeToString(sum[:]))[:5]
	if strings.Contains(buf.String(), prefix) || !strings.Contains(buf.String(), "connection refused") {
		t.Fatalf("log = %s", buf.String())
	}
}

func TestNoBreachCheck(t *testing.T) {
	if (NoBreachCheck{}).IsBreached(context.Background(), "password") {
		t.Fatal("NoBreachCheck reported a breach")
	}
}

func TestPHPIntval(t *testing.T) {
	for in, want := range map[string]int64{
		"42": 42, " 42": 42, "42abc": 42, "abc": 0, "": 0, "-3": -3, "+7": 7,
		"99999999999999999999": 1<<63 - 1,
	} {
		if got := phpIntval(in); got != want {
			t.Errorf("phpIntval(%q) = %d, want %d", in, got, want)
		}
	}
}
