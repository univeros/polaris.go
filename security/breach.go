package security

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// HIBPRangeEndpoint is the Have I Been Pwned k-anonymity range API.
const HIBPRangeEndpoint = "https://api.pwnedpasswords.com/range/"

// ponytail: response cap, real padded responses are ~40 KiB; raise if HIBP ever grows past it.
const hibpMaxBody = 4 << 20

// HIBP checks passwords against Have I Been Pwned through the k-anonymity range API: only the
// first five hex characters of the password's SHA-1 leave the process; the suffix comparison
// happens locally.
//
// It is fail-open: a transport error, a non-200 answer or an unreadable body logs a warning
// and reports "not breached". The zero value is ready to use (http.DefaultClient,
// slog.Default()).
type HIBP struct {
	Client *http.Client
	Logger *slog.Logger
}

var _ BreachedPasswordCheck = HIBP{}

// IsBreached reports whether password appears in the HIBP corpus with a non-zero count.
func (h HIBP) IsBreached(ctx context.Context, password string) bool {
	sum := sha1.Sum([]byte(password))
	digest := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := digest[:5], digest[5:]

	breached, err := h.query(ctx, prefix, suffix)
	if err != nil {
		// A *url.Error names the URL, which carries the hash prefix: log the cause only.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		h.logger().WarnContext(ctx, "HIBP range query failed; treating as not breached.", "reason", err.Error())
		return false
	}
	return breached
}

func (h HIBP) query(ctx context.Context, prefix, suffix string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, HIBPRangeEndpoint+prefix, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Add-Padding", "true")
	client := h.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("HIBP range query returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, hibpMaxBody))
	if err != nil {
		return false, err
	}
	return rangeListsSuffix(string(body), suffix), nil
}

// rangeListsSuffix scans "SUFFIX:COUNT" lines. Padding rows and dataset removals carry a count
// of 0 and read as clean.
func rangeListsSuffix(body, suffix string) bool {
	for _, line := range strings.Split(body, "\n") {
		name, count, _ := strings.Cut(strings.ReplaceAll(line, "\r", ""), ":")
		if name == suffix && phpIntval(count) > 0 {
			return true
		}
	}
	return false
}

// phpIntval is PHP's (int) cast of a string: leading whitespace, optional sign, then the
// leading digits; anything else reads as 0.
func phpIntval(s string) int64 {
	s = strings.TrimLeft(s, " \t\n\r\v\f")
	n, sign := int64(0), int64(1)
	if s != "" && (s[0] == '+' || s[0] == '-') {
		if s[0] == '-' {
			sign = -1
		}
		s = s[1:]
	}
	for i := 0; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
		if n > (1<<63-1)/10 {
			return sign * (1<<63 - 1) // PHP saturates on overflow
		}
		n = n*10 + int64(s[i]-'0')
	}
	return sign * n
}

func (h HIBP) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

// NoBreachCheck is the default check: nothing is ever considered breached.
type NoBreachCheck struct{}

var _ BreachedPasswordCheck = NoBreachCheck{}

// IsBreached always returns false.
func (NoBreachCheck) IsBreached(context.Context, string) bool { return false }
