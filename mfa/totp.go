package mfa

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/config"
)

// TOTPProvider generates and checks RFC 6238 authenticator-app codes. Secrets are base32.
type TOTPProvider interface {
	// GenerateSecret returns a fresh base32 shared secret for a new factor.
	GenerateSecret() string
	// ProvisioningURI returns the otpauth://totp/ URI an authenticator app scans; account is the
	// identifier shown in the app (typically the email).
	ProvisioningURI(secret, account string) (string, error)
	// Match reports whether code is valid for secret now, within the configured skew window, and
	// returns the start (Unix seconds) of the matching time step. Callers reject a step at or
	// before the last accepted one, so a code cannot be replayed within its validity window.
	Match(secret, code string) (step int64, ok bool, err error)
}

// secretBytes is the generated secret size: 64 random bytes, 103 base32 characters.
const secretBytes = 64

var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// TOTP is the default TOTPProvider, configured from config.TOTP. Safe for concurrent use.
type TOTP struct {
	cfg    config.TOTP
	clock  clock.Clock
	period int64
	opts   totp.ValidateOpts
}

// NewTOTP returns a TOTP for cfg on clk (nil means the system clock). It fails on an invalid cfg
// and on an issuer containing a colon, which authenticator apps cannot represent.
func NewTOTP(cfg config.TOTP, clk clock.Clock) (*TOTP, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if hasColon(cfg.Issuer) {
		return nil, fmt.Errorf("%w: Auth.OTP.TOTP.Issuer %q must not contain a colon (auth.otp.totp.issuer)", config.ErrInvalid, cfg.Issuer)
	}
	if clk == nil {
		clk = clock.System{}
	}
	period := int64(cfg.Period / time.Second)
	algorithm := map[config.TOTPAlgorithm]otp.Algorithm{
		config.SHA1: otp.AlgorithmSHA1, config.SHA256: otp.AlgorithmSHA256, config.SHA512: otp.AlgorithmSHA512,
	}[cfg.Algorithm]
	return &TOTP{
		cfg:    cfg,
		clock:  clk,
		period: period,
		opts:   totp.ValidateOpts{Period: uint(period), Digits: otp.Digits(cfg.Digits), Algorithm: algorithm}, //nolint:gosec // G115: period is validated positive
	}, nil
}

// GenerateSecret implements TOTPProvider.
func (p *TOTP) GenerateSecret() string {
	b := make([]byte, secretBytes)
	rand.Read(b) // never fails: crypto/rand aborts the process instead (Go ≥ 1.24)
	return base32NoPad.EncodeToString(b)
}

// ProvisioningURI implements TOTPProvider. The URI stays byte-identical across releases: label
// "issuer:account" and parameters sorted, both RFC 3986-encoded, defaults (sha1, 6 digits, 30 s)
// left out.
func (p *TOTP) ProvisioningURI(secret, account string) (string, error) {
	switch {
	case account == "":
		return "", fmt.Errorf("mfa: the TOTP account label must not be empty")
	case hasColon(account):
		return "", fmt.Errorf("mfa: the TOTP account label %q must not contain a colon", account)
	}

	var q []string // in key order: algorithm, digits, issuer, period, secret
	if p.cfg.Algorithm != config.SHA1 {
		q = append(q, "algorithm="+strings.ToLower(string(p.cfg.Algorithm)))
	}
	if p.cfg.Digits != 6 {
		q = append(q, fmt.Sprintf("digits=%d", p.cfg.Digits))
	}
	q = append(q, "issuer="+rawURLEncode(p.cfg.Issuer))
	if p.period != 30 {
		q = append(q, fmt.Sprintf("period=%d", p.period))
	}
	q = append(q, "secret="+rawURLEncode(normalizeSecret(secret)))

	return "otpauth://totp/" + rawURLEncode(p.cfg.Issuer+":"+account) + "?" + strings.Join(q, "&"), nil
}

// Match implements TOTPProvider. Each candidate is compared in constant time.
func (p *TOTP) Match(secret, code string) (int64, bool, error) {
	if code == "" {
		return 0, false, nil
	}
	secret = normalizeSecret(secret)
	if _, err := base32NoPad.DecodeString(secret); err != nil {
		return 0, false, fmt.Errorf("mfa: the TOTP secret is not valid base32: %w", err)
	}

	now := p.clock.Now().Unix()
	window := int64(p.cfg.Window)
	// A code matches exactly one step, so the order does not change which step is returned.
	for offset := -window; offset <= window; offset++ {
		ts := now + offset*p.period
		if ts < 0 {
			continue
		}
		want, err := totp.GenerateCodeCustom(secret, time.Unix(ts, 0), p.opts)
		if err != nil {
			return 0, false, fmt.Errorf("mfa: generate TOTP code: %w", err)
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return ts - ts%p.period, true, nil
		}
	}
	return 0, false, nil
}

// normalizeSecret upper-cases a secret and trims its '=' padding.
func normalizeSecret(secret string) string { return strings.ToUpper(strings.Trim(secret, "=")) }

func hasColon(s string) bool {
	return strings.Contains(s, ":") || strings.Contains(s, "%3A") || strings.Contains(s, "%3a")
}

// rawURLEncode percent-encodes everything but RFC 3986 unreserved characters, upper-case hex (a
// space is %20).
func rawURLEncode(s string) string {
	// url.PathEscape leaves sub-delims and ':' '@' alone; QueryEscape differs only in '+' for ' '.
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}
