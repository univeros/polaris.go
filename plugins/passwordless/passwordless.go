// Package passwordless is the passwordless plugin (port of polaris/passwordless): four ways to sign
// in without a password, each ending in core's login envelope behind core's MFA gate.
//
//   - Magic links: POST /magic-link/send emails a link to GET /magic-link/verify, valid once for 15
//     minutes; the verify redirects to an allowed redirect URI with a one-minute code that
//     POST /magic-link/exchange trades, once, for the envelope (tokens never travel in a URL).
//   - Email codes: POST /email-otp/send emails a 6-digit code (5 minutes, 5 attempts) for signing in
//     (POST /email-otp/verify), verifying the address (POST /email-otp/verify-email) or resetting the
//     password (POST /email-otp/reset-password).
//   - Phone codes: a signed-in user adds a verified phone (POST /phone/add, /phone/confirm) and later
//     signs in with an SMS code (POST /phone/send, /phone/verify). A phone never signs anyone up.
//   - One-time tokens: a live session hands itself to another device (POST /one-time-token/generate,
//     then /one-time-token/verify within 3 minutes); the new session inherits how the first one
//     authenticated.
//
// Integration is one line; the zero Config is upstream's defaults:
//
//	p, err := polaris.New(polaris.Config{…, Plugins: []polaris.Plugin{
//		passwordless.New(passwordless.Config{RedirectURIs: []string{"https://app.example.com/signed-in"}}),
//	}})
//
// Links and codes go out through polaris.Config.Mailer (templates "magic_link" {link, ttl} and
// notify.TemplateOTPCode {code, ttl}) and polaris.Config.SMS. Every send answers the same 202 for
// known and unknown identifiers, and a wrong code answers like an unknown identifier.
package passwordless

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"strings"
	"time"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/internal/upstream"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/wiring"
)

// ID is the plugin id; its routes read polaris.passwordless.*.
const ID = "passwordless"

// TemplateMagicLink is the Mailer template of a magic link; its data is {link, ttl} (ttl in seconds).
const TemplateMagicLink = "magic_link"

// Defaults.
const (
	DefaultMagicLinkTTL    = 15 * time.Minute
	DefaultOTPTTL          = 5 * time.Minute
	DefaultOTPLength       = 6
	DefaultMaxAttempts     = 5
	DefaultOneTimeTokenTTL = 3 * time.Minute
)

// AMR values of the sessions the methods open.
const (
	AMRMagicLink    = "magic_link"
	AMREmailOTP     = "email_otp"
	AMRPhone        = "phone"
	AMROneTimeToken = "one_time_token" // only when the generating session carried no amr
)

// Email code purposes (the purpose field of POST /email-otp/send).
const (
	PurposeSignIn        = "sign-in"
	PurposeVerifyEmail   = "verify-email"
	PurposeResetPassword = "reset-password"
)

// SentinelRoutes are the send and sign-in routes for the sentinel plugin's route list (path to
// attempt kind), as upstream's PasswordlessPlugin::SENTINEL_ROUTES.
var SentinelRoutes = map[string]string{
	"/magic-link/send":  "otp_send",
	"/email-otp/send":   "otp_send",
	"/phone/send":       "otp_send",
	"/phone/add":        "otp_send",
	"/email-otp/verify": "sign_in",
	"/phone/verify":     "sign_in",
}

// Config configures the plugin; the zero value is upstream's defaults.
type Config struct {
	// BaseURL is where the Polaris routes are mounted, as the magic link must point there
	// ("https://app.example.com/auth"); default: the issuer plus polaris.Config.PathPrefix.
	BaseURL string
	// RedirectURIs are the exact URLs a magic link may end on; the first is the default. Without
	// any, POST /magic-link/send answers redirect_not_allowed.
	RedirectURIs []string
	// DisableSignUp stops magic links and email codes from creating an account for an unknown
	// address (it then receives nothing, and the answer is the same).
	DisableSignUp bool
	// SkipMFAGate opens a session even for a user with a confirmed second factor. By default such a
	// user gets core's mfa_required envelope and completes it at /auth/mfa/verify.
	SkipMFAGate bool
	// MagicLinkTTL, OTPTTL and OneTimeTokenTTL are lifetimes, whole seconds; zero: 15 min, 5 min, 3 min.
	MagicLinkTTL    time.Duration
	OTPTTL          time.Duration
	OneTimeTokenTTL time.Duration
	// OTPLength is the digits of a code, 6 to 10; zero: 6.
	OTPLength int
	// MaxAttempts is how many guesses a code takes; zero: 5.
	MaxAttempts int
}

type settings struct {
	baseURL         string
	redirectURIs    []string
	signUp          bool
	respectMFA      bool
	magicLinkTTL    time.Duration
	otpTTL          time.Duration
	oneTimeTokenTTL time.Duration
	otpLength       int
	maxAttempts     int
}

func (c Config) settings(g *wiring.Graph) (settings, error) {
	s := settings{
		baseURL: c.BaseURL, redirectURIs: append([]string(nil), c.RedirectURIs...), signUp: !c.DisableSignUp,
		respectMFA: !c.SkipMFAGate, otpLength: c.OTPLength, maxAttempts: c.MaxAttempts,
	}
	if s.baseURL == "" {
		s.baseURL = strings.TrimRight(g.Auth().Issuer, "/") + "/" + strings.Trim(g.Config().PathPrefix, "/")
	}
	var errs []error
	if u, err := url.Parse(s.baseURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		errs = append(errs, fmt.Errorf("passwordless: Config.BaseURL is %q, want an absolute http(s) URL where Polaris is mounted", s.baseURL))
	}
	s.baseURL = strings.TrimRight(s.baseURL, "/")
	var err error
	if s.magicLinkTTL, err = ttl("MagicLinkTTL", c.MagicLinkTTL, DefaultMagicLinkTTL); err != nil {
		errs = append(errs, err)
	}
	if s.otpTTL, err = ttl("OTPTTL", c.OTPTTL, DefaultOTPTTL); err != nil {
		errs = append(errs, err)
	}
	if s.oneTimeTokenTTL, err = ttl("OneTimeTokenTTL", c.OneTimeTokenTTL, DefaultOneTimeTokenTTL); err != nil {
		errs = append(errs, err)
	}
	if s.otpLength == 0 {
		s.otpLength = DefaultOTPLength
	}
	if s.otpLength < 6 || s.otpLength > 10 {
		errs = append(errs, fmt.Errorf("passwordless: Config.OTPLength is %d, want 6 to 10 digits (0 means %d)", c.OTPLength, DefaultOTPLength))
	}
	if s.maxAttempts == 0 {
		s.maxAttempts = DefaultMaxAttempts
	}
	if s.maxAttempts < 1 {
		errs = append(errs, fmt.Errorf("passwordless: Config.MaxAttempts is %d, want at least 1 (0 means %d)", c.MaxAttempts, DefaultMaxAttempts))
	}
	return s, errors.Join(errs...)
}

func ttl(field string, v, def time.Duration) (time.Duration, error) {
	switch {
	case v == 0:
		return def, nil
	case v < time.Second || v%time.Second != 0:
		return 0, fmt.Errorf("passwordless: Config.%s is %s, want whole seconds, at least 1s (0 means %s)", field, v, def)
	}
	return v, nil
}

// Plugin is the passwordless plugin. Its services exist once polaris.New has run.
type Plugin struct {
	cfg Config
	svc *service
}

// New returns the plugin; configuration errors surface from polaris.New.
func New(cfg Config) *Plugin { return &Plugin{cfg: cfg} }

// ID implements wiring.Plugin.
func (*Plugin) ID() string { return ID }

// Schema declares polaris_passwordless_secret and polaris_passwordless_phone.
func (*Plugin) Schema() []schema.Model { return Models() }

// Manifest returns the plugin's routes (upstream api/passwordless).
func (*Plugin) Manifest() fs.FS {
	sub, err := fs.Sub(upstream.API, "api/passwordless")
	if err != nil {
		panic(err) // the embedded tree is fixed at build time
	}
	return sub
}

// Init validates the configuration and builds the services.
func (p *Plugin) Init(g *wiring.Graph) error {
	s, err := p.cfg.settings(g)
	if err != nil {
		return err
	}
	p.svc = &service{g: g, s: s, secrets: &secrets{db: g.DB(), pepper: g.Pepper(), clock: g.Clock(), maxAttempts: s.maxAttempts}}
	return nil
}

// Endpoints serves the 13 passwordless routes.
func (p *Plugin) Endpoints(*wiring.Graph) (map[string]endpoint.Endpoint, error) {
	return p.endpoints(), nil
}

// Kind classifies a refused step; it names the problem type passwordless/<kind>.
type Kind string

// Kinds.
const (
	KindInvalidInput       Kind = "invalid_input"
	KindRedirectNotAllowed Kind = "redirect_not_allowed"
	KindCodeInvalid        Kind = "code_invalid"
	KindTokenInvalid       Kind = "token_invalid"
	KindAccountDisabled    Kind = "account_disabled"
	KindPasswordInvalid    Kind = "password_invalid"
	KindPhoneTaken         Kind = "phone_taken"
	KindSessionRequired    Kind = "session_required"
)

// Error is a refused passwordless step; Detail is what the client may read, Errors the rule
// violations of an invalid input or password.
type Error struct {
	Kind   Kind
	Detail string
	Errors []string
}

func (e *Error) Error() string { return "passwordless: " + string(e.Kind) + ": " + e.Detail }

// Is matches the sentinels by kind: errors.Is(err, passwordless.ErrCodeInvalid).
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Kind == e.Kind && t.Detail == ""
}

// Sentinels for errors.Is.
var (
	ErrInvalidInput       error = &Error{Kind: KindInvalidInput}
	ErrRedirectNotAllowed error = &Error{Kind: KindRedirectNotAllowed}
	ErrCodeInvalid        error = &Error{Kind: KindCodeInvalid}
	ErrTokenInvalid       error = &Error{Kind: KindTokenInvalid}
	ErrAccountDisabled    error = &Error{Kind: KindAccountDisabled}
	ErrPasswordInvalid    error = &Error{Kind: KindPasswordInvalid}
	ErrPhoneTaken         error = &Error{Kind: KindPhoneTaken}
	ErrSessionRequired    error = &Error{Kind: KindSessionRequired}
)

var (
	errCodeInvalid     = &Error{Kind: KindCodeInvalid, Detail: "The code is wrong, used or expired."}
	errTokenInvalid    = &Error{Kind: KindTokenInvalid, Detail: "The token is unknown, used or expired."}
	errDisabled        = &Error{Kind: KindAccountDisabled, Detail: "This account is disabled."}
	errPhoneTaken      = &Error{Kind: KindPhoneTaken, Detail: "Another account uses this phone number."}
	errSessionRequired = &Error{Kind: KindSessionRequired, Detail: "A one-time token needs a live session."}
)
