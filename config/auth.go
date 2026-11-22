package config

import (
	"regexp"
	"slices"
	"time"
)

// Signer is the access-token signing algorithm.
type Signer string

// The accepted signers.
const (
	SignerRS256 Signer = "RS256"
	SignerEdDSA Signer = "EdDSA"
)

// PasswordAlgo is the password hashing algorithm.
type PasswordAlgo string

// The accepted password algorithms.
const (
	Argon2id PasswordAlgo = "argon2id"
	Argon2i  PasswordAlgo = "argon2i"
	Bcrypt   PasswordAlgo = "bcrypt"
)

// TOTPAlgorithm is the HMAC digest of authenticator-app codes.
type TOTPAlgorithm string

// The accepted TOTP digests.
const (
	SHA1   TOTPAlgorithm = "SHA1"
	SHA256 TOTPAlgorithm = "SHA256"
	SHA512 TOTPAlgorithm = "SHA512"
)

// TokenDelivery is where sign-in and refresh put the refresh token.
type TokenDelivery string

// The accepted deliveries.
const (
	// DeliveryBody returns the refresh token in the JSON body (the default).
	DeliveryBody TokenDelivery = "body"
	// DeliveryCookie puts it in an HttpOnly; Secure; SameSite=Strict cookie, guarded against CSRF.
	DeliveryCookie TokenDelivery = "cookie"
)

// MaxTOTPWindow caps the TOTP skew window: ±10 steps (±5 min at 30 s) tolerates generous drift
// without accepting a wide range of codes at once.
const MaxTOTPWindow = 10

// Auth is the validated root of the auth settings (the `auth` namespace). Start from
// [Defaults]; a zero Auth is not valid. Durations are whole seconds.
type Auth struct {
	Issuer       string // AUTH_ISSUER, auth.issuer; required
	Audience     string // AUTH_AUDIENCE, auth.audience; "" means none
	AccessToken  AccessToken
	RefreshToken RefreshToken
	Password     Password
	Lockout      Lockout
	OTP          OTP
	MFA          MFA
	StepUpMaxAge time.Duration // auth.step_up.max_age
	Flows        Flows
	RateLimits   RateLimits // auth.rate_limits
}

// AccessToken holds the JWT access-token settings (auth.access_token).
type AccessToken struct {
	TTL        time.Duration
	Signer     Signer
	EmbedScope bool // embed flat permissions instead of roles only
	// Denylist (AUTH_ACCESS_TOKEN_DENYLIST) is the per-user revocation watermark: logging out
	// everywhere, disabling, erasing or converting a guest refuses the user's outstanding access
	// tokens at once. Off, an access token is stateless and answers until it expires (TTL), though
	// its sessions can no longer refresh and a disabled user holds no permission.
	Denylist bool
}

// RefreshToken holds the refresh-token settings (auth.refresh_token).
type RefreshToken struct {
	TTL            time.Duration
	Rotation       bool // rotate on every use
	ReuseDetection bool // revoke the family on replay
	Sliding        bool // extend expiry on use
	MaxLifetime    time.Duration
}

// Password holds the password policy (auth.password).
type Password struct {
	MinLength   int
	Algo        PasswordAlgo
	BreachCheck bool // AUTH_PASSWORD_BREACH_CHECK
}

// Lockout holds the failed-login lockout policy (auth.lockout). MaxAttempts and Duration also
// bound the second factor: after MaxAttempts second-factor codes that did not clear (the MFA login
// step and step-up, recovery codes included), every code of that user is refused as a wrong one
// until Duration has passed since the first of them; a code that clears resets the count.
type Lockout struct {
	MaxAttempts int
	Window      time.Duration
	Duration    time.Duration // auth.lockout.lock_duration
}

// OTP holds the SMS/email one-time-code settings and the TOTP settings (auth.otp).
type OTP struct {
	Length         int
	TTL            time.Duration
	MaxAttempts    int
	ResendCooldown time.Duration
	SendMax        int
	SendWindow     time.Duration
	TOTP           TOTP
}

// TOTP holds the authenticator-app (RFC 6238) settings (auth.otp.totp).
type TOTP struct {
	Digits    int
	Period    time.Duration
	Algorithm TOTPAlgorithm
	Window    int    // ±steps of skew accepted, 0..MaxTOTPWindow
	Issuer    string // label shown in the authenticator app
}

// MFA holds the multi-factor policy (auth.mfa).
type MFA struct {
	Enforce       bool // require MFA for every user
	GraceEnroll   bool // allow login-then-enroll when enforced
	LoginTokenTTL time.Duration
}

// Flows holds the flow switches (auth.flows), cookie mode included.
type Flows struct {
	RequireVerifiedEmail bool
	TokenDelivery        TokenDelivery
	// CookieTrustedOrigins are origins besides the request's own allowed to sign in and refresh in
	// cookie mode, each "https://host[:port]" in lower case (auth.flows.cookie.trusted_origins).
	// The host's CORS layer must allow credentials and X-Polaris-CSRF for exactly these.
	CookieTrustedOrigins []string
}

// Defaults returns the documented defaults. Issuer is
// empty and must be set; FromEnv defaults it to "polaris".
func Defaults() Auth {
	return Auth{
		AccessToken:  AccessToken{TTL: 900 * time.Second, Signer: SignerRS256},
		RefreshToken: RefreshToken{TTL: 2592000 * time.Second, Rotation: true, ReuseDetection: true, MaxLifetime: 7776000 * time.Second},
		Password:     Password{MinLength: 12, Algo: Argon2id},
		Lockout:      Lockout{MaxAttempts: 5, Window: 900 * time.Second, Duration: 900 * time.Second},
		OTP: OTP{
			Length: 6, TTL: 300 * time.Second, MaxAttempts: 5, ResendCooldown: 30 * time.Second,
			SendMax: 5, SendWindow: 3600 * time.Second,
			TOTP: TOTP{Digits: 6, Period: 30 * time.Second, Algorithm: SHA1, Window: 1, Issuer: "Univeros"},
		},
		MFA:          MFA{GraceEnroll: true, LoginTokenTTL: 300 * time.Second},
		StepUpMaxAge: 300 * time.Second,
		Flows:        Flows{RequireVerifiedEmail: true, TokenDelivery: DeliveryBody},
		RateLimits:   DefaultRateLimits(),
	}
}

// An origin is a scheme, a host and an optional port; cookie mode only ever trusts https.
var httpsOrigin = regexp.MustCompile(`^https://[a-z0-9.-]+(:[0-9]{1,5})?$`)

// Validate reports every broken invariant at once; each error wraps ErrInvalid.
func (a Auth) Validate() error {
	var p problems
	if a.Issuer == "" {
		p.add(`Auth.Issuer is empty: set AUTH_ISSUER (or Auth.Issuer) to your issuer URL, e.g. "https://auth.example.com" (auth.issuer)`)
	}

	p.seconds("Auth.AccessToken.TTL", " (auth.access_token.ttl)", a.AccessToken.TTL, time.Second)
	if !slices.Contains([]Signer{SignerRS256, SignerEdDSA}, a.AccessToken.Signer) {
		p.add("Auth.AccessToken.Signer is %q, must be one of: RS256, EdDSA (auth.access_token.signer)", a.AccessToken.Signer)
	}

	p.seconds("Auth.RefreshToken.TTL", " (auth.refresh_token.ttl)", a.RefreshToken.TTL, time.Second)
	if a.RefreshToken.MaxLifetime < a.RefreshToken.TTL {
		p.add("Auth.RefreshToken.MaxLifetime (%v) must be >= Auth.RefreshToken.TTL (%v) (auth.refresh_token.max_lifetime)", a.RefreshToken.MaxLifetime, a.RefreshToken.TTL)
	}

	if a.Password.MinLength < 8 {
		p.add("Auth.Password.MinLength is %d, must be at least 8 (auth.password.min_length)", a.Password.MinLength)
	}
	if !slices.Contains([]PasswordAlgo{Argon2id, Argon2i, Bcrypt}, a.Password.Algo) {
		p.add("Auth.Password.Algo is %q, must be one of: argon2id, argon2i, bcrypt (auth.password.algo)", a.Password.Algo)
	}

	if a.Lockout.MaxAttempts <= 0 {
		p.add("Auth.Lockout.MaxAttempts is %d, must be a positive integer (auth.lockout.max_attempts)", a.Lockout.MaxAttempts)
	}
	p.seconds("Auth.Lockout.Window", " (auth.lockout.window)", a.Lockout.Window, time.Second)
	p.seconds("Auth.Lockout.Duration", " (auth.lockout.lock_duration)", a.Lockout.Duration, time.Second)

	a.OTP.validate(&p)
	a.OTP.TOTP.validate(&p)

	p.seconds("Auth.MFA.LoginTokenTTL", " (auth.mfa.login_token_ttl)", a.MFA.LoginTokenTTL, time.Second)
	p.seconds("Auth.StepUpMaxAge", " (auth.step_up.max_age)", a.StepUpMaxAge, time.Second)

	if !slices.Contains([]TokenDelivery{DeliveryBody, DeliveryCookie}, a.Flows.TokenDelivery) {
		p.add("Auth.Flows.TokenDelivery is %q, must be one of: body, cookie (auth.flows.token_delivery)", a.Flows.TokenDelivery)
	}
	for _, origin := range a.Flows.CookieTrustedOrigins {
		if !httpsOrigin.MatchString(origin) {
			p.add(`Auth.Flows.CookieTrustedOrigins entries must be https origins (https://host[:port], lower case, no path), got %q (auth.flows.cookie.trusted_origins)`, origin)
		}
	}

	a.RateLimits.validate(&p)
	return p.err()
}

func (o OTP) validate(p *problems) {
	if o.Length < 4 || o.Length > 10 {
		p.add("Auth.OTP.Length is %d, must be between 4 and 10 (auth.otp.length)", o.Length)
	}
	p.seconds("Auth.OTP.TTL", " (auth.otp.ttl)", o.TTL, time.Second)
	if o.MaxAttempts <= 0 {
		p.add("Auth.OTP.MaxAttempts is %d, must be a positive integer (auth.otp.max_attempts)", o.MaxAttempts)
	}
	p.seconds("Auth.OTP.ResendCooldown", " (auth.otp.resend_cooldown)", o.ResendCooldown, 0)
	if o.SendMax <= 0 {
		p.add("Auth.OTP.SendMax is %d, must be a positive integer (auth.otp.send_max)", o.SendMax)
	}
	p.seconds("Auth.OTP.SendWindow", " (auth.otp.send_window)", o.SendWindow, time.Second)
}

// Validate reports every broken TOTP invariant; Auth.Validate includes it.
func (t TOTP) Validate() error {
	var p problems
	t.validate(&p)
	return p.err()
}

func (t TOTP) validate(p *problems) {
	if t.Digits < 6 || t.Digits > 8 {
		p.add("Auth.OTP.TOTP.Digits is %d, must be between 6 and 8 (auth.otp.totp.digits)", t.Digits)
	}
	p.seconds("Auth.OTP.TOTP.Period", " (auth.otp.totp.period)", t.Period, time.Second)
	if !slices.Contains([]TOTPAlgorithm{SHA1, SHA256, SHA512}, t.Algorithm) {
		p.add("Auth.OTP.TOTP.Algorithm is %q, must be one of: SHA1, SHA256, SHA512 (auth.otp.totp.algorithm)", t.Algorithm)
	}
	if t.Window < 0 || t.Window > MaxTOTPWindow {
		p.add("Auth.OTP.TOTP.Window is %d, must be between 0 and %d (auth.otp.totp.window)", t.Window, MaxTOTPWindow)
	}
	if t.Issuer == "" {
		p.add("Auth.OTP.TOTP.Issuer is empty, set the name shown in authenticator apps (auth.otp.totp.issuer)")
	}
}
