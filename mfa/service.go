package mfa

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/notify"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/security"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

var (
	// ErrInvalidOTP reports a code that does not verify: wrong, expired, attempt-exhausted,
	// already used, a replayed TOTP step, or a factor that takes no sent challenge. The endpoints
	// answer a generic 422 that never says which.
	ErrInvalidOTP = errors.New("mfa: the verification code is invalid")
	// ErrOTPCooldown reports a code requested before the resend cooldown elapsed, or past the
	// per-account / per-destination send budget. The endpoints answer 429.
	ErrOTPCooldown = errors.New("mfa: please wait before requesting another code")
	// ErrFactorNotFound reports a factor that does not exist, is another user's, has the wrong
	// type for the operation, is unconfirmed where a confirmed one is needed, or has a type no
	// one verifies. The endpoints answer 404: another user's factor looks like no factor.
	ErrFactorNotFound = errors.New("mfa: factor not found")
	// ErrInvalidFactorState reports a management change the factor's state forbids (422); the
	// error is a *PolicyError carrying the client-facing message.
	ErrInvalidFactorState = errors.New("mfa: invalid factor state")
	// ErrLastFactorProtected reports removing the last confirmed factor of a user for whom MFA
	// is enforced (409); the error is a *PolicyError carrying the client-facing message.
	ErrLastFactorProtected = errors.New("mfa: last factor protected")
	// ErrInvalidConfig reports a Config missing a dependency or registering a bad factor type.
	ErrInvalidConfig = errors.New("mfa: invalid configuration")
)

// PolicyError is a refused factor-management change. Message is the explanation sent to the
// client verbatim; Err is ErrInvalidFactorState or ErrLastFactorProtected.
type PolicyError struct {
	Err     error
	Message string
}

func (e *PolicyError) Error() string { return e.Err.Error() + ": " + e.Message }
func (e *PolicyError) Unwrap() error { return e.Err }

// FactorType is an MFA factor type a plugin adds to core's gate (passkey adds "passkey"). Core
// owns the auth_mfa_factors row (listed, relabelled, defaulted and removed by core, confirmed
// through Service.ConfirmFactor), the login_mfa ticket and the verify routes; the type owns the
// verification of what the client sends as the code. Core's own types (totp, sms, email) cannot
// be replaced.
type FactorType interface {
	// Type is the auth_mfa_factors.type value of the rows this verifies.
	Type() string
	// Verify checks code for a confirmed factor of this type under purpose and returns nil when
	// it clears. A code that does not verify returns an error wrapping ErrInvalidOTP (answered
	// as a wrong code, never more); any other error is an infrastructure failure.
	Verify(ctx context.Context, factor model.MFAFactor, code string, purpose ChallengePurpose) error
}

// Sessions opens and steps up sessions; *session.Service is the implementation.
type Sessions interface {
	Issue(ctx context.Context, p token.SessionPrincipal, client token.ClientContext) (token.IssuedTokens, error)
	StepUp(ctx context.Context, userID, organizationID, sessionID string) (string, error)
}

// Tickets mints the short-lived login_mfa ticket; *session.MFATickets is the implementation.
type Tickets interface {
	Issue(userID string) (string, error)
}

// PrincipalResolver resolves a user's authorization context for the post-MFA session;
// *authz.Principals is the production implementation.
type PrincipalResolver interface {
	Resolve(ctx context.Context, userID, organizationID string) (token.SessionPrincipal, error)
}

// Config wires a Service. Every field but QR, FactorTypes, Clock and Events is required; Auth
// supplies the OTP and MFA settings (start from config.Defaults()).
type Config struct {
	DB         store.Adapter
	Pepper     *security.Pepper   // hashes OTP codes (context "otp") and recovery codes ("recovery")
	Encrypter  security.Encrypter // seals TOTP secrets at rest
	TOTP       TOTPProvider       // *TOTP in production
	QR         QRRenderer         // nil: SVGQRCode
	SMS        notify.SMSSender
	Mailer     notify.Mailer
	Cache      cache.Cache // OTP send budgets; share it between replicas
	Sessions   Sessions
	Tickets    Tickets
	Principals PrincipalResolver
	// FactorTypes are the plugins' factor types; a core type name or a duplicate fails New.
	FactorTypes []FactorType
	Auth        config.Auth
	Clock       clock.Clock      // nil: clock.System
	Events      event.Dispatcher // nil: event.Nop
}

// Service is multi-factor authentication: TOTP, SMS and email factors (enrollment,
// confirmation, management), the OTP engine, recovery codes, and the login MFA gate and step-up
// that verify them. It is safe for concurrent use: single-use codes are claimed with conditional
// updates in the database, not with locks in the process.
type Service struct {
	db         store.Adapter
	repos      *repository.Repos
	pepper     *security.Pepper
	encrypter  security.Encrypter
	totp       TOTPProvider
	qr         QRRenderer
	sms        notify.SMSSender
	mailer     notify.Mailer
	cache      cache.Cache
	sessions   Sessions
	tickets    Tickets
	principals PrincipalResolver
	types      map[string]FactorType
	otp        config.OTP
	mfa        config.MFA
	clock      clock.Clock
	events     event.Dispatcher

	quotaMu sync.Mutex // serializes the send-budget read-modify-write within this process
}

// New validates cfg and returns a Service.
func New(cfg Config) (*Service, error) {
	var missing []string
	for _, c := range []struct {
		name   string
		absent bool
	}{
		{"DB", cfg.DB == nil}, {"Pepper", cfg.Pepper == nil}, {"Encrypter", cfg.Encrypter == nil},
		{"TOTP", cfg.TOTP == nil}, {"SMS", cfg.SMS == nil}, {"Mailer", cfg.Mailer == nil}, {"Cache", cfg.Cache == nil},
		{"Sessions", cfg.Sessions == nil}, {"Tickets", cfg.Tickets == nil}, {"Principals", cfg.Principals == nil},
	} {
		if c.absent {
			missing = append(missing, "Config."+c.name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: %s required", ErrInvalidConfig, strings.Join(missing, ", "))
	}
	if cfg.Auth.OTP.Length <= 0 || cfg.Auth.OTP.MaxAttempts <= 0 {
		return nil, fmt.Errorf("%w: Config.Auth.OTP.Length and MaxAttempts must be positive (auth.otp.length, auth.otp.max_attempts): start from config.Defaults()", ErrInvalidConfig)
	}
	types, err := factorTypes(cfg.FactorTypes)
	if err != nil {
		return nil, err
	}
	s := &Service{
		db: cfg.DB, repos: repository.New(cfg.DB), pepper: cfg.Pepper, encrypter: cfg.Encrypter, totp: cfg.TOTP,
		qr: cfg.QR, sms: cfg.SMS, mailer: cfg.Mailer, cache: cfg.Cache, sessions: cfg.Sessions, tickets: cfg.Tickets,
		principals: cfg.Principals, types: types, otp: cfg.Auth.OTP, mfa: cfg.Auth.MFA, clock: cfg.Clock, events: cfg.Events,
	}
	if s.qr == nil {
		s.qr = SVGQRCode{}
	}
	if s.clock == nil {
		s.clock = clock.System{}
	}
	if s.events == nil {
		s.events = event.Nop{}
	}
	return s, nil
}

var coreTypes = []string{model.FactorTOTP, model.FactorSMS, model.FactorEmail}

func factorTypes(list []FactorType) (map[string]FactorType, error) {
	types := make(map[string]FactorType, len(list))
	for _, t := range list {
		if t == nil || t.Type() == "" {
			return nil, fmt.Errorf("%w: Config.FactorTypes holds a nil or unnamed factor type", ErrInvalidConfig)
		}
		name := t.Type()
		if _, dup := types[name]; dup || slices.Contains(coreTypes, name) {
			return nil, fmt.Errorf("%w: the MFA factor type %q is already verified by core or another plugin: rename it", ErrInvalidConfig, name)
		}
		types[name] = t
	}
	return types, nil
}

// owned returns the user's factor id, or ErrFactorNotFound when it is unknown or another user's.
func (s *Service) owned(ctx context.Context, userID, factorID string) (model.MFAFactor, error) {
	f, err := s.repos.MFAFactors.Get(ctx, factorID)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		return model.MFAFactor{}, ErrFactorNotFound
	case err != nil:
		return model.MFAFactor{}, fmt.Errorf("mfa: load factor: %w", err)
	case f.UserID != userID:
		return model.MFAFactor{}, ErrFactorNotFound
	}
	return f, nil
}

func ptr[T any](v T) *T { return &v }

// optional is nil for "", as the nullable columns and event fields store "none".
func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
