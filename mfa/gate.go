package mfa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/token"
)

// ConfirmedFactors returns the user's confirmed factors, the only ones that can satisfy the
// login gate or step-up.
func (s *Service) ConfirmedFactors(ctx context.Context, userID string) ([]model.MFAFactor, error) {
	fs, err := s.Factors(ctx, userID)
	if err != nil {
		return nil, err
	}
	var confirmed []model.MFAFactor
	for _, f := range fs {
		if f.ConfirmedAt != nil {
			confirmed = append(confirmed, f)
		}
	}
	return confirmed, nil
}

// HasConfirmedFactor reports whether MFA (and so step-up) applies to the user.
func (s *Service) HasConfirmedFactor(ctx context.Context, userID string) (bool, error) {
	fs, err := s.ConfirmedFactors(ctx, userID)
	return len(fs) > 0, err
}

// Challenge sends a code for the user's confirmed sms or email factor under purpose
// (PurposeLoginMFA at the gate, PurposeStepUp for step-up). ErrFactorNotFound: not one of the
// user's confirmed factors; ErrInvalidOTP: a factor type with no sent code (TOTP, a plugin's);
// ErrOTPCooldown: throttled (see SendOTP).
func (s *Service) Challenge(ctx context.Context, userID, factorID string, purpose ChallengePurpose, client token.ClientContext) (OTPChallengeResult, error) {
	f, err := s.confirmed(ctx, userID, factorID)
	if err != nil {
		return OTPChallengeResult{}, err
	}
	if f.Type != model.FactorSMS && f.Type != model.FactorEmail {
		return OTPChallengeResult{}, fmt.Errorf("%w: this factor does not require a challenge", ErrInvalidOTP)
	}
	return s.SendOTP(ctx, userID, f, purpose, client)
}

// Verify checks code against the user's confirmed factor under purpose, or, with no factorID,
// against the user's recovery codes. It returns the factor that cleared ("" for a recovery
// code). It mints nothing and dispatches no gate event: VerifyLogin and VerifyStepUp do.
// ErrFactorNotFound: not one of the user's confirmed factors, or a type no one verifies;
// ErrInvalidOTP: the code failed.
func (s *Service) Verify(ctx context.Context, userID, factorID, code string, purpose ChallengePurpose) (string, error) {
	if factorID == "" {
		ok, err := s.VerifyRecoveryCode(ctx, userID, code)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", ErrInvalidOTP
		}
		return "", nil
	}

	f, err := s.confirmed(ctx, userID, factorID)
	if err != nil {
		return "", err
	}
	switch f.Type {
	case model.FactorTOTP:
		err = s.verifyTOTP(ctx, userID, factorID, code)
	case model.FactorSMS, model.FactorEmail:
		err = s.VerifyOTP(ctx, userID, factorID, code, purpose)
	default:
		t, ok := s.types[f.Type]
		if !ok {
			return "", ErrFactorNotFound // a row of a type nobody verifies is unusable
		}
		err = t.Verify(ctx, f, code, purpose)
	}
	if err != nil {
		return "", err
	}
	return factorID, nil
}

// verifyCounted is Verify behind the per-user attempt limit of the gate and step-up: every
// attempt is counted before its code is checked, and one that clears resets the count. After
// auth.lockout.max_attempts attempts that did not clear, every code (a right one, a recovery code)
// is refused as ErrInvalidOTP, checked against nothing, until auth.lockout.lock_duration has
// passed since the first of them. The password lockout does not cover this step: the login_mfa
// ticket is stateless, and whoever holds the password can mint another.
func (s *Service) verifyCounted(ctx context.Context, userID, factorID, code string, purpose ChallengePurpose) (string, error) {
	key := "mfa.verify.acct." + userID
	if err := s.reserveAttempt(ctx, key); err != nil {
		return "", err
	}
	verified, err := s.Verify(ctx, userID, factorID, code, purpose)
	if err != nil {
		return "", err
	}
	if err := s.cache.Delete(ctx, key); err != nil {
		return "", fmt.Errorf("mfa: reset second-factor attempts: %w", err)
	}
	return verified, nil
}

// reserveAttempt counts one attempt under key, or returns ErrInvalidOTP when the limit is spent.
// Like the send budget, the cache read-modify-write is atomic within the process, not across
// replicas; the per-IP rate limit bounds the residual.
func (s *Service) reserveAttempt(ctx context.Context, key string) error {
	now := s.clock.Now().Unix()
	s.quotaMu.Lock()
	defer s.quotaMu.Unlock()
	b, err := s.readBudget(ctx, key, now, s.lockout.Duration)
	if err != nil {
		return err
	}
	if b.Count >= s.lockout.MaxAttempts {
		return ErrInvalidOTP
	}
	raw, _ := json.Marshal(sendBudget{Count: b.Count + 1, Start: b.Start}) // cannot fail
	if err := s.cache.Set(ctx, key, raw, s.lockout.Duration); err != nil {
		return fmt.Errorf("mfa: count second-factor attempt: %w", err)
	}
	return nil
}

// LoginChallenge is the MFA-required outcome of a password login: no session yet, a short-lived
// login_mfa ticket and the factors the client may complete the second step with.
type LoginChallenge struct {
	UserID   string
	MFAToken string
	Factors  []FactorView
}

// BeginLogin mints the login_mfa ticket for a user who passed the first step and lists confirmed
// (from ConfirmedFactors, or the part of it the first step leaves usable) as the client sees them.
// The ticket completes the gate with those factors only (or a recovery code): a factor left out
// is refused at /auth/mfa/challenge and /auth/mfa/verify.
func (s *Service) BeginLogin(userID string, confirmed []model.MFAFactor) (LoginChallenge, error) {
	ids := make([]string, len(confirmed))
	views := make([]FactorView, len(confirmed))
	for i, f := range confirmed {
		ids[i], views[i] = f.ID, ViewOf(f)
	}
	ticket, err := s.tickets.IssueFor(userID, ids)
	if err != nil {
		return LoginChallenge{}, fmt.Errorf("mfa: issue login ticket: %w", err)
	}
	return LoginChallenge{UserID: userID, MFAToken: ticket, Factors: views}, nil
}

// VerifyLogin completes an MFA login: it verifies code (see Verify, purpose login_mfa) and opens
// the real session, its access token recording a full second-factor authentication
// (amr ["pwd","otp"], mfa true, auth_time now). It dispatches event.MFAVerified and
// event.UserLoggedIn; a refused code dispatches event.MFAVerifyFailed.
func (s *Service) VerifyLogin(ctx context.Context, userID, factorID, code string, client token.ClientContext) (token.IssuedTokens, error) {
	verified, err := s.verifyCounted(ctx, userID, factorID, code, PurposeLoginMFA)
	if err != nil {
		s.verifyFailed(ctx, userID, factorID, err)
		return token.IssuedTokens{}, err
	}

	base, err := s.principals.Resolve(ctx, userID, "")
	if err != nil {
		return token.IssuedTokens{}, fmt.Errorf("mfa: resolve principal: %w", err)
	}
	amr := []string{"pwd", "otp"}
	p := token.SessionPrincipal{
		UserID: base.UserID, OrganizationID: base.OrganizationID, Roles: base.Roles, Scope: base.Scope,
		EmailVerified: base.EmailVerified, MFA: true, AMR: amr, AuthTime: ptr(s.clock.Now().Unix()),
	}
	tokens, err := s.sessions.Issue(ctx, p, client)
	if err != nil {
		return token.IssuedTokens{}, err
	}
	s.events.Dispatch(ctx, event.MFAVerified{UserID: userID, FactorID: optional(verified)})
	s.events.Dispatch(ctx, event.UserLoggedIn{UserID: userID, SessionID: tokens.SessionID, IP: optional(client.IP), UserAgent: optional(client.UserAgent), AMR: amr})
	return tokens, nil
}

// VerifyStepUp re-verifies a factor (or recovery code) in a live session, purpose step_up, and
// returns a fresh access token for that session recording the new authentication; no new
// session, no refresh rotation. organizationID is the session's ("" for none). It dispatches
// event.MFAStepUpCompleted; a refused code dispatches event.MFAVerifyFailed. A session that is no
// longer live fails with the session service's error.
func (s *Service) VerifyStepUp(ctx context.Context, userID, organizationID, sessionID, factorID, code string) (string, error) {
	if _, err := s.verifyCounted(ctx, userID, factorID, code, PurposeStepUp); err != nil {
		s.verifyFailed(ctx, userID, factorID, err)
		return "", err
	}
	access, err := s.sessions.StepUp(ctx, userID, organizationID, sessionID)
	if err != nil {
		return "", err
	}
	s.events.Dispatch(ctx, event.MFAStepUpCompleted{UserID: userID, SessionID: sessionID})
	return access, nil
}

// verifyFailed dispatches the gate-failure event for a refused code, recording the attempted
// factor and, only when it is the user's confirmed factor, its type (the response discloses no
// more, so neither does the audit row). The factor-less path is a recovery-code attempt.
func (s *Service) verifyFailed(ctx context.Context, userID, factorID string, err error) {
	if !errors.Is(err, ErrInvalidOTP) && !errors.Is(err, ErrFactorNotFound) {
		return
	}
	e := event.MFAVerifyFailed{UserID: userID, Type: ptr(event.MFAVerifyFailedTypeRecovery)}
	if factorID != "" {
		e.FactorID, e.Type = &factorID, nil
		if f, err := s.confirmed(ctx, userID, factorID); err == nil {
			e.Type = &f.Type
		}
	}
	s.events.Dispatch(ctx, e)
}

// confirmed returns the user's confirmed factor, or ErrFactorNotFound.
func (s *Service) confirmed(ctx context.Context, userID, factorID string) (model.MFAFactor, error) {
	f, err := s.owned(ctx, userID, factorID)
	if err == nil && f.ConfirmedAt == nil {
		return model.MFAFactor{}, ErrFactorNotFound
	}
	return f, err
}
