package mfa

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/security"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

// TOTPEnrollResult starts a TOTP enrollment: the new unconfirmed factor, the base32 secret and
// otpauth:// URI for manual or scanned setup, and the URI as an SVG QR code. The secret is shown
// only until confirmation; it is kept out of fmt and slog output, with the URI and QR that embed it.
type TOTPEnrollResult struct {
	FactorID   string
	Secret     string
	OTPAuthURI string
	QRSVG      string
}

func (r TOTPEnrollResult) String() string {
	return "mfa.TOTPEnrollResult{FactorID:" + r.FactorID + " Secret:[redacted] OTPAuthURI:[redacted] QRSVG:[redacted]}"
}

// GoString keeps the secret out of %#v output.
func (r TOTPEnrollResult) GoString() string { return r.String() }

// LogValue keeps the secret out of logs.
func (r TOTPEnrollResult) LogValue() slog.Value {
	return slog.GroupValue(slog.String("factor_id", r.FactorID), slog.String("secret", "[redacted]"))
}

// OTPEnrollResult starts an SMS or email enrollment: the new unconfirmed factor, the channel and
// the masked destination the code went to.
type OTPEnrollResult struct {
	FactorID          string
	Channel           string
	MaskedDestination string
}

// ConfirmFactor marks an already-verified factor confirmed. The user's first confirmed factor
// also becomes the default, gets a batch of recovery codes (returned once) and dispatches
// event.MFAEnrolled. Plugins confirm their own factor types through it.
func (s *Service) ConfirmFactor(ctx context.Context, factor model.MFAFactor) (ConfirmResult, error) {
	return s.confirm(ctx, factor, factor)
}

// confirm writes changed (stored plus the caller's own changes, e.g. the TOTP step) confirmed.
func (s *Service) confirm(ctx context.Context, stored, changed model.MFAFactor) (ConfirmResult, error) {
	now := s.clock.Now()
	first := false
	if stored.ConfirmedAt == nil {
		others, err := s.ConfirmedFactors(ctx, stored.UserID)
		if err != nil {
			return ConfirmResult{}, err
		}
		first = !containsOther(others, stored.ID)
		changed.ConfirmedAt = &now
	}
	if first {
		changed.IsDefault = true
	}
	changed.UpdatedAt = now

	codes := []string{}
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		if err := s.repos.MFAFactors.Update(ctx, stored, changed); err != nil {
			return fmt.Errorf("mfa: confirm factor: %w", err)
		}
		if !first {
			return nil
		}
		var err error
		codes, err = s.issueRecoveryCodes(ctx, stored.UserID)
		return err
	})
	if err != nil {
		return ConfirmResult{}, err
	}
	if first {
		s.events.Dispatch(ctx, event.MFAEnrolled{UserID: stored.UserID, FactorID: stored.ID, Type: &changed.Type})
	}
	return ConfirmResult{RecoveryCodes: codes}, nil
}

func containsOther(fs []model.MFAFactor, id string) bool {
	for _, f := range fs {
		if f.ID != id {
			return true
		}
	}
	return false
}

// EnrollTOTP starts authenticator-app enrollment for user: a fresh secret, stored encrypted on a
// new unconfirmed factor, returned with its provisioning URI (labelled with the user's email)
// and QR code.
func (s *Service) EnrollTOTP(ctx context.Context, user model.User) (TOTPEnrollResult, error) {
	secret := s.totp.GenerateSecret()
	uri, err := s.totp.ProvisioningURI(secret, user.Email)
	if err != nil {
		return TOTPEnrollResult{}, err
	}
	svg, err := s.qr.SVG(uri)
	if err != nil {
		return TOTPEnrollResult{}, err
	}
	sealed, err := s.encrypter.Encrypt(secret)
	if err != nil {
		return TOTPEnrollResult{}, fmt.Errorf("mfa: encrypt TOTP secret: %w", err)
	}
	now := s.clock.Now()
	f := model.MFAFactor{ID: repository.NewID(), UserID: user.ID, Type: model.FactorTOTP, SecretEncrypted: &sealed, CreatedAt: now, UpdatedAt: now}
	if err := s.repos.MFAFactors.Insert(ctx, f); err != nil {
		return TOTPEnrollResult{}, fmt.Errorf("mfa: store TOTP factor: %w", err)
	}
	return TOTPEnrollResult{FactorID: f.ID, Secret: secret, OTPAuthURI: uri, QRSVG: svg}, nil
}

// ConfirmTOTP verifies the first code from the app and confirms the user's TOTP factor (see
// ConfirmFactor). ErrFactorNotFound: not the user's TOTP factor; ErrInvalidOTP: a wrong code or
// a replayed time step.
func (s *Service) ConfirmTOTP(ctx context.Context, userID, factorID, code string) (ConfirmResult, error) {
	f, err := s.ownedOfType(ctx, userID, factorID, model.FactorTOTP)
	if err != nil {
		return ConfirmResult{}, err
	}
	fenced, err := s.fenceTOTP(ctx, f, code)
	if err != nil {
		return ConfirmResult{}, err
	}
	return s.confirm(ctx, fenced, fenced)
}

// verifyTOTP checks a code for the user's TOTP factor at the gate: the same check and replay
// fence as ConfirmTOTP, recording the step, without the enrollment tail.
func (s *Service) verifyTOTP(ctx context.Context, userID, factorID, code string) error {
	f, err := s.ownedOfType(ctx, userID, factorID, model.FactorTOTP)
	if err != nil {
		return err
	}
	fenced, err := s.fenceTOTP(ctx, f, code)
	if err != nil {
		return err
	}
	touched := fenced
	touched.UpdatedAt = s.clock.Now()
	if err := s.repos.MFAFactors.Update(ctx, fenced, touched); err != nil {
		return fmt.Errorf("mfa: record TOTP step: %w", err)
	}
	return nil
}

// fenceTOTP matches code within the skew window, rejects a step at or before the last accepted
// one (replay), and claims the matched step in last_used_at with one conditional UPDATE, so of
// two concurrent uses of one code exactly one passes. It returns f as now stored.
func (s *Service) fenceTOTP(ctx context.Context, f model.MFAFactor, code string) (model.MFAFactor, error) {
	secret, err := s.encrypter.Decrypt(deref(f.SecretEncrypted))
	if errors.Is(err, security.ErrDecrypt) {
		// Corruption or a rotated key cannot verify a code: a wrong code, not a 500.
		return f, ErrInvalidOTP
	}
	if err != nil {
		return f, fmt.Errorf("mfa: decrypt TOTP secret: %w", err)
	}
	step, ok, err := s.totp.Match(secret, code)
	if err != nil {
		return f, err
	}
	if !ok {
		return f, ErrInvalidOTP
	}
	if f.LastUsedAt != nil && step <= f.LastUsedAt.Unix() {
		return f, fmt.Errorf("%w: the code has already been used", ErrInvalidOTP)
	}
	stepAt := time.Unix(step, 0).UTC()
	// The database re-checks the fence: last_used_at still NULL, or still before this step.
	var fence any = store.Lt(stepAt)
	if f.LastUsedAt == nil {
		fence = nil
	}
	n, err := s.db.Update(ctx, factorsTable, store.Criteria{"id": f.ID, "last_used_at": fence}, store.Data{"last_used_at": stepAt})
	if err != nil {
		return f, fmt.Errorf("mfa: claim TOTP step: %w", err)
	}
	if n != 1 {
		return f, fmt.Errorf("%w: the code has already been used", ErrInvalidOTP)
	}
	f.LastUsedAt = &stepAt
	return f, nil
}

const factorsTable = "auth_mfa_factors"

// EnrollOTPFactor creates an unconfirmed sms or email factor (factorType model.FactorSMS or
// model.FactorEmail) for destination, an E.164 phone or an email address validated by the
// caller, and sends its enroll code. A still-unconfirmed factor of that channel is replaced, so
// re-enrolling cannot pile up rows (or sends).
func (s *Service) EnrollOTPFactor(ctx context.Context, user model.User, factorType, destination string, client token.ClientContext) (OTPEnrollResult, error) {
	if factorType != model.FactorSMS && factorType != model.FactorEmail {
		return OTPEnrollResult{}, fmt.Errorf("mfa: OTP factor type %q is not sms or email", factorType)
	}
	now := s.clock.Now()
	f := model.MFAFactor{ID: repository.NewID(), UserID: user.ID, Type: factorType, CreatedAt: now, UpdatedAt: now}
	if factorType == model.FactorSMS {
		f.PhoneE164 = &destination
	} else {
		f.Email = &destination
	}
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		existing, err := s.repos.MFAFactors.ListByUserAndType(ctx, user.ID, factorType)
		if err != nil {
			return err
		}
		for _, e := range existing {
			if e.ConfirmedAt == nil {
				if err := s.repos.MFAFactors.Delete(ctx, e); err != nil {
					return err
				}
			}
		}
		return s.repos.MFAFactors.Insert(ctx, f)
	})
	if err != nil {
		return OTPEnrollResult{}, fmt.Errorf("mfa: store %s factor: %w", factorType, err)
	}

	sent, err := s.SendOTP(ctx, user.ID, f, PurposeEnroll, client)
	if err != nil {
		return OTPEnrollResult{}, err
	}
	return OTPEnrollResult{FactorID: f.ID, Channel: sent.Channel, MaskedDestination: sent.MaskedDestination}, nil
}

// ConfirmOTPFactor verifies the enroll code of the user's sms or email factor and confirms it
// (see ConfirmFactor). ErrFactorNotFound: not the user's sms/email factor; ErrInvalidOTP: the
// code failed (see VerifyOTP).
func (s *Service) ConfirmOTPFactor(ctx context.Context, userID, factorID, code string) (ConfirmResult, error) {
	f, err := s.owned(ctx, userID, factorID)
	if err != nil {
		return ConfirmResult{}, err
	}
	if f.Type != model.FactorSMS && f.Type != model.FactorEmail {
		return ConfirmResult{}, ErrFactorNotFound
	}
	if err := s.VerifyOTP(ctx, userID, factorID, code, PurposeEnroll); err != nil {
		return ConfirmResult{}, err
	}
	used := f
	used.LastUsedAt = ptr(s.clock.Now())
	return s.confirm(ctx, f, used)
}

func (s *Service) ownedOfType(ctx context.Context, userID, factorID, factorType string) (model.MFAFactor, error) {
	f, err := s.owned(ctx, userID, factorID)
	if err == nil && f.Type != factorType {
		return model.MFAFactor{}, ErrFactorNotFound
	}
	return f, err
}
