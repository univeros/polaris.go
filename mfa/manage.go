package mfa

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
)

// maxLabelLength is the auth_mfa_factors.label column width, in characters.
const maxLabelLength = 80

// Factors returns every factor of the user, confirmed or pending.
func (s *Service) Factors(ctx context.Context, userID string) ([]model.MFAFactor, error) {
	fs, err := s.repos.MFAFactors.ListByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("mfa: load factors: %w", err)
	}
	return fs, nil
}

// UpdateFactor relabels the user's factor and/or makes it the default, returning it as stored.
// A nil label leaves the label alone, an empty one clears it; only a confirmed factor can become
// the default (the previous default is cleared). Errors: ErrFactorNotFound, or a *PolicyError
// wrapping ErrInvalidFactorState.
func (s *Service) UpdateFactor(ctx context.Context, userID, factorID string, label *string, makeDefault bool) (model.MFAFactor, error) {
	f, err := s.owned(ctx, userID, factorID)
	if err != nil {
		return model.MFAFactor{}, err
	}
	changed := f
	if label != nil {
		if utf8.RuneCountInString(*label) > maxLabelLength {
			return model.MFAFactor{}, &PolicyError{ErrInvalidFactorState, fmt.Sprintf("A factor label may be at most %d characters.", maxLabelLength)}
		}
		changed.Label = optional(*label)
	}
	if makeDefault && f.ConfirmedAt == nil {
		return model.MFAFactor{}, &PolicyError{ErrInvalidFactorState, "Only a confirmed factor can be the default."}
	}
	now := s.clock.Now()
	changed.IsDefault = changed.IsDefault || makeDefault
	changed.UpdatedAt = now

	err = s.db.Tx(ctx, func(ctx context.Context) error {
		if makeDefault {
			if err := s.setDefault(ctx, userID, factorID, false, now); err != nil {
				return err
			}
		}
		return s.repos.MFAFactors.Update(ctx, f, changed)
	})
	if err != nil {
		return model.MFAFactor{}, fmt.Errorf("mfa: update factor: %w", err)
	}
	return changed, nil
}

// RemoveFactor deletes the user's factor and dispatches event.MFAFactorRemoved. Removing the
// last confirmed factor of a user for whom MFA is enforced is refused with a *PolicyError
// wrapping ErrLastFactorProtected; removing the default promotes the oldest other confirmed
// factor, so a confirmed user always keeps a default.
func (s *Service) RemoveFactor(ctx context.Context, userID, factorID string) error {
	f, err := s.owned(ctx, userID, factorID)
	if err != nil {
		return err
	}
	if f.ConfirmedAt != nil {
		confirmed, err := s.ConfirmedFactors(ctx, userID)
		if err != nil {
			return err
		}
		if !containsOther(confirmed, factorID) {
			enforced, err := s.IsEnforced(ctx, userID)
			if err != nil {
				return err
			}
			if enforced {
				return &PolicyError{ErrLastFactorProtected, "Enrol another factor before removing your last one."}
			}
		}
	}

	err = s.db.Tx(ctx, func(ctx context.Context) error {
		if f.IsDefault {
			if err := s.setDefault(ctx, userID, factorID, true, s.clock.Now()); err != nil {
				return err
			}
		}
		return s.repos.MFAFactors.Delete(ctx, f)
	})
	if err != nil {
		return fmt.Errorf("mfa: remove factor: %w", err)
	}
	s.events.Dispatch(ctx, event.MFAFactorRemoved{UserID: userID, FactorID: factorID})
	return nil
}

// setDefault, for every factor of the user but except: with promote false, clears the default
// flag; with promote true, makes the oldest confirmed one the default.
func (s *Service) setDefault(ctx context.Context, userID, except string, promote bool, now time.Time) error {
	fs, err := s.repos.MFAFactors.ListByUser(ctx, userID)
	if err != nil {
		return err
	}
	var candidate *model.MFAFactor
	for i, f := range fs {
		switch {
		case f.ID == except:
		case !promote && f.IsDefault:
			cleared := f
			cleared.IsDefault, cleared.UpdatedAt = false, now
			if err := s.repos.MFAFactors.Update(ctx, f, cleared); err != nil {
				return err
			}
		case promote && f.ConfirmedAt != nil && (candidate == nil || f.CreatedAt.Before(candidate.CreatedAt)):
			candidate = &fs[i]
		}
	}
	if candidate == nil {
		return nil
	}
	promoted := *candidate
	promoted.IsDefault, promoted.UpdatedAt = true, now
	return s.repos.MFAFactors.Update(ctx, *candidate, promoted)
}

// IsEnforced reports whether MFA is enforced for the user: the global auth.mfa.enforce switch or
// the user's mfa_enforced flag. Enforcement makes the last confirmed factor undeletable.
func (s *Service) IsEnforced(ctx context.Context, userID string) (bool, error) {
	if s.mfa.Enforce {
		return true, nil
	}
	u, err := s.repos.Users.Get(ctx, userID)
	if errors.Is(err, repository.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("mfa: load user: %w", err)
	}
	return u.MFAEnforced, nil
}
