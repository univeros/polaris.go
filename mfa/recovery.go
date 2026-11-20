package mfa

import (
	"context"
	"fmt"
	"math/big"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
)

// RecoveryCodeCount is the number of codes in a recovery batch.
const RecoveryCodeCount = 10

const (
	recoveryPepperContext = "recovery"
	// recoveryAlphabet is base32 without the look-alikes 0/1/8/9/o/i/l.
	recoveryAlphabet    = "abcdefghjkmnpqrstuvwxyz234567"
	recoveryGroupLength = 5
)

// issueRecoveryCodes stores a fresh batch (hashed, pepper context "recovery") and returns the
// plaintext codes, formatted xxxxx-xxxxx. Run it in the caller's transaction so issuance commits
// with the change that triggered it.
func (s *Service) issueRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	now := s.clock.Now()
	codes := make([]string, RecoveryCodeCount)
	for i := range codes {
		codes[i] = recoveryGroup() + "-" + recoveryGroup()
		row := model.RecoveryCode{ID: repository.NewID(), UserID: userID, CodeHash: s.pepper.Hash(recoveryPepperContext, codes[i]), CreatedAt: now}
		if err := s.repos.RecoveryCodes.Insert(ctx, row); err != nil {
			return nil, fmt.Errorf("mfa: store recovery code: %w", err)
		}
	}
	return codes, nil
}

// VerifyRecoveryCode spends a recovery code: true when code matches one of the user's unused
// codes, which is then used up (event.MFARecoveryUsed); false, changing nothing, otherwise.
// Every unused code is compared, so the timing does not depend on which one matched; the spend
// is a compare-and-swap, so of two concurrent verifies of one code exactly one succeeds.
func (s *Service) VerifyRecoveryCode(ctx context.Context, userID, code string) (bool, error) {
	unused, err := s.unusedRecoveryCodes(ctx, userID)
	if err != nil {
		return false, err
	}
	var match *model.RecoveryCode
	for i := range unused {
		if s.pepper.Matches(recoveryPepperContext, code, unused[i].CodeHash) {
			match = &unused[i]
		}
	}
	if match == nil {
		return false, nil
	}

	claimed, err := s.repos.RecoveryCodes.ClaimUse(ctx, match.ID, s.clock.Now())
	if err != nil {
		return false, fmt.Errorf("mfa: spend recovery code: %w", err)
	}
	if !claimed {
		return false, nil
	}
	s.events.Dispatch(ctx, event.MFARecoveryUsed{UserID: userID, Remaining: len(unused) - 1})
	return true, nil
}

// RegenerateRecoveryCodes retires every unused code of the user and returns a fresh batch, in
// one transaction, then dispatches event.MFARecoveryRegenerated. The codes are shown once.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	now := s.clock.Now()
	var codes []string
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		unused, err := s.unusedRecoveryCodes(ctx, userID)
		if err != nil {
			return err
		}
		for _, c := range unused {
			retired := c
			retired.UsedAt = &now
			if err := s.repos.RecoveryCodes.Update(ctx, c, retired); err != nil {
				return fmt.Errorf("mfa: retire recovery code: %w", err)
			}
		}
		codes, err = s.issueRecoveryCodes(ctx, userID)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.events.Dispatch(ctx, event.MFARecoveryRegenerated{UserID: userID})
	return codes, nil
}

// RemainingRecoveryCodes counts the user's unused recovery codes, the signal a host surfaces
// (say, 3 or fewer left) to prompt regeneration.
func (s *Service) RemainingRecoveryCodes(ctx context.Context, userID string) (int, error) {
	unused, err := s.unusedRecoveryCodes(ctx, userID)
	return len(unused), err
}

// unusedRecoveryCodes returns the user's spendable codes. The query is scoped to used_at IS NULL;
// the re-check is the authoritative single-use guard, whatever the store returned.
func (s *Service) unusedRecoveryCodes(ctx context.Context, userID string) ([]model.RecoveryCode, error) {
	rows, err := s.repos.RecoveryCodes.ListUnusedByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("mfa: load recovery codes: %w", err)
	}
	var unused []model.RecoveryCode
	for _, r := range rows {
		if r.UsedAt == nil {
			unused = append(unused, r)
		}
	}
	return unused, nil
}

func recoveryGroup() string {
	n := big.NewInt(int64(len(recoveryAlphabet)))
	b := make([]byte, recoveryGroupLength)
	for i := range b {
		b[i] = recoveryAlphabet[randomBelow(n).Int64()]
	}
	return string(b)
}
