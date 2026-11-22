package mfa

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/notify"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/token"
)

const otpPepperContext = "otp"

// OTPChallengeResult is an issued OTP challenge: its id, the channel it went over and the masked
// destination safe to echo to the client (+1 *** *** 0101). The code itself is never returned.
type OTPChallengeResult struct {
	ChallengeID       string
	Channel           string
	MaskedDestination string
}

// SendOTP issues and sends a fresh one-time code for an sms or email factor under purpose.
//
// The code is otp.length CSPRNG digits, stored only as its keyed hash (pepper context "otp"),
// valid otp.ttl and otp.max_attempts tries, single-use. A request inside otp.resend_cooldown of
// the newest live challenge, or past the per-account or per-destination budget of otp.send_max
// sends per otp.send_window, fails with ErrOTPCooldown. A new challenge supersedes the older live
// ones, so only the freshest code works. A factor of another type, or with no destination, fails
// with ErrInvalidOTP.
func (s *Service) SendOTP(ctx context.Context, userID string, factor model.MFAFactor, purpose ChallengePurpose, client token.ClientContext) (OTPChallengeResult, error) {
	if factor.Type != model.FactorSMS && factor.Type != model.FactorEmail {
		return OTPChallengeResult{}, fmt.Errorf("%w: OTP challenges apply only to sms/email factors", ErrInvalidOTP)
	}
	channel := factor.Type
	destination := deref(factor.Email)
	if channel == model.FactorSMS {
		destination = deref(factor.PhoneE164)
	}
	if destination == "" {
		return OTPChallengeResult{}, fmt.Errorf("%w: the factor has no destination to send a code to", ErrInvalidOTP)
	}

	now := s.clock.Now()
	pending, err := s.pending(ctx, userID, factor.ID, purpose, now)
	if err != nil {
		return OTPChallengeResult{}, err
	}
	// Both guards run before anything is written, so a throttled request changes nothing.
	if newest, ok := newestOf(pending); ok && now.Unix()-newest.CreatedAt.Unix() < int64(s.otp.ResendCooldown/time.Second) {
		return OTPChallengeResult{}, ErrOTPCooldown
	}
	if err := s.spendSendBudget(ctx, userID, destination, now); err != nil {
		return OTPChallengeResult{}, err
	}

	code := s.generateCode()
	challenge := model.OTPChallenge{
		ID: repository.NewID(), UserID: userID, FactorID: &factor.ID, Purpose: string(purpose), Channel: channel,
		CodeHash: ptr(s.pepper.Hash(otpPepperContext, code)), Destination: &destination, MaxAttempts: s.otp.MaxAttempts,
		ExpiresAt: now.Add(s.otp.TTL), IP: optional(client.IP), CreatedAt: now,
	}
	err = s.db.Tx(ctx, func(ctx context.Context) error {
		for _, p := range pending {
			superseded := p
			superseded.ConsumedAt = &now
			if err := s.repos.OTPChallenges.Update(ctx, p, superseded); err != nil {
				return err
			}
		}
		return s.repos.OTPChallenges.Insert(ctx, challenge)
	})
	if err != nil {
		return OTPChallengeResult{}, fmt.Errorf("mfa: store OTP challenge: %w", err)
	}

	if err := s.deliver(ctx, channel, destination, code); err != nil {
		return OTPChallengeResult{}, fmt.Errorf("mfa: deliver OTP over %s: %w", channel, err)
	}
	s.events.Dispatch(ctx, event.OTPChallengeSent{UserID: userID, FactorID: factor.ID, Channel: channel})
	return OTPChallengeResult{ChallengeID: challenge.ID, Channel: channel, MaskedDestination: MaskDestination(channel, destination)}, nil
}

// VerifyOTP checks code against the newest live challenge of the user's factor under purpose and
// consumes it. Every presented code spends an attempt, before it is compared. Any failure is
// ErrInvalidOTP: no live challenge, its attempts spent (even with the right code), a wrong code
// (which dispatches event.OTPVerifyFailed), or a challenge another request consumed first.
func (s *Service) VerifyOTP(ctx context.Context, userID, factorID, code string, purpose ChallengePurpose) error {
	now := s.clock.Now()
	pending, err := s.pending(ctx, userID, factorID, purpose, now)
	if err != nil {
		return err
	}
	// No live challenge, or its budget spent: the same failure as a wrong code (no oracle for
	// whether a challenge exists).
	c, ok := newestOf(pending)
	if !ok || c.Attempts >= c.MaxAttempts {
		return ErrInvalidOTP
	}

	// Reserve the attempt before comparing: the database counts attempts < max_attempts, so of
	// any number of concurrent requests only max_attempts ever get a compare, whatever each read.
	// A right code spends an attempt too.
	reserved, err := s.repos.OTPChallenges.SpendAttempt(ctx, c.ID, c.MaxAttempts)
	if err != nil {
		return fmt.Errorf("mfa: spend OTP attempt: %w", err)
	}
	if !reserved {
		return ErrInvalidOTP
	}
	if !s.pepper.Matches(otpPepperContext, code, deref(c.CodeHash)) {
		left := max(0, c.MaxAttempts-c.Attempts-1)
		s.events.Dispatch(ctx, event.OTPVerifyFailed{UserID: userID, FactorID: factorID, AttemptsLeft: &left})
		return ErrInvalidOTP
	}

	// Compare-and-swap on consumed_at: of two presentations of one correct code, one wins.
	claimed, err := s.repos.OTPChallenges.ClaimConsumption(ctx, c.ID, now)
	if err != nil {
		return fmt.Errorf("mfa: consume OTP challenge: %w", err)
	}
	if !claimed {
		return ErrInvalidOTP
	}
	return nil
}

// pending returns the live (unconsumed, unexpired) challenges of a factor under purpose: an
// expired challenge neither gates a resend nor satisfies a verify.
func (s *Service) pending(ctx context.Context, userID, factorID string, purpose ChallengePurpose, now time.Time) ([]model.OTPChallenge, error) {
	all, err := s.repos.OTPChallenges.ListForFactor(ctx, userID, factorID, string(purpose))
	if err != nil {
		return nil, fmt.Errorf("mfa: load OTP challenges: %w", err)
	}
	var live []model.OTPChallenge
	for _, c := range all {
		if c.ConsumedAt == nil && c.ExpiresAt.After(now) {
			live = append(live, c)
		}
	}
	return live, nil
}

func newestOf(cs []model.OTPChallenge) (model.OTPChallenge, bool) {
	var newest model.OTPChallenge
	for i, c := range cs {
		if i == 0 || c.CreatedAt.After(newest.CreatedAt) {
			newest = c
		}
	}
	return newest, len(cs) > 0
}

// sendBudget is a fixed-window send counter, anchored on the window's first send (Start, Unix
// seconds) rather than the cache TTL, which would slide forward on every write.
type sendBudget struct {
	Count int   `json:"count"`
	Start int64 `json:"start"`
}

// spendSendBudget caps sends per account and per destination within otp.send_window, so a
// caller cannot OTP-bomb a phone or inbox or run up SMS cost. The cache read-modify-write is not
// atomic across replicas; the resend cooldown and the per-IP rate limit bound the residual.
func (s *Service) spendSendBudget(ctx context.Context, userID, destination string, now time.Time) error {
	digest := sha256.Sum256([]byte(destination))
	keys := []string{"otp.send.acct." + userID, "otp.send.dest." + hex.EncodeToString(digest[:])}

	// ponytail: one process-wide lock; per-key locks if OTP sends ever contend.
	s.quotaMu.Lock()
	defer s.quotaMu.Unlock()
	budgets := make([]sendBudget, len(keys))
	for i, key := range keys {
		b, err := s.readBudget(ctx, key, now.Unix(), s.otp.SendWindow)
		if err != nil {
			return err
		}
		if b.Count >= s.otp.SendMax {
			return ErrOTPCooldown
		}
		budgets[i] = b
	}
	for i, key := range keys {
		raw, _ := json.Marshal(sendBudget{Count: budgets[i].Count + 1, Start: budgets[i].Start}) // cannot fail
		if err := s.cache.Set(ctx, key, raw, s.otp.SendWindow); err != nil {
			return fmt.Errorf("mfa: record OTP send: %w", err)
		}
	}
	return nil
}

// readBudget returns the key's counter, or a fresh window when it elapsed, never existed or is
// unreadable.
func (s *Service) readBudget(ctx context.Context, key string, now int64, window time.Duration) (sendBudget, error) {
	raw, ok, err := s.cache.Get(ctx, key)
	if err != nil {
		return sendBudget{}, fmt.Errorf("mfa: read budget: %w", err)
	}
	var b sendBudget
	if !ok || json.Unmarshal(raw, &b) != nil || now-b.Start >= int64(window/time.Second) {
		return sendBudget{Start: now}, nil
	}
	return b, nil
}

func (s *Service) deliver(ctx context.Context, channel, destination, code string) error {
	if channel == model.FactorSMS {
		return s.sms.Send(ctx, destination, "Your verification code is "+code+".")
	}
	return s.mailer.Send(ctx, destination, notify.TemplateOTPCode, map[string]any{"code": code, "ttl": int(s.otp.TTL / time.Second)})
}

// generateCode returns otp.length uniformly random decimal digits.
func (s *Service) generateCode() string {
	limit := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(s.otp.Length)), nil)
	return fmt.Sprintf("%0*d", s.otp.Length, randomBelow(limit))
}

// randomBelow is a CSPRNG integer in [0, n).
func randomBelow(n *big.Int) *big.Int {
	v, err := rand.Int(rand.Reader, n)
	if err != nil {
		panic(err) // unreachable: crypto/rand never fails on Go ≥ 1.24, and n > 0
	}
	return v
}
