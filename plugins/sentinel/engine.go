package sentinel

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/univeros/polaris.go/event"
)

// The kinds of attempt the guarded routes are.
const (
	SignUp           = "sign_up"
	SignIn           = "sign_in"
	PasswordReset    = "password_reset"
	VerificationSend = "verification_send"
	OTPSend          = "otp_send"
)

// The policy's actions.
const (
	Allow     = "allow"
	Challenge = "challenge"
	Block     = "block"
)

// Attempt is what the engine judges: the action, who (email, IP, user agent, device cookie) and
// what the request carried that a signal may check (a captcha token; the password, for the breach
// lookup only). Nothing but the email and the IP is stored.
type Attempt struct {
	Kind         string
	Email        string // lower-cased and trimmed by Evaluate
	IP           string
	UserAgent    string
	DeviceID     string
	CaptchaToken string
	Password     string
}

// Verdict is one signal's opinion: a score (0 is silence; negative clears the attempt, as an IP
// allow rule does), its reasons, and whether it proves a passed challenge (a valid captcha).
type Verdict struct {
	Signal          string
	Score           int
	Reasons         []string
	PassedChallenge bool
}

// Signal is one heuristic. Evaluating may count the attempt (velocity does); an error skips the
// signal (the engine fails open) and is logged.
type Signal interface {
	Name() string
	Evaluate(ctx context.Context, a Attempt) (Verdict, error)
}

// Resettable is a signal whose counters an operator's unblock clears for an identifier (an email
// or an IP address).
type Resettable interface {
	Reset(ctx context.Context, identifier string) error
}

// Decision is the policy's outcome: the action, the summed score and the verdicts of the signals
// that spoke. In observe mode Action is what would have happened and Enforced is false.
type Decision struct {
	Action   string
	Score    int
	Verdicts []Verdict
	Enforced bool
}

// Signals names the signals that spoke, in order.
func (d Decision) Signals() []string {
	out := make([]string, 0, len(d.Verdicts))
	for _, v := range d.Verdicts {
		out = append(out, v.Signal)
	}
	return out
}

// Reasons joins the reasons of the signals that spoke, in order.
func (d Decision) Reasons() []string {
	out := []string{}
	for _, v := range d.Verdicts {
		out = append(out, v.Reasons...)
	}
	return out
}

// Policy maps the summed score (capped at 100, floored at 0) to an action: below ChallengeAt
// allow, from it challenge, from BlockAt block. A passed challenge turns a challenge into an allow;
// a block stays a block. Zero thresholds mean 40 and 80.
type Policy struct {
	ChallengeAt int
	BlockAt     int
}

// Decide sums the verdicts and maps the score.
func (p Policy) Decide(verdicts []Verdict, enforced bool) Decision {
	challengeAt, blockAt := p.ChallengeAt, p.BlockAt
	if challengeAt == 0 {
		challengeAt = 40
	}
	if blockAt == 0 {
		blockAt = 80
	}
	score, passed := 0, false
	fired := []Verdict{}
	for _, v := range verdicts {
		if v.Score != 0 || v.PassedChallenge {
			fired = append(fired, v)
		}
		score += v.Score
		passed = passed || v.PassedChallenge
	}
	score = max(0, min(100, score))
	action := Allow
	switch {
	case score >= blockAt:
		action = Block
	case score >= challengeAt && !passed:
		action = Challenge
	}
	return Decision{Action: action, Score: score, Verdicts: fired, Enforced: enforced}
}

// Engine runs the signals over an attempt, lets the policy decide and records the decision when a
// signal spoke (polaris_sentinel_decision and the sentinel.evaluated event). Safe for concurrent
// use.
type Engine struct {
	signals   []Signal
	policy    Policy
	enforce   bool
	decisions *Decisions
	events    event.Dispatcher
	logger    *slog.Logger
}

// Evaluate judges a; err is only a failing decision store.
func (e *Engine) Evaluate(ctx context.Context, a Attempt) (Decision, error) {
	a.Email = strings.ToLower(strings.TrimSpace(a.Email))
	var verdicts []Verdict
	for _, s := range e.signals {
		v, err := s.Evaluate(ctx, a)
		if err != nil {
			e.logger.ErrorContext(ctx, "sentinel: signal failed", "signal", s.Name(), "reason", err.Error())
			continue
		}
		verdicts = append(verdicts, v)
	}
	d := e.policy.Decide(verdicts, e.enforce)
	if len(d.Verdicts) > 0 {
		if err := e.decisions.record(ctx, a, d); err != nil {
			return d, fmt.Errorf("sentinel: record decision: %w", err)
		}
		e.events.Dispatch(ctx, Evaluated{Attempt: a, Decision: d})
	}
	return d, nil
}

// Unblock clears every resettable signal's counters for identifier (an email or an address).
func (e *Engine) Unblock(ctx context.Context, identifier string) error {
	for _, s := range e.signals {
		if r, ok := s.(Resettable); ok {
			if err := r.Reset(ctx, identifier); err != nil {
				return fmt.Errorf("sentinel: unblock %s: %w", s.Name(), err)
			}
		}
	}
	return nil
}

// Enforces reports whether the engine runs in enforce mode.
func (e *Engine) Enforces() bool { return e.enforce }
