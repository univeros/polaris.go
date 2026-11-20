package sentinel

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/univeros/polaris-go/clock"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/security"
)

// The built-in signals' names, as recorded with each decision.
const (
	SignalIPList             = "ip_list"
	SignalVelocity           = "velocity"
	SignalCredentialStuffing = "credential_stuffing"
	SignalDisposableEmail    = "disposable_email"
	SignalDevice             = "device"
	SignalBot                = "bot"
	SignalImpossibleTravel   = "impossible_travel"
	SignalBreachedPassword   = "breached_password"
)

func silent(name string) Verdict { return Verdict{Signal: name} }

// ipList applies the operators' rules: a block rule refuses the address outright (100), an allow
// rule clears it of every other signal (-100).
type ipList struct{ rules *IPRules }

func (ipList) Name() string { return SignalIPList }

func (s ipList) Evaluate(ctx context.Context, a Attempt) (Verdict, error) {
	if a.IP == "" {
		return silent(SignalIPList), nil
	}
	r, ok, err := s.rules.Match(ctx, a.IP)
	switch {
	case err != nil || !ok:
		return silent(SignalIPList), err
	case r.Action == Block:
		return Verdict{Signal: SignalIPList, Score: 100, Reasons: []string{"address blocked by rule " + r.CIDR}}, nil
	default:
		return Verdict{Signal: SignalIPList, Score: -100, Reasons: []string{"address allowed by rule " + r.CIDR}}, nil
	}
}

// Limit is a velocity budget: Max attempts in Window.
type Limit struct {
	Max    int
	Window time.Duration
}

// DefaultVelocity is the velocity budget per dimension when Config.Velocity is nil.
var DefaultVelocity = map[string]Limit{
	"ip":     {20, 10 * time.Minute},
	"email":  {10, 10 * time.Minute},
	"device": {30, 10 * time.Minute},
}

// velocity counts attempts per address, email and device; each dimension over its limit adds the
// score, so one runaway dimension challenges and two block.
type velocity struct {
	counters CounterStore
	limits   map[string]Limit
	score    int
}

func (velocity) Name() string { return SignalVelocity }

func (s velocity) Evaluate(ctx context.Context, a Attempt) (Verdict, error) {
	v := silent(SignalVelocity)
	for _, d := range [][2]string{{"ip", a.IP}, {"email", a.Email}, {"device", a.DeviceID}} {
		l, ok := s.limits[d[0]]
		if d[1] == "" || !ok {
			continue
		}
		n, err := s.counters.Increment(ctx, "velocity:"+d[0]+":"+d[1], l.Window)
		if err != nil {
			return v, err
		}
		if n > l.Max {
			v.Score += s.score
			v.Reasons = append(v.Reasons, fmt.Sprintf("%s: %d attempts in %d s (limit %d)", d[0], n, int(l.Window/time.Second), l.Max))
		}
	}
	return v, nil
}

func (s velocity) Reset(ctx context.Context, identifier string) error {
	var errs []error
	for d, l := range s.limits {
		errs = append(errs, s.counters.Reset(ctx, "velocity:"+d+":"+identifier, l.Window))
	}
	return errors.Join(errs...)
}

// stuffing sees one address trying many accounts (distinct emails in the window) or failing most
// of its sign-ins (failures, counted by the listener, over attempts).
type stuffing struct {
	counters       CounterStore
	seen           *seenSet
	window         time.Duration
	distinctEmails int
	minAttempts    int
	failureRatio   float64
	score          int
}

func (stuffing) Name() string { return SignalCredentialStuffing }

func (s *stuffing) Evaluate(ctx context.Context, a Attempt) (Verdict, error) {
	v := silent(SignalCredentialStuffing)
	if a.Kind != SignIn || a.IP == "" {
		return v, nil
	}
	attempts, err := s.counters.Increment(ctx, "stuffing:attempts:"+a.IP, s.window)
	if err != nil {
		return v, err
	}
	if a.Email != "" {
		distinct, err := s.seen.add(ctx, a.IP, sha256Hex(a.Email), s.window)
		if err != nil {
			return v, err
		}
		if distinct >= s.distinctEmails {
			v.Score += s.score
			v.Reasons = append(v.Reasons, fmt.Sprintf("%d distinct accounts from one address in %d s", distinct, int(s.window/time.Second)))
		}
	}
	failures, err := s.counters.Count(ctx, "stuffing:failures:"+a.IP, s.window)
	if err != nil {
		return v, err
	}
	if attempts >= s.minAttempts && float64(failures)/float64(attempts) >= s.failureRatio {
		v.Score += s.score
		v.Reasons = append(v.Reasons, fmt.Sprintf("%d of %d sign-ins from the address failed", failures, attempts))
	}
	return v, nil
}

// failed counts a failed sign-in from ip.
func (s *stuffing) failed(ctx context.Context, ip string) error {
	if ip == "" {
		return nil
	}
	_, err := s.counters.Increment(ctx, "stuffing:failures:"+ip, s.window)
	return err
}

func (s *stuffing) Reset(ctx context.Context, identifier string) error {
	return errors.Join(
		s.counters.Reset(ctx, "stuffing:attempts:"+identifier, s.window),
		s.counters.Reset(ctx, "stuffing:failures:"+identifier, s.window),
		s.seen.reset(ctx, identifier),
	)
}

// disposable flags a sign-up from a disposable mailbox.
type disposable struct {
	domains DomainList
	kinds   []string
	score   int
}

func (disposable) Name() string { return SignalDisposableEmail }

func (s disposable) Evaluate(_ context.Context, a Attempt) (Verdict, error) {
	at := strings.LastIndexByte(a.Email, '@')
	if at < 0 || !slices.Contains(s.kinds, a.Kind) {
		return silent(SignalDisposableEmail), nil
	}
	domain := a.Email[at+1:]
	if !s.domains.Contains(domain) {
		return silent(SignalDisposableEmail), nil
	}
	return Verdict{Signal: SignalDisposableEmail, Score: s.score, Reasons: []string{"disposable domain " + domain}}, nil
}

// users finds an account by email; repository.Users is the implementation.
type users interface {
	ByEmail(ctx context.Context, email string) (model.User, error)
}

// userByEmail answers the user, ok false when there is none.
func userByEmail(ctx context.Context, u users, email string) (model.User, bool, error) {
	user, err := u.ByEmail(ctx, email)
	if errors.Is(err, repository.ErrNotFound) {
		return model.User{}, false, nil
	}
	return user, err == nil, err
}

// device flags a sign-in from a device the user never signed in from, once they have one.
type device struct {
	devices *devices
	users   users
	score   int
}

func (device) Name() string { return SignalDevice }

func (s device) Evaluate(ctx context.Context, a Attempt) (Verdict, error) {
	v := silent(SignalDevice)
	if a.Kind != SignIn || a.Email == "" {
		return v, nil
	}
	user, ok, err := userByEmail(ctx, s.users, a.Email)
	if err != nil || !ok {
		return v, err
	}
	if n, err := s.devices.count(ctx, user.ID); err != nil || n == 0 {
		return v, err
	}
	if a.DeviceID != "" {
		if known, err := s.devices.find(ctx, user.ID, a.DeviceID); err != nil || known {
			return v, err
		}
	}
	reason := "unknown device"
	if a.DeviceID == "" {
		reason = "no device cookie"
	}
	return Verdict{Signal: SignalDevice, Score: s.score, Reasons: []string{reason}}, nil
}

// bot verifies a captcha token: valid, it proves a passed challenge; invalid, it is a bot's guess;
// absent, the signal is silent.
type bot struct {
	verifier BotVerifier
	score    int
}

func (bot) Name() string { return SignalBot }

func (s bot) Evaluate(ctx context.Context, a Attempt) (Verdict, error) {
	switch {
	case a.CaptchaToken == "":
		return silent(SignalBot), nil
	case s.verifier.Verify(ctx, a.CaptchaToken, a.IP):
		return Verdict{Signal: SignalBot, Reasons: []string{"captcha passed"}, PassedChallenge: true}, nil
	default:
		return Verdict{Signal: SignalBot, Score: s.score, Reasons: []string{"captcha token invalid"}}, nil
	}
}

// travel flags a sign-in from a place the user could not have reached since the last one.
type travel struct {
	geo     GeoResolver
	devices *devices
	users   users
	clock   clock.Clock
	maxKmh  float64
	score   int
}

func (travel) Name() string { return SignalImpossibleTravel }

func (s travel) Evaluate(ctx context.Context, a Attempt) (Verdict, error) {
	v := silent(SignalImpossibleTravel)
	if a.Kind != SignIn || a.Email == "" || a.IP == "" {
		return v, nil
	}
	here, ok := s.geo.Resolve(ctx, a.IP)
	if !ok {
		return v, nil
	}
	user, ok, err := userByEmail(ctx, s.users, a.Email)
	if err != nil || !ok {
		return v, err
	}
	last, ok, err := s.devices.latest(ctx, user.ID)
	if err != nil || !ok || last.Location == nil {
		return v, err
	}
	km := last.Location.DistanceTo(here)
	hours := max(1.0/60, s.clock.Now().Sub(last.LastSeenAt).Truncate(time.Second).Hours())
	if kmh := km / hours; kmh > s.maxKmh {
		v.Score = s.score
		v.Reasons = []string{fmt.Sprintf("%.0f km since the last sign-in %.1f h ago (%.0f km/h)", km, hours, kmh)}
	}
	return v, nil
}

// breached flags a new password (sign-up, password reset) found in a breach corpus.
type breached struct {
	checker security.BreachedPasswordCheck
	kinds   []string
	score   int
}

func (breached) Name() string { return SignalBreachedPassword }

func (s breached) Evaluate(ctx context.Context, a Attempt) (Verdict, error) {
	if a.Password == "" || !slices.Contains(s.kinds, a.Kind) || !s.checker.IsBreached(ctx, a.Password) {
		return silent(SignalBreachedPassword), nil
	}
	return Verdict{Signal: SignalBreachedPassword, Score: s.score, Reasons: []string{"password found in a breach"}}, nil
}
