package config

import (
	"fmt"
	"time"
)

// RateLimit is a fixed-window policy: at most Limit hits per Window, counted under KeyPrefix.
type RateLimit struct {
	Limit     int
	Window    time.Duration // whole seconds, at least 1s
	KeyPrefix string        // keeps groups apart on a shared cache
}

// Validate reports a non-positive budget or window.
func (r RateLimit) Validate() error {
	var p problems
	r.validate(&p, "RateLimit", "")
	return p.err()
}

func (r RateLimit) validate(p *problems, field, key string) {
	if r.Limit < 1 {
		p.add("%s.Limit is %d, must be >= 1%s", field, r.Limit, keyHint(key, "limit"))
	}
	p.seconds(field+".Window", keyHint(key, "window"), r.Window, time.Second)
}

func keyHint(group, leaf string) string {
	if group == "" {
		return ""
	}
	return fmt.Sprintf(" (auth.rate_limits.%s.%s)", group, leaf)
}

// RateLimits are the per-group budgets of the auth endpoints (docs/auth/security.md §5). All are
// per client IP except Authenticated, the global per-user budget across authenticated endpoints.
type RateLimits struct {
	Login          RateLimit
	Register       RateLimit
	PasswordForgot RateLimit
	TokenRefresh   RateLimit
	MFAEnroll      RateLimit
	MFAConfirm     RateLimit
	MFASend        RateLimit
	TokenConsume   RateLimit
	Authenticated  RateLimit
}

// DefaultRateLimits returns the budgets of docs/auth/security.md §5.
func DefaultRateLimits() RateLimits {
	policy := func(limit, windowSeconds int, group string) RateLimit {
		return RateLimit{Limit: limit, Window: time.Duration(windowSeconds) * time.Second, KeyPrefix: "auth." + group}
	}
	return RateLimits{
		Login:          policy(10, 300, "login"),
		Register:       policy(5, 3600, "register"),
		PasswordForgot: policy(5, 3600, "password_forgot"),
		TokenRefresh:   policy(60, 60, "token_refresh"),
		MFAEnroll:      policy(5, 3600, "mfa_enroll"),
		MFAConfirm:     policy(10, 300, "mfa_confirm"),
		MFASend:        policy(5, 600, "mfa_send"),
		TokenConsume:   policy(10, 300, "token_consume"),
		Authenticated:  policy(600, 60, "authenticated"),
	}
}

// Validate reports every non-positive budget or window.
func (r RateLimits) Validate() error {
	var p problems
	r.validate(&p)
	return p.err()
}

func (r RateLimits) validate(p *problems) {
	for _, g := range r.groups() {
		g.limit.validate(p, "Auth.RateLimits."+g.field, g.key)
	}
}

type rateGroup struct {
	field, key string
	limit      RateLimit
}

func (r RateLimits) groups() []rateGroup {
	return []rateGroup{
		{"Login", "login", r.Login},
		{"Register", "register", r.Register},
		{"PasswordForgot", "password_forgot", r.PasswordForgot},
		{"TokenRefresh", "token_refresh", r.TokenRefresh},
		{"MFAEnroll", "mfa_enroll", r.MFAEnroll},
		{"MFAConfirm", "mfa_confirm", r.MFAConfirm},
		{"MFASend", "mfa_send", r.MFASend},
		{"TokenConsume", "token_consume", r.TokenConsume},
		{"Authenticated", "authenticated", r.Authenticated},
	}
}
