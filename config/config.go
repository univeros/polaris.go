// Package config holds Polaris configuration: the boot secrets ([Secrets]) and the auth settings
// ([Auth]), with the defaults, environment variables and validation rules of upstream
// `docs/auth/configuration.md`.
//
// Start from the environment or from [Defaults], change what you need, then validate:
//
//	secrets, auth, err := config.FromEnv() // APP_KEY, AUTH_JWT_*, AUTH_ISSUER, …
//	if err != nil {
//		log.Fatal(err) // every problem, each with its fix
//	}
//
// Every validation error wraps [ErrInvalid] and names the field, the upstream config key or
// environment variable, and what to do about it. A zero [Auth] is not valid: use [Defaults].
package config

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// ErrInvalid is wrapped by every configuration error, so callers can test with errors.Is.
var ErrInvalid = errors.New("invalid Polaris config")

// LookupFunc reads one environment variable; os.LookupEnv has this shape.
type LookupFunc func(key string) (string, bool)

// FromEnv reads the secrets and the auth settings from the process environment.
// See [FromLookup].
func FromEnv() (Secrets, Auth, error) { return FromLookup(os.LookupEnv) }

// FromLookup reads the secrets (APP_KEY, AUTH_JWT_*) and the auth settings hosts commonly flip
// (AUTH_ISSUER, default "polaris"; AUTH_AUDIENCE; AUTH_ACCESS_TOKEN_DENYLIST and
// AUTH_PASSWORD_BREACH_CHECK, on when "1", "true" or "on"), over [Defaults]. Both values are
// validated; on error both are zero and the error lists every problem.
func FromLookup(lookup LookupFunc) (Secrets, Auth, error) {
	secrets, secretsErr := SecretsFromLookup(lookup)

	auth := Defaults()
	auth.Issuer = "polaris"
	if v, _ := lookup("AUTH_ISSUER"); v != "" {
		auth.Issuer = v
	}
	auth.Audience, _ = lookup("AUTH_AUDIENCE")
	auth.AccessToken.Denylist = flag(lookup, "AUTH_ACCESS_TOKEN_DENYLIST")
	auth.Password.BreachCheck = flag(lookup, "AUTH_PASSWORD_BREACH_CHECK")

	if err := errors.Join(secretsErr, auth.Validate()); err != nil {
		return Secrets{}, Auth{}, err
	}
	return secrets, auth, nil
}

func flag(lookup LookupFunc, key string) bool {
	switch v, _ := lookup(key); v {
	case "1", "true", "on":
		return true
	}
	return false
}

// problems collects validation errors so one run reports all of them.
type problems []error

func (p *problems) add(format string, args ...any) {
	*p = append(*p, fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...))
}

func (p problems) err() error { return errors.Join(p...) }

// seconds checks a duration that upstream expresses as a whole number of seconds; hint is the
// upstream key, as " (auth.x.y)", or empty.
func (p *problems) seconds(field, hint string, d, least time.Duration) {
	switch {
	case d < least:
		p.add("%s is %v, must be at least %v%s", field, d, least, hint)
	case d%time.Second != 0:
		p.add("%s is %v, must be a whole number of seconds%s", field, d, hint)
	}
}
