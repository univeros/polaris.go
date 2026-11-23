package manifest

import "testing"

// A route that adds a way to authenticate, or turns a session into another credential, takes a recent
// authentication: a stolen access token alone must not.
func TestRoutesThatAddACredentialTakeAStepUp(t *testing.T) {
	want := map[string]bool{
		"POST /auth/mfa/totp/confirm": true, "POST /auth/mfa/sms/confirm": true, "POST /auth/mfa/email/confirm": true,
		"POST /auth/password/change": true, "POST /passkey/register/options": true, "POST /passkey/register/verify": true,
		"POST /phone/add": true, "POST /phone/confirm": true, "POST /social/{provider}/link": true,
		"POST /one-time-token/generate": true, "POST /api-keys": true, "POST /api-keys/{id}/rotate": true,
	}
	for _, r := range loadAll(t).Routes() {
		if key := r.Method + " " + r.Path; want[key] {
			delete(want, key)
			if !r.StepUp {
				t.Errorf("%s is not a step-up route", key)
			}
		}
	}
	if len(want) != 0 {
		t.Errorf("routes not found: %v", want)
	}
}
