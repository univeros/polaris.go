package httpapi_test

import (
	"testing"

	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/polaristest"
)

func newMFACase(t *testing.T) *mfaCase {
	t.Helper()
	srv := polaristest.New(t)
	return &mfaCase{t: t, srv: srv, c: contracttest.NewClient(t, srv.Handler(), nil)}
}

// Confirming a factor adds a way to authenticate: with a factor already there it takes a recent
// authentication, or a stolen access token would enrol its own and step up with it.
func TestConfirmingAnotherFactorTakesAFreshStepUp(t *testing.T) {
	m := newMFACase(t)
	access := m.registerVerifyLogin("ada@example.com")
	factorID, _ := m.enrollTOTP(access)
	m.enrollConfirmSMS(access)
	stale := contracttest.Bearer(m.staleToken(mfaSubjectOf(t, access)))
	for _, kind := range []string{"totp", "sms", "email"} {
		resp := m.c.Post("/auth/mfa/"+kind+"/confirm", map[string]any{"factor_id": factorID, "code": "000000"}, stale)
		mfaStatus(t, resp, 401)
		if contracttest.JSON(t, resp)["error"] != "step_up_required" {
			t.Fatalf("%s: want step_up_required", kind)
		}
	}
}

// A first factor is confirmed however old the authentication: there is nothing to step up with.
func TestConfirmingTheFirstFactorTakesNone(t *testing.T) {
	m := newMFACase(t)
	access := m.registerVerifyLogin("ada@example.com")
	factorID, secret := m.enrollTOTP(access)
	mfaStatus(t, m.confirmTOTP(factorID, m.totpCode(secret, 0), m.staleToken(mfaSubjectOf(t, access))), 200)
}
