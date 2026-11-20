package httpapi_test

import (
	"slices"
	"testing"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
)

func TestMfaLoginGateEndpoints(t *testing.T) {
	const email = "gate@example.com"
	// challenge logs in again once a factor is confirmed and returns the MFA challenge data.
	challenge := func(m *mfaCase) (mfaToken string, factors []any) {
		m.t.Helper()
		data := mfaData(m.t, m.login(email))
		mfaToken, _ = data["mfa_token"].(string)
		factors, _ = data["factors"].([]any)
		return mfaToken, factors
	}
	firstFactorID := func(factors []any) any {
		if len(factors) == 0 {
			return nil
		}
		return factors[0].(map[string]any)["id"]
	}
	mfaRun(t, "MfaLoginGateEndpointsTest", map[string]func(*mfaCase){
		"testLoginReturnsAnMfaChallengeOnceAFactorIsConfirmed": func(m *mfaCase) {
			access := m.registerVerifyLogin(email)
			m.enrollConfirmTOTP(access)

			data := mfaData(m.t, m.login(email))
			if data["mfa_required"] != true || data["mfa_token"] == "" {
				m.t.Fatalf("login data = %v", data)
			}
			if _, ok := data["access_token"]; ok {
				m.t.Fatal("no session is opened until MFA completes")
			}
			factors, _ := data["factors"].([]any)
			if len(factors) == 0 {
				m.t.Fatal("no factors")
			}
			if f := factors[0].(map[string]any); f["type"] != "totp" || f["default"] != true {
				m.t.Fatalf("factor = %v", f)
			}
		},
		"testTheMfaTokenIsRejectedOnANormalRoute": func(m *mfaCase) {
			access := m.registerVerifyLogin(email)
			m.enrollConfirmTOTP(access)
			mfaToken, _ := challenge(m)
			mfaStatus(m.t, m.c.Get("/auth/me", contracttest.Bearer(mfaToken)), 401)
		},
		"testTotpVerifyCompletesLoginAndMintsARealSession": func(m *mfaCase) {
			access := m.registerVerifyLogin(email)
			_, secret, _ := m.enrollConfirmTOTP(access)
			mfaToken, factors := challenge(m)

			// Confirm consumed the current step: the replay fence needs a next-step code.
			resp := m.c.Post("/auth/mfa/verify", map[string]any{"factor_id": firstFactorID(factors), "code": m.totpCode(secret, 1)}, contracttest.Bearer(mfaToken))
			mfaStatus(m.t, resp, 200)
			data := mfaData(m.t, resp)
			fresh, _ := data["access_token"].(string)
			if fresh == "" || data["refresh_token"] == "" {
				m.t.Fatalf("verify data = %v", data)
			}
			claims := mfaClaims(m.t, fresh)
			if amr, _ := claims["amr"].([]any); claims["mfa"] != true || !slices.Equal(amr, []any{"pwd", "otp"}) {
				m.t.Fatalf("claims = %v", claims)
			}
			if n := len(mfaEventsOf[event.MFAVerified](m.srv)); n != 1 {
				m.t.Fatalf("%d mfa.verified events, want 1", n)
			}
			mfaStatus(m.t, m.c.Get("/auth/me", contracttest.Bearer(fresh)), 200)
		},
		"testAWrongCodeIsRejectedAndEmitsFailure": func(m *mfaCase) {
			access := m.registerVerifyLogin(email)
			m.enrollConfirmTOTP(access)
			mfaToken, factors := challenge(m)

			resp := m.c.Post("/auth/mfa/verify", map[string]any{"factor_id": firstFactorID(factors), "code": "000000"}, contracttest.Bearer(mfaToken))
			mfaStatus(m.t, resp, 422)
			if n := len(mfaEventsOf[event.MFAVerifyFailed](m.srv)); n != 1 {
				m.t.Fatalf("%d mfa.verify_failed events, want 1", n)
			}
		},
		"testARecoveryCodeCompletesLogin": func(m *mfaCase) {
			access := m.registerVerifyLogin(email)
			_, _, recovery := m.enrollConfirmTOTP(access)
			mfaToken, _ := challenge(m)
			if len(recovery) == 0 {
				m.t.Fatal("no recovery codes")
			}

			resp := m.c.Post("/auth/mfa/verify", map[string]any{"type": "recovery", "code": recovery[0]}, contracttest.Bearer(mfaToken))
			mfaStatus(m.t, resp, 200)
			if mfaData(m.t, resp)["access_token"] == "" {
				m.t.Fatal("no access token")
			}
		},
		"testSmsChallengeThenVerifyCompletesLogin": func(m *mfaCase) {
			access := m.registerVerifyLogin(email)
			factorID := m.enrollConfirmSMS(access)
			mfaToken, _ := challenge(m)

			sent := m.c.Post("/auth/mfa/challenge", map[string]any{"factor_id": factorID}, contracttest.Bearer(mfaToken))
			mfaStatus(m.t, sent, 200)
			if d := mfaData(m.t, sent)["destination"]; d != "+1 *** *** 0101" {
				m.t.Fatalf("destination = %v", d)
			}
			resp := m.c.Post("/auth/mfa/verify", map[string]any{"factor_id": factorID, "code": m.lastSMSCode()}, contracttest.Bearer(mfaToken))
			mfaStatus(m.t, resp, 200)
			if mfaData(m.t, resp)["access_token"] == "" {
				m.t.Fatal("no access token")
			}
		},
		"testChallengingATotpFactorIsRejected": func(m *mfaCase) {
			access := m.registerVerifyLogin(email)
			m.enrollConfirmTOTP(access)
			mfaToken, factors := challenge(m)

			resp := m.c.Post("/auth/mfa/challenge", map[string]any{"factor_id": firstFactorID(factors)}, contracttest.Bearer(mfaToken))
			mfaStatus(m.t, resp, 422) // TOTP takes its code from the app, not a sent challenge
		},
		"testTheGateRoutesRequireATicket": func(m *mfaCase) {
			mfaStatus(m.t, m.c.Post("/auth/mfa/verify", map[string]any{"code": "123456"}), 401)
			mfaStatus(m.t, m.c.Post("/auth/mfa/challenge", map[string]any{"factor_id": "x"}), 401)
		},
		"testTheTicketPrincipalCannotBeSpoofedViaTheBody": func(m *mfaCase) {
			// A body key named like the ticket attribute is plain input: the request runs for the
			// ticket's own principal and fails on the wrong code.
			access := m.registerVerifyLogin(email)
			m.enrollConfirmTOTP(access)
			mfaToken, _ := challenge(m)

			resp := m.c.Post("/auth/mfa/verify", map[string]any{"polaris:mfa:ticket": "victim-user-id", "type": "recovery", "code": "aaaaa-bbbbb"}, contracttest.Bearer(mfaToken))
			mfaStatus(m.t, resp, 422)
			if e := contracttest.JSON(m.t, resp)["error"]; e != "invalid_code" {
				m.t.Fatalf("error = %v", e)
			}
		},
	})
}
