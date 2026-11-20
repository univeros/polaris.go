package httpapi_test

import (
	"strings"
	"testing"

	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/internal/contracttest"
)

func TestMfaTotpEndpoints(t *testing.T) {
	const email = "ada@example.com"
	mfaRun(t, "MfaTotpEndpointsTest", map[string]func(*mfaCase){
		"testEnrollReturnsSecretUriAndQr": func(m *mfaCase) {
			access := m.registerVerifyLogin(email)
			data := mfaData(m.t, m.c.Post("/auth/mfa/totp/enroll", nil, contracttest.Bearer(access)))
			if data["factor_id"] == "" || data["secret"] == "" {
				m.t.Fatalf("empty factor_id or secret: %v", data)
			}
			if uri, _ := data["otpauth_uri"].(string); !strings.HasPrefix(uri, "otpauth://totp/") {
				m.t.Fatalf("otpauth_uri = %q", uri)
			}
			if qr, _ := data["qr_svg"].(string); !strings.Contains(qr, "<svg") {
				m.t.Fatal("qr_svg is not an SVG")
			}
		},
		"testConfirmWithAValidCodeIssuesRecoveryCodesOnce": func(m *mfaCase) {
			access := m.registerVerifyLogin(email)
			factorID, secret := m.enrollTOTP(access)

			resp := m.confirmTOTP(factorID, m.totpCode(secret, 0), access)
			mfaStatus(m.t, resp, 200)
			data := mfaData(m.t, resp)
			if data["status"] != "confirmed" {
				m.t.Fatalf("status = %v", data["status"])
			}
			if codes, _ := data["recovery_codes"].([]any); len(codes) != 10 {
				m.t.Fatalf("%d recovery codes, want 10", len(codes))
			}
			if n := len(mfaEventsOf[event.MFAEnrolled](m.srv)); n != 1 {
				m.t.Fatalf("%d mfa.enrolled events, want 1", n)
			}
		},
		"testConfirmRejectsAWrongCodeAndAReplayedCode": func(m *mfaCase) {
			access := m.registerVerifyLogin(email)
			factorID, secret := m.enrollTOTP(access)

			mfaStatus(m.t, m.confirmTOTP(factorID, "000000", access), 422)
			code := m.totpCode(secret, 0)
			mfaStatus(m.t, m.confirmTOTP(factorID, code, access), 200)
			mfaStatus(m.t, m.confirmTOTP(factorID, code, access), 422) // replayed within its window
		},
		"testASecondFactorConfirmIssuesNoNewRecoveryCodes": func(m *mfaCase) {
			access := m.registerVerifyLogin(email)
			m.enrollConfirmTOTP(access)

			factorID, secret := m.enrollTOTP(access)
			data := mfaData(m.t, m.confirmTOTP(factorID, m.totpCode(secret, 0), access))
			if data["status"] != "confirmed" {
				m.t.Fatalf("status = %v", data["status"])
			}
			if _, ok := data["recovery_codes"]; ok {
				m.t.Fatal("recovery codes are issued only for the first factor")
			}
		},
		"testEnrollAndConfirmRequireAuthentication": func(m *mfaCase) {
			mfaStatus(m.t, m.c.Post("/auth/mfa/totp/enroll", nil), 401)
			mfaStatus(m.t, m.c.Post("/auth/mfa/totp/confirm", map[string]any{"factor_id": "x", "code": "123456"}), 401)
		},
	})
}
