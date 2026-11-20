package httpapi_test

import (
	"fmt"
	"testing"

	"github.com/univeros/polaris-go/internal/contracttest"
)

func TestMfaSmsEmailEndpoints(t *testing.T) {
	const email = "ada@example.com"
	mfaRun(t, "MfaSmsEmailEndpointsTest", map[string]func(*mfaCase){
		"testSmsEnrollAndConfirmIssuesRecoveryCodes": func(m *mfaCase) {
			access := m.registerVerifyLogin(email)
			enroll := mfaData(m.t, m.c.Post("/auth/mfa/sms/enroll", map[string]any{"phone_e164": mfaPhone}, contracttest.Bearer(access)))
			if enroll["destination"] != "+1 *** *** 0101" {
				m.t.Fatalf("destination = %v", enroll["destination"])
			}
			resp := m.c.Post("/auth/mfa/sms/confirm", map[string]any{"factor_id": enroll["factor_id"], "code": m.lastSMSCode()}, contracttest.Bearer(access))
			mfaStatus(m.t, resp, 200)
			data := mfaData(m.t, resp)
			if codes, _ := data["recovery_codes"].([]any); data["status"] != "confirmed" || len(codes) != 10 {
				m.t.Fatalf("confirm data = %v", data)
			}
		},
		"testSmsEnrollRejectsAnInvalidE164": func(m *mfaCase) {
			access := m.registerVerifyLogin(email)
			mfaStatus(m.t, m.c.Post("/auth/mfa/sms/enroll", map[string]any{"phone_e164": "415-555-0101"}, contracttest.Bearer(access)), 422)
		},
		"testSmsConfirmRejectsAWrongCode": func(m *mfaCase) {
			access := m.registerVerifyLogin(email)
			enroll := mfaData(m.t, m.c.Post("/auth/mfa/sms/enroll", map[string]any{"phone_e164": mfaPhone}, contracttest.Bearer(access)))
			resp := m.c.Post("/auth/mfa/sms/confirm", map[string]any{"factor_id": enroll["factor_id"], "code": "000000"}, contracttest.Bearer(access))
			mfaStatus(m.t, resp, 422)
		},
		"testEmailEnrollDefaultsToTheAccountEmailAndConfirms": func(m *mfaCase) {
			access := m.registerVerifyLogin(email)
			resp := m.c.Post("/auth/mfa/email/enroll", nil, contracttest.Bearer(access))
			mfaStatus(m.t, resp, 200)
			factorID := mfaData(m.t, resp)["factor_id"]

			sent := m.srv.Mailer.Sent()
			last := sent[len(sent)-1]
			if last.To != email {
				m.t.Fatalf("code sent to %q, want the account email", last.To)
			}
			confirm := m.c.Post("/auth/mfa/email/confirm", map[string]any{"factor_id": factorID, "code": fmt.Sprint(last.Data["code"])}, contracttest.Bearer(access))
			mfaStatus(m.t, confirm, 200)
		},
		"testEnrollAndConfirmRequireAuthentication": func(m *mfaCase) {
			mfaStatus(m.t, m.c.Post("/auth/mfa/sms/enroll", map[string]any{"phone_e164": mfaPhone}), 401)
			mfaStatus(m.t, m.c.Post("/auth/mfa/email/confirm", map[string]any{"factor_id": "x", "code": "123456"}), 401)
		},
	})
}
