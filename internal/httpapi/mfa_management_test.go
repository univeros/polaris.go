package httpapi_test

import (
	"context"
	"slices"
	"testing"

	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/internal/contracttest"
)

func TestMfaManagementEndpoints(t *testing.T) {
	const email = "manage@example.com"
	factors := func(m *mfaCase, access string) map[string]map[string]any {
		m.t.Helper()
		list, _ := mfaData(m.t, m.c.Get("/auth/mfa/factors", contracttest.Bearer(access)))["factors"].([]any)
		byID := map[string]map[string]any{}
		for _, f := range list {
			f := f.(map[string]any)
			byID[f["id"].(string)] = f
		}
		return byID
	}
	mfaRun(t, "MfaManagementEndpointsTest", map[string]func(*mfaCase){
		"testListShowsConfirmedAndPendingFactors": func(m *mfaCase) {
			access := m.registerVerifyLogin(email)
			m.enrollConfirmTOTP(access)
			m.c.Post("/auth/mfa/sms/enroll", map[string]any{"phone_e164": mfaPhone}, contracttest.Bearer(access)) // pending

			byType := map[string]map[string]any{}
			list := factors(m, access)
			for _, f := range list {
				byType[f["type"].(string)] = f
			}
			if len(list) != 2 || byType["totp"]["confirmed"] != true || byType["sms"]["confirmed"] != false {
				m.t.Fatalf("factors = %v", list)
			}
			if byType["sms"]["destination"] != "+1 *** *** 0101" {
				m.t.Fatalf("sms destination = %v", byType["sms"]["destination"])
			}
		},
		"testRelabelAndSetDefault": func(m *mfaCase) {
			access := m.registerVerifyLogin(email)
			totpID, _, _ := m.enrollConfirmTOTP(access) // first factor: default
			smsID := m.enrollConfirmSMS(access)

			patched := mfaData(m.t, m.c.Patch("/auth/mfa/factors/"+smsID, map[string]any{"label": "Personal phone", "default": true}, contracttest.Bearer(access)))
			if patched["label"] != "Personal phone" || patched["default"] != true {
				m.t.Fatalf("patched = %v", patched)
			}
			list := factors(m, access)
			if list[smsID]["default"] != true || list[totpID]["default"] != false {
				m.t.Fatalf("the previous default is cleared: %v", list)
			}
		},
		"testDeleteRemovesAFactor": func(m *mfaCase) {
			access := m.registerVerifyLogin(email)
			totpID, _, _ := m.enrollConfirmTOTP(access)
			smsID := m.enrollConfirmSMS(access)

			mfaStatus(m.t, m.c.Delete("/auth/mfa/factors/"+smsID, contracttest.Bearer(access)), 200)
			if n := len(mfaEventsOf[event.MFAFactorRemoved](m.srv)); n != 1 {
				m.t.Fatalf("%d mfa.factor_removed events, want 1", n)
			}
			if list := factors(m, access); len(list) != 1 || list[totpID] == nil {
				m.t.Fatalf("remaining = %v", list)
			}
		},
		"testRemovingTheLastConfirmedFactorIsBlockedWhenEnforced": func(m *mfaCase) {
			access := m.registerVerifyLogin(email)
			totpID, _, _ := m.enrollConfirmTOTP(access)
			mfaEnforce(m, mfaSubjectOf(m.t, access))

			resp := m.c.Delete("/auth/mfa/factors/"+totpID, contracttest.Bearer(access))
			mfaStatus(m.t, resp, 409)
			if contracttest.JSON(m.t, resp)["error"] != "last_factor_protected" {
				m.t.Fatal("want last_factor_protected")
			}
			if n := len(mfaEventsOf[event.MFAFactorRemoved](m.srv)); n != 0 {
				m.t.Fatalf("%d mfa.factor_removed events, want 0", n)
			}
		},
		"testDeletingAFactorRequiresAFreshStepUp": func(m *mfaCase) {
			access := m.registerVerifyLogin(email)
			m.enrollConfirmTOTP(access)
			smsID := m.enrollConfirmSMS(access)
			stale := m.staleToken(mfaSubjectOf(m.t, access))

			resp := m.c.Delete("/auth/mfa/factors/"+smsID, contracttest.Bearer(stale))
			mfaStatus(m.t, resp, 401)
			if contracttest.JSON(m.t, resp)["error"] != "step_up_required" {
				m.t.Fatal("want step_up_required")
			}
			if n := len(mfaEventsOf[event.MFAFactorRemoved](m.srv)); n != 0 {
				m.t.Fatal("the factor is not removed without step-up")
			}
		},
		"testOtpSendBombingIsCapped": func(m *mfaCase) {
			access := m.registerVerifyLogin(email)
			// send_max defaults to 5 per destination/account per window; each enrol sends one code.
			var statuses []int
			for range 6 {
				statuses = append(statuses, m.c.Post("/auth/mfa/sms/enroll", map[string]any{"phone_e164": mfaPhone}, contracttest.Bearer(access)).StatusCode)
			}
			if !slices.Equal(statuses, []int{200, 200, 200, 200, 200, 429}) {
				m.t.Fatalf("statuses = %v, the sixth send to the destination is throttled", statuses)
			}
		},
	})
}

// mfaEnforce turns on mfa_enforced for the user, as an admin would.
func mfaEnforce(m *mfaCase, userID string) {
	m.t.Helper()
	ctx := context.Background()
	users := m.srv.Graph().Repos().Users
	before, err := users.Get(ctx, userID)
	if err != nil {
		m.t.Fatalf("load user: %v", err)
	}
	after := before
	after.MFAEnforced = true
	if err := users.Update(ctx, before, after); err != nil {
		m.t.Fatalf("enforce mfa: %v", err)
	}
}
