package httpapi_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
)

func TestStepUpEndpoints(t *testing.T) {
	const email = "stepup@example.com"
	// userWithTOTP registers a user with a confirmed TOTP factor.
	userWithTOTP := func(m *mfaCase) (secret, userID, factorID string) {
		m.t.Helper()
		access := m.registerVerifyLogin(email)
		factorID, secret, _ = m.enrollConfirmTOTP(access)
		return secret, mfaSubjectOf(m.t, access), factorID
	}
	// stepUp clears step-up with a next-step code (the confirm consumed the current step).
	stepUp := func(m *mfaCase, secret, factorID, access string) string {
		m.t.Helper()
		resp := m.c.Post("/auth/mfa/step-up", map[string]any{"factor_id": factorID, "code": m.totpCode(secret, 1)}, contracttest.Bearer(access))
		mfaStatus(m.t, resp, 200)
		if n := len(mfaEventsOf[event.MFAStepUpCompleted](m.srv)); n != 1 {
			m.t.Fatalf("%d mfa.step_up_completed events, want 1", n)
		}
		fresh, _ := mfaData(m.t, resp)["access_token"].(string)
		return fresh
	}
	changePassword := func(m *mfaCase, access string) *http.Response {
		return m.c.Post("/auth/password/change", map[string]any{"current_password": mfaPassword, "new_password": "a different strong password"}, contracttest.Bearer(access))
	}
	mfaRun(t, "StepUpEndpointsTest", map[string]func(*mfaCase){
		"testStalePasswordChangeIsRejectedThenAllowedAfterStepUp": func(m *mfaCase) {
			secret, userID, factorID := userWithTOTP(m)
			stale := m.staleToken(userID)

			blocked := changePassword(m, stale)
			mfaStatus(m.t, blocked, 401)
			if contracttest.JSON(m.t, blocked)["error"] != "step_up_required" {
				m.t.Fatal("want step_up_required")
			}
			if h := blocked.Header.Get("WWW-Authenticate"); !strings.Contains(h, "step_up_required") {
				m.t.Fatalf("WWW-Authenticate = %q", h)
			}
			fresh := stepUp(m, secret, factorID, stale)
			mfaStatus(m.t, changePassword(m, fresh), 200)
		},
		"testRegenerateRecoveryCodesRequiresStepUp": func(m *mfaCase) {
			secret, userID, factorID := userWithTOTP(m)
			stale := m.staleToken(userID)

			mfaStatus(m.t, m.c.Post("/auth/mfa/recovery-codes/regenerate", nil, contracttest.Bearer(stale)), 401)
			fresh := stepUp(m, secret, factorID, stale)
			regen := m.c.Post("/auth/mfa/recovery-codes/regenerate", nil, contracttest.Bearer(fresh))
			mfaStatus(m.t, regen, 200)
			if codes, _ := mfaData(m.t, regen)["recovery_codes"].([]any); len(codes) != 10 {
				m.t.Fatalf("%d recovery codes, want 10", len(codes))
			}
		},
		"testStepUpRejectsAWrongCode": func(m *mfaCase) {
			_, userID, factorID := userWithTOTP(m)
			stale := m.staleToken(userID)

			resp := m.c.Post("/auth/mfa/step-up", map[string]any{"factor_id": factorID, "code": "000000"}, contracttest.Bearer(stale))
			mfaStatus(m.t, resp, 422)
			if n := len(mfaEventsOf[event.MFAStepUpCompleted](m.srv)); n != 0 {
				m.t.Fatalf("%d mfa.step_up_completed events, want 0", n)
			}
		},
		"testStepUpChallengeRejectsATotpFactor": func(m *mfaCase) {
			_, userID, factorID := userWithTOTP(m)
			stale := m.staleToken(userID)

			resp := m.c.Post("/auth/mfa/step-up/challenge", map[string]any{"factor_id": factorID}, contracttest.Bearer(stale))
			mfaStatus(m.t, resp, 422) // TOTP takes its code from the app, not a sent challenge
		},
		"testAUserWithoutMfaCanChangePasswordWithoutStepUp": func(m *mfaCase) {
			// No factor enrolled: step-up does not apply even to a stale token.
			access := m.registerVerifyLogin(email)
			stale := m.staleToken(mfaSubjectOf(m.t, access))
			mfaStatus(m.t, changePassword(m, stale), 200)
		},
	})
}
