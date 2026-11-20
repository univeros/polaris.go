package httpapi_test

import (
	"testing"

	"github.com/univeros/polaris-go/contracttest"
	"github.com/univeros/polaris-go/polaristest"
)

// TestMfaEndpointErrors covers the documented error answers no upstream fixture records.
func TestMfaEndpointErrors(t *testing.T) {
	t.Parallel()
	srv := polaristest.New(t)
	m := &mfaCase{t: t, srv: srv, c: contracttest.NewClient(t, srv.Handler(), nil)}
	access := m.registerVerifyLogin("errors@example.com")
	bearer := contracttest.Bearer(access)
	pendingID, _ := mfaData(t, m.c.Post("/auth/mfa/sms/enroll", map[string]any{"phone_e164": mfaPhone}, bearer))["factor_id"].(string)

	expect := func(name string, status int, code string, body map[string]any) {
		t.Helper()
		resp := m.c.Post(name, body, bearer)
		got := contracttest.JSON(t, resp)
		if resp.StatusCode != status || got["error"] != code && !(code == "validation_failed" && got["errors"] != nil) {
			t.Errorf("%s %v: %v, want %d %s", name, body, got, status, code)
		}
	}
	expect("/auth/mfa/totp/confirm", 422, "validation_failed", map[string]any{"factor_id": " ", "code": "123456"})
	expect("/auth/mfa/totp/confirm", 404, "not_found", map[string]any{"factor_id": "nope", "code": 123456})
	expect("/auth/mfa/sms/confirm", 404, "not_found", map[string]any{"factor_id": "nope", "code": "123456"})
	expect("/auth/mfa/email/enroll", 422, "validation_failed", map[string]any{"email": "not-an-email"})
	expect("/auth/mfa/step-up/challenge", 422, "validation_failed", map[string]any{})
	expect("/auth/mfa/step-up/challenge", 404, "not_found", map[string]any{"factor_id": pendingID}) // unconfirmed
	expect("/auth/mfa/step-up", 422, "validation_failed", map[string]any{"factor_id": pendingID})
	expect("/auth/mfa/step-up", 404, "not_found", map[string]any{"factor_id": "nope", "code": "123456"})
	expect("/auth/mfa/step-up", 422, "invalid_code", map[string]any{"type": "recovery", "factor_id": "ignored", "code": "aaaaa-bbbbb"})

	resp := m.c.Patch("/auth/mfa/factors/"+pendingID, map[string]any{"default": "1"}, bearer)
	if mfaStatus(t, resp, 422); contracttest.JSON(t, resp)["error"] != "invalid_state" {
		t.Error("making a pending factor the default: want invalid_state")
	}
	mfaStatus(t, m.c.Patch("/auth/mfa/factors/nope", map[string]any{"label": "x"}, bearer), 404)
	mfaStatus(t, m.c.Delete("/auth/mfa/factors/nope", bearer), 404)

	labelled := mfaData(t, m.c.Patch("/auth/mfa/factors/"+pendingID, map[string]any{"label": "Work", "default": 0}, bearer))
	cleared := mfaData(t, m.c.Patch("/auth/mfa/factors/"+pendingID, map[string]any{"label": ""}, bearer))
	if labelled["label"] != "Work" || cleared["label"] != nil {
		t.Errorf("label set %v then cleared %v", labelled, cleared)
	}
	if _, ok := mfaData(t, m.c.Patch("/auth/mfa/factors/"+pendingID, map[string]any{}, bearer))["label"]; ok {
		t.Error("an omitted label must leave the cleared label alone")
	}
}
