package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/manifest"
	"github.com/univeros/polaris.go/mfa"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/wiring"
)

// mfaEndpoints serves upstream/api/core/auth/mfa: factor enrollment and management (this file)
// and the login gate and step-up (mfa_gate.go).
//
// Input is checked by each endpoint, not by the manifest rules: upstream's core endpoints answer
// their own 422 messages ("A valid E.164 phone number is required."), which the fixtures freeze.
func mfaEndpoints(g *wiring.Graph) map[string]endpoint.Endpoint {
	m := &mfaAPI{g: g}
	return map[string]endpoint.Endpoint{
		"polaris.auth.mfa.totp-enroll":               endpoint.Func(m.totpEnroll),
		"polaris.auth.mfa.totp-confirm":              endpoint.Func(m.totpConfirm),
		"polaris.auth.mfa.sms-enroll":                endpoint.Func(m.smsEnroll),
		"polaris.auth.mfa.sms-confirm":               endpoint.Func(m.otpConfirm),
		"polaris.auth.mfa.email-enroll":              endpoint.Func(m.emailEnroll),
		"polaris.auth.mfa.email-confirm":             endpoint.Func(m.otpConfirm),
		"polaris.auth.mfa.factors-list":              endpoint.Func(m.factors),
		"polaris.auth.mfa.factor-update":             endpoint.Func(m.updateFactor),
		"polaris.auth.mfa.factor-delete":             endpoint.Func(m.deleteFactor),
		"polaris.auth.mfa.recovery-codes-regenerate": endpoint.Func(m.regenerateRecoveryCodes),
		"polaris.auth.mfa.challenge":                 endpoint.Func(m.challenge),
		"polaris.auth.mfa.verify":                    endpoint.Func(m.verify),
		"polaris.auth.mfa.step-up-challenge":         endpoint.Func(m.stepUpChallenge),
		"polaris.auth.mfa.step-up":                   endpoint.Func(m.stepUp),
	}
}

type mfaAPI struct{ g *wiring.Graph }

// The messages upstream answers; the fixtures freeze them.
const (
	mfaMsgFactorNotFound = "MFA factor not found."
	mfaMsgInvalidCode    = "The verification code is invalid."
	mfaMsgWait           = "Please wait before requesting another code."
	mfaMsgNeedFactorCode = "A factor id and verification code are required."
	mfaMsgNeedFactor     = "A factor id is required."
	mfaMsgNeedCode       = "A verification code is required."
)

func (m *mfaAPI) totpEnroll(ctx context.Context, _ *endpoint.Input) endpoint.Result {
	user, res, ok := m.user(ctx)
	if !ok {
		return res
	}
	r, err := m.g.MFA().EnrollTOTP(ctx, user)
	if err != nil {
		return m.fail(ctx, "totp enroll", err)
	}
	return endpoint.Data(http.StatusOK, map[string]any{
		"factor_id": r.FactorID, "secret": r.Secret, "otpauth_uri": r.OTPAuthURI, "qr_svg": r.QRSVG,
	})
}

func (m *mfaAPI) totpConfirm(ctx context.Context, in *endpoint.Input) endpoint.Result {
	return m.confirm(ctx, in, m.g.MFA().ConfirmTOTP)
}

// otpConfirm serves both the sms and the email confirm routes: the factor is resolved by id and
// the code checked against that factor's own challenge, so the route hit does not matter.
func (m *mfaAPI) otpConfirm(ctx context.Context, in *endpoint.Input) endpoint.Result {
	return m.confirm(ctx, in, m.g.MFA().ConfirmOTPFactor)
}

func (m *mfaAPI) confirm(ctx context.Context, in *endpoint.Input, confirm func(ctx context.Context, userID, factorID, code string) (mfa.ConfirmResult, error)) endpoint.Result {
	userID := mfaSubject(ctx)
	if userID == "" {
		return endpoint.Unauthorized()
	}
	factorID, code := mfaField(in, "factor_id"), mfaField(in, "code")
	if factorID == "" || code == "" {
		return endpoint.Unprocessable([]string{mfaMsgNeedFactorCode})
	}
	r, err := confirm(ctx, userID, factorID, code)
	switch {
	case errors.Is(err, mfa.ErrFactorNotFound):
		return endpoint.NotFound(mfaMsgFactorNotFound)
	case errors.Is(err, mfa.ErrInvalidOTP):
		return endpoint.Error(http.StatusUnprocessableEntity, "invalid_code", mfaMsgInvalidCode)
	case err != nil:
		return m.fail(ctx, "confirm factor", err)
	}
	data := map[string]any{"status": "confirmed"}
	if len(r.RecoveryCodes) > 0 {
		data["recovery_codes"] = r.RecoveryCodes
	}
	return endpoint.Data(http.StatusOK, data)
}

func (m *mfaAPI) smsEnroll(ctx context.Context, in *endpoint.Input) endpoint.Result {
	user, res, ok := m.user(ctx)
	if !ok {
		return res
	}
	phone := mfaField(in, "phone_e164")
	if !mfa.ValidE164(phone) {
		return endpoint.Unprocessable([]string{"A valid E.164 phone number is required."})
	}
	return m.enrollOTP(ctx, user, model.FactorSMS, phone)
}

func (m *mfaAPI) emailEnroll(ctx context.Context, in *endpoint.Input) endpoint.Result {
	user, res, ok := m.user(ctx)
	if !ok {
		return res
	}
	email := mfaField(in, "email")
	if email == "" {
		email = user.Email
	} else if !manifest.IsEmail(email) { // IsEmail bounds the address at 320 bytes, the column size
		return endpoint.Unprocessable([]string{"A valid email address is required."})
	}
	return m.enrollOTP(ctx, user, model.FactorEmail, email)
}

func (m *mfaAPI) enrollOTP(ctx context.Context, user model.User, factorType, destination string) endpoint.Result {
	r, err := m.g.MFA().EnrollOTPFactor(ctx, user, factorType, destination, endpoint.Client(ctx))
	switch {
	case errors.Is(err, mfa.ErrOTPCooldown):
		return endpoint.Error(http.StatusTooManyRequests, "rate_limited", mfaMsgWait)
	case err != nil:
		return m.fail(ctx, factorType+" enroll", err)
	}
	return endpoint.Data(http.StatusOK, map[string]any{"factor_id": r.FactorID, "destination": r.MaskedDestination})
}

func (m *mfaAPI) factors(ctx context.Context, _ *endpoint.Input) endpoint.Result {
	userID := mfaSubject(ctx)
	if userID == "" {
		return endpoint.Unauthorized()
	}
	rows, err := m.g.MFA().Factors(ctx, userID)
	if err != nil {
		return m.fail(ctx, "list factors", err)
	}
	views := make([]mfa.ManagedFactorView, len(rows))
	for i, f := range rows {
		views[i] = mfa.ManagedViewOf(f)
	}
	return endpoint.Data(http.StatusOK, map[string]any{"factors": views})
}

func (m *mfaAPI) updateFactor(ctx context.Context, in *endpoint.Input) endpoint.Result {
	userID := mfaSubject(ctx)
	if userID == "" {
		return endpoint.Unauthorized()
	}
	factorID := mfaField(in, "id")
	if factorID == "" {
		return endpoint.Unprocessable([]string{mfaMsgNeedFactor})
	}
	var label *string // omitted leaves the label alone; present (even null or "") replaces it
	if in.Has("label") {
		l := mfaString(in.Value("label"))
		label = &l
	}
	f, err := m.g.MFA().UpdateFactor(ctx, userID, factorID, label, mfaTruthy(in.Value("default")))
	var policy *mfa.PolicyError
	switch {
	case errors.Is(err, mfa.ErrFactorNotFound):
		return endpoint.NotFound(mfaMsgFactorNotFound)
	case errors.As(err, &policy) && errors.Is(err, mfa.ErrInvalidFactorState):
		return endpoint.Error(http.StatusUnprocessableEntity, "invalid_state", policy.Message)
	case err != nil:
		return m.fail(ctx, "update factor", err)
	}
	return endpoint.Data(http.StatusOK, mfa.ManagedViewOf(f))
}

func (m *mfaAPI) deleteFactor(ctx context.Context, in *endpoint.Input) endpoint.Result {
	userID := mfaSubject(ctx)
	if userID == "" {
		return endpoint.Unauthorized()
	}
	factorID := mfaField(in, "id")
	if factorID == "" {
		return endpoint.Unprocessable([]string{mfaMsgNeedFactor})
	}
	err := m.g.MFA().RemoveFactor(ctx, userID, factorID)
	var policy *mfa.PolicyError
	switch {
	case errors.Is(err, mfa.ErrFactorNotFound):
		return endpoint.NotFound(mfaMsgFactorNotFound)
	case errors.As(err, &policy) && errors.Is(err, mfa.ErrLastFactorProtected):
		return endpoint.Error(http.StatusConflict, "last_factor_protected", policy.Message)
	case err != nil:
		return m.fail(ctx, "remove factor", err)
	}
	return endpoint.Data(http.StatusOK, map[string]any{"status": "removed"})
}

// regenerateRecoveryCodes is step-up gated by the pipeline; it only needs the user.
func (m *mfaAPI) regenerateRecoveryCodes(ctx context.Context, _ *endpoint.Input) endpoint.Result {
	userID := mfaSubject(ctx)
	if userID == "" {
		return endpoint.Unauthorized()
	}
	codes, err := m.g.MFA().RegenerateRecoveryCodes(ctx, userID)
	if err != nil {
		return m.fail(ctx, "regenerate recovery codes", err)
	}
	return endpoint.Data(http.StatusOK, map[string]any{"recovery_codes": codes})
}

// user loads the principal's account; a token whose user is gone is 401, as upstream.
func (m *mfaAPI) user(ctx context.Context) (model.User, endpoint.Result, bool) {
	userID := mfaSubject(ctx)
	if userID == "" {
		return model.User{}, endpoint.Unauthorized(), false
	}
	u, err := m.g.Repos().Users.Get(ctx, userID)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		return model.User{}, endpoint.Unauthorized(), false
	case err != nil:
		return model.User{}, m.fail(ctx, "load user", err), false
	}
	return u, endpoint.Result{}, true
}

// fail answers 500 for a failing service, logging the cause (never a secret: the errors carry ids).
func (m *mfaAPI) fail(ctx context.Context, op string, err error) endpoint.Result {
	m.g.Logger().ErrorContext(ctx, "polaris mfa: "+op+" failed", "error", err)
	return endpoint.Error(http.StatusInternalServerError, "server_error", "The server could not complete the request.")
}

// mfaSubject is the bearer principal's user id, "" without one.
func mfaSubject(ctx context.Context) string {
	if t := endpoint.Token(ctx); t != nil {
		return t.Subject()
	}
	return ""
}

// mfaField is key as upstream reads it: cast to string, then trimmed.
func mfaField(in *endpoint.Input, key string) string {
	return strings.Trim(mfaString(in.Value(key)), " \t\n\r\x00\x0B")
}

// mfaString is PHP's (string) cast for the scalars a JSON or form body carries; anything else is "".
func mfaString(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case bool:
		if v {
			return "1"
		}
	}
	return ""
}

// mfaTruthy is PHP's (bool) cast: false, 0, "", "0", null and empty collections are false.
func mfaTruthy(v any) bool {
	switch v := v.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		return v != "" && v != "0"
	case json.Number:
		f, err := v.Float64()
		return err != nil || f != 0
	case []any:
		return len(v) > 0
	case map[string]any:
		return len(v) > 0
	}
	return true
}
