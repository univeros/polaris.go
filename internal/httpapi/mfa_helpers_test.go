package httpapi_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/token"
)

const (
	mfaPassword = "correct horse battery staple"
	mfaPhone    = "+14155550101"
)

// mfaCase is one ported functional test: a fresh server (as upstream's setUp) and a client
// replaying the test's fixture.
type mfaCase struct {
	t   *testing.T
	srv *polaristest.Server
	c   *contracttest.Client
}

// mfaRun runs each PHP test method of phpClass as a subtest named after it, so its fixture resolves.
func mfaRun(t *testing.T, phpClass string, tests map[string]func(*mfaCase)) {
	dir := contracttest.Fixtures(t, "core")
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fx := contracttest.For(t, dir, `Polaris\Tests\Functional\`+phpClass, name)
			srv := polaristest.New(t)
			test(&mfaCase{t: t, srv: srv, c: contracttest.NewClient(t, srv.Handler(), fx)})
		})
	}
}

// registerVerifyLogin registers email, verifies it and logs in, returning the access token.
func (m *mfaCase) registerVerifyLogin(email string) string {
	m.t.Helper()
	m.c.Post("/auth/register", map[string]any{"email": email, "password": mfaPassword})
	registered := mfaEventsOf[event.UserRegistered](m.srv)
	if len(registered) == 0 {
		m.t.Fatal("no user.registered event")
	}
	m.c.Post("/auth/email/verify", map[string]any{"token": registered[0].VerificationToken})
	access, _ := mfaData(m.t, m.login(email))["access_token"].(string)
	return access
}

func (m *mfaCase) login(email string) *http.Response {
	return m.c.Post("/auth/login", map[string]any{"email": email, "password": mfaPassword})
}

// enrollTOTP starts a TOTP enrollment and returns its factor id and secret.
func (m *mfaCase) enrollTOTP(access string) (factorID, secret string) {
	m.t.Helper()
	data := mfaData(m.t, m.c.Post("/auth/mfa/totp/enroll", nil, contracttest.Bearer(access)))
	factorID, _ = data["factor_id"].(string)
	secret, _ = data["secret"].(string)
	return factorID, secret
}

func (m *mfaCase) confirmTOTP(factorID, code, access string) *http.Response {
	return m.c.Post("/auth/mfa/totp/confirm", map[string]any{"factor_id": factorID, "code": code}, contracttest.Bearer(access))
}

// enrollConfirmTOTP enrolls and confirms a TOTP factor: its id, secret and the recovery codes the
// confirmation returned (nil unless it was the first factor).
func (m *mfaCase) enrollConfirmTOTP(access string) (factorID, secret string, recovery []any) {
	m.t.Helper()
	factorID, secret = m.enrollTOTP(access)
	data := mfaData(m.t, m.confirmTOTP(factorID, m.totpCode(secret, 0), access))
	recovery, _ = data["recovery_codes"].([]any)
	return factorID, secret, recovery
}

// enrollConfirmSMS enrolls and confirms an SMS factor with the texted code.
func (m *mfaCase) enrollConfirmSMS(access string) string {
	m.t.Helper()
	factorID, _ := mfaData(m.t, m.c.Post("/auth/mfa/sms/enroll", map[string]any{"phone_e164": mfaPhone}, contracttest.Bearer(access)))["factor_id"].(string)
	m.c.Post("/auth/mfa/sms/confirm", map[string]any{"factor_id": factorID, "code": m.lastSMSCode()}, contracttest.Bearer(access))
	return factorID
}

// totpCode is the authenticator's code for secret on the server's clock, shifted by steps periods.
func (m *mfaCase) totpCode(secret string, steps int) string {
	m.t.Helper()
	at := m.srv.Graph().Clock().Now().Add(time.Duration(steps) * 30 * time.Second)
	code, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		m.t.Fatalf("totp code: %v", err)
	}
	return code
}

var mfaSixDigits = regexp.MustCompile(`\b(\d{6})\b`)

// lastSMSCode is the code of the last text sent.
func (m *mfaCase) lastSMSCode() string {
	m.t.Helper()
	sent := m.srv.SMS.Sent()
	if len(sent) == 0 {
		m.t.Fatal("no SMS sent")
	}
	match := mfaSixDigits.FindStringSubmatch(sent[len(sent)-1].Message)
	if match == nil {
		m.t.Fatalf("no code in %q", sent[len(sent)-1].Message)
	}
	return match[1]
}

// staleToken mints an access token for userID that authenticated long ago (step-up applies).
func (m *mfaCase) staleToken(userID string) string {
	m.t.Helper()
	authTime := time.Now().Unix() - 100000
	tokens, err := m.srv.Graph().Sessions().Issue(context.Background(), token.SessionPrincipal{
		UserID: userID, EmailVerified: true, MFA: true, AMR: []string{"pwd", "otp"}, AuthTime: &authTime,
	}, token.ClientContext{})
	if err != nil {
		m.t.Fatalf("issue stale token: %v", err)
	}
	return tokens.AccessToken
}

// mfaData is the "data" object of a response body ({} when absent).
func mfaData(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	data, _ := contracttest.JSON(t, resp)["data"].(map[string]any)
	if data == nil {
		return map[string]any{}
	}
	return data
}

// mfaEventsOf returns the dispatched events of type T, in order.
func mfaEventsOf[T event.Event](srv *polaristest.Server) []T {
	var out []T
	for _, e := range srv.Events.All() {
		if v, ok := e.(T); ok {
			out = append(out, v)
		}
	}
	return out
}

// mfaClaims decodes a JWT's payload without verifying it.
func mfaClaims(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwt)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("JWT payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("JWT payload: %v", err)
	}
	return claims
}

func mfaSubjectOf(t *testing.T, jwt string) string {
	sub, _ := mfaClaims(t, jwt)["sub"].(string)
	return sub
}

func mfaStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("status %d, want %d", resp.StatusCode, want)
	}
}
