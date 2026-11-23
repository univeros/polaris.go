package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/internal/services"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/repository"
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

// A login_mfa ticket stands for the first step: what ends every session of the account ends it.
func TestAnMFATicketDiesWithTheSessionsOfItsUser(t *testing.T) {
	for name, end := range map[string]func(t *testing.T, srv *polaristest.Server, u polaris.User){
		"password reset": func(t *testing.T, srv *polaristest.Server, u polaris.User) {
			if err := services.Of(srv.Graph()).Identity.SetPassword(t.Context(), u.ID, "an entirely different passphrase"); err != nil {
				t.Fatal(err)
			}
		},
		"logout everywhere": func(t *testing.T, srv *polaristest.Server, u polaris.User) {
			if err := srv.Sessions().RevokeAll(t.Context(), u.ID); err != nil {
				t.Fatal(err)
			}
		},
		"disable": func(t *testing.T, srv *polaristest.Server, u polaris.User) {
			if err := srv.Graph().Identity().DisableUser(t.Context(), "operator", u.ID); err != nil {
				t.Fatal(err)
			}
		},
		"nothing": nil,
	} {
		t.Run(name, func(t *testing.T) {
			clk := clock.NewFrozen(time.Now())
			srv := polaristest.New(t, polaristest.WithConfig(func(c *polaris.Config) { c.Clock = clk }))
			u, err := srv.Users().Create(t.Context(), polaris.NewUser{Email: "ada@example.com", Password: mfaPassword, EmailVerified: true})
			if err != nil {
				t.Fatal(err)
			}
			email := "ada+mfa@example.com"
			now := clk.Now()
			factor := model.MFAFactor{ID: repository.NewID(), UserID: u.ID, Type: model.FactorEmail, Email: &email, ConfirmedAt: &now, CreatedAt: now, UpdatedAt: now}
			if err := srv.Graph().Repos().MFAFactors.Insert(t.Context(), factor); err != nil {
				t.Fatal(err)
			}
			post := func(path, bearer, body string) (int, map[string]any) {
				r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Authorization", "Bearer "+bearer)
				w := httptest.NewRecorder()
				srv.Handler().ServeHTTP(w, r)
				var doc struct{ Data map[string]any }
				_ = json.Unmarshal(w.Body.Bytes(), &doc)
				return w.Code, doc.Data
			}
			_, data := post("/auth/login", "", `{"email":"ada@example.com","password":"`+mfaPassword+`"}`)
			ticket, _ := data["mfa_token"].(string)
			if ticket == "" {
				t.Fatalf("login: %v", data)
			}
			clk.Advance(2 * time.Second)
			want := http.StatusOK
			if end != nil {
				end(t, srv, u)
				want = http.StatusUnauthorized
			}
			if code, body := post("/auth/mfa/challenge", ticket, `{"factor_id":"`+factor.ID+`"}`); code != want {
				t.Fatalf("challenge: %d %v, want %d", code, body, want)
			}
			if code, body := post("/auth/mfa/verify", ticket, `{"factor_id":"`+factor.ID+`","code":"`+sentCode(srv)+`"}`); code != want {
				t.Fatalf("verify: %d %v, want %d", code, body, want)
			}
		})
	}
}

// sentCode is the last code mailed, "000000" when none was.
func sentCode(srv *polaristest.Server) string {
	for _, m := range slices.Backward(srv.Mailer.Sent()) {
		if code, ok := m.Data["code"].(string); ok {
			return code
		}
	}
	return "000000"
}
