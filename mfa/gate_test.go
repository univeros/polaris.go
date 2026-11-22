package mfa

// The MFA login gate, step-up and the plugin factor-type seam, plus the shared verifier.

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/session"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

// The production types satisfy the consumer-side interfaces.
var (
	_ Sessions          = (*session.Service)(nil)
	_ Tickets           = (*session.MFATickets)(nil)
	_ PrincipalResolver = (*authz.Principals)(nil)
	_ PrincipalResolver = session.UserPrincipals{}
)

const gateAt = "2026-06-09 12:00:00"

// stampType verifies "stamp:<factor id>": a plugin factor type for the tests.
type stampType struct {
	name     string
	mu       sync.Mutex
	verified [][3]string
}

func (s *stampType) Type() string { return s.name }

func (s *stampType) Verify(_ context.Context, f model.MFAFactor, code string, purpose ChallengePurpose) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verified = append(s.verified, [3]string{f.ID, code, string(purpose)})
	if code != "stamp:"+f.ID {
		return ErrInvalidOTP
	}
	return nil
}

func TestConfirmedFactorsKeepsOnlyConfirmedOnes(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, gateAt)
		h.insertFactor(t, model.MFAFactor{ID: "f-2", Type: model.FactorTOTP})
		h.insertFactor(t, model.MFAFactor{ID: "f-1", Type: model.FactorTOTP, ConfirmedAt: ptr(at(gateAt))})
		s := h.service(t)
		fs, err := s.ConfirmedFactors(ctx, "user-1")
		must(t, err)
		if len(fs) != 1 || fs[0].ID != "f-1" {
			t.Fatalf("%+v", fs)
		}
		if ok, err := s.HasConfirmedFactor(ctx, "user-1"); err != nil || !ok {
			t.Fatal("has one")
		}
		if ok, err := s.HasConfirmedFactor(ctx, "user-2"); err != nil || ok {
			t.Fatal("has none")
		}
	})
}

func TestBeginLoginMintsATicketAndMasksFactorViews(t *testing.T) {
	h := newHarness(t, memDB(), gateAt)
	totpF := model.MFAFactor{ID: "f-totp", UserID: "user-1", Type: model.FactorTOTP, Label: ptr("Authenticator"), IsDefault: true, ConfirmedAt: ptr(at(gateAt))}
	smsF := model.MFAFactor{ID: "f-sms", UserID: "user-1", Type: model.FactorSMS, PhoneE164: ptr("+14155550123"), ConfirmedAt: ptr(at(gateAt))}
	res, err := h.service(t).BeginLogin("user-1", []model.MFAFactor{totpF, smsF})
	must(t, err)
	if res.UserID != "user-1" || res.MFAToken != "ticket-user-1" {
		t.Fatalf("%+v", res)
	}
	want := []FactorView{
		{ID: "f-totp", Type: "totp", Default: true, Label: "Authenticator"},
		{ID: "f-sms", Type: "sms", Destination: "+1 *** *** 0123"},
	}
	if !slices.Equal(res.Factors, want) {
		t.Fatalf("%+v", res.Factors)
	}
}

func TestVerifyLoginWithARecoveryCodeMintsTheSessionAndEmits(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, gateAt)
		s := h.service(t)
		codes := issue(t, s, "user-1")
		tokens, err := s.VerifyLogin(ctx, "user-1", "", codes[0], token.ClientContext{IP: "203.0.113.7", UserAgent: "ua/1"})
		must(t, err)
		if tokens.AccessToken != "access-user-1" || len(h.sessions.issued) != 1 {
			t.Fatalf("%+v", tokens)
		}
		p := h.sessions.issued[0]
		if !p.MFA || !slices.Equal(p.AMR, []string{"pwd", "otp"}) || p.AuthTime == nil || *p.AuthTime != at(gateAt).Unix() ||
			!p.EmailVerified || !slices.Equal(p.Roles, []string{"member"}) || p.OrganizationID != "" {
			t.Fatalf("%+v", p)
		}
		verified := ofType[event.MFAVerified](h.events)
		loggedIn := ofType[event.UserLoggedIn](h.events)
		if len(verified) != 1 || verified[0].FactorID != nil || len(loggedIn) != 1 || loggedIn[0].SessionID != "session-1" ||
			*loggedIn[0].IP != "203.0.113.7" || *loggedIn[0].UserAgent != "ua/1" || !slices.Equal(loggedIn[0].AMR, []string{"pwd", "otp"}) {
			t.Fatalf("%+v %+v", verified, loggedIn)
		}
		if len(ofType[event.MFAVerifyFailed](h.events)) != 0 {
			t.Fatal("no failure")
		}
	})
}

func TestVerifyLoginWithAWrongRecoveryCodeFailsAndEmitsNoSession(t *testing.T) {
	h := newHarness(t, memDB(), gateAt)
	s := h.service(t)
	issue(t, s, "user-1")
	if _, err := s.VerifyLogin(ctx, "user-1", "", "aaaaa-bbbbb", token.ClientContext{}); !errors.Is(err, ErrInvalidOTP) {
		t.Fatal(err)
	}
	if len(h.sessions.issued) != 0 {
		t.Fatal("no session on failure")
	}
	failures := ofType[event.MFAVerifyFailed](h.events)
	if len(failures) != 1 || failures[0].FactorID != nil || *failures[0].Type != event.MFAVerifyFailedTypeRecovery {
		t.Fatalf("the factor-less path is a recovery attempt: %+v", failures)
	}
	if len(ofType[event.MFAVerified](h.events)) != 0 {
		t.Fatal("not verified")
	}
}

func TestVerifyLoginRejectsAnUnknownOrUnconfirmedFactor(t *testing.T) {
	h := newHarness(t, memDB(), gateAt)
	h.insertFactor(t, model.MFAFactor{ID: "f-1", Type: model.FactorTOTP})
	s := h.service(t)
	if _, err := s.VerifyLogin(ctx, "user-1", "f-1", "123456", token.ClientContext{}); !errors.Is(err, ErrFactorNotFound) {
		t.Fatal(err)
	}
	failures := ofType[event.MFAVerifyFailed](h.events)
	if len(failures) != 1 || *failures[0].FactorID != "f-1" || failures[0].Type != nil {
		t.Fatalf("an unconfirmed factor must not disclose its type: %+v", failures)
	}
	if len(h.sessions.issued) != 0 {
		t.Fatal("no session")
	}
}

func TestVerifyLoginWithAConfirmedFactorRecordsItsTypeOnFailure(t *testing.T) {
	h := newHarness(t, memDB(), gateAt)
	h.insertFactor(t, model.MFAFactor{ID: "f-1", Type: model.FactorTOTP, SecretEncrypted: ptr(h.encrypt(t, "JBSWY3DPEHPK3PXP")), ConfirmedAt: ptr(at(gateAt))})
	s := h.service(t, withTOTP(0, false))
	if _, err := s.VerifyLogin(ctx, "user-1", "f-1", "000000", token.ClientContext{}); !errors.Is(err, ErrInvalidOTP) {
		t.Fatal(err)
	}
	if f := ofType[event.MFAVerifyFailed](h.events); len(f) != 1 || *f[0].Type != "totp" {
		t.Fatalf("%+v", f)
	}
	// And a good code clears the gate with the factor recorded.
	tokens, err := h.service(t).VerifyLogin(ctx, "user-1", "f-1", "123456", token.ClientContext{})
	must(t, err)
	if v := ofType[event.MFAVerified](h.events); tokens.SessionID != "session-1" || len(v) != 1 || *v[0].FactorID != "f-1" {
		t.Fatalf("%+v", v)
	}
}

func TestTheGateRoutesSmsCodesThroughTheOTPEngine(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, gateAt)
		h.insertFactor(t, model.MFAFactor{ID: "f-sms", Type: model.FactorSMS, PhoneE164: ptr("+14155550101"), ConfirmedAt: ptr(at(gateAt))})
		h.insertFactor(t, model.MFAFactor{ID: "f-totp", Type: model.FactorTOTP, ConfirmedAt: ptr(at(gateAt))})
		s := h.service(t)
		res, err := s.Challenge(ctx, "user-1", "f-sms", PurposeLoginMFA, token.ClientContext{})
		must(t, err)
		if res.MaskedDestination != "+1 *** *** 0101" {
			t.Fatalf("%+v", res)
		}
		code := sixDigits.FindStringSubmatch(h.sms.Sent()[0].Message)[1]
		if _, err := s.VerifyStepUp(ctx, "user-1", "", "session-1", "f-sms", code); !errors.Is(err, ErrInvalidOTP) {
			t.Fatal("a login_mfa code cannot clear step-up:", err)
		}
		if _, err := s.VerifyLogin(ctx, "user-1", "f-sms", code, token.ClientContext{}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Challenge(ctx, "user-1", "f-totp", PurposeLoginMFA, token.ClientContext{}); !errors.Is(err, ErrInvalidOTP) {
			t.Fatal("a TOTP factor has no sent challenge:", err)
		}
		if _, err := s.Challenge(ctx, "user-1", "missing", PurposeLoginMFA, token.ClientContext{}); !errors.Is(err, ErrFactorNotFound) {
			t.Fatal(err)
		}
	})
}

func TestStepUpWithARecoveryCodeRefreshesTheSessionAndEmits(t *testing.T) {
	h := newHarness(t, memDB(), gateAt)
	s := h.service(t)
	codes := issue(t, s, "user-1")
	access, err := s.VerifyStepUp(ctx, "user-1", "org-1", "session-xyz", "", codes[0])
	must(t, err)
	if access != "stepped-up-session-xyz" || h.sessions.steppedUp[0] != [3]string{"user-1", "org-1", "session-xyz"} {
		t.Fatalf("%q %+v", access, h.sessions.steppedUp)
	}
	if ev := ofType[event.MFAStepUpCompleted](h.events); len(ev) != 1 || ev[0] != (event.MFAStepUpCompleted{UserID: "user-1", SessionID: "session-xyz"}) {
		t.Fatalf("%+v", ev)
	}
	if len(ofType[event.MFAVerifyFailed](h.events)) != 0 {
		t.Fatal("no failure")
	}
}

func TestStepUpWithAWrongCodeFailsWithoutRefreshing(t *testing.T) {
	h := newHarness(t, memDB(), gateAt)
	s := h.service(t)
	issue(t, s, "user-1")
	if _, err := s.VerifyStepUp(ctx, "user-1", "", "session-xyz", "", "aaaaa-bbbbb"); !errors.Is(err, ErrInvalidOTP) {
		t.Fatal(err)
	}
	if len(h.sessions.steppedUp) != 0 || len(ofType[event.MFAVerifyFailed](h.events)) != 1 || len(ofType[event.MFAStepUpCompleted](h.events)) != 0 {
		t.Fatal("no refresh, one failure event")
	}
}

func TestStepUpRejectsAnUnconfirmedFactor(t *testing.T) {
	h := newHarness(t, memDB(), gateAt)
	h.insertFactor(t, model.MFAFactor{ID: "f-1", Type: model.FactorTOTP})
	if _, err := h.service(t).VerifyStepUp(ctx, "user-1", "", "session-xyz", "f-1", "123456"); !errors.Is(err, ErrFactorNotFound) {
		t.Fatal(err)
	}
	if len(ofType[event.MFAVerifyFailed](h.events)) != 1 || len(h.sessions.steppedUp) != 0 {
		t.Fatal("one failure event, no refresh")
	}
}

func TestStepUpPassesASessionErrorThrough(t *testing.T) {
	h := newHarness(t, memDB(), gateAt)
	h.sessions.failStep = session.ErrInvalidGrant
	s := h.service(t)
	codes := issue(t, s, "user-1")
	if _, err := s.VerifyStepUp(ctx, "user-1", "", "gone", "", codes[0]); !errors.Is(err, session.ErrInvalidGrant) {
		t.Fatal(err)
	}
	if len(ofType[event.MFAStepUpCompleted](h.events)) != 0 || len(ofType[event.MFAVerifyFailed](h.events)) != 0 {
		t.Fatal("neither completed nor a code failure")
	}
}

// The factor-type seam (MfaFactorTypeTest).

func TestAPluginsTypeClearsTheGateAndStepUpWithItsOwnVerification(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, gateAt)
		stamp := &stampType{name: "stamp"}
		s := h.service(t, func(c *Config) { c.FactorTypes = []FactorType{stamp} })
		f := h.insertFactor(t, model.MFAFactor{Type: "stamp", Label: ptr("YubiKey"), IsDefault: true, ConfirmedAt: ptr(at(gateAt))})

		fs, err := s.ConfirmedFactors(ctx, "user-1")
		must(t, err)
		if fs[0].Type != "stamp" {
			t.Fatal("core lists the plugin's factor")
		}
		if _, err := s.VerifyLogin(ctx, "user-1", f.ID, "stamp:"+f.ID, token.ClientContext{}); err != nil {
			t.Fatal(err)
		}
		if p := h.sessions.issued[0]; !p.MFA || !slices.Equal(p.AMR, []string{"pwd", "otp"}) {
			t.Fatal("core's post-MFA session")
		}
		if _, err := s.VerifyLogin(ctx, "user-1", f.ID, "wrong", token.ClientContext{}); !errors.Is(err, ErrInvalidOTP) {
			t.Fatal("the type refused:", err)
		}
		if ev := ofType[event.MFAVerifyFailed](h.events); len(ev) != 1 || *ev[0].Type != "stamp" {
			t.Fatalf("%+v", ev)
		}
		if _, err := s.VerifyStepUp(ctx, "user-1", "", "session-1", f.ID, "stamp:"+f.ID); err != nil {
			t.Fatal(err)
		}
		want := [][3]string{{f.ID, "stamp:" + f.ID, "login_mfa"}, {f.ID, "wrong", "login_mfa"}, {f.ID, "stamp:" + f.ID, "step_up"}}
		if !slices.Equal(stamp.verified, want) {
			t.Fatalf("%v", stamp.verified)
		}
		if _, err := s.Challenge(ctx, "user-1", f.ID, PurposeLoginMFA, token.ClientContext{}); !errors.Is(err, ErrInvalidOTP) {
			t.Fatal("no sent challenge for a plugin type:", err)
		}
	})
}

func TestAFactorOfATypeNobodyVerifiesIsUnusable(t *testing.T) {
	h := newHarness(t, memDB(), gateAt)
	f := h.insertFactor(t, model.MFAFactor{Type: "stamp", ConfirmedAt: ptr(at(gateAt))})
	if _, err := h.service(t).VerifyLogin(ctx, "user-1", f.ID, "stamp:"+f.ID, token.ClientContext{}); !errors.Is(err, ErrFactorNotFound) {
		t.Fatal(err)
	}
}

func TestCoresOwnTypesAndADuplicateCannotBeRegistered(t *testing.T) {
	h := newHarness(t, memDB(), gateAt)
	for _, types := range [][]FactorType{
		{&stampType{name: "totp"}}, {&stampType{name: "sms"}}, {&stampType{name: "email"}},
		{&stampType{name: "stamp"}, &stampType{name: "stamp"}}, {&stampType{name: ""}}, {nil},
	} {
		cfg := h.cfg
		cfg.FactorTypes = types
		if _, err := New(cfg); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%v: %v", types, err)
		}
	}
}

func TestNewRequiresDependencies(t *testing.T) {
	_, err := New(Config{})
	if !errors.Is(err, ErrInvalidConfig) || err.Error() != "mfa: invalid configuration: Config.DB, Config.Pepper, Config.Encrypter, "+
		"Config.TOTP, Config.SMS, Config.Mailer, Config.Cache, Config.Sessions, Config.Tickets, Config.Principals required" {
		t.Fatal(err)
	}
	h := newHarness(t, memDB(), gateAt)
	cfg := h.cfg
	cfg.Auth.OTP.Length = 0
	if _, err := New(cfg); !errors.Is(err, ErrInvalidConfig) {
		t.Fatal("a zero OTP length is refused:", err)
	}
}

func TestViews(t *testing.T) {
	email := model.MFAFactor{ID: "e", Type: model.FactorEmail, Email: ptr("ada@example.com"), Label: ptr("")}
	if v := ManagedViewOf(email); v != (ManagedFactorView{FactorView: FactorView{ID: "e", Type: "email", Destination: "a***@example.com"}}) {
		t.Fatalf("%+v", v)
	}
	totpF := model.MFAFactor{ID: "t", Type: model.FactorTOTP, Label: ptr("Authenticator"), IsDefault: true, ConfirmedAt: ptr(at(gateAt))}
	raw, err := json.Marshal([]any{ViewOf(totpF), ManagedViewOf(email)})
	must(t, err)
	if string(raw) != `[{"id":"t","type":"totp","default":true,"label":"Authenticator"},{"id":"e","type":"email","default":false,"destination":"a***@example.com","confirmed":false}]` {
		t.Fatalf("%s", raw)
	}
	if e := (&PolicyError{ErrLastFactorProtected, "Enrol."}); e.Error() != "mfa: last factor protected: Enrol." {
		t.Fatal(e)
	}
	plugin := model.MFAFactor{ID: "p", Type: "passkey", Email: ptr("ignored"), ConfirmedAt: ptr(at(gateAt))}
	if v := ManagedViewOf(plugin); v.Destination != "" || !v.Confirmed {
		t.Fatalf("%+v", v)
	}
}
