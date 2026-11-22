package mfa

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/model"
)

func TestConfirmResultKeepsTheRecoveryCodesOutOfFmtAndLogs(t *testing.T) {
	r := ConfirmResult{RecoveryCodes: []string{"aaaaa-bbbbb"}}
	var log strings.Builder
	slog.New(slog.NewTextHandler(&log, nil)).Info("confirmed", "result", r)
	for _, out := range []string{fmt.Sprint(r), fmt.Sprintf("%+v", r), fmt.Sprintf("%#v", r), log.String()} {
		if strings.Contains(out, "aaaaa") {
			t.Errorf("recovery code in %q", out)
		}
	}
}

func TestPolicyErrorMatchesItsSentinelAndCarriesTheMessage(t *testing.T) {
	var err error = &PolicyError{Err: ErrLastFactorProtected, Message: "Enrol."}
	if !errors.Is(err, ErrLastFactorProtected) || err.Error() != "mfa: last factor protected: Enrol." {
		t.Fatalf("err = %v", err)
	}
}

func TestViewOfMasksTheDestinationAndOmitsWhatIsAbsent(t *testing.T) {
	phone, email, label := "+14155550101", "ada@example.com", "Work"
	views := []FactorView{
		ViewOf(model.MFAFactor{ID: "t", Type: model.FactorTOTP, IsDefault: true, Label: &label}),
		ViewOf(model.MFAFactor{ID: "s", Type: model.FactorSMS, PhoneE164: &phone}),
		ViewOf(model.MFAFactor{ID: "e", Type: model.FactorEmail, Email: &email}),
	}
	raw, err := json.Marshal(views)
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"id":"t","type":"totp","default":true,"label":"Work"},` +
		`{"id":"s","type":"sms","default":false,"destination":"+1 *** *** 0101"},` +
		`{"id":"e","type":"email","default":false,"destination":"a***@example.com"}]`
	if string(raw) != want {
		t.Fatalf("views = %s", raw)
	}
}
