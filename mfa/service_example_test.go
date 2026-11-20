package mfa_test

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/univeros/polaris-go/cache"
	"github.com/univeros/polaris-go/clock"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/mfa"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/notify/notifytest"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/security"
	"github.com/univeros/polaris-go/store/memstore"
	"github.com/univeros/polaris-go/token"
)

// These stand in for the session service, the login-ticket codec and authz.Principals, which
// enrollment does not use; production wiring passes *session.Service, *session.MFATickets and
// *authz.Principals.
type (
	sessions   struct{ mfa.Sessions }
	tickets    struct{ mfa.Tickets }
	principals struct{ mfa.PrincipalResolver }
)

func ExampleService_EnrollOTPFactor() {
	ctx := context.Background()
	const appKey = "an-application-key-of-32-bytes!!"
	pepper, _ := security.NewPepper(appKey)
	enc, _ := security.NewXChaCha20Poly1305(appKey)
	clk := clock.NewFrozen(time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC))
	totp, _ := mfa.NewTOTP(config.Defaults().OTP.TOTP, clk)
	sms := &notifytest.SMSSender{}

	s, err := mfa.New(mfa.Config{
		DB: memstore.New(schema.Core()...), Pepper: pepper, Encrypter: enc, TOTP: totp,
		SMS: sms, Mailer: &notifytest.Mailer{}, Cache: cache.NewMemory(clk),
		Sessions: sessions{}, Tickets: tickets{}, Principals: principals{}, Auth: config.Defaults(), Clock: clk,
	})
	if err != nil {
		panic(err)
	}

	user := model.User{ID: "user-1", Email: "ada@example.com"}
	enrolled, err := s.EnrollOTPFactor(ctx, user, model.FactorSMS, "+14155550101", token.ClientContext{})
	if err != nil {
		panic(err)
	}
	fmt.Println(enrolled.MaskedDestination)

	code := regexp.MustCompile(`\d{6}`).FindString(sms.Sent()[0].Message) // what the user types
	confirmed, err := s.ConfirmOTPFactor(ctx, user.ID, enrolled.FactorID, code)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(confirmed.RecoveryCodes), "recovery codes, shown once")
	// Output:
	// +1 *** *** 0101
	// 10 recovery codes, shown once
}
