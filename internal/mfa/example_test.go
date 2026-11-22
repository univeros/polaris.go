package mfa_test

import (
	"fmt"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/internal/mfa"
)

func ExampleTOTP() {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	p, err := mfa.NewTOTP(config.Defaults().OTP.TOTP, clock.NewFrozen(now))
	if err != nil {
		panic(err)
	}
	uri, _ := p.ProvisioningURI("JBSWY3DPEHPK3PXP", "ada@example.com")
	fmt.Println(uri)

	code, _ := totp.GenerateCode("JBSWY3DPEHPK3PXP", now) // what the user's app shows
	step, ok, _ := p.Match("JBSWY3DPEHPK3PXP", code)
	fmt.Println(ok, time.Unix(step, 0).UTC().Format(time.TimeOnly))
	// Output:
	// otpauth://totp/Univeros%3Aada%40example.com?issuer=Univeros&secret=JBSWY3DPEHPK3PXP
	// true 12:00:00
}
