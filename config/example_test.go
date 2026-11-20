package config_test

import (
	"fmt"
	"time"

	"github.com/univeros/polaris.go/config"
)

func ExampleFromLookup() {
	env := map[string]string{
		"APP_KEY":              "0123456789abcdef0123456789abcdef",
		"AUTH_JWT_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----…",
		"AUTH_JWT_PUBLIC_KEY":  "-----BEGIN PUBLIC KEY-----…",
		"AUTH_ISSUER":          "https://auth.example.com",
	}
	// In production: config.FromEnv().
	_, auth, err := config.FromLookup(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil {
		panic(err)
	}
	fmt.Println(auth.Issuer, auth.AccessToken.TTL)
	// Output: https://auth.example.com 15m0s
}

func ExampleAuth_Validate() {
	auth := config.Defaults()
	auth.Issuer = "https://auth.example.com"
	auth.Flows.TokenDelivery = config.DeliveryCookie
	auth.Flows.CookieTrustedOrigins = []string{"https://app.example.com"}
	auth.RateLimits.Login.Limit = 3
	auth.OTP.TTL = 90 * time.Second
	fmt.Println(auth.Validate())

	auth.OTP.Length = 12
	fmt.Println(auth.Validate())
	// Output:
	// <nil>
	// invalid Polaris config: Auth.OTP.Length is 12, must be between 4 and 10 (auth.otp.length)
}
