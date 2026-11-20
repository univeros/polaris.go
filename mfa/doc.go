// Package mfa holds multi-factor authentication (upstream docs/auth/mfa-otp.md).
//
// [Service] is the whole of it: TOTP, SMS and email factors (enroll, confirm, list, relabel,
// re-default, remove), the SMS/email one-time-code engine (hashed, time-boxed, attempt-bounded,
// single-use codes with a resend cooldown and send budgets), recovery codes, and the login MFA
// gate and step-up that verify any of them, including the factor types plugins add
// ([FactorType]). It consumes the session service, the login ticket and the principal resolver
// through small interfaces ([Sessions], [Tickets], [PrincipalResolver]).
//
// The primitives it builds on are here too: TOTP (RFC 6238) secrets, provisioning URIs and
// verification ([TOTP]), QR rendering of provisioning URIs ([SVGQRCode]), OTP challenge purposes,
// E.164 phone validation and destination masking.
package mfa
