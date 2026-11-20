package mfa

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// MaskDestination masks an OTP destination for display: enough to recognise the device, never
// the full contact. channel "email" masks an address (a***@example.com); any other channel masks
// a phone (+1 *** *** 0101). An empty destination stays empty.
func MaskDestination(channel, destination string) string {
	if destination == "" {
		return ""
	}
	if channel == "email" { // model.OtpChallenge CHANNEL_EMAIL upstream
		at := strings.LastIndexByte(destination, '@')
		if at <= 0 {
			return "***"
		}
		_, size := utf8.DecodeRuneInString(destination)
		return destination[:size] + "***" + destination[at:]
	}

	last4 := destination[max(0, len(destination)-4):]
	prefix := ""
	if strings.Contains(destination, "+") {
		prefix = destination[:min(2, len(destination))]
	}
	return strings.TrimSpace(prefix + " *** *** " + last4)
}

// e164 is a leading +, a non-zero first digit and 7–15 digits in all (7 is the practical ITU-T
// minimum, so +12 is rejected before a provider would).
var e164 = regexp.MustCompile(`^\+[1-9][0-9]{5,14}$`)

// ValidE164 reports whether phone is in E.164 form, e.g. +14155550101.
func ValidE164(phone string) bool { return e164.MatchString(phone) }
