package ui

import (
	"maps"
	"strings"
)

// English is the built-in message catalog: every text the pages show, by key. Config.Messages
// overrides any of them per locale ("en" included); a key a locale leaves out falls back to this.
var English = map[string]string{
	"sign_in_title":     "Sign in",
	"sign_in":           "Sign in",
	"sign_up_title":     "Create your account",
	"sign_up":           "Create account",
	"mfa_title":         "Two-step verification",
	"mfa_intro":         "Enter the code from your authenticator app, or have one sent to you.",
	"mfa_method":        "Verification method",
	"mfa_recovery":      "A recovery code",
	"mfa_send":          "Send me a code",
	"mfa_sent":          "A code is on its way to {destination}.",
	"verify":            "Verify",
	"code":              "Code",
	"email":             "Email",
	"password":          "Password",
	"new_password":      "New password",
	"password_hint":     "At least {min} characters.",
	"forgot_link":       "Forgot your password?",
	"no_account":        "No account yet?",
	"have_account":      "Already have an account?",
	"check_email_title": "Check your email",
	"check_email":       "If the address can be registered, we sent a message to it. Open the link in it, or paste its code below.",
	"resend_title":      "Did not get it?",
	"resend":            "Send it again",
	"resent":            "If the address is registered and not yet verified, a new message is on its way.",
	"verify_title":      "Verify your email",
	"verify_intro":      "Paste the code from the message we sent you.",
	"verified_title":    "Email verified",
	"verified":          "Your email address is verified. You can sign in now.",
	"forgot_title":      "Reset your password",
	"forgot_intro":      "Enter your email and we will send you a link to choose a new password.",
	"forgot_send":       "Send the link",
	"forgot_sent":       "If an account exists for that address, a message with a reset link is on its way.",
	"reset_title":       "Choose a new password",
	"reset_code":        "Code from the email",
	"reset":             "Change password",
	"reset_done_title":  "Password changed",
	"reset_done":        "Your password is changed and every session is signed out. Sign in with the new password.",
	"sign_out_title":    "Sign out",
	"sign_out_intro":    "Sign out of this browser?",
	"sign_out":          "Sign out",
	"consent_title":     "Authorize access",
	"consent_intro":     "{client} wants to access your account. It will be able to:",
	"consent_redirect":  "You will be sent back to {uri}.",
	"approve":           "Allow",
	"deny":              "Deny",
	"device_title":      "Connect a device",
	"device_intro":      "Enter the code shown on your device.",
	"device_code":       "Device code",
	"continue":          "Continue",
	"device_ask":        "{client} on your device wants to access your account. It will be able to:",
	"device_approved":   "The device is connected. You can return to it now.",
	"device_denied":     "The device was not connected.",
	"back_to_sign_in":   "Back to sign in",
	"terms":             "Terms",
	"privacy":           "Privacy",
	"not_found_title":   "Page not found",
	"not_found":         "There is nothing at this address.",
	"error_title":       "Something went wrong",
	"error_summary":     "There is a problem",

	"error_generic":             "The request could not be completed. Try again.",
	"error_csrf":                "This form expired. Reload the page and try again.",
	"error_insecure":            "Signing in needs a secure (HTTPS) connection.",
	"error_origin":              "This form only works at {origin}. Open the page there and try again.",
	"error_rate_limited":        "Too many attempts. Wait {seconds} seconds and try again.",
	"error_invalid_credentials": "Incorrect email or password.",
	"error_email_unverified":    "Verify your email address before signing in.",
	"error_account_disabled":    "This account is disabled.",
	"error_invalid_token":       "This link or code is invalid or has expired.",
	"error_invalid_code":        "That code is not correct, or it expired.",
	"error_mfa_expired":         "The sign-in took too long. Sign in again.",
	"error_sentinel_blocked":    "The request was refused.",
	"error_challenge_required":  "Complete the challenge and try again.",
	"error_device_code":         "That code is unknown or has expired.",
	"error_request_expired":     "This authorization request is unknown or has expired. Start again from the application.",
	"error_required":            "Fill in every field.",
}

// errorKeys maps the error codes of the JSON routes to catalog keys.
var errorKeys = map[string]string{
	"invalid_credentials":           "error_invalid_credentials",
	"email_unverified":              "error_email_unverified",
	"account_disabled":              "error_account_disabled",
	"invalid_token":                 "error_invalid_token",
	"invalid_code":                  "error_invalid_code",
	"sentinel_blocked":              "error_sentinel_blocked",
	"sentinel_challenge_required":   "error_challenge_required",
	"passwordless_account_disabled": "error_account_disabled",
}

// catalogs merges English with the host's messages: locale (lower case) to a complete catalog.
func catalogs(host map[string]map[string]string) map[string]map[string]string {
	out := map[string]map[string]string{"en": English}
	for locale, msgs := range host {
		c := maps.Clone(English)
		maps.Copy(c, msgs)
		out[strings.ToLower(locale)] = c
	}
	return out
}

// negotiate picks the catalog for an Accept-Language header: the first listed locale (browsers
// list them by preference) the catalogs hold, exactly or by its base language; else English.
// ponytail: q-values are not sorted; add it if a client lists locales out of order.
func negotiate(cats map[string]map[string]string, header string) (string, map[string]string) {
	for part := range strings.SplitSeq(header, ",") {
		tag, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" || tag == "*" || strings.ReplaceAll(params, " ", "") == "q=0" {
			continue
		}
		if c, ok := cats[tag]; ok {
			return tag, c
		}
		base, _, _ := strings.Cut(tag, "-")
		if c, ok := cats[base]; ok {
			return base, c
		}
	}
	return "en", cats["en"]
}

// format replaces {name} placeholders.
func format(s string, args ...string) string {
	for i := 0; i+1 < len(args); i += 2 {
		s = strings.ReplaceAll(s, "{"+args[i]+"}", args[i+1])
	}
	return s
}
