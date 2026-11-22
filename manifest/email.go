package manifest

import (
	"regexp"
	"strings"
)

// IsEmail reports whether s is an email address by the rules the "email" input rule has always
// applied (clients and stored addresses depend on the exact set): at most 320 bytes, ASCII only, an RFC 5321 local part (dot-atoms or quoted strings) of at most 64 units, a
// whole address of at most 254 units, and a domain that is a dotted host name (labels of at most
// 63 characters, a top-level label starting with a letter, or an xn-- label) or a bracketed IPv4,
// IPv6 or IPv6-mapped IPv4 literal.
//
// The rules are one PCRE pattern with lookaheads; RE2 has none, so the lookaheads are checked by
// hand around the same alternatives, case-insensitively like the pattern's /i.
func IsEmail(s string) bool {
	if len(s) > 320 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 { // no part of the pattern accepts a byte above 0x7F
			return false
		}
	}
	if !unitBounds(s) {
		return false
	}
	at := strings.LastIndexByte(s, '@') // neither domain form contains "@"
	if at < 0 || !emailLocal.MatchString(s[:at]) {
		return false
	}
	domain := s[at+1:]
	if emailHost.MatchString(domain) {
		return !hasLongLabel(domain)
	}
	if len(domain) < 2 || domain[0] != '[' || domain[len(domain)-1] != ']' {
		return false
	}
	return isAddressLiteral(domain[1 : len(domain)-1])
}

const (
	atom   = "[\\x21\\x23-\\x27\\x2A\\x2B\\x2D\\x2F-\\x39\\x3D\\x3F\\x5E-\\x7E]+"
	quoted = "\\x22(?:[\\x01-\\x08\\x0B\\x0C\\x0E-\\x1F\\x21\\x23-\\x5B\\x5D-\\x7F]|\\x5C[\\x00-\\x7F])*\\x22"
	word   = "(?:" + atom + "|" + quoted + ")"
	octet  = "(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
	ipv4   = octet + "(?:\\." + octet + "){3}"
	hex4   = "[a-f0-9]{1,4}"
)

var (
	emailLocal = regexp.MustCompile(`(?i)\A` + word + `(?:\.` + word + `)*\z`)
	// (?:label\.){1,126} repeated {1,} is one or more labels.
	emailHost   = regexp.MustCompile(`(?i)\A(?:(?:xn--)?[a-z0-9]+(?:-+[a-z0-9]+)*\.)+(?:[a-z][a-z0-9]*|xn--[a-z0-9]+)(?:-+[a-z0-9]+)*\z`)
	ipv6Full    = regexp.MustCompile(`(?i)\AIPv6:` + hex4 + `(?::` + hex4 + `){7}\z`)
	ipv6Comp    = regexp.MustCompile(`(?i)\AIPv6:(?:` + hex4 + `(?::` + hex4 + `){0,5})?::(?:` + hex4 + `(?::` + hex4 + `){0,5})?\z`)
	ipv4Plain   = regexp.MustCompile(`\A` + ipv4 + `\z`)
	ipv4v6Full  = regexp.MustCompile(`(?i)\AIPv6:` + hex4 + `(?::` + hex4 + `){5}:` + ipv4 + `\z`)
	ipv4v6Comp  = regexp.MustCompile(`(?i)\AIPv6:(?:` + hex4 + `(?::` + hex4 + `){0,3})?::(?:` + hex4 + `(?::` + hex4 + `){0,3}:)?` + ipv4 + `\z`)
	hexThenStop = regexp.MustCompile(`(?i)[a-f0-9][:\]]`)
	hexThenColn = regexp.MustCompile(`(?i)[a-f0-9]:`)
)

// isAddressLiteral matches the bracketed domain forms; the compressed IPv6 forms carry the
// lookaheads (?!(?:.*[a-f0-9][:\]]){7,}) and (?!(?:.*[a-f0-9]:){5,}), applied after "IPv6:".
func isAddressLiteral(literal string) bool {
	switch {
	case ipv6Full.MatchString(literal), ipv4Plain.MatchString(literal), ipv4v6Full.MatchString(literal):
		return true
	case ipv6Comp.MatchString(literal):
		return len(hexThenStop.FindAllString(literal[5:]+"]", -1)) < 7
	case ipv4v6Comp.MatchString(literal):
		return len(hexThenColn.FindAllString(literal[5:], -1)) < 5
	}
	return false
}

// hasLongLabel is the lookahead (?!.*[^.]{64,}) at the start of a host name: no run of 64 non-dots.
func hasLongLabel(host string) bool {
	for _, label := range strings.Split(host, ".") {
		if len(label) >= 64 {
			return true
		}
	}
	return false
}

// unitBounds checks the pattern's two leading lookaheads,
//
//	(?!(?:(?:\x22?\x5C[\x00-\x7E]\x22?)|(?:\x22?[^\x5C\x22]\x22?)){255,})
//	(?!(?:(?:\x22?\x5C[\x00-\x7E]\x22?)|(?:\x22?[^\x5C\x22]\x22?)){65,}@)
//
// by tracking every position a run of k units can reach: no run reaches 255 units, and no run of
// 65 or more units stops before an "@".
func unitBounds(s string) bool {
	reach := map[int]bool{0: true}
	for k := 0; len(reach) > 0; k++ {
		if k >= 255 {
			return false
		}
		next := map[int]bool{}
		for p := range reach {
			if k >= 65 && p < len(s) && s[p] == '@' {
				return false
			}
			for _, end := range unitEnds(s, p) {
				next[end] = true
			}
		}
		reach = next
	}
	return true
}

// unitEnds returns where one unit starting at p can end: an optional quote, an escaped character
// or any character but a backslash or quote, an optional quote.
func unitEnds(s string, p int) []int {
	var ends []int
	starts := []int{p}
	if p < len(s) && s[p] == '"' {
		starts = append(starts, p+1)
	}
	for _, q := range starts {
		var e int
		switch {
		case q < len(s) && s[q] == '\\':
			if q+1 >= len(s) || s[q+1] > 0x7E {
				continue
			}
			e = q + 2
		case q < len(s) && s[q] != '"':
			e = q + 1
		default:
			continue
		}
		ends = append(ends, e)
		if e < len(s) && s[e] == '"' {
			ends = append(ends, e+1)
		}
	}
	return ends
}
