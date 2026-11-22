package manifest

import (
	"regexp"
	"strings"
)

// IsEmail reports whether s is an email address by Polaris's email rule, the one the "email" input
// rule and account creation apply. An address is ASCII only, at most 320 bytes, and:
//
//   - a local part of dot-separated atoms (RFC 5322 atext) or quoted strings (ASCII but NUL, tab, CR,
//     LF, space, quote and backslash, or a backslash escaping any ASCII character), at most 64 units;
//   - an "@";
//   - a domain that is a host name of at least two dot-separated labels (letters, digits and inner
//     hyphens, at most 63 characters each, an optional xn-- prefix; the last label starts with a
//     letter or is an xn-- label), or a bracketed literal: IPv4 (no leading zeros), or IPv6 (full,
//     compressed or IPv4-mapped) after an "IPv6:" tag;
//   - at most 254 units in all, where a unit is one character, one escaped character, or either
//     of those with the quotes around it.
//
// Letters match in any case. Nothing is trimmed. The accepted set is a contract and does not change:
// testdata/manifest/email.tsv and TestEmailRuleEdgeCases pin it.
func IsEmail(s string) bool {
	if len(s) > 320 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 { // ASCII only
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

// isAddressLiteral matches the bracketed domain forms. A compressed IPv6 literal holds at most six
// groups (fewer than seven hex digits followed by ":" or the closing bracket), a compressed
// IPv4-mapped one at most four (fewer than five hex digits followed by ":").
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

// hasLongLabel reports a host-name label of 64 characters or more.
func hasLongLabel(host string) bool {
	for _, label := range strings.Split(host, ".") {
		if len(label) >= 64 {
			return true
		}
	}
	return false
}

// unitBounds checks the two length limits in units (see IsEmail): no reading of s as a run of
// units reaches 255, and none of 65 or more ends right before an "@". It tracks every position a
// run of k units can reach.
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
