// Package strutil holds the two string rules core applies in several places and must apply
// identically: the edge trim of input and stored values, and RFC 3986 percent-encoding.
package strutil

import (
	"net/url"
	"strings"
)

// trimSet is space, tab, LF, CR, NUL and vertical tab.
const trimSet = " \t\n\r\x00\x0B"

// Trim strips space, tab, LF, CR, NUL and vertical tab from both ends of s. It is not
// strings.TrimSpace, which also strips form feed and Unicode spaces: emails, names and secrets
// trimmed by earlier releases were stored with this set, and a lookup must trim the same way to
// find them.
func Trim(s string) string { return strings.Trim(s, trimSet) }

// PercentEncode percent-encodes every byte of s but the RFC 3986 unreserved characters
// A-Z a-z 0-9 - _ . ~, with upper-case hex; a space is %20, not +.
func PercentEncode(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}
