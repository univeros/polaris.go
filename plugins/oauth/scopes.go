package oauth

import (
	"fmt"
	"github.com/univeros/polaris.go/wiring"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/token"
)

// The OpenID scopes; every other scope is a permission name or one of Config.Scopes.
const (
	ScopeOpenID        = "openid"
	ScopeProfile       = "profile"
	ScopeEmail         = "email"
	ScopeOfflineAccess = "offline_access"
)

var whitespace = regexp.MustCompile(`\s+`)

// scopes is the vocabulary: the OpenID scopes, the permission catalog, the host's extras, in that
// order (a later description of a known name replaces the earlier one and keeps its position).
type scopes struct {
	names       []string
	description map[string]string
	permission  map[string]bool
}

func newScopes(catalog wiring.Catalog, extra map[string]string) *scopes {
	s := &scopes{description: map[string]string{}, permission: map[string]bool{}}
	add := func(name, description string) {
		if _, ok := s.description[name]; !ok {
			s.names = append(s.names, name)
		}
		s.description[name] = description
	}
	add(ScopeOpenID, "Sign in with OpenID Connect (an ID token)")
	add(ScopeProfile, "Your name")
	add(ScopeEmail, "Your email address and whether it is verified")
	add(ScopeOfflineAccess, "Access while you are away (a refresh token)")
	for _, p := range catalog.Permissions() {
		add(p.Key, p.Description)
		s.permission[p.Key] = true
	}
	for _, name := range slices.Sorted(maps.Keys(extra)) {
		add(name, extra[name])
	}
	return s
}

func (s *scopes) known(name string) bool { _, ok := s.description[name]; return ok }

// parse reads a scope parameter: every name known and, when the client lists scopes, allowed to it.
// An empty parameter is no scope.
func (s *scopes) parse(scope string, c *Client) ([]string, error) {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return []string{}, nil
	}
	out := []string{}
	for _, name := range whitespace.Split(scope, -1) {
		if !s.known(name) {
			return nil, refusal(CodeInvalidScope, fmt.Sprintf("Unknown scope \"%s\".", name))
		}
		if c != nil && len(c.Scopes) > 0 && !slices.Contains(c.Scopes, name) {
			return nil, refusal(CodeInvalidScope, fmt.Sprintf("The client may not ask for \"%s\".", name))
		}
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out, nil
}

// permissions are the permission names among sc: what a token may do on Polaris routes.
func (s *scopes) permissions(sc []string) []string {
	out := []string{}
	for _, name := range sc {
		if s.permission[name] {
			out = append(out, name)
		}
	}
	return out
}

// described is the scope list a consent screen or a device page shows.
func (s *scopes) described(sc []string) []map[string]any {
	out := []map[string]any{}
	for _, name := range sc {
		d, ok := s.description[name]
		if !ok {
			d = name
		}
		out = append(out, map[string]any{"name": name, "description": d})
	}
	return out
}

// within keeps a refresh or an exchange inside what was granted: it narrows, never widens.
func within(requested, granted []string) ([]string, error) {
	for _, name := range requested {
		if !slices.Contains(granted, name) {
			return nil, refusal(CodeInvalidScope, fmt.Sprintf("\"%s\" is beyond what was granted.", name))
		}
	}
	return requested, nil
}

// words splits a space-separated parameter; nil when it is blank.
func words(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	return whitespace.Split(v, -1)
}

// openIDClaims are the claims sc allows about u, in the fixed order the ID token and userinfo
// responses list them.
func openIDClaims(u model.User, sc []string) token.Claims {
	c := token.Claims{}
	if slices.Contains(sc, ScopeEmail) {
		c = c.With("email", u.Email).With("email_verified", u.EmailVerifiedAt != nil)
	}
	if slices.Contains(sc, ScopeProfile) {
		var name any
		if u.DisplayName != nil {
			name = *u.DisplayName
		}
		c = c.With("name", name).With("updated_at", u.UpdatedAt.Unix())
	}
	return c
}
