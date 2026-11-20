package social

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// provider is one configured provider: its definition (discovered at first use for an Issuer),
// its client credentials, and Apple's and GitHub's protocol differences.
type provider struct {
	id       string
	def      Definition
	discover *discovery // an Issuer-configured provider: def comes from discovery
	clientID string
	secret   string
	out      *outbound

	apple         *ecdsa.PrivateKey // Apple: the client secret is a JWT signed with the team key
	teamID, keyID string
	github        bool // GitHub: the verified primary email comes from /user/emails
}

// tokens is what a token endpoint answered.
type tokens struct {
	access    string
	refresh   string // "" when none came
	expiresIn *int
	scopes    []string
	idToken   string
	raw       map[string]any
}

const appleSecretTTL = time.Hour

var scopeSplit = regexp.MustCompile(`[\s,]+`)

// resolved returns the provider with its definition, discovering it for an Issuer.
func (p *provider) resolved(ctx context.Context) (*provider, error) {
	if p.discover == nil {
		return p, nil
	}
	def, err := p.discover.definition(ctx, p.out)
	if err != nil {
		return nil, err
	}
	cp := *p
	cp.def, cp.discover = def, nil
	if cp.def.Name == "" {
		cp.def.Name = p.id
	}
	return &cp, nil
}

// authorizationURL is where the browser goes: upstream's parameters in upstream's order.
func (p *provider) authorizationURL(callback, state string, scopes []string, challenge, nonce string) string {
	if len(scopes) == 0 {
		scopes = p.def.Scopes
	}
	sep := p.def.ScopeSeparator
	if sep == "" {
		sep = " "
	}
	q := query{{p.clientIDParam(), p.clientID}, {"redirect_uri", callback}, {"response_type", "code"}, {"scope", strings.Join(scopes, sep)}, {"state", state}}
	for _, k := range slices.Sorted(maps.Keys(p.def.AuthorizationParams)) {
		q = q.set(k, p.def.AuthorizationParams.Get(k))
	}
	if challenge != "" {
		q = append(q, [2]string{"code_challenge", challenge}, [2]string{"code_challenge_method", "S256"})
	}
	if p.def.oidc() {
		q = append(q, [2]string{"nonce", nonce})
	}
	if p.def.FormPost {
		q = append(q, [2]string{"response_mode", "form_post"})
	}
	return appendQuery(p.def.AuthorizationURL, q.encode())
}

func (p *provider) clientIDParam() string {
	if p.def.ClientIDParam == "" {
		return "client_id"
	}
	return p.def.ClientIDParam
}

// exchange trades the authorization code for tokens.
func (p *provider) exchange(ctx context.Context, code, redirectURI, verifier string) (tokens, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	return p.tokenRequest(ctx, form)
}

// refresh trades a refresh token for new tokens.
func (p *provider) refresh(ctx context.Context, refreshToken string) (tokens, error) {
	return p.tokenRequest(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}})
}

func (p *provider) tokenRequest(ctx context.Context, form url.Values) (tokens, error) {
	header := http.Header{}
	form.Set(p.clientIDParam(), p.clientID)
	switch {
	case p.apple != nil:
		secret, err := p.appleSecret()
		if err != nil {
			return tokens{}, err
		}
		form.Set("client_id", p.clientID)
		form.Set("client_secret", secret)
	case p.def.BasicAuth:
		header.Set("Authorization", "Basic "+basic(p.clientID, p.secret))
	case p.secret != "":
		form.Set("client_secret", p.secret)
	}
	if ua, ok := p.def.UserinfoHeaders["User-Agent"]; ok {
		header.Set("User-Agent", ua)
	}
	body, err := p.out.postForm(ctx, p.def.TokenURL, form, header)
	if err != nil {
		return tokens{}, err
	}
	return tokensOf(body)
}

// appleSecret is Apple's client secret: an ES256 JWT from the team, valid an hour.
func (p *provider) appleSecret() (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: p.apple},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", p.keyID))
	if err != nil {
		return "", err
	}
	now := p.out.clock.Now().Unix()
	claims, err := json.Marshal(map[string]any{"iss": p.teamID, "iat": now, "exp": now + int64(appleSecretTTL/time.Second), "aud": "https://appleid.apple.com", "sub": p.clientID})
	if err != nil {
		return "", err
	}
	signed, err := signer.Sign(claims)
	if err != nil {
		return "", err
	}
	return signed.CompactSerialize()
}

func tokensOf(body any) (tokens, error) {
	m, _ := body.(map[string]any)
	access, _ := m["access_token"].(string)
	if access == "" {
		return tokens{}, refuse(kindProviderError, "the token endpoint answered no access token")
	}
	t := tokens{access: access, scopes: []string{}, raw: m}
	t.refresh, _ = m["refresh_token"].(string)
	t.idToken, _ = m["id_token"].(string)
	switch s := m["scope"].(type) {
	case string:
		for _, scope := range scopeSplit.Split(s, -1) {
			if scope != "" {
				t.scopes = append(t.scopes, scope)
			}
		}
	case []any:
		for _, v := range s {
			if scope, ok := v.(string); ok {
				t.scopes = append(t.scopes, scope)
			}
		}
	}
	switch e := m["expires_in"].(type) {
	case json.Number:
		if n, err := strconv.Atoi(e.String()); err == nil {
			t.expiresIn = &n
		}
	case string:
		if e != "" {
			n, _ := strconv.Atoi(strings.TrimSpace(e))
			t.expiresIn = &n
		}
	}
	return t, nil
}

// profile reads who signed in: the id_token verified (OpenID Connect), merged under the userinfo
// document or the token response; Apple's name from the first callback; GitHub's verified email.
func (p *provider) profile(ctx context.Context, t tokens, nonce string, callback map[string]any) (Profile, error) {
	prof, err := p.baseProfile(ctx, t, nonce)
	if err != nil {
		return Profile{}, err
	}
	switch {
	case p.apple != nil:
		if name := appleName(callback["user"]); name != "" {
			prof.Name = name
		}
	case p.github:
		if email := p.githubEmail(ctx, t.access); email != "" {
			prof.Email, prof.EmailVerified = email, true
		}
	}
	return prof, nil
}

func (p *provider) baseProfile(ctx context.Context, t tokens, nonce string) (Profile, error) {
	claims := map[string]any{}
	if p.def.oidc() && t.idToken != "" {
		var err error
		if claims, err = p.out.verifyIDToken(ctx, p.def, p.clientID, t.idToken, &nonce); err != nil {
			return Profile{}, err
		}
	}
	if p.def.ProfileInTokenResponse {
		return p.def.Profile(merge(claims, t.raw)), nil
	}
	if p.def.UserinfoURL == "" {
		if len(claims) == 0 {
			return Profile{}, refuse(kindProviderError, "the provider answered no id_token")
		}
		return p.def.Profile(claims), nil
	}
	method := http.MethodGet
	if p.def.UserinfoPOST {
		method = http.MethodPost
	}
	userinfo, err := p.out.getJSON(ctx, method, p.def.UserinfoURL, t.access, p.def.UserinfoHeaders)
	if err != nil {
		return Profile{}, err
	}
	info, _ := userinfo.(map[string]any)
	return p.def.Profile(merge(claims, info)), nil
}

// verifyIDToken checks an id_token the client obtained itself (Google One Tap); nonce nil skips
// the nonce check.
func (p *provider) verifyIDToken(ctx context.Context, idToken string, nonce *string) (Profile, error) {
	if p.apple != nil && idToken == "" {
		return Profile{}, refuse(kindInvalidInput, "id_token is required.")
	}
	if !p.def.oidc() {
		return Profile{}, refuse(kindInvalidInput, "This provider does not issue id_tokens.")
	}
	claims, err := p.out.verifyIDToken(ctx, p.def, p.clientID, idToken, nonce)
	if err != nil {
		return Profile{}, err
	}
	return p.def.Profile(claims), nil
}

// appleName is the name Apple's form_post carries in user on the first sign-in only.
func appleName(user any) string {
	if s, ok := user.(string); ok {
		var decoded any
		if json.Unmarshal([]byte(s), &decoded) != nil {
			return ""
		}
		user = decoded
	}
	name, _ := at(user, "name").(map[string]any)
	if name == nil {
		return ""
	}
	return strings.TrimSpace(str(name["firstName"]) + " " + str(name["lastName"]))
}

const githubEmails = "https://api.github.com/user/emails"

// githubEmail is the verified primary address, else the first verified one ("" when none).
func (p *provider) githubEmail(ctx context.Context, access string) string {
	list, err := p.out.getJSON(ctx, http.MethodGet, githubEmails, access, p.def.UserinfoHeaders)
	if err != nil {
		return ""
	}
	entries, _ := list.([]any)
	chosen := ""
	for _, e := range entries {
		email, _ := at(e, "email").(string)
		if at(e, "verified") != true || email == "" {
			continue
		}
		if at(e, "primary") == true {
			return email
		}
		if chosen == "" {
			chosen = email
		}
	}
	return chosen
}

func merge(base, over map[string]any) map[string]any {
	out := maps.Clone(base)
	if out == nil {
		out = map[string]any{}
	}
	maps.Copy(out, over)
	return out
}

// query is an ordered query string.
type query [][2]string

// set replaces k in place, or appends it.
func (q query) set(k, v string) query {
	for i := range q {
		if q[i][0] == k {
			q[i][1] = v
			return q
		}
	}
	return append(q, [2]string{k, v})
}

// encode is PHP's http_build_query with PHP_QUERY_RFC3986.
func (q query) encode() string {
	parts := make([]string, len(q))
	for i, kv := range q {
		parts[i] = rawURLEncode(kv[0]) + "=" + rawURLEncode(kv[1])
	}
	return strings.Join(parts, "&")
}

// rawURLEncode is PHP's rawurlencode: everything but A-Za-z0-9-_.~ escaped, space as %20.
func rawURLEncode(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }

func appendQuery(base, encoded string) string {
	if strings.Contains(base, "?") {
		return base + "&" + encoded
	}
	return base + "?" + encoded
}
