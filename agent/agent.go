package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// The protocol's fixed values.
const (
	// DiscoveryPath is where the configuration document lives under the mount.
	DiscoveryPath = "/.well-known/agent-configuration"
	// TokenExchange is the RFC 8693 grant type of Token with a SubjectToken.
	TokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	// AccessTokenType is the RFC 8693 subject_token_type of a user's access token.
	AccessTokenType = "urn:ietf:params:oauth:token-type:access_token"
)

// The routes the SDK calls, under the mount.
const (
	pathRegister     = "/agents/register"
	pathEnroll       = "/agents/enroll"
	pathCapabilities = "/agents/capabilities"
	pathGrants       = "/agents/grants/request"
	pathSession      = "/agents/session"
	pathExecute      = "/agents/execute"
	pathJWKS         = "/auth/.well-known/jwks.json"
)

// maxBody caps what the SDK reads of an answer.
const maxBody = 10 << 20

// Agent is an agent of a Polaris server: it registers or enrols, asks for grants and waits for
// their approval, executes capabilities with signed request JWTs (or an access token), mints
// tokens and verifies receipts. It is immutable and safe for concurrent use: Register, Enroll and
// WithToken answer a new Agent.
type Agent struct {
	config       *Configuration
	client       *http.Client
	key          *Key
	id           string
	accessToken  string
	clientSecret string
	ttl          time.Duration
	waiter       waiter
	jwks         *jwksCache
}

type jwksCache struct {
	mu   sync.Mutex
	keys []JWK
}

// Option configures New.
type Option func(*Agent)

// WithKey is the agent's key: it signs the request JWTs and the private_key_jwt assertions.
func WithKey(k *Key) Option { return func(a *Agent) { a.key = k } }

// WithID is the id of an agent registered or enrolled before (a restarted agent).
func WithID(id string) Option { return func(a *Agent) { a.id = id } }

// WithClientSecret is the pcs_ secret of a client_secret agent, for Token.
func WithClientSecret(secret string) Option { return func(a *Agent) { a.clientSecret = secret } }

// WithHTTPClient sends every call through c (timeouts, proxies, tracing); http.DefaultClient
// otherwise.
func WithHTTPClient(c *http.Client) Option { return func(a *Agent) { a.client = c } }

// WithRequestTTL is how long a request JWT lives: 60 seconds by default, at most 300.
func WithRequestTTL(d time.Duration) Option { return func(a *Agent) { a.ttl = d } }

// New discovers the Polaris server at serverURL (where Polaris is mounted, or the discovery
// document's own URL) and answers an Agent for it.
func New(ctx context.Context, serverURL string, opts ...Option) (*Agent, error) {
	a, err := build(nil, opts)
	if err != nil {
		return nil, err
	}
	if a.config, err = discover(ctx, a.client, serverURL); err != nil {
		return nil, err
	}
	return a, nil
}

func build(config *Configuration, opts []Option) (*Agent, error) {
	a := &Agent{config: config, client: http.DefaultClient, ttl: DefaultRequestTTL, waiter: waiter{now: time.Now, sleep: sleepContext}, jwks: &jwksCache{}}
	for _, opt := range opts {
		opt(a)
	}
	if a.ttl < time.Second || a.ttl > MaxRequestTTL {
		return nil, fmt.Errorf("agent: WithRequestTTL(%s): must be between 1s and 300s", a.ttl)
	}
	if a.client == nil {
		a.client = http.DefaultClient
	}
	return a, nil
}

// Discover reads the discovery document at serverURL (the mount, or the document's own URL) with
// c (http.DefaultClient when nil).
func Discover(ctx context.Context, serverURL string, c *http.Client) (*Configuration, error) {
	if c == nil {
		c = http.DefaultClient
	}
	return discover(ctx, c, serverURL)
}

func discover(ctx context.Context, c *http.Client, serverURL string) (*Configuration, error) {
	u, err := url.Parse(serverURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("agent: server URL %q: give the absolute http(s) URL Polaris is mounted at, such as https://app.example.com/auth", serverURL)
	}
	doc := strings.TrimRight(serverURL, "/")
	if !strings.HasSuffix(doc, DiscoveryPath) {
		doc += DiscoveryPath
	}
	var raw struct {
		Configuration
		Endpoints map[string]any `json:"endpoints"`
	}
	if err := send(ctx, c, http.MethodGet, doc, nil, "", nil, &raw); err != nil {
		return nil, err
	}
	config := raw.Configuration
	config.Endpoints = map[string]string{}
	for name, v := range raw.Endpoints {
		if s, ok := v.(string); ok {
			config.Endpoints[name] = s
		}
	}
	execute := config.Endpoints["execute"]
	if config.TokenEndpoint == "" || !strings.HasSuffix(execute, pathExecute) {
		return nil, fmt.Errorf("%w: %s", ErrNotConfiguration, doc)
	}
	config.Mount = strings.TrimSuffix(execute, pathExecute)
	return &config, nil
}

// Configuration is the server's discovery document.
func (a *Agent) Configuration() *Configuration { return a.config }

// ID is the agent's id; empty before it is registered or enrolled.
func (a *Agent) ID() string { return a.id }

// WithToken is the same agent sending accessToken (from Token) instead of request JWTs.
func (a *Agent) WithToken(accessToken string) *Agent {
	c := *a
	c.accessToken = accessToken
	return &c
}

// Register registers the agent through its owner (ownerToken: the owner's access token) with
// POST /agents/register. It answers the registered agent, ready to call, and its record (with
// the client secret once, and the approval its pending grants wait for).
func (a *Agent) Register(ctx context.Context, ownerToken string, r Registration) (*Agent, *Registered, error) {
	return a.registerAt(ctx, pathRegister, ownerToken, r)
}

// Enroll enrols the agent through a host (enrollmentToken: the host's peh_ token) with
// POST /agents/enroll, under the host's owner with its default capabilities. Only Name, Mode and
// Auth of r are sent.
func (a *Agent) Enroll(ctx context.Context, enrollmentToken string, r Registration) (*Agent, *Registered, error) {
	return a.registerAt(ctx, pathEnroll, enrollmentToken, Registration{Name: r.Name, Mode: r.Mode, Auth: r.Auth})
}

func (a *Agent) registerAt(ctx context.Context, path, bearer string, r Registration) (*Agent, *Registered, error) {
	body := struct {
		Name           string              `json:"name"`
		Mode           Mode                `json:"mode"`
		OrganizationID string              `json:"organization_id,omitempty"`
		Capabilities   []CapabilityRequest `json:"capabilities,omitempty"`
		Auth           Auth                `json:"auth"`
		JWK            *JWK                `json:"jwk,omitempty"`
	}{Name: r.Name, Mode: r.Mode, OrganizationID: r.OrganizationID, Capabilities: r.Capabilities, Auth: r.Auth}
	if body.Auth == "" {
		body.Auth = ClientSecret
		if a.key != nil {
			body.Auth = PrivateKeyJWT
		}
	}
	if body.Auth == PrivateKeyJWT {
		if a.key == nil {
			return nil, nil, fmt.Errorf("agent: private_key_jwt needs a key: %w", ErrNoCredential)
		}
		jwk := a.key.PublicJWK()
		body.JWK = &jwk
	}
	var answer struct {
		Data Registered `json:"data"`
	}
	if err := a.post(ctx, path, body, "Bearer "+bearer, nil, &answer); err != nil {
		return nil, nil, err
	}
	bound := *a
	bound.id = answer.Data.ID
	if answer.Data.ClientSecret != "" {
		bound.clientSecret = answer.Data.ClientSecret
	}
	return &bound, &answer.Data, nil
}

// RequestGrants asks for capability grants with POST /agents/grants/request: what the policy
// approves is active at once, the rest waits in the result's Approval (see WaitForApproval).
func (a *Agent) RequestGrants(ctx context.Context, r GrantRequest) (*GrantResult, error) {
	if r.Capabilities == nil {
		r.Capabilities = []CapabilityRequest{}
	}
	var out GrantResult
	if err := a.post(ctx, pathGrants, r, "", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// WaitForApproval polls the agent's session every approval.Interval seconds until the approval's
// grants are active, and answers them. It fails with ErrApprovalDenied, ErrApprovalExpired, the
// context's error, or the poll's refusal; a 429 or slow_down slows the polling by SlowDown.
func (a *Agent) WaitForApproval(ctx context.Context, approval Approval) ([]Grant, error) {
	return a.waiter.wait(ctx, approval, func(ctx context.Context) ([]Grant, error) {
		s, err := a.Session(ctx)
		if err != nil {
			return nil, err
		}
		return s.Grants, nil
	}, 0)
}

// Execute runs a capability with POST /agents/execute: arguments (any JSON-encodable value; nil
// sends {}) checked against the capability's schema and the grant's constraints, the budget
// spent, a receipt appended. only, when given, restricts the request JWT to those capabilities.
// Decode Result.Data into the handler's result type.
func (a *Agent) Execute(ctx context.Context, capability string, arguments any, only ...string) (*Result, error) {
	args, err := json.Marshal(arguments)
	if err != nil {
		return nil, fmt.Errorf("agent: encode the arguments of %s: %w", capability, err)
	}
	if string(args) == "null" {
		args = []byte("{}")
	}
	body := struct {
		Capability string          `json:"capability"`
		Arguments  json.RawMessage `json:"arguments"`
	}{capability, args}
	var out Result
	if err := a.post(ctx, pathExecute, body, "", only, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Session is GET /agents/session: the agent, its owner, its host and its grants with their
// remaining budgets.
func (a *Agent) Session(ctx context.Context) (*Session, error) {
	u := a.config.Mount + pathSession
	auth, err := a.credential(http.MethodGet, u, nil, nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Data Session `json:"data"`
	}
	if err := send(ctx, a.client, http.MethodGet, u, nil, "", header(auth), &out); err != nil {
		return nil, err
	}
	return &out.Data, nil
}

// Capabilities lists the server's capabilities (GET /agents/capabilities), with GrantStatus when
// the agent can authenticate.
func (a *Agent) Capabilities(ctx context.Context) ([]Capability, error) {
	u := a.config.Mount + pathCapabilities
	var h http.Header
	if a.id != "" && (a.key != nil || a.accessToken != "") {
		auth, err := a.credential(http.MethodGet, u, nil, nil)
		if err != nil {
			return nil, err
		}
		h = header(auth)
	}
	var out struct {
		Data struct {
			Capabilities []Capability `json:"capabilities"`
		} `json:"data"`
	}
	if err := send(ctx, a.client, http.MethodGet, u, nil, "", h, &out); err != nil {
		return nil, err
	}
	if out.Data.Capabilities == nil {
		return []Capability{}, nil
	}
	return out.Data.Capabilities, nil
}

// Token mints an access token at the token endpoint: client credentials for an autonomous
// agent, or with r.SubjectToken the RFC 8693 exchange of a user's token for a delegated one. The
// agent authenticates with a private_key_jwt assertion signed by its key, else its client secret
// (HTTP Basic), else as a public client (client_id).
func (a *Agent) Token(ctx context.Context, r TokenRequest) (*Token, error) {
	if a.id == "" {
		return nil, ErrNotRegistered
	}
	endpoint := a.config.TokenEndpoint
	form := url.Values{}
	h := http.Header{}
	switch {
	case a.key != nil:
		assertion, err := signAssertion(a.key, a.id, endpoint, a.waiter.now())
		if err != nil {
			return nil, err
		}
		form.Set("client_assertion_type", AssertionType)
		form.Set("client_assertion", assertion)
	case a.clientSecret != "":
		h.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(a.id+":"+a.clientSecret)))
	default:
		form.Set("client_id", a.id)
	}
	if r.SubjectToken != "" {
		form.Set("grant_type", TokenExchange)
		form.Set("subject_token", r.SubjectToken)
		form.Set("subject_token_type", AccessTokenType)
	} else {
		form.Set("grant_type", "client_credentials")
	}
	for name, v := range map[string]string{"scope": r.Scope, "resource": r.Resource, "audience": r.Audience} {
		if v != "" {
			form.Set(name, v)
		}
	}
	var out Token
	if err := send(ctx, a.client, http.MethodPost, endpoint, []byte(form.Encode()), "application/x-www-form-urlencoded", h, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyReceipt verifies a receipt locally against the server's JWKS (fetched once per Agent and
// the Agents derived from it), and its link to previous when given. The error is only the JWKS
// fetch's.
func (a *Agent) VerifyReceipt(ctx context.Context, r Receipt, previous *Receipt) (Verification, error) {
	keys, err := a.serverKeys(ctx)
	if err != nil {
		return Verification{}, err
	}
	return VerifyReceipt(r, keys, previous), nil
}

func (a *Agent) serverKeys(ctx context.Context) ([]JWK, error) {
	a.jwks.mu.Lock()
	defer a.jwks.mu.Unlock()
	if a.jwks.keys != nil {
		return a.jwks.keys, nil
	}
	var set struct {
		Keys []JWK `json:"keys"`
	}
	if err := send(ctx, a.client, http.MethodGet, a.config.Mount+pathJWKS, nil, "", nil, &set); err != nil {
		return nil, err
	}
	if set.Keys == nil {
		set.Keys = []JWK{}
	}
	a.jwks.keys = set.Keys
	return set.Keys, nil
}

// Do sends req as the agent: it signs a request JWT for req's exact URL, method and body (or sets
// the access token) and sends it with the Agent's HTTP client. Use it for a capability with a
// Location (its response carries the receipt id in X-Polaris-Receipt) or any other route that
// authenticates agents. Like http.Client.Do, it consumes req.Body and a non-2xx status is no
// error; req's headers are left as they were.
func (a *Agent) Do(req *http.Request) (*http.Response, error) {
	var body []byte
	out := req.Clone(req.Context())
	if req.Body != nil && req.Body != http.NoBody {
		var err error
		body, err = io.ReadAll(req.Body)
		_ = req.Body.Close() // read fully; a close error changes nothing
		if err != nil {
			return nil, fmt.Errorf("agent: read the request body: %w", err)
		}
		out.Body = io.NopCloser(bytes.NewReader(body))
		out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
		out.ContentLength = int64(len(body))
	}
	auth, err := a.credential(req.Method, req.URL.String(), body, nil)
	if err != nil {
		return nil, err
	}
	out.Header.Set("Authorization", auth)
	return a.client.Do(out)
}

// post sends body as JSON to the route, authorized by bearer or else the agent's credential for
// the exact bytes sent.
func (a *Agent) post(ctx context.Context, path string, body any, bearer string, only []string, out any) error {
	u := a.config.Mount + path
	encoded, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("agent: encode %s: %w", path, err)
	}
	if bearer == "" {
		if bearer, err = a.credential(http.MethodPost, u, encoded, only); err != nil {
			return err
		}
	}
	return send(ctx, a.client, http.MethodPost, u, encoded, "application/json", header(bearer), out)
}

// credential is the Authorization value of a call: the access token when the agent has one, else
// a request JWT for its exact URL and body.
func (a *Agent) credential(method, u string, body []byte, only []string) (string, error) {
	if a.accessToken != "" {
		return "Bearer " + a.accessToken, nil
	}
	if a.key == nil {
		return "", ErrNoCredential
	}
	if a.id == "" {
		return "", ErrNotRegistered
	}
	jwt, err := signRequest(a.key, a.id, method, u, body, only, a.ttl, a.waiter.now())
	if err != nil {
		return "", err
	}
	return "Bearer " + jwt, nil
}

func header(authorization string) http.Header {
	return http.Header{"Authorization": {authorization}}
}

// send makes one call: the body sent exactly as given (the request JWT hashes those bytes), the
// JSON answer decoded into out, a non-2xx answer returned as an *Error.
func send(ctx context.Context, c *http.Client, method, u string, body []byte, contentType string, h http.Header, out any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return fmt.Errorf("agent: %s %s: %w", method, u, err)
	}
	for name, values := range h {
		req.Header[name] = values
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("agent: %s %s: %w", method, u, err)
	}
	defer resp.Body.Close()
	text, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("agent: %s %s: read the answer: %w", method, u, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return refusal(method, u, resp.StatusCode, text)
	}
	if err := json.Unmarshal(text, out); err != nil {
		return &Error{Status: resp.StatusCode, Code: "request_failed", msg: fmt.Sprintf("agent: %s %s did not answer JSON: %v", method, u, err)}
	}
	return nil
}
