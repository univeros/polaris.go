package agent_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/univeros/polaris-go/agent"
)

// fakePolaris stands in for a Polaris server with plugins/agents, mounted at /auth, for the
// examples: it verifies the request JWTs as the server does (EdDSA keys, sub, aud = the exact URL,
// htm, body_hash, lifetime, jti once), approves what policy allows, lets the owner approve the rest
// on the first poll, executes, and signs receipts with an RS256 key its JWKS publishes.
type fakePolaris struct {
	*httptest.Server
	mu       sync.Mutex
	signer   *rsa.PrivateKey
	keys     map[string]agent.JWK
	grants   []agent.Grant
	receipts []agent.Receipt
	jtis     map[string]bool
}

const enrollmentToken = "peh_demo"

func newFakePolaris() *fakePolaris {
	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	f := &fakePolaris{signer: signer, keys: map[string]agent.JWK{}, jtis: map[string]bool{}}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	return f
}

func (f *fakePolaris) mount() string { return f.URL + "/auth" }

func (f *fakePolaris) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	route := r.Method + " " + strings.TrimPrefix(r.URL.Path, "/auth")
	switch route {
	case "GET /.well-known/agent-configuration":
		reply(w, 200, map[string]any{"provider_name": "Polaris demo", "issuer": f.URL, "token_endpoint": f.mount() + "/oauth2/token",
			"endpoints": map[string]string{"execute": f.mount() + "/agents/execute", "token": f.mount() + "/oauth2/token"}})
		return
	case "GET /auth/.well-known/jwks.json":
		reply(w, 200, map[string]any{"keys": []agent.JWK{{Kty: "RSA", Alg: "RS256", Use: "sig", Kid: "server-key", N: b64(f.signer.N.Bytes()), E: b64(big.NewInt(int64(f.signer.E)).Bytes())}}})
		return
	case "POST /agents/enroll":
		f.enroll(w, r, body)
		return
	case "GET /agents/agent-1/receipts": // the owner's listing (its session check is left out here)
		reply(w, 200, map[string]any{"data": f.receipts})
		return
	}
	if err := f.authenticate(r, body); err != "" {
		reply(w, 401, map[string]any{"type": "https://polaris.univeros.io/problems/agents/invalid_jwt", "title": "Unauthorized", "status": 401, "detail": err, "error": "invalid_jwt"})
		return
	}
	switch route {
	case "POST /agents/grants/request":
		f.requestGrants(w, body)
	case "GET /agents/session":
		for i := range f.grants { // the owner approved while the agent waited
			f.grants[i].Status = "active"
		}
		reply(w, 200, map[string]any{"data": map[string]any{"authenticated_via": "jwt", "grants": f.grants}})
	case "POST /agents/execute":
		var in struct {
			Capability string         `json:"capability"`
			Arguments  map[string]any `json:"arguments"`
		}
		_ = json.Unmarshal(body, &in)
		f.execute(w, in.Capability, in.Arguments, func(receipt agent.Receipt) {
			reply(w, 200, map[string]any{"data": map[string]any{"echo": in.Arguments}, "receipt": map[string]any{"id": receipt.ID, "seq": receipt.Seq, "hash": receipt.Hash}})
		})
	case "POST /host/invite": // a capability with a location, behind the request middleware
		var args map[string]any
		_ = json.Unmarshal(body, &args)
		f.execute(w, "members.invite", args, func(receipt agent.Receipt) {
			w.Header().Set("X-Polaris-Receipt", receipt.ID)
			w.WriteHeader(http.StatusCreated)
		})
	default:
		reply(w, 404, map[string]any{"error": "not_found"})
	}
}

func (f *fakePolaris) enroll(w http.ResponseWriter, r *http.Request, body []byte) {
	var in struct {
		Name string    `json:"name"`
		Mode string    `json:"mode"`
		Auth string    `json:"auth"`
		JWK  agent.JWK `json:"jwk"`
	}
	if r.Header.Get("Authorization") != "Bearer "+enrollmentToken || json.Unmarshal(body, &in) != nil || in.JWK.Crv != "Ed25519" {
		reply(w, 401, map[string]any{"error": "unauthorized"})
		return
	}
	f.keys["agent-1"] = in.JWK
	now := time.Now().UTC().Format(time.RFC3339)
	reply(w, 201, map[string]any{"data": map[string]any{"id": "agent-1", "name": in.Name, "mode": in.Mode, "auth": in.Auth, "public_jwk": in.JWK,
		"status": "active", "created_at": now, "updated_at": now, "grants": []any{}, "approval": nil}})
}

func (f *fakePolaris) requestGrants(w http.ResponseWriter, body []byte) {
	var in struct {
		Capabilities []string `json:"capabilities"`
	}
	_ = json.Unmarshal(body, &in)
	approval := map[string]any{"id": "ap-1", "method": "device_authorization", "strength": "step_up", "user_code": "BTMR-XVSK",
		"verification_uri": "https://app.example.com/approve", "verification_uri_complete": "https://app.example.com/approve?user_code=BTMR-XVSK", "expires_in": 600, "interval": 1}
	for _, name := range in.Capabilities {
		g := agent.Grant{ID: "g-" + name, AgentID: "agent-1", Capability: name, Status: "active", ApprovedVia: "auto"}
		if name == "deploy.production" { // a high-risk capability waits for its owner
			g.Status, g.ApprovedVia, g.ApprovalID = "pending", "", "ap-1"
		}
		f.grants = append(f.grants, g)
	}
	var pending any
	for _, g := range f.grants {
		if g.Status == "pending" {
			pending = approval
		}
	}
	reply(w, 200, map[string]any{"agent_id": "agent-1", "agent_capability_grants": f.grants, "approval": pending})
}

func (f *fakePolaris) execute(w http.ResponseWriter, capability string, args map[string]any, answer func(agent.Receipt)) {
	var grant *agent.Grant
	for i := range f.grants {
		if f.grants[i].Capability == capability && f.grants[i].Status == "active" {
			grant = &f.grants[i]
		}
	}
	if grant == nil {
		reply(w, 403, map[string]any{"type": "https://polaris.univeros.io/problems/agents/capability_not_granted", "status": 403, "error": "capability_not_granted", "detail": capability + " is not granted"})
		return
	}
	in, _ := json.Marshal(args)
	sum := sha256.Sum256(in)
	r := agent.Receipt{ID: fmt.Sprintf("r-%d", len(f.receipts)+1), AgentID: "agent-1", Seq: len(f.receipts) + 1, GrantID: &grant.ID, Capability: &capability,
		InputHash: fmt.Sprintf("%x", sum), Outcome: "success", CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	if n := len(f.receipts); n > 0 {
		r.PrevHash = &f.receipts[n-1].Hash
	}
	r.Hash = agent.ReceiptHash(r)
	r.Signature = f.sign(map[string]any{"typ": agent.ReceiptType, "alg": "RS256", "kid": "server-key"},
		map[string]any{"iss": f.URL, "receipt_hash": r.Hash, "receipt_id": r.ID, "agent_id": r.AgentID, "seq": r.Seq})
	f.receipts = append(f.receipts, r)
	answer(r)
}

// authenticate checks the request JWT as the server's RequestJwt does; "" when it passes.
func (f *fakePolaris) authenticate(r *http.Request, body []byte) string {
	parts := strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), ".")
	if len(parts) != 3 {
		return "not a JWT"
	}
	var header struct{ Typ, Alg string }
	var c struct {
		Sub, Aud, Jti, Htm, Htu string
		Iat, Exp                int64
		BodyHash                string `json:"body_hash"`
	}
	if decode(parts[0], &header) != nil || decode(parts[1], &c) != nil || header.Typ != agent.RequestJWTType || header.Alg != "EdDSA" {
		return "typ must be agent+jwt"
	}
	jwk, ok := f.keys[c.Sub]
	x, _ := base64.RawURLEncoding.DecodeString(jwk.X)
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if !ok || len(x) != ed25519.PublicKeySize || !ed25519.Verify(x, []byte(parts[0]+"."+parts[1]), sig) {
		return "the signature does not verify with the agent's key"
	}
	called := "http://" + r.Host + r.URL.Path
	sum := sha256.Sum256(body)
	now := time.Now().Unix()
	switch {
	case c.Aud != called || c.Htu != called || c.Htm != r.Method:
		return "aud must be the exact URL called"
	case len(body) > 0 && c.BodyHash != b64(sum[:]):
		return "body_hash does not match the request body"
	case c.Exp <= c.Iat || c.Exp-c.Iat > 300 || c.Exp < now-60 || c.Iat > now+60:
		return "expired"
	case f.jtis[c.Jti]:
		return "the JWT was already used (jti)"
	}
	f.jtis[c.Jti] = true
	return ""
}

func (f *fakePolaris) sign(header, claims map[string]any) string {
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	input := b64(h) + "." + b64(c)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.signer, crypto.SHA256, digest[:])
	if err != nil {
		panic(err)
	}
	return input + "." + b64(sig)
}

// ownerReceipts is the agent's chain as its owner lists it, GET <mount>/agents/{id}/receipts.
func ownerReceipts(server *fakePolaris, agentID string) []agent.Receipt {
	resp, err := http.Get(server.mount() + "/agents/" + agentID + "/receipts")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	var out struct {
		Data []agent.Receipt `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		panic(err)
	}
	return out.Data
}

func reply(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func decode(seg string, out any) error {
	data, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
