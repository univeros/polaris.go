package agents_test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/agents"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/store"
)

// locatedCase is an agent of a host with a key that was granted the capability with a Location.
type locatedCase struct {
	*hostCase
	key *agentKey
	id  string
	// What the host's handler reads, and what it answers.
	read    []string
	calls   []agents.Call
	answers func(w http.ResponseWriter)
}

func (l *locatedCase) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	call, _ := agents.CallFrom(r.Context())
	l.calls = append(l.calls, call)
	l.read = append(l.read, fmt.Sprintf("%s %d %s", body, r.ContentLength, r.Header.Get("Content-Length")))
	l.answers(w)
}

func answersJSON(status int, body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func located(t *testing.T) *locatedCase {
	t.Helper()
	l := &locatedCase{hostCase: unrecorded(t), answers: answersJSON(200, `{"invited":true}`)}
	var resp *http.Response
	l.key, resp = l.registers(map[string]any{"capabilities": []any{map[string]any{"name": "invite", "constraints": map[string]any{"email": map[string]any{"not_in": []any{"mallory@evil.test"}}}}}})
	registered := l.json(resp)
	l.id = str(registered["agent_id"])
	l.decides(registered["approval"], "approve")
	return l
}

func (l *locatedCase) jwt(claims map[string]any) string {
	all := map[string]any{"capabilities": []any{"invite"}}
	for n, v := range claims {
		all[n] = v
	}
	return l.key.requestJWT(l.id, location, all, nil)
}

// posts sends body to the location, through Protect.
func (l *locatedCase) posts(jwt, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, location, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Content-Length", fmt.Sprint(len(body)))
	r.Header.Set("Authorization", "Bearer "+jwt)
	w := httptest.NewRecorder()
	l.plugin.Protect("invite", l).ServeHTTP(w, r)
	return w
}

const invites = `{"capability":"invite","arguments":{ "email": "bob@acme.test" }}`

// §2.15: a protocol client posts {capability, arguments} to the location; the host's handler reads the
// arguments alone, the bytes that were checked, and answers as any other.
func TestSection2_15AProtocolAgentAtALocation(t *testing.T) {
	l := located(t)
	ok := l.posts(l.jwt(nil), invites)
	l.equal([]any{ok.Code, ok.Body.String(), ok.Header().Get("Content-Type"), ok.Header().Get("Content-Length")}, []any{200, `{"data":{"invited":true}}`, "application/json; charset=utf-8", ""}, "§5.11: data")
	l.equal([]any{len(l.read), l.read[0]}, []any{1, `{ "email": "bob@acme.test" } 28 28`}, "the arguments as they were sent")
	l.equal([]any{l.calls[0].Capability, l.calls[0].Arguments, l.calls[0].Agent.ID}, []any{"invite", map[string]any{"email": "bob@acme.test"}, l.id}, "the call")
	row, _ := l.srv.Graph().DB().FindOne(l.ctx, agents.TableReceipts, store.Criteria{"id": ok.Header().Get(agents.ReceiptHeader)})
	l.equal([]any{row.String("capability"), row.String("outcome")}, []any{"invite", "success"}, "a receipt")

	// Guard, and a JWT that binds the body as it was sent.
	r := httptest.NewRequest(http.MethodPost, location, strings.NewReader(invites))
	r.Header.Set("Authorization", "Bearer "+l.jwt(map[string]any{"body_hash": bodyHash([]byte(invites))}))
	w := httptest.NewRecorder()
	l.plugin.Guard(l).ServeHTTP(w, r)
	l.equal([]any{w.Code, len(l.read)}, []any{200, 2}, "Guard, body_hash")
}

// Only the body is checked, so nothing else of the request may carry arguments, and the body is JSON to whoever
// reads its type.
func TestWhatAHandlerReadsAtALocationWasChecked(t *testing.T) {
	l := located(t)
	var form string
	guarded := l.plugin.Protect("invite", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		form = r.FormValue("email") + r.Header.Get("Content-Type") + r.Header.Get("Content-Encoding") + fmt.Sprint(len(r.Trailer))
	}))
	send := func(query string) int {
		r := httptest.NewRequest(http.MethodPost, location+query, strings.NewReader(invites))
		r.Header.Set("Authorization", "Bearer "+l.jwt(nil))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Content-Encoding", "gzip")
		r.Trailer = http.Header{"Email": {"mallory@evil.test"}}
		w := httptest.NewRecorder()
		guarded.ServeHTTP(w, r)
		return w.Code
	}
	l.equal([]any{send("?email=mallory@evil.test"), form}, []any{400, ""}, "a query")
	l.equal([]any{send(""), form}, []any{200, "application/json0"}, "a form")
}

// An agent a host's JWT registered is the protocol's even when its host is gone, and is refused then (§4.5).
func TestAnAgentWhoseHostIsGoneIsRefused(t *testing.T) {
	l := located(t)
	if _, err := l.srv.Graph().DB().Delete(l.ctx, agents.TableHosts, store.Criteria{"id": l.hostID}); err != nil {
		t.Fatal(err)
	}
	w := l.posts(l.jwt(nil), invites)
	l.equal(fmt.Sprint(w.Code, " ", problemOf(w)["error"]), "401 invalid_jwt", "at a location")
	l.agentsProblem(l.executes(l.key, l.id, "invite", nil), 401, "invalid_jwt", "", "on the protocol's routes")
	l.equal(len(l.calls), 0, "nothing ran")
}

// The body is the protocol's and nothing else; refusals are its too (§5.13), and nothing runs.
func TestSection5_13WhatIsRefusedAtALocation(t *testing.T) {
	l := located(t)
	for body, want := range map[string]string{
		``:                          "400 invalid_request",
		`[]`:                        "400 invalid_request",
		`null`:                      "400 invalid_request",
		`{"email":"bob@acme.test"}`: "400 invalid_request", // the arguments alone, as another agent sends them
		`{"arguments":{"email":"bob@acme.test"}}`:                                                           "400 invalid_request",
		`{"capability":"members.list","arguments":{"email":"bob@acme.test"}}`:                               "400 invalid_request",
		`{"capability":5,"arguments":{"email":"bob@acme.test"}}`:                                            "400 invalid_request",
		`{"capability":"invite"}`:                                                                           "400 invalid_request", // email is required
		`{"capability":"invite","arguments":null}`:                                                          "400 invalid_request",
		`{"capability":"invite","arguments":[]}`:                                                            "400 invalid_request",
		`{"capability":"invite","arguments":"{}"}`:                                                          "400 invalid_request",
		`{"capability":"invite","arguments":{"email":"bob@acme.test"},"email":"x"}`:                         "400 invalid_request",
		`{"capability":"invite","arguments":{"email":"bob@acme.test"},"Arguments":{}}`:                      "400 invalid_request",
		`{"capability":"invite","Arguments":{"email":"bob@acme.test"}}`:                                     "400 invalid_request",
		`{"capability":"invite","arguments":{"email":"bob@acme.test"},"arguments":{"email":"mallory@x"}}`:   "400 invalid_request",
		`{"capability":"invite","arguments":{"email":"bob@acme.test","Email":"mallory@evil.test"}}`:         "400 invalid_request",
		`{"capability":"invite","arguments":{"EMAIL":"mallory@evil.test"}}`:                                 "400 invalid_request",
		`{"capability":"invite","arguments":{"email":"bob@acme.test"}}{}`:                                   "400 invalid_request",
		`{"capability":"invite","arguments":{"email":"mallory@evil.test"}}`:                                 "403 constraint_violated",
		`{"capability":"invite","arguments":{"capability":"invite","arguments":{"email":"bob@acme.test"}}}`: "400 invalid_request",
	} {
		w := l.posts(l.jwt(nil), body)
		l.equal(fmt.Sprint(w.Code, " ", problemOf(w)["error"]), want, body)
	}
	violated := problemOf(l.posts(l.jwt(nil), `{"capability":"invite","arguments":{"email":"mallory@evil.test"}}`))
	l.equal(at(violated["violations"], 0)["constraint"], map[string]any{"not_in": []any{"mallory@evil.test"}}, "§5.11: the constraint")
	now := time.Now().Unix()
	for name, jwt := range map[string]string{
		"no slash more":       l.jwt(map[string]any{"aud": location + "/"}), // §8.18: exactly
		"the execute route":   l.jwt(map[string]any{"aud": base + "/capability/execute"}),
		"31 s ahead (§8.2)":   l.jwt(map[string]any{"iat": now + 35, "exp": now + 60}),
		"expired 31 s ago":    l.jwt(map[string]any{"iat": now - 90, "exp": now - 31}),
		"another host's iss":  l.jwt(map[string]any{"iss": newKey("EdDSA").kid()}),
		"another agent's key": newKey("EdDSA").requestJWT(l.id, location, nil, nil),
	} {
		w := l.posts(jwt, invites)
		l.equal(fmt.Sprint(w.Code, " ", problemOf(w)["error"]), "401 invalid_jwt", name)
	}
	used := l.jwt(nil)
	l.equal([]any{l.posts(used, invites).Code, l.posts(used, invites).Code}, []any{200, 401}, "once")
	ran := len(l.calls)
	l.status(l.c.Post("/agents/"+l.id+"/suspend", nil, contracttest.Bearer(l.session)), 200, "suspend")
	w := l.posts(l.jwt(nil), invites)
	l.equal(fmt.Sprint(w.Code, " ", problemOf(w)["error"]), "403 agent_suspended", "§5.13: 403")
	l.status(l.c.Delete("/agents/hosts/"+l.hostID, contracttest.Bearer(l.session)), 200, "revoke the host")
	w = l.posts(l.jwt(nil), invites)
	l.equal(fmt.Sprint(w.Code, " ", problemOf(w)["error"]), "403 agent_revoked", "§8.5")
	l.equal([]any{ran, len(l.calls)}, []any{1, 1}, "the handler ran once")
}

// §5.11: a sync success holds data and nothing of an asynchronous answer, whatever the handler wrote.
func TestSection5_11WhatAHandlerAnswersAtALocation(t *testing.T) {
	l := located(t)
	raw := func(status int, contentType, body string) func(http.ResponseWriter) {
		return func(w http.ResponseWriter) {
			if contentType != "" {
				w.Header().Set("Content-Type", contentType)
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}
	}
	for name, c := range map[string]struct {
		answers func(http.ResponseWriter)
		status  int
		body    string
		media   string
	}{
		"an asynchronous answer": {answersJSON(202, `{"status":"pending","status_url":"https://evil.test"}`), 200, `{"data":{"status":"pending","status_url":"https://evil.test"}}`, "application/json; charset=utf-8"},
		"created":                {answersJSON(201, " [1]\n"), 200, `{"data":[1]}`, "application/json; charset=utf-8"},
		"a scalar":               {answersJSON(200, `null`), 200, `{"data":null}`, "application/json; charset=utf-8"},
		"data already":           {answersJSON(200, `{"data":1}`), 200, `{"data":{"data":1}}`, "application/json; charset=utf-8"},
		"another JSON":           {raw(200, "application/vnd.api+json", `{"a":1}`), 200, `{"data":{"a":1}}`, "application/vnd.api+json"},
		"no type":                {raw(200, "", `{"a":1}`), 200, `{"data":{"a":1}}`, "application/json"},
		"nothing":                {raw(204, "", ""), 200, `{"data":null}`, "application/json"},
		"nothing, of a type":     {raw(200, "application/json", ""), 200, `{"data":null}`, "application/json"},
		"nothing, as text":       {raw(200, "text/plain", ""), 200, `{"data":null}`, "application/json"},
		"a part":                 {answersJSON(206, `{"a":1}`), 206, `{"a":1}`, "application/json; charset=utf-8"},
		"text":                   {raw(200, "text/plain", `{"a":1}`), 200, `{"a":1}`, "text/plain"},
		"broken JSON":            {raw(200, "application/json", `{"a":`), 200, `{"a":`, "application/json"},
		"a refusal":              {answersJSON(422, `{"error":"taken"}`), 422, `{"error":"taken"}`, "application/json; charset=utf-8"},
		"a redirect":             {raw(303, "", ""), 303, "", ""},
	} {
		l.answers = c.answers
		w := l.posts(l.jwt(nil), invites)
		l.equal([]any{w.Code, w.Body.String(), w.Header().Get("Content-Type"), w.Header().Get(agents.ReceiptHeader) != ""}, []any{c.status, c.body, c.media, true}, name)
	}
	l.answers = func(w http.ResponseWriter) {
		w.Header().Set("ETag", `"1"`)
		w.Header().Set("Content-Digest", "sha-256=:x:")
		answersJSON(200, `{"a":1}`)(w)
	}
	w := l.posts(l.jwt(nil), invites)
	l.equal([]any{w.Header().Get("ETag"), w.Header().Get("Content-Digest")}, []any{"", ""}, "what described the body as it was")
	compressed := []byte("1") // valid JSON by chance
	l.answers = func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(compressed)
	}
	l.equal(bytes.Equal(l.posts(l.jwt(nil), invites).Body.Bytes(), compressed), true, "encoded")
}

// Any other agent sends the arguments alone, and reads what the handler wrote, as in v1.0.0: the host decides,
// not the body.
func TestAnotherAgentAtALocationIsAsItWas(t *testing.T) {
	l := located(t)
	key := newKey("EdDSA")
	owned := str(l.registerAgent(l.session, map[string]any{"name": "Owned", "auth": "private_key_jwt", "jwk": key.jwk()})["id"])
	host := l.data(l.c.Post("/agents/hosts", map[string]any{"name": "Laptop"}, contracttest.Bearer(l.session)))
	enrolled := l.data(l.c.Post("/agents/enroll", map[string]any{"name": "Enrolled", "mode": "delegated", "auth": "private_key_jwt", "jwk": key.jwk()}, contracttest.Bearer(str(host["enrollment_token"]))))
	l.answers = answersJSON(201, `{"invited":true}`)
	for name, id := range map[string]string{"its owner's": owned, "a token host's": str(enrolled["id"])} {
		asked := l.json(l.signed(key, id, "POST", "/agents/grants/request", map[string]any{"capabilities": []any{"invite"}, "preferred_method": "in_app"}, nil))
		l.decides(asked["approval"], "approve")
		jwt := func() string { return key.requestJWT(id, location+"/", nil, nil) } // compared normalised
		l.read = nil
		w := l.posts(jwt(), `{"email":"bob@acme.test"}`)
		l.equal([]any{w.Code, w.Body.String(), l.read}, []any{201, `{"invited":true}`, []string{`{"email":"bob@acme.test"} 25 25`}}, name)
		w = l.posts(jwt(), invites)
		l.equal(fmt.Sprint(w.Code, " ", problemOf(w)["error"]), "422 agents_invalid_arguments", name+": the protocol's body is arguments of its own")
	}
}

// An access token of a protocol agent (§12.1) is the same agent, with the same body.
func TestSection12_1AnAccessTokenAtALocation(t *testing.T) {
	l := located(t)
	minted := l.form("/oauth2/token", map[string]string{"grant_type": oauth.GrantTokenExchange, "subject_token": l.session, "subject_token_type": exchangeType, "scope": "members.invite",
		"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "client_assertion": l.key.assertion(l.id, base+"/oauth2/token")})
	l.status(minted, 200, "the exchange")
	tok := str(l.json(minted)["access_token"])
	w := l.posts(tok, invites)
	l.equal([]any{w.Code, w.Body.String()}, []any{200, `{"data":{"invited":true}}`}, "an access token")
}

// A registration nobody approved yet is told so in the protocol's words.
func TestAPendingRegistrationAtALocation(t *testing.T) {
	u := anUnknownHost(t, nil)
	key, registered := u.registers(map[string]any{"capabilities": []any{"invite"}})
	r := httptest.NewRequest(http.MethodPost, location, strings.NewReader(invites))
	r.Header.Set("Authorization", "Bearer "+key.requestJWT(str(registered["agent_id"]), location, nil, nil))
	w := httptest.NewRecorder()
	u.plugin.Protect("invite", http.NotFoundHandler()).ServeHTTP(w, r)
	u.equal(fmt.Sprint(w.Code, " ", problemOf(w)["error"]), "403 agent_pending", "§5.13")
}
