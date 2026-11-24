package agents

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/univeros/polaris.go/internal/strictjson"
)

// What an agent that a host's JWT registered does at a capability's Location: the Agent Auth Protocol's way.
// Its client posts {capability, arguments} there as to the execute route (§2.15) and reads {data} (§5.11); any
// other agent sends the arguments alone. How it was registered decides which, never the body: a capability
// may take arguments of those names itself.

// atLocation authenticates a request at the capability's location; protocol is whether the caller is an
// agent a host's JWT registered, whatever the outcome.
func (s *service) atLocation(r *http.Request, body []byte, c *Capability) (pr principal, protocol bool, err error) {
	url := requestURL(r)
	if m := credentialScheme.FindStringSubmatch(r.Header.Get("Authorization")); m != nil {
		if peeked, ok := peekRequestJWT(m[2]); ok {
			a, err := s.named(r.Context(), peeked.sub)
			if err != nil {
				return principal{}, false, err
			}
			// Not verified yet: it only says which rules the JWT is held to, and those bind its sub.
			rules, protocol := s.jwts, a.ofHostJWT()
			if protocol { // §4.3, §8.18: aud is exactly the location; §8.2: 30 s
				rules = &requestJWTs{cache: s.jwts.cache, clock: s.jwts.clock, maxAge: s.jwts.maxAge, audience: c.Location, skew: protocolSkew}
			}
			pr, err := s.signedBy(a, rules, r, m[2], peeked, body, url)
			return pr, protocol, err
		}
	}
	pr, err = s.authenticate(r, body, url)
	return pr, pr.agent.ofHostJWT(), err // an access token (§12.1)
}

// executionArguments are the arguments of the execution body asks for, as they were sent: {capability,
// arguments}, of the location's capability, and nothing else.
func executionArguments(body []byte, c *Capability) (json.RawMessage, error) {
	var members map[string]json.RawMessage
	if strictjson.Decode(body, &members) != nil || members == nil || !unambiguous(body) {
		return nil, refuse(ErrInvalidRequest, "The body is one JSON object, {capability, arguments}, no two members of which have the same name.")
	}
	name, args := members["capability"], members["arguments"]
	delete(members, "capability")
	delete(members, "arguments")
	var named string
	if json.Unmarshal(name, &named) != nil || named != c.Name || len(members) > 0 {
		return nil, refuse(ErrInvalidRequest, "The body is {capability, arguments}, and capability \""+c.Name+"\" at this location.")
	}
	if args == nil || string(args) == "null" {
		return json.RawMessage("{}"), nil
	}
	if !bytes.HasPrefix(args, []byte("{")) {
		return nil, refuse(ErrInvalidRequest, "arguments is an object.")
	}
	return args, nil
}

// withArguments is r whose body is the arguments. Nothing else of it was checked, so nothing else may carry
// arguments, whoever the agent is: no query, no form something parsed before, no trailer. r itself is left as
// it was.
func withArguments(r *http.Request, body []byte) (*http.Request, error) {
	if r.URL.RawQuery != "" {
		return r, invalidRequest("The location is called without a query: the arguments are the JSON body.")
	}
	out := r.Clone(r.Context())
	out.Body, out.ContentLength, out.TransferEncoding, out.Trailer = io.NopCloser(bytes.NewReader(body)), int64(len(body)), nil, nil
	out.GetBody = nil // the body as it was sent
	out.Form, out.PostForm, out.MultipartForm = nil, nil, nil
	out.Header.Del("Content-Encoding")
	if out.Header.Get("Content-Length") != "" {
		out.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}
	return out, nil
}

// declaresJSON refuses a body whose type is not JSON, once and in UTF-8: a handler, or what it passes the
// request on to, reads the body as its type says, and it was checked as JSON. A request without a body has
// no arguments, whatever its type.
func declaresJSON(r *http.Request, body []byte) error {
	if len(bytes.TrimLeft(body, jsonSpace)) == 0 {
		return nil
	}
	declared := r.Header.Values("Content-Type")
	if len(declared) == 1 {
		media, params, err := mime.ParseMediaType(declared[0])
		charset := params["charset"]
		if err == nil && isJSON(media) && !strings.Contains(declared[0], "*") && // charset*= is no parameter to Go
			(charset == "" || strings.EqualFold(charset, "utf-8")) {
			return nil
		}
	}
	return invalidRequest("The body is one JSON object, sent with Content-Type: application/json.")
}

func isJSON(media string) bool {
	return media == "application/json" || strings.HasSuffix(media, "+json")
}

// asData makes a handler's JSON success the protocol's, {data} (§5.11): its own body could otherwise read
// as an asynchronous answer, whose status_url a client polls with its JWT. Any other answer is as it is.
func (b *buffered) asData() {
	if b.status >= 300 || b.status == http.StatusPartialContent || b.header.Get("Content-Encoding") != "" {
		return
	}
	body := bytes.TrimSpace(b.body.Bytes())
	media, _, _ := mime.ParseMediaType(b.header.Get("Content-Type"))
	switch {
	case len(body) == 0:
		body, media = []byte("null"), ""
	case media != "" && !isJSON(media), !json.Valid(body):
		return
	}
	if media == "" {
		b.header.Set("Content-Type", "application/json")
	}
	for _, described := range []string{"Content-Length", "ETag", "Content-Digest", "Repr-Digest", "Digest", "Content-MD5"} {
		b.header.Del(described) // the body as it was
	}
	b.status = http.StatusOK
	wrapped := append(append([]byte(`{"data":`), body...), '}')
	b.body.Reset()
	b.body.Write(wrapped)
}
