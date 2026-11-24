package agents

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/internal/strictjson"
)

// ReceiptHeader names the receipt of an execution on a guarded host route's response.
const ReceiptHeader = "X-Polaris-Receipt"

type callKey struct{}

// CallFrom is the execution a host handler behind Protect or Guard runs in: the agent, the grant
// (its budget already charged) and the arguments (the JSON body). ok is false outside one.
func CallFrom(ctx context.Context) (Call, bool) {
	c, ok := ctx.Value(callKey{}).(Call)
	return c, ok
}

// Protect guards a host route that is a capability's location: every request through it must
// authenticate an agent (a request JWT whose aud is the URL called, or one of its access tokens)
// holding a live grant whose constraints the arguments (the JSON body) satisfy, checked BEFORE
// next runs; then the budget is spent, next runs and the receipt (outcome from the response
// status: below 300 is success) is appended, in one transaction. next reads the execution with
// CallFrom; the response carries X-Polaris-Receipt. The response is buffered until the receipt is
// written.
//
// Only the JSON body is checked, so a query, and a body that is not one JSON object sent as JSON
// (its Content-Type, when it has one), are refused. Headers and path values are not arguments: no constraint covers them.
//
// An agent of a host with a key (an Agent Auth Protocol client's) posts {capability, arguments} and is
// answered {"data": ...}: next reads the arguments alone, and its JSON answer is wrapped.
//
//	mux.Handle("POST /invitations", agentsPlugin.Protect("invite", inviteHandler))
//
// It panics when capability is not a configured capability with a Location (a startup mistake).
// Use it after polaris.New.
func (p *Plugin) Protect(capability string, next http.Handler) http.Handler {
	c := p.caps.find(capability)
	if c == nil || c.Location == "" {
		panic(fmt.Sprintf("agents: Protect(%q): not a capability with a Location; declare it in agents.Config.Capabilities with Location set", capability))
	}
	return p.guard(c, next)
}

// Guard is the unbound form of Protect for a whole host mux: a request whose URL is a capability's
// location (compared normalised, whatever its spelling or scheme, and by its path when the Host is no
// location's) is checked as Protect does; every other request passes through untouched.
func (p *Plugin) Guard(next http.Handler) http.Handler { return p.guard(nil, next) }

func (p *Plugin) guard(bound *Capability, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capability, ambiguous := bound, false
		if capability == nil {
			capability, ambiguous = p.caps.at(r, requestURL(r))
		}
		if ambiguous {
			p.answer(w, r, refuse(ErrCapabilityNotFound, "The URL is no capability's location under this host name."))
			return
		}
		if capability == nil {
			next.ServeHTTP(w, r)
			return
		}
		if p.s == nil {
			panic("agents: the plugin is not initialised; pass it to polaris.New before serving")
		}
		body, err := readBody(w, r, p.s.settings.maxBody)
		if err != nil {
			p.answer(w, r, err)
			return
		}
		ctx := r.Context()
		pr, protocol, err := p.s.atLocation(r, body, capability)
		refused := func(err error) {
			if protocol {
				endpoint.Write(w, p.protocolFail(ctx, p.s.executionRefusal(ctx, pr.agent, capability.Name, err)))
				return
			}
			p.answer(w, r, err)
		}
		if err != nil {
			refused(err)
			return
		}
		if protocol {
			if err = p.s.spendAgent(ctx, pr.agent); err != nil {
				refused(err)
				return
			}
			if body, err = executionArguments(body, capability); err != nil {
				refused(err)
				return
			}
		}
		args, err := bodyArguments(body)
		if err == nil && !protocol { // whose handler is told JSON, whatever its client said
			err = declaresJSON(r, body)
		}
		if err == nil {
			err = checkSpelling(capability, args)
		}
		if err == nil {
			r, err = withArguments(r, body)
		}
		if err == nil && (protocol || len(body) > 0 && len(r.Header.Values("Content-Type")) == 0) {
			r.Header.Set("Content-Type", "application/json")
		}
		var ev evaluation
		if err == nil {
			ev, err = p.s.evaluate(ctx, pr, capability.Name, args)
		}
		if err != nil {
			if e, ok := asError(err); ok {
				p.s.deny(ctx, pr.agent, capability.Name, e, client{})
			}
			refused(err)
			return
		}
		rec := &buffered{header: http.Header{}, status: http.StatusOK}
		run := func(ctx context.Context, call Call) (any, error) {
			next.ServeHTTP(rec, r.WithContext(context.WithValue(ctx, callKey{}, call)))
			return rec, nil
		}
		outcome := func(any) string {
			if rec.status < 300 {
				return OutcomeSuccess
			}
			return OutcomeFailed
		}
		done, err := p.s.run(ctx, ev, run, outcome, client{})
		if err != nil {
			refused(err)
			return
		}
		if protocol {
			rec.asData()
		}
		for k, v := range rec.header {
			w.Header()[k] = v
		}
		w.Header().Set(ReceiptHeader, done.receipt.ID)
		w.WriteHeader(rec.status)
		_, _ = w.Write(rec.body.Bytes())
	})
}

// bodyArguments are the JSON object the whole body is, nothing for a request without a body. Any other body,
// or one in which two members of one object have the same name, upper and lower case alike, is refused: the
// handler may read what was not checked.
func bodyArguments(body []byte) (map[string]any, error) {
	switch text := bytes.TrimLeft(body, jsonSpace); {
	case len(text) == 0:
		return map[string]any{}, nil
	case text[0] != '{':
		return nil, invalidRequest("The body is one JSON object, sent with Content-Type: application/json.")
	}
	var args map[string]any
	if !utf8.Valid(body) || strictjson.Decode(body, &args) != nil {
		return nil, ambiguousBody("it is not one JSON object")
	}
	if !unambiguous(body) {
		return nil, ambiguousBody("two members of one object have the same name")
	}
	return args, nil
}

// jsonSpace is what may stand before a JSON value.
const jsonSpace = " \t\r\n"

func ambiguousBody(why string) error {
	return &Error{Type: ErrInvalidArguments, Detail: "The body is ambiguous: " + why + ".", Extra: map[string]any{"errors": []string{why}}}
}

// invalidRequest is a request that could carry arguments nothing checked.
func invalidRequest(why string) error {
	return &Error{Type: ErrInvalidArguments, Detail: why, Extra: map[string]any{"errors": []string{why}}}
}

// checkSpelling refuses arguments that differ from a declared one in case alone.
func checkSpelling(c *Capability, args map[string]any) error {
	if name := misspelled(c.Input, args); name != "" {
		return ambiguousBody(strconv.Quote(name) + " differs from a declared argument in case alone")
	}
	return nil
}

// misspelled is a member of args, at any depth the schema describes, whose name differs from one of the
// schema's properties in case alone: the checks read past it, a Go handler decoding the body into a
// struct does not. "" when there is none.
func misspelled(schema, args map[string]any) string {
	properties, _ := schema["properties"].(map[string]any)
	for name, value := range args {
		property, declared := properties[name].(map[string]any)
		if !declared {
			for known := range properties {
				if known != name && strings.EqualFold(known, name) {
					return name
				}
			}
			continue
		}
		if found := misspelledIn(property, value); found != "" {
			return found
		}
	}
	return ""
}

func misspelledIn(schema map[string]any, value any) string {
	switch value := value.(type) {
	case map[string]any:
		return misspelled(schema, value)
	case []any:
		items, _ := schema["items"].(map[string]any)
		for _, item := range value {
			if found := misspelledIn(items, item); found != "" {
				return found
			}
		}
	}
	return ""
}

// unambiguous reports whether no object of a JSON value has two members whose names are equal under
// the case folding encoding/json matches struct fields with.
func unambiguous(body []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(body))
	var open []map[string]bool // the names seen in each open object; nil for an open array
	name := false              // whether the next token, in an object, is a member's name
	for {
		t, err := dec.Token()
		if err != nil {
			return err == io.EOF
		}
		in := len(open) - 1
		if t == json.Delim('}') || t == json.Delim(']') {
			open = open[:in]
		} else if s, ok := t.(string); ok && name && in >= 0 && open[in] != nil {
			key := strings.Map(fold, s)
			if open[in][key] {
				return false
			}
			open[in][key] = true
			name = false
			continue
		} else if t == json.Delim('{') {
			open = append(open, map[string]bool{})
		} else if t == json.Delim('[') {
			open = append(open, nil)
		}
		name = true // a value ended, or an object began
	}
}

// fold is the smallest rune r is equal to under simple case folding.
func fold(r rune) rune {
	least := r
	for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
		least = min(least, next)
	}
	return least
}

// buffered holds a host handler's response until the receipt is written.
type buffered struct {
	header http.Header
	status int
	wrote  bool
	body   bytes.Buffer
}

func (b *buffered) Header() http.Header { return b.header }

func (b *buffered) WriteHeader(status int) {
	if !b.wrote {
		b.status, b.wrote = status, true
	}
}

func (b *buffered) Write(p []byte) (int, error) {
	b.wrote = true
	return b.body.Write(p)
}
