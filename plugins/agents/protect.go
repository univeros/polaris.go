package agents

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

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
// location (compared normalised, whatever its spelling or scheme) is checked as Protect does;
// every other request passes through untouched.
func (p *Plugin) Guard(next http.Handler) http.Handler { return p.guard(nil, next) }

func (p *Plugin) guard(bound *Capability, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capability := bound
		if capability == nil {
			capability = p.caps.at(requestURL(r))
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
		pr, err := p.s.authenticate(r, body, requestURL(r))
		if err != nil {
			p.answer(w, r, err)
			return
		}
		ev, err := p.s.evaluate(ctx, pr, capability.Name, bodyArguments(body))
		if err != nil {
			if e, ok := asError(err); ok {
				p.s.deny(ctx, pr.agent, capability.Name, e, client{})
			}
			p.answer(w, r, err)
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
			p.answer(w, r, err)
			return
		}
		for k, v := range rec.header {
			w.Header()[k] = v
		}
		w.Header().Set(ReceiptHeader, done.receipt.ID)
		w.WriteHeader(rec.status)
		_, _ = w.Write(rec.body.Bytes())
	})
}

// bodyArguments are the JSON object the whole body is, nothing otherwise.
func bodyArguments(body []byte) map[string]any {
	var args map[string]any
	if strictjson.Decode(body, &args) != nil || args == nil {
		return map[string]any{}
	}
	return args
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
