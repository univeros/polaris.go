package sentinel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/plugins/admin"
)

// DeviceCookie names the device cookie the middleware sets (one year, HttpOnly, SameSite=Lax,
// Secure over TLS) when a guarded request has none.
const DeviceCookie = "polaris_device"

const deviceCookieTTL = 31536000

// DefaultRoutes are the guarded routes (manifest path => attempt kind).
var DefaultRoutes = map[string]string{
	"/auth/register":            SignUp,
	"/auth/login":               SignIn,
	"/auth/password/forgot":     PasswordReset,
	"/auth/email/verify/resend": VerificationSend,
	"/auth/mfa/challenge":       OTPSend,
}

type attemptKey struct{}

// attemptFrom is the attempt the middleware judged for the request in flight (the listener reads
// the device of a successful sign-in from it).
func attemptFrom(ctx context.Context) (Attempt, bool) {
	a, ok := ctx.Value(attemptKey{}).(Attempt)
	return a, ok
}

// guard judges the attempt of a guarded route before the endpoint runs.
func (p *Plugin) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rt := endpoint.Route(ctx)
		kind := ""
		if rt != nil {
			kind = p.routes[rt.Path]
		}
		if kind == "" {
			next.ServeHTTP(w, r)
			return
		}
		body := readBody(r)
		client := endpoint.Client(ctx)
		a := Attempt{Kind: kind, Email: str(body["email"]), IP: client.IP, UserAgent: client.UserAgent,
			CaptchaToken: str(body["captcha_token"]), Password: str(body["password"])}
		if c, err := r.Cookie(DeviceCookie); err == nil {
			a.DeviceID = c.Value
		}
		d, err := p.engine.Evaluate(ctx, a)
		if err != nil {
			p.g.Logger.ErrorContext(ctx, "sentinel: evaluation failed", "error", err)
			endpoint.Write(w, endpoint.Error(http.StatusInternalServerError, "server_error", "The server could not complete the request."))
			return
		}
		switch {
		case d.Enforced && d.Action == Block:
			endpoint.Write(w, endpoint.Problem(http.StatusForbidden, "sentinel/blocked", "Blocked", "The request was refused.", nil))
			return
		case d.Enforced && d.Action == Challenge && p.cfg.Captcha != nil:
			endpoint.Write(w, endpoint.Problem(http.StatusForbidden, "sentinel/challenge_required", "Challenge required",
				"Complete the challenge and try again.", map[string]any{"challenge": "captcha"}))
			return
		}
		a.Email = strings.ToLower(strings.TrimSpace(a.Email))
		r = r.WithContext(context.WithValue(ctx, attemptKey{}, a))
		if a.DeviceID == "" {
			w = &cookieWriter{ResponseWriter: w, cookie: deviceCookie(r.TLS != nil)}
		}
		next.ServeHTTP(w, r)
	})
}

// readBody decodes a JSON object or form body, as the endpoint will, and puts the bytes back for
// it; anything else reads as empty.
func readBody(r *http.Request) map[string]any {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	raw, _ := io.ReadAll(r.Body) // the pipeline already buffered and bounded it
	r.Body = io.NopCloser(bytes.NewReader(raw))
	body := map[string]any{}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		form, _ := url.ParseQuery(string(raw))
		for k := range form {
			body[k] = form.Get(k)
		}
		return body
	}
	_ = json.Unmarshal(raw, &body)
	return body
}

func str(v any) string { s, _ := v.(string); return s }

func deviceCookie(secure bool) string {
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	c := fmt.Sprintf("%s=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Lax", DeviceCookie, hex.EncodeToString(id), deviceCookieTTL)
	if secure {
		c += "; Secure"
	}
	return c
}

// cookieWriter adds the device cookie when the response starts, after the endpoint set its own
// headers (an endpoint replacing Set-Cookie cannot drop it).
type cookieWriter struct {
	http.ResponseWriter
	cookie  string
	written bool
}

func (w *cookieWriter) WriteHeader(status int) {
	if !w.written {
		w.written = true
		w.Header().Add("Set-Cookie", w.cookie)
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *cookieWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *cookieWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Route names (polaris.sentinel.<file>).
const (
	RouteDecisionsList = "polaris.sentinel.decisions-list"
	RouteIPRulesList   = "polaris.sentinel.ip-rules-list"
	RouteIPRulesCreate = "polaris.sentinel.ip-rules-create"
	RouteIPRulesDelete = "polaris.sentinel.ip-rules-delete"
	RouteUnblock       = "polaris.sentinel.unblock"
)

const maxNote = 255

func (p *Plugin) endpoints() map[string]endpoint.Endpoint {
	return map[string]endpoint.Endpoint{
		RouteDecisionsList: endpoint.Func(p.listDecisions),
		RouteIPRulesList:   endpoint.Func(p.listRules),
		RouteIPRulesCreate: endpoint.Func(p.createRule),
		RouteIPRulesDelete: endpoint.Func(p.deleteRule),
		RouteUnblock:       endpoint.Func(p.unblock),
	}
}

func (p *Plugin) fail(ctx context.Context, what string, err error) endpoint.Result {
	p.g.Logger.ErrorContext(ctx, "sentinel: "+what+" failed", "error", err)
	return endpoint.Error(http.StatusInternalServerError, "server_error", "The server could not complete the request.")
}

// recorded records the operator's action and answers res; a failing audit write answers 500.
func (p *Plugin) recorded(ctx context.Context, res endpoint.Result, name string, op admin.Principal, subjectID string, data map[string]any) endpoint.Result {
	if err := p.admin.Record(ctx, name, op, subjectID, "", data); err != nil {
		return p.fail(ctx, "audit "+name, err)
	}
	return res
}

// text is a non-empty string value, "" otherwise (upstream's AdminRoute::text).
func text(v any) string { return str(v) }

// positiveInt reads an optional numeric limit of at least 1; def when absent or "".
func positiveInt(v any, def int) (int, bool) {
	var s string
	switch v := v.(type) {
	case nil:
		return def, true
	case string:
		s = strings.TrimSpace(v)
	case json.Number:
		s = v.String()
	default:
		return 0, false
	}
	if s == "" {
		return def, true
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 1 {
		return 0, false
	}
	return int(min(f, MaxLimit)), true
}

func (p *Plugin) listDecisions(ctx context.Context, in *endpoint.Input) endpoint.Result {
	if _, res, ok := admin.Authorize(ctx, admin.Read, ""); !ok {
		return res
	}
	action := text(in.Value("action"))
	if action != "" && action != Allow && action != Challenge && action != Block {
		return admin.Invalid("action must be allow, challenge or block.")
	}
	limit, ok := positiveInt(in.Value("limit"), DefaultLimit)
	if !ok {
		return admin.Invalid("limit must be a positive integer.")
	}
	page, err := p.decisions.List(ctx, Filter{Email: strings.ToLower(text(in.Value("email"))), IP: text(in.Value("ip")),
		Action: action, Cursor: text(in.Value("cursor")), Limit: limit})
	if err != nil {
		return p.fail(ctx, "list decisions", err)
	}
	return endpoint.JSON(http.StatusOK, page)
}

func (p *Plugin) listRules(ctx context.Context, _ *endpoint.Input) endpoint.Result {
	if _, res, ok := admin.Authorize(ctx, admin.Read, ""); !ok {
		return res
	}
	rules, err := p.rules.All(ctx)
	if err != nil {
		return p.fail(ctx, "list ip rules", err)
	}
	data := make([]map[string]any, 0, len(rules))
	for _, r := range rules {
		data = append(data, r.Map())
	}
	return endpoint.Data(http.StatusOK, data)
}

func (p *Plugin) createRule(ctx context.Context, in *endpoint.Input) endpoint.Result {
	op, res, ok := admin.Authorize(ctx, admin.Own, "")
	if !ok {
		return res
	}
	cidr := strings.TrimSpace(str(in.Value("cidr")))
	if cidr == "" || !admin.ValidAllowlistEntry(cidr) {
		return admin.Invalid("cidr must be an IP address or a CIDR block.")
	}
	action := str(in.Value("action"))
	if action != Allow && action != Block {
		return admin.Invalid("action must be allow or block.")
	}
	note := text(in.Value("note"))
	if utf8.RuneCountInString(note) > maxNote {
		return admin.Invalid("note must be at most 255 characters.")
	}
	rule, err := p.rules.Add(ctx, cidr, action, note, op.ID)
	if err != nil {
		return p.fail(ctx, "create ip rule", err)
	}
	return p.recorded(ctx, endpoint.Data(http.StatusCreated, rule.Map()), AuditIPRuleCreated, op, rule.ID,
		map[string]any{"cidr": cidr, "action": action})
}

func (p *Plugin) deleteRule(ctx context.Context, in *endpoint.Input) endpoint.Result {
	op, res, ok := admin.Authorize(ctx, admin.Own, "")
	if !ok {
		return res
	}
	id := in.String("id")
	removed, err := p.rules.Remove(ctx, id)
	if err != nil {
		return p.fail(ctx, "delete ip rule", err)
	}
	if !removed {
		return admin.NotFound("The rule does not exist.")
	}
	return p.recorded(ctx, endpoint.Data(http.StatusOK, map[string]any{"status": "deleted"}), AuditIPRuleDeleted, op, id, nil)
}

func (p *Plugin) unblock(ctx context.Context, in *endpoint.Input) endpoint.Result {
	op, res, ok := admin.Authorize(ctx, admin.Support, "")
	if !ok {
		return res
	}
	identifier := strings.ToLower(strings.TrimSpace(str(in.Value("identifier"))))
	if identifier == "" {
		return admin.Invalid("identifier must be an email or an IP address.")
	}
	if err := p.engine.Unblock(ctx, identifier); err != nil {
		return p.fail(ctx, "unblock", err)
	}
	kind := "ip"
	if strings.Contains(identifier, "@") {
		kind = "email"
	}
	return p.recorded(ctx, endpoint.Data(http.StatusOK, map[string]any{"status": "unblocked", "identifier": identifier}),
		AuditUnblocked, op, "", map[string]any{"identifier_hash": sha256Hex(identifier), "kind": kind})
}
