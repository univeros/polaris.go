package multisession

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/token"
)

// Route names.
const (
	RouteList       = "polaris.multi-session.list"
	RouteSwitch     = "polaris.multi-session.switch"
	RouteRevoke     = "polaris.multi-session.revoke"
	RouteLastMethod = "polaris.multi-session.last-method"
)

const cookieTTL = 31536000 // one year, in seconds

type deviceKey struct{}

// device is the device id the middleware accepted for the request, "" when none.
func device(ctx context.Context) string {
	d, _ := ctx.Value(deviceKey{}).(string)
	return d
}

// middleware accepts a known device id from the header (or the cookie) and hands it to the
// endpoints; on a route that opens or refreshes a session, a 200/201 carrying a token pair is
// recorded against the device (minted when the request had none), and the device id answered.
// Other routes, and host routes behind Protect, are neither looked up nor buffered.
func (p *Plugin) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt := endpoint.Route(r.Context())
		if rt == nil || (rt.Session == "" && !strings.HasPrefix(rt.Name, "polaris."+ID+".")) {
			next.ServeHTTP(w, r)
			return
		}
		presented := r.Header.Get(Header)
		if presented == "" {
			if c, err := r.Cookie(Cookie); err == nil {
				presented = c.Value
			}
		}
		deviceID := ""
		if presented != "" {
			known, err := p.devices.known(r.Context(), presented)
			if err != nil {
				p.fail(w, r, err)
				return
			}
			if known {
				deviceID = presented
			}
		}
		r = r.WithContext(context.WithValue(r.Context(), deviceKey{}, deviceID))
		if rt.Session == "" {
			next.ServeHTTP(w, r)
			return
		}
		buf := &buffered{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(buf, r)
		p.recordSignIn(r, buf, deviceID)
		w.WriteHeader(buf.status)
		_, _ = w.Write(buf.body.Bytes())
	})
}

// recordSignIn records the token pair buf carries, if any, and sets the device headers.
func (p *Plugin) recordSignIn(r *http.Request, buf *buffered, deviceID string) {
	userID, sessionID, amr, ok := p.issued(buf)
	if !ok {
		return
	}
	if deviceID == "" {
		deviceID = mint()
	}
	deviceID, err := p.devices.record(r.Context(), deviceID, userID, sessionID, amr)
	if err != nil { // the session is open: answer it, untracked
		p.g.Logger().ErrorContext(r.Context(), "polaris multi-session: device not recorded", "error", err)
		return
	}
	h := buf.Header()
	h.Set(Header, deviceID)
	if c, err := r.Cookie(Cookie); p.cfg.DisableCookie || (err == nil && c.Value == deviceID) {
		return
	}
	// Secure follows where Polaris is configured to live, not only this connection: behind a
	// proxy that ends TLS the request arrives plain.
	secure := ""
	if r.TLS != nil || strings.HasPrefix(p.g.Auth().Issuer, "https://") {
		secure = "; Secure"
	}
	h.Add("Set-Cookie", fmt.Sprintf("%s=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Lax%s", Cookie, deviceID, cookieTTL, secure))
}

// issued reads the user, session and amr of the token pair a successful response carries.
func (p *Plugin) issued(buf *buffered) (userID, sessionID string, amr []string, ok bool) {
	if buf.status != http.StatusOK && buf.status != http.StatusCreated {
		return "", "", nil, false
	}
	var body struct {
		Data struct {
			AccessToken  *string `json:"access_token"`
			RefreshToken *string `json:"refresh_token"`
		} `json:"data"`
	}
	if json.Unmarshal(buf.body.Bytes(), &body) != nil || body.Data.AccessToken == nil || body.Data.RefreshToken == nil {
		return "", "", nil, false
	}
	tok, err := p.g.Tokens().Parse(*body.Data.AccessToken)
	if err != nil {
		return "", "", nil, false
	}
	sid, _ := tok.Claim("sid").(string)
	if tok.Subject() == "" || sid == "" {
		return "", "", nil, false
	}
	list, _ := tok.Claim("amr").([]any)
	for _, m := range list {
		if s, ok := m.(string); ok {
			amr = append(amr, s)
		}
	}
	return tok.Subject(), sid, amr, true
}

// buffered holds the response until the device is recorded; headers go straight to the wrapped
// writer's map.
type buffered struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (b *buffered) WriteHeader(code int)        { b.status = code }
func (b *buffered) Write(p []byte) (int, error) { return b.body.Write(p) }

func (p *Plugin) fail(w http.ResponseWriter, r *http.Request, err error) {
	p.g.Logger().ErrorContext(r.Context(), "polaris multi-session: operation failed", "error", err)
	endpoint.Write(w, endpoint.Error(http.StatusInternalServerError, "server_error", "The server could not complete the request."))
}

func (p *Plugin) endpoints() map[string]endpoint.Endpoint {
	authed := func(f func(ctx context.Context, in *endpoint.Input, sid string) endpoint.Result) endpoint.Endpoint {
		return endpoint.Func(func(ctx context.Context, in *endpoint.Input) endpoint.Result {
			tok := endpoint.Token(ctx)
			if tok == nil {
				return endpoint.Unauthorized()
			}
			sid, _ := tok.Claim("sid").(string)
			return f(ctx, in, sid)
		})
	}
	return map[string]endpoint.Endpoint{
		RouteList:       authed(p.list),
		RouteSwitch:     authed(p.switchTo),
		RouteRevoke:     authed(p.revoke),
		RouteLastMethod: endpoint.Func(p.lastMethod),
	}
}

// refuse answers a refusal as its problem document, any other error as a 500.
func (p *Plugin) refuse(ctx context.Context, err error) endpoint.Result {
	switch {
	case errors.Is(err, errDeviceUnknown):
		return endpoint.Problem(http.StatusForbidden, ID+"/device_unknown", "Device unknown", err.Error(), nil)
	case errors.Is(err, errSessionNotFound):
		return endpoint.Problem(http.StatusNotFound, ID+"/session_not_found", "Session not found", err.Error(), nil)
	}
	p.g.Logger().ErrorContext(ctx, "polaris multi-session: operation failed", "error", err)
	return endpoint.Error(http.StatusInternalServerError, "server_error", "The server could not complete the request.")
}

func (p *Plugin) lastMethod(ctx context.Context, _ *endpoint.Input) endpoint.Result {
	m, err := p.devices.lastMethod(ctx, device(ctx))
	if err != nil {
		return p.refuse(ctx, err)
	}
	return endpoint.Data(http.StatusOK, map[string]any{"last_method": m})
}

func (p *Plugin) list(ctx context.Context, _ *endpoint.Input, sid string) endpoint.Result {
	sessions, err := p.devices.list(ctx, device(ctx), sid)
	if err != nil {
		return p.refuse(ctx, err)
	}
	return endpoint.Data(http.StatusOK, sessions)
}

func (p *Plugin) switchTo(ctx context.Context, in *endpoint.Input, sid string) endpoint.Result {
	target := in.String("session_id")
	if target == "" {
		return endpoint.Problem(http.StatusUnprocessableEntity, ID+"/invalid_input", "Invalid input", "session_id is required.",
			map[string]any{"errors": []string{"session_id is required."}})
	}
	tokens, u, err := p.devices.switchTo(ctx, device(ctx), sid, target, endpoint.Client(ctx))
	if err != nil {
		return p.refuse(ctx, err)
	}
	return endpoint.Data(http.StatusOK, envelope(tokens, u.ID, u.Email, u.EmailVerifiedAt != nil))
}

func (p *Plugin) revoke(ctx context.Context, in *endpoint.Input, sid string) endpoint.Result {
	if err := p.devices.revoke(ctx, device(ctx), sid, in.String("sessionId")); err != nil {
		return p.refuse(ctx, err)
	}
	return endpoint.Data(http.StatusOK, map[string]any{"status": "revoked"})
}

// envelope is core's login envelope.
func envelope(t token.IssuedTokens, userID, email string, verified bool) map[string]any {
	return map[string]any{
		"access_token":  t.AccessToken,
		"token_type":    "Bearer",
		"expires_in":    t.AccessExpiresIn,
		"refresh_token": t.RefreshToken,
		"user":          map[string]any{"id": userID, "email": email, "email_verified": verified},
	}
}
