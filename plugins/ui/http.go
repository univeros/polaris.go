package ui

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxForm bounds a form body.
const maxForm = 64 << 10

// routes serves the pages under p.base; every response carries the security headers.
func (p *Plugin) routes() http.Handler {
	mux := http.NewServeMux()
	b := p.base
	handle := func(path string, get, post http.HandlerFunc) {
		mux.HandleFunc("GET "+b+path, get)
		if post != nil {
			mux.HandleFunc("POST "+b+path, p.form(post))
		}
	}
	handle("/style.css", p.style, nil)
	handle("/sign-in", p.signInPage, p.signIn)
	handle("/mfa", p.mfaPage, p.mfa)
	handle("/sign-up", p.page("sign-up", "sign_up_title"), p.signUp)
	handle("/check-email", p.page("check-email", "check_email_title"), p.resend)
	handle("/verify", p.verifyPage, p.verify)
	handle("/forgot", p.page("forgot", "forgot_title"), p.forgot)
	handle("/reset", p.resetPage, p.reset)
	handle("/sign-out", p.page("sign-out", "sign_out_title"), p.signOut)
	handle("/refresh", p.refresh, nil)
	handle("/consent", p.consentPage, p.consent)
	handle("/device", p.devicePage, p.device)
	mux.HandleFunc(b+"/", p.notFound)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.headers(w)
		if r.URL.Path == b {
			http.Redirect(w, r, b+"/sign-in", http.StatusSeeOther)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// form parses a form post, bounded. It refuses it when the configured origin is plain http (the
// Secure cookies would not stick), when the browser posts from another origin (another name
// for this service included: the pages live on the configured origin only), and without a valid
// CSRF token.
func (p *Plugin) form(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case !p.secure:
			p.message(w, r, http.StatusForbidden, "error_title", "error_insecure", "", "")
			return
		case !p.sameOrigin(r, false):
			p.message(w, r, http.StatusForbidden, "error_title", "error_origin", p.origin+p.base+"/sign-in", "continue", "origin", p.origin)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxForm)
		if err := r.ParseForm(); err != nil {
			p.message(w, r, http.StatusBadRequest, "error_title", "error_generic", r.URL.Path, "continue")
			return
		}
		if !p.csrfOK(r) {
			p.message(w, r, http.StatusForbidden, "error_title", "error_csrf", r.URL.Path, "continue")
			return
		}
		next(w, r)
	}
}

// page renders a form without state.
func (p *Plugin) page(name, titleKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p.render(w, r, http.StatusOK, name, p.newView(w, r, titleKey))
	}
}

func (p *Plugin) style(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(p.css)
}

func (p *Plugin) notFound(w http.ResponseWriter, r *http.Request) {
	p.message(w, r, http.StatusNotFound, "not_found_title", "not_found", p.base+"/sign-in", "back_to_sign_in")
}

// fail answers 500 for a failure of the in-process call, logged.
func (p *Plugin) fail(w http.ResponseWriter, r *http.Request, err error) {
	p.g.Logger().ErrorContext(r.Context(), "ui: page failed", "path", r.URL.Path, "error", err)
	p.message(w, r, http.StatusInternalServerError, "error_title", "error_generic", "", "")
}

// problems are the texts for a refused route: the catalog's for the codes it knows, the route's
// own validation messages, else fallback.
func problems(t map[string]string, rep reply, fallback string) []string {
	if rep.status == http.StatusTooManyRequests {
		seconds := rep.header.Get("Retry-After")
		if seconds == "" {
			seconds = "60"
		}
		return []string{format(t["error_rate_limited"], "seconds", seconds)}
	}
	if key, ok := errorKeys[str(rep.body, "error")]; ok {
		return []string{t[key]}
	}
	if list, ok := rep.body["errors"].([]any); ok && len(list) > 0 {
		out := make([]string, 0, len(list))
		for _, e := range list {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return []string{t[fallback]}
}

// --- sign in ---

func (p *Plugin) signInPage(w http.ResponseWriter, r *http.Request) {
	v := p.newView(w, r, "sign_in_title")
	if rt := r.URL.Query().Get("return_to"); p.allowed(rt) {
		v.ReturnTo = rt
	}
	p.render(w, r, http.StatusOK, "sign-in", v)
}

func (p *Plugin) signIn(w http.ResponseWriter, r *http.Request) {
	email, returnTo := strings.TrimSpace(r.PostFormValue("email")), r.PostFormValue("return_to")
	body := map[string]any{"email": email, "password": r.PostFormValue("password")}
	if c := r.PostFormValue("captcha_token"); c != "" {
		body["captcha_token"] = c // sentinel's challenge, when a host template renders one
	}
	rep, err := p.call(w, r, http.MethodPost, "/auth/login", body, "")
	switch {
	case err != nil:
		p.fail(w, r, err)
	case !rep.ok():
		v := p.newView(w, r, "sign_in_title")
		v.Email, v.Errors = email, problems(v.T, rep, "error_invalid_credentials")
		if p.allowed(returnTo) {
			v.ReturnTo = returnTo
		}
		p.render(w, r, rep.status, "sign-in", v)
	case rep.data()["mfa_required"] == true:
		p.startMFA(w, r, rep.data(), returnTo)
	default:
		p.signedIn(w, r, rep.data(), returnTo)
	}
}

// signedIn keeps the session in its cookies and ends the flow.
func (p *Plugin) signedIn(w http.ResponseWriter, r *http.Request, data map[string]any, returnTo string) {
	expires, _ := data["expires_in"].(float64)
	p.setCookie(w, sessionCookie, str(data, "access_token"), time.Duration(expires)*time.Second, http.SameSiteLaxMode)
	p.setCookie(w, refreshCookie, str(data, "refresh_token"), p.g.Auth().RefreshToken.TTL, http.SameSiteLaxMode)
	if cookie(r, mfaCookie) != "" {
		p.clearCookie(w, mfaCookie)
	}
	http.Redirect(w, r, p.target(returnTo), http.StatusSeeOther) //nolint:gosec // target allows only same-origin paths and the configured origins (G710)
}

// --- two-step verification ---

// mfaState is what the MFA cookie holds between the password and the code.
type mfaState struct {
	Ticket   string           `json:"t"`
	Factors  []map[string]any `json:"f"`
	ReturnTo string           `json:"r,omitempty"`
}

func (p *Plugin) startMFA(w http.ResponseWriter, r *http.Request, data map[string]any, returnTo string) {
	st := mfaState{Ticket: str(data, "mfa_token"), ReturnTo: returnTo}
	list, _ := data["factors"].([]any)
	for _, f := range list {
		if m, ok := f.(map[string]any); ok {
			st.Factors = append(st.Factors, m)
		}
	}
	raw, _ := json.Marshal(st) // plain strings and maps always encode
	p.setCookie(w, mfaCookie, base64.RawURLEncoding.EncodeToString(raw), p.g.Auth().MFA.LoginTokenTTL, http.SameSiteLaxMode)
	http.Redirect(w, r, p.base+"/mfa", http.StatusSeeOther)
}

func (p *Plugin) mfaState(r *http.Request) (mfaState, bool) {
	var st mfaState
	raw, err := base64.RawURLEncoding.DecodeString(cookie(r, mfaCookie))
	if err != nil || json.Unmarshal(raw, &st) != nil || st.Ticket == "" {
		return mfaState{}, false
	}
	return st, true
}

func (p *Plugin) mfaView(w http.ResponseWriter, r *http.Request, st mfaState, selected string) *view {
	v := p.newView(w, r, "mfa_title")
	for _, f := range st.Factors {
		label := str(f, "label")
		if label == "" {
			label = str(f, "type")
		}
		if d := str(f, "destination"); d != "" {
			label += " (" + d + ")"
		}
		id := str(f, "id")
		v.Factors = append(v.Factors, factorView{ID: id, Label: label, Checked: id == selected || selected == "" && f["default"] == true})
	}
	return v
}

func (p *Plugin) mfaPage(w http.ResponseWriter, r *http.Request) {
	st, ok := p.mfaState(r)
	if !ok {
		http.Redirect(w, r, p.base+"/sign-in", http.StatusSeeOther)
		return
	}
	p.render(w, r, http.StatusOK, "mfa", p.mfaView(w, r, st, ""))
}

func (p *Plugin) mfa(w http.ResponseWriter, r *http.Request) {
	st, ok := p.mfaState(r)
	if !ok {
		http.Redirect(w, r, p.base+"/sign-in", http.StatusSeeOther)
		return
	}
	factor := r.PostFormValue("factor_id")
	var rep reply
	var err error
	if r.PostFormValue("action") == "send" {
		rep, err = p.call(w, r, http.MethodPost, "/auth/mfa/challenge", map[string]any{"factor_id": factor}, st.Ticket)
	} else {
		body := map[string]any{"code": strings.TrimSpace(r.PostFormValue("code"))}
		if factor == "recovery" {
			body["type"] = "recovery"
		} else if factor != "" {
			body["factor_id"] = factor
		}
		rep, err = p.call(w, r, http.MethodPost, "/auth/mfa/verify", body, st.Ticket)
	}
	switch {
	case err != nil:
		p.fail(w, r, err)
	case rep.status == http.StatusUnauthorized: // the ticket expired
		p.clearCookie(w, mfaCookie)
		v := p.newView(w, r, "sign_in_title")
		v.Errors = []string{v.T["error_mfa_expired"]}
		p.render(w, r, http.StatusUnauthorized, "sign-in", v)
	case !rep.ok():
		v := p.mfaView(w, r, st, factor)
		v.Errors = problems(v.T, rep, "error_invalid_code")
		p.render(w, r, rep.status, "mfa", v)
	case r.PostFormValue("action") == "send":
		v := p.mfaView(w, r, st, factor)
		v.Notice = format(v.T["mfa_sent"], "destination", str(rep.data(), "destination"))
		p.render(w, r, http.StatusOK, "mfa", v)
	default:
		p.signedIn(w, r, rep.data(), st.ReturnTo)
	}
}

// --- sign up and email verification ---

func (p *Plugin) signUp(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.PostFormValue("email"))
	rep, err := p.call(w, r, http.MethodPost, "/auth/register", map[string]any{"email": email, "password": r.PostFormValue("password")}, "")
	switch {
	case err != nil:
		p.fail(w, r, err)
	case rep.ok(): // the same answer whether or not the address was free
		http.Redirect(w, r, p.base+"/check-email", http.StatusSeeOther)
	default:
		v := p.newView(w, r, "sign_up_title")
		v.Email, v.Errors = email, problems(v.T, rep, "error_generic")
		p.render(w, r, rep.status, "sign-up", v)
	}
}

func (p *Plugin) resend(w http.ResponseWriter, r *http.Request) {
	rep, err := p.call(w, r, http.MethodPost, "/auth/email/verify/resend", map[string]any{"email": strings.TrimSpace(r.PostFormValue("email"))}, "")
	if err != nil {
		p.fail(w, r, err)
		return
	}
	v := p.newView(w, r, "check_email_title")
	if rep.ok() {
		v.Notice = v.T["resent"]
	} else {
		v.Errors = problems(v.T, rep, "error_generic")
	}
	p.render(w, r, rep.status, "check-email", v)
}

// verifyPage never verifies: mail scanners follow a message's links with GET, and would confirm
// a registration its recipient never made. With the token of an email link it answers a page
// whose one button posts the token (the CSRF-guarded POST verifies); without one it asks for the
// code.
func (p *Plugin) verifyPage(w http.ResponseWriter, r *http.Request) {
	v := p.newView(w, r, "verify_title")
	v.Token = r.URL.Query().Get("token")
	v.TokenGiven = v.Token != ""
	p.render(w, r, http.StatusOK, "verify", v)
}

func (p *Plugin) verify(w http.ResponseWriter, r *http.Request) {
	p.verifyToken(w, r, strings.TrimSpace(r.PostFormValue("token")))
}

func (p *Plugin) verifyToken(w http.ResponseWriter, r *http.Request, token string) {
	rep, err := p.call(w, r, http.MethodPost, "/auth/email/verify", map[string]any{"token": token}, "")
	switch {
	case err != nil:
		p.fail(w, r, err)
	case rep.ok():
		p.message(w, r, http.StatusOK, "verified_title", "verified", p.base+"/sign-in", "sign_in")
	default:
		v := p.newView(w, r, "verify_title")
		v.Errors = problems(v.T, rep, "error_invalid_token")
		p.render(w, r, rep.status, "verify", v)
	}
}

// --- forgot and reset password ---

func (p *Plugin) forgot(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.PostFormValue("email"))
	rep, err := p.call(w, r, http.MethodPost, "/auth/password/forgot", map[string]any{"email": email}, "")
	switch {
	case err != nil:
		p.fail(w, r, err)
	case rep.ok(): // the same answer whether or not an account exists
		p.message(w, r, http.StatusOK, "forgot_title", "forgot_sent", p.base+"/sign-in", "back_to_sign_in")
	default:
		v := p.newView(w, r, "forgot_title")
		v.Email, v.Errors = email, problems(v.T, rep, "error_generic")
		p.render(w, r, rep.status, "forgot", v)
	}
}

func (p *Plugin) resetPage(w http.ResponseWriter, r *http.Request) {
	v := p.newView(w, r, "reset_title")
	v.Token = r.URL.Query().Get("token")
	v.TokenGiven = v.Token != ""
	p.render(w, r, http.StatusOK, "reset", v)
}

func (p *Plugin) reset(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.PostFormValue("token"))
	rep, err := p.call(w, r, http.MethodPost, "/auth/password/reset", map[string]any{"token": token, "new_password": r.PostFormValue("new_password")}, "")
	switch {
	case err != nil:
		p.fail(w, r, err)
	case rep.ok(): // every session ended with the reset
		p.clearSession(w, r)
		p.message(w, r, http.StatusOK, "reset_done_title", "reset_done", p.base+"/sign-in", "sign_in")
	default:
		v := p.newView(w, r, "reset_title")
		v.Token, v.Errors = token, problems(v.T, rep, "error_invalid_token")
		p.render(w, r, rep.status, "reset", v)
	}
}

// --- sign out and refresh ---

func (p *Plugin) signOut(w http.ResponseWriter, r *http.Request) {
	access := p.session(r)
	if access == "" { // an expired access token: renew it once to know the session to end
		if rep, err := p.renew(w, r); err == nil && rep.ok() {
			access = str(rep.data(), "access_token")
		}
	}
	if access != "" {
		if _, err := p.call(w, r, http.MethodPost, "/auth/logout", nil, access); err != nil {
			p.fail(w, r, err)
			return
		}
	}
	p.clearSession(w, r)
	http.Redirect(w, r, p.cfg.AfterSignOut, http.StatusSeeOther)
}

func (p *Plugin) clearSession(w http.ResponseWriter, r *http.Request) {
	for _, name := range []string{sessionCookie, refreshCookie, mfaCookie} {
		if cookie(r, name) != "" {
			p.clearCookie(w, name)
		}
	}
}

// renew rotates the refresh cookie's token through core's refresh route; rep is not ok without
// one.
func (p *Plugin) renew(w http.ResponseWriter, r *http.Request) (reply, error) {
	rt := cookie(r, refreshCookie)
	if rt == "" {
		return reply{status: http.StatusUnauthorized}, nil
	}
	return p.call(w, r, http.MethodPost, "/auth/token/refresh", map[string]any{"refresh_token": rt}, "")
}

// refresh renews the session and returns to return_to; without a usable refresh cookie it asks the
// user to sign in, then returns there. This GET rotates the refresh token, and the cookie is
// SameSite=Lax, so another site can navigate the browser here: twice with the same cookie reads
// as a reused token and ends the session. So a navigation the browser says another site started
// (Sec-Fetch-Site neither same-origin nor none) rotates nothing; the page offers a link, and
// following it is a same-origin navigation. A browser that sends no Sec-Fetch-Site is served as
// before.
func (p *Plugin) refresh(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")
	site := r.Header.Get("Sec-Fetch-Site")
	if p.secure && cookie(r, refreshCookie) != "" && site != "" && site != "same-origin" && site != "none" {
		p.message(w, r, http.StatusOK, "refresh_title", "refresh_intro",
			p.base+"/refresh?return_to="+url.QueryEscape(p.target(returnTo)), "continue")
		return
	}
	if p.secure {
		rep, err := p.renew(w, r)
		switch {
		case err != nil:
			p.fail(w, r, err)
			return
		case rep.ok():
			p.signedIn(w, r, rep.data(), returnTo)
			return
		}
		if cookie(r, refreshCookie) != "" {
			p.clearCookie(w, refreshCookie)
		}
	}
	http.Redirect(w, r, p.base+"/sign-in?return_to="+url.QueryEscape(p.target(returnTo)), http.StatusSeeOther)
}

// toSignIn sends a browser without a session through refresh (then sign-in), back to this page.
func (p *Plugin) toSignIn(w http.ResponseWriter, r *http.Request, back string) {
	http.Redirect(w, r, p.base+"/refresh?return_to="+url.QueryEscape(back), http.StatusSeeOther)
}
