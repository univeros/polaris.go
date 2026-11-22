package ui

import (
	"net/http"
	"net/url"
	"strings"
)

// The OAuth pages run plugins/oauth's routes in process as the signed-in user; without the oauth
// plugin those routes do not exist and the pages answer an error.

// consentPage shows a parked authorization request. A trusted client, or scopes the user already
// granted, get their code at once: the decision route without approve says which.
func (p *Plugin) consentPage(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("request")
	access := p.session(r)
	switch {
	case id == "":
		p.message(w, r, http.StatusBadRequest, "error_title", "error_request_expired", "", "")
		return
	case access == "":
		p.toSignIn(w, r, p.base+"/consent?request="+url.QueryEscape(id))
		return
	}
	rep, err := p.call(w, r, http.MethodPost, "/oauth2/authorize/decision", map[string]any{"request": id}, access)
	switch {
	case err != nil:
		p.fail(w, r, err)
		return
	case rep.ok():
		http.Redirect(w, r, str(rep.data(), "redirect_to"), http.StatusSeeOther)
		return
	case rep.status == http.StatusUnauthorized:
		p.toSignIn(w, r, p.base+"/consent?request="+url.QueryEscape(id))
		return
	case rep.status != http.StatusConflict: // anything but consent_required
		p.message(w, r, http.StatusBadRequest, "error_title", "error_request_expired", "", "")
		return
	}
	req, err := p.call(w, r, http.MethodGet, "/oauth2/authorize?request="+url.QueryEscape(id), nil, "")
	if err != nil {
		p.fail(w, r, err)
		return
	}
	if !req.ok() {
		p.message(w, r, http.StatusBadRequest, "error_title", "error_request_expired", "", "")
		return
	}
	d := req.data()
	redirect := str(d, "redirect_uri")
	if src := cspSource(redirect); src != "" {
		p.headers(w, src) // the decision's redirect goes there
	}
	v := p.decisionView(w, r, "consent_title", "consent_intro", d)
	v.Page, v.Request = "consent", id
	v.Redirect = format(v.T["consent_redirect"], "uri", redirect)
	p.render(w, r, http.StatusOK, "consent", v)
}

func (p *Plugin) consent(w http.ResponseWriter, r *http.Request) {
	id := r.PostFormValue("request")
	access := p.session(r)
	if access == "" {
		p.toSignIn(w, r, p.base+"/consent?request="+url.QueryEscape(id))
		return
	}
	rep, err := p.call(w, r, http.MethodPost, "/oauth2/authorize/decision", map[string]any{"request": id, "approve": r.PostFormValue("approve") == "true"}, access)
	switch {
	case err != nil:
		p.fail(w, r, err)
	case rep.ok():
		http.Redirect(w, r, str(rep.data(), "redirect_to"), http.StatusSeeOther)
	default:
		p.message(w, r, http.StatusBadRequest, "error_title", "error_request_expired", "", "")
	}
}

// decisionView fills the client and the scopes of a consent or device page.
func (p *Plugin) decisionView(w http.ResponseWriter, r *http.Request, titleKey, introKey string, d map[string]any) *view {
	v := p.newView(w, r, titleKey)
	client, _ := d["client"].(map[string]any)
	v.Client = clientView{Name: str(client, "name"), Policy: str(client, "policy_uri"), Terms: str(client, "tos_uri")}
	if v.Client.Name == "" {
		v.Client.Name = str(client, "client_id")
	}
	v.Intro = format(v.T[introKey], "client", v.Client.Name)
	scopes, _ := d["scopes"].([]any)
	for _, s := range scopes {
		m, _ := s.(map[string]any)
		v.Scopes = append(v.Scopes, scopeView{Name: str(m, "name"), Description: str(m, "description")})
	}
	return v
}

// devicePage asks for the code a device shows, then what the device wants.
func (p *Plugin) devicePage(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.URL.Query().Get("user_code"))
	access := p.session(r)
	if access == "" {
		p.toSignIn(w, r, p.base+"/device?user_code="+url.QueryEscape(code))
		return
	}
	if code == "" {
		p.render(w, r, http.StatusOK, "device", p.newView(w, r, "device_title"))
		return
	}
	rep, err := p.call(w, r, http.MethodGet, "/oauth2/device/verify?user_code="+url.QueryEscape(code), nil, access)
	switch {
	case err != nil:
		p.fail(w, r, err)
	case rep.status == http.StatusUnauthorized:
		p.toSignIn(w, r, p.base+"/device?user_code="+url.QueryEscape(code))
	case !rep.ok():
		v := p.newView(w, r, "device_title")
		v.UserCode, v.Errors = code, []string{v.T["error_device_code"]}
		p.render(w, r, rep.status, "device", v)
	default:
		v := p.decisionView(w, r, "device_title", "device_ask", rep.data())
		v.Page, v.UserCode = "device", str(rep.data(), "user_code")
		p.render(w, r, http.StatusOK, "consent", v)
	}
}

func (p *Plugin) device(w http.ResponseWriter, r *http.Request) {
	code := r.PostFormValue("user_code")
	access := p.session(r)
	if access == "" {
		p.toSignIn(w, r, p.base+"/device?user_code="+url.QueryEscape(code))
		return
	}
	approve := r.PostFormValue("approve") == "true"
	rep, err := p.call(w, r, http.MethodPost, "/oauth2/device/approve", map[string]any{"user_code": code, "approve": approve}, access)
	switch {
	case err != nil:
		p.fail(w, r, err)
	case !rep.ok():
		v := p.newView(w, r, "device_title")
		v.UserCode, v.Errors = code, []string{v.T["error_device_code"]}
		p.render(w, r, rep.status, "device", v)
	case approve:
		p.message(w, r, http.StatusOK, "device_title", "device_approved", "", "")
	default:
		p.message(w, r, http.StatusOK, "device_title", "device_denied", "", "")
	}
}
