package ui

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strconv"
)

//go:embed templates
var builtin embed.FS

// pageNames are the page templates; each defines "content" for layout.html.
var pageNames = []string{"sign-in", "mfa", "sign-up", "check-email", "verify", "forgot", "reset", "sign-out", "consent", "device", "message"}

// file reads a template file: the host's override, else the built-in one.
func (p *Plugin) file(name string) ([]byte, error) {
	if p.cfg.Templates != nil {
		b, err := fs.ReadFile(p.cfg.Templates, name)
		if err == nil {
			return b, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("ui: Config.Templates: %w", err)
		}
	}
	return builtin.ReadFile("templates/" + name)
}

// parse builds every page (layout + page) and the stylesheet.
func (p *Plugin) parse() error {
	layout, err := p.file("layout.html")
	if err != nil {
		return err
	}
	p.pages = map[string]*template.Template{}
	for _, name := range pageNames {
		src, err := p.file(name + ".html")
		if err != nil {
			return err
		}
		t, err := template.New("layout.html").Parse(string(layout))
		if err == nil {
			_, err = t.New(name + ".html").Parse(string(src))
		}
		if err != nil {
			return fmt.Errorf("ui: template %s.html: %w", name, err)
		}
		p.pages[name] = t
	}
	css, err := p.file("style.css")
	if err != nil {
		return err
	}
	light, dark := p.cfg.PrimaryColor, p.cfg.PrimaryColorDark
	if dark == "" {
		dark = light
	}
	if light != "" {
		css = fmt.Appendf(css, ":root { --accent: %s; }\n", light)
	}
	if dark != "" {
		css = fmt.Appendf(css, "@media (prefers-color-scheme: dark) { :root { --accent: %s; } }\n", dark)
	}
	p.css = css
	return nil
}

// app is what the layout shows of the host.
type app struct{ Name, Logo, Terms, Privacy string }

// view is the data every page renders. Values reach the HTML through html/template, escaped for
// their context.
type view struct {
	Lang     string
	T        map[string]string
	App      app
	Base     string // the pages' URL path
	Title    string
	CSRF     string
	Errors   []string
	Notice   string
	ReturnTo string

	Email, Token string
	TokenGiven   bool
	MinLength    int
	PasswordHint string

	Factors []factorView

	Page, Intro, Redirect, Request, UserCode string
	Client                                   clientView
	Scopes                                   []scopeView

	Text, Link, LinkText string
}

type factorView struct {
	ID, Label string
	Checked   bool
}

type clientView struct{ Name, Logo, Policy, Terms string }

type scopeView struct{ Name, Description string }

// newView starts the data of a page for r: the negotiated messages, the app, a CSRF token.
func (p *Plugin) newView(w http.ResponseWriter, r *http.Request, titleKey string) *view {
	lang, t := negotiate(p.catalogs, r.Header.Get("Accept-Language"))
	minLen := p.g.Auth().Password.MinLength
	return &view{
		Lang: lang, T: t, Base: p.base, Title: t[titleKey], CSRF: p.csrfToken(w, r),
		App:       app{Name: p.cfg.AppName, Logo: p.cfg.LogoURL, Terms: p.cfg.TermsURL, Privacy: p.cfg.PrivacyURL},
		MinLength: minLen, PasswordHint: format(t["password_hint"], "min", strconv.Itoa(minLen)),
	}
}

// render writes page with status. A template error answers a bare 500 (logged): the host's
// override is broken.
func (p *Plugin) render(w http.ResponseWriter, r *http.Request, status int, page string, v *view) {
	var buf bytes.Buffer
	if err := p.pages[page].ExecuteTemplate(&buf, "layout.html", v); err != nil {
		p.g.Logger().ErrorContext(r.Context(), "ui: rendering failed", "page", page, "error", err)
		http.Error(w, "The page could not be rendered.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// message renders the generic page: a title, a text and an optional link, by catalog key.
func (p *Plugin) message(w http.ResponseWriter, r *http.Request, status int, titleKey, textKey, link, linkKey string) {
	v := p.newView(w, r, titleKey)
	v.Text, v.Link, v.LinkText = v.T[textKey], link, v.T[linkKey]
	p.render(w, r, status, "message", v)
}
