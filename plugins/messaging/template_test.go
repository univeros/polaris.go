package messaging

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris-go/clock"
	"github.com/univeros/polaris-go/store/memstore"
)

func newRenderer(instance map[string]map[string]Template, strs Strings, locale string) (*renderer, *memstore.Store) {
	db := memstore.New(Models()...)
	tpl := &Templates{db: db, clock: clock.NewFrozen(time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)), instance: instance}
	return &renderer{templates: tpl, translator: strs, defaultLocale: locale}, db
}

func TestEveryBundledTemplateRendersInEveryLocaleWithItsPlaceholders(t *testing.T) {
	ctx := context.Background()
	r, _ := newRenderer(nil, nil, "en")
	vars := map[string]any{"token": "tok", "code": "123456", "ttl": 300, "link": "https://app.example/m", "ip": "203.0.113.7",
		"user_agent": "UA", "method": "reset", "remaining": 3}
	for _, locale := range Locales {
		for _, key := range TemplateKeys {
			got, err := r.render(ctx, key, locale, vars, "")
			check(t, err == nil, "%s %s: %v", locale, key, err)
			check(t, !strings.Contains(got.Text, "{"), "%s %s leaves a placeholder: %q", locale, key, got.Text)
			check(t, strings.HasPrefix(key, "email.") == (got.Subject != ""), "%s %s subject", locale, key)
		}
	}
	otp, _ := r.render(ctx, "email.otp", "en", vars, "")
	check(t, otp.Text == "Your verification code is 123456. It expires in 300 seconds.", "%q", otp.Text)
	check(t, strings.Contains(otp.HTML, "<strong>123456</strong>"), "%q", otp.HTML)
	es, _ := r.render(ctx, "sms.otp", "es", vars, "")
	check(t, es.Text == "Tu código de verificación es 123456.", "%q", es.Text)
}

func TestAnUnknownLocaleFallsBackToTheDefaultAndAnUnknownKeyIsAnError(t *testing.T) {
	r, _ := newRenderer(nil, nil, "es")
	got, err := r.render(context.Background(), "sms.otp", "xx", map[string]any{"code": 1}, "")
	check(t, err == nil && got.Text == "Tu código de verificación es 1.", "%q %v", got.Text, err)
	_, err = r.render(context.Background(), "sms.nope", "en", nil, "")
	check(t, errors.Is(err, ErrTemplateNotFound), "%v", err)
}

func TestOverridesWinInOrderAndTheHtmlIsEscaped(t *testing.T) {
	ctx := context.Background()
	r, db := newRenderer(map[string]map[string]Template{"en": {"email.otp": {Subject: "Code {code}", Text: "Instance says {code}", HTML: "<b>{code}</b>"}}},
		Strings{"en": {"sms.otp.text": "Host string {code}"}}, "en")
	templates := r.templates

	host, _ := r.render(ctx, "sms.otp", "en", map[string]any{"code": 7}, "")
	check(t, host.Text == "Host string 7", "the host's strings win over the bundled ones: %q", host.Text)
	inst, _ := r.render(ctx, "email.otp", "en", map[string]any{"code": "<1>"}, "")
	check(t, inst.Subject == "Code <1>" && inst.Text == "Instance says <1>" && inst.HTML == "<b>&lt;1&gt;</b>", "%+v", inst)

	if err := templates.Set(ctx, "org-a", "email.otp", "en", Template{Text: "Acme says {code}", Subject: "Acme code"}); err != nil {
		t.Fatal(err)
	}
	org, _ := r.render(ctx, "email.otp", "en", map[string]any{"code": 9}, "org-a")
	check(t, org == Template{Subject: "Acme code", Text: "Acme says 9"}, "%+v", org)
	other, _ := r.render(ctx, "email.otp", "en", map[string]any{"code": 9}, "org-b")
	check(t, other.Text == "Instance says 9", "another organization gets the instance's: %q", other.Text)
	if err := templates.Set(ctx, "org-a", "email.otp", "en", Template{Text: "Acme now says {code}"}); err != nil {
		t.Fatal(err)
	}
	n, _ := db.Count(ctx, TableTemplates, nil)
	check(t, n == 1, "set replaces: %d rows", n)
	now, _ := r.render(ctx, "email.otp", "en", map[string]any{"code": 9}, "org-a")
	check(t, now.Text == "Acme now says 9", "%q", now.Text)
	removed, err := templates.Remove(ctx, "org-a", "email.otp", "en")
	check(t, removed && err == nil, "remove")
	removed, _ = templates.Remove(ctx, "org-a", "email.otp", "en")
	check(t, !removed, "removed twice")
	check(t, templates.Set(ctx, "", "k", "en", Template{}) != nil, "an override needs an organization")
}

func TestVariablesRenderAsPHPCastsThem(t *testing.T) {
	cases := map[string]any{"1": true, "": false, "3": int64(3), "2.5": 2.5, "0.5": float32(0.5), "42": json.Number("42"), "x": "x"}
	for want, v := range cases {
		check(t, scalar(v) == want, "%v => %q", v, scalar(v))
	}
	check(t, scalar(nil) == "" && scalar([]any{1}) == "", "non-scalars are empty")
	check(t, htmlEscaper.Replace(`<a href="x">'&'</a>`) == "&lt;a href=&quot;x&quot;&gt;&#039;&amp;&#039;&lt;/a&gt;", "escaping")
	check(t, sibling("sms.otp", KindEmail) == "email.otp" && sibling("otp", KindEmail) == "email.otp", "sibling")
}
