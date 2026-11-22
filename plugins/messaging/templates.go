package messaging

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html"
	"strconv"
	"strings"
	"time"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
)

// TemplateKeys are the bundled templates, each translated in every bundled locale. Email keys have
// a subject, a text and an HTML part; SMS keys a text.
var TemplateKeys = []string{
	"email.verify", "email.reset_password", "email.magic_link", "email.otp", "email.invite", "email.new_device",
	"email.password_changed", "email.account_locked", "email.mfa_enrolled", "email.mfa_factor_removed",
	"email.recovery_codes_regenerated", "email.recovery_code_used", "sms.otp", "sms.new_device",
}

// Locales are the bundled locales.
var Locales = []string{"en", "es", "de", "fr", "pt"}

// Template is a subject (email only), a text and an optional HTML, each with {placeholders}.
type Template struct {
	Subject string
	Text    string
	HTML    string
}

// Translator gives the strings of the templates by id ("email.verify.subject") and locale; ok is
// false when it has none. The plugin's default is the bundled strings plus Config.Strings.
type Translator interface {
	Translate(id, locale string) (s string, ok bool)
}

//go:embed translations/*.json
var translations embed.FS

// bundled holds the embedded strings, locale => id => string, parsed once at init.
var bundled = func() map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, locale := range Locales {
		raw, err := translations.ReadFile("translations/" + locale + ".json")
		if err != nil {
			panic(err) // fixed at build time
		}
		var strs map[string]string
		if err := json.Unmarshal(raw, &strs); err != nil {
			panic(err)
		}
		out[locale] = strs
	}
	return out
}()

// Strings is a Translator over the bundled strings, with the host's additions (locale => id =>
// string) winning over them.
type Strings map[string]map[string]string

// Translate implements Translator.
func (s Strings) Translate(id, locale string) (string, bool) {
	if v, ok := s[locale][id]; ok {
		return v, true
	}
	v, ok := bundled[locale][id]
	return v, ok
}

// Templates resolves and stores template overrides: an organization's in
// polaris_messaging_template (its branding, written with Set), the instance's from Config.Templates.
type Templates struct {
	db       store.Adapter
	clock    clock.Clock
	instance map[string]map[string]Template // locale => key => template
}

// Override returns the organization's override of key in locale, else the instance's; ok false
// when neither exists. organizationID "" skips the organization's.
func (t *Templates) Override(ctx context.Context, key, locale, organizationID string) (Template, bool, error) {
	if organizationID != "" {
		r, err := t.db.FindOne(ctx, TableTemplates, store.Criteria{"organization_id": organizationID, "key": key, "locale": locale})
		if err != nil {
			return Template{}, false, fmt.Errorf("messaging: template override: %w", err)
		}
		if r != nil {
			return Template{Subject: r.String("subject"), Text: r.String("text"), HTML: r.String("html")}, true, nil
		}
	}
	tpl, ok := t.instance[locale][key]
	return tpl, ok, nil
}

// Set stores (or replaces) an organization's override of key in locale. Empty Subject and HTML
// are stored as NULL.
func (t *Templates) Set(ctx context.Context, organizationID, key, locale string, tpl Template) error {
	if organizationID == "" || key == "" || locale == "" {
		return fmt.Errorf("messaging: an override needs an organization id, a key and a locale")
	}
	criteria := store.Criteria{"organization_id": organizationID, "key": key, "locale": locale}
	data := store.Data{"subject": nullable(tpl.Subject), "text": tpl.Text, "html": nullable(tpl.HTML),
		"updated_at": t.clock.Now().UTC().Truncate(time.Second)}
	err := t.db.Tx(ctx, func(ctx context.Context) error {
		n, err := t.db.Update(ctx, TableTemplates, criteria, data)
		if err != nil || n > 0 {
			return err
		}
		row := store.Row{"id": repository.NewID()}
		for k, v := range criteria {
			row[k] = v
		}
		for k, v := range data {
			row[k] = v
		}
		return t.db.Insert(ctx, TableTemplates, row)
	})
	if err != nil {
		return fmt.Errorf("messaging: set template: %w", err)
	}
	return nil
}

// Remove deletes an organization's override; false when there was none.
func (t *Templates) Remove(ctx context.Context, organizationID, key, locale string) (bool, error) {
	n, err := t.db.Delete(ctx, TableTemplates, store.Criteria{"organization_id": organizationID, "key": key, "locale": locale})
	if err != nil {
		return false, fmt.Errorf("messaging: remove template: %w", err)
	}
	return n > 0, nil
}

// renderer resolves a template (organization override, instance override, the locale's strings,
// the default locale's) and substitutes the variables.
type renderer struct {
	templates     *Templates
	translator    Translator
	defaultLocale string
}

// render answers the template key for locale with vars substituted ({name}; HTML-escaped in the
// HTML part). Wraps ErrTemplateNotFound when nothing has the key.
func (r *renderer) render(ctx context.Context, key, locale string, vars map[string]any, organizationID string) (Template, error) {
	tpl, ok, err := r.templates.Override(ctx, key, locale, organizationID)
	if err == nil && !ok {
		tpl, ok, err = r.templates.Override(ctx, key, r.defaultLocale, organizationID)
	}
	if err != nil {
		return Template{}, err
	}
	if !ok {
		tpl, ok = r.bundled(key, locale)
	}
	if !ok {
		tpl, ok = r.bundled(key, r.defaultLocale)
	}
	if !ok {
		return Template{}, fmt.Errorf("%w: no template %q for locale %s", ErrTemplateNotFound, key, locale)
	}
	plain := make([]string, 0, 2*len(vars))
	escaped := make([]string, 0, 2*len(vars))
	for name, value := range vars {
		s := scalar(value)
		plain = append(plain, "{"+name+"}", s)
		escaped = append(escaped, "{"+name+"}", html.EscapeString(s))
	}
	p, e := strings.NewReplacer(plain...), strings.NewReplacer(escaped...)
	return Template{Subject: p.Replace(tpl.Subject), Text: p.Replace(tpl.Text), HTML: e.Replace(tpl.HTML)}, nil
}

func (r *renderer) bundled(key, locale string) (Template, bool) {
	text, ok := r.translator.Translate(key+".text", locale)
	if !ok {
		return Template{}, false
	}
	subject, _ := r.translator.Translate(key+".subject", locale)
	html, _ := r.translator.Translate(key+".html", locale)
	return Template{Subject: subject, Text: text, HTML: html}, true
}

// scalar renders a scalar variable as text: a bool as "true" or "false", numbers in their shortest
// plain form (no exponent); anything else (nil, lists, maps) is "".
func scalar(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return fmt.Sprint(v)
	case float32:
		return strconv.FormatFloat(float64(v), 'f', -1, 32)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case json.Number:
		return v.String()
	}
	return ""
}
