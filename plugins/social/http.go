package social

import (
	"context"
	"net/http"
	"strings"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/token"
)

// Route names.
const (
	RouteStart        = "polaris.social.start"
	RouteCallback     = "polaris.social.callback"
	RouteCallbackPost = "polaris.social.callback-post"
	RouteExchange     = "polaris.social.exchange"
	RouteOneTap       = "polaris.social.one-tap"
	RouteAccounts     = "polaris.social.accounts"
	RouteLink         = "polaris.social.link"
	RouteUnlink       = "polaris.social.unlink"
	RouteToken        = "polaris.social.token"
)

func (p *Plugin) endpoints() map[string]endpoint.Endpoint {
	authed := func(f func(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result) endpoint.Endpoint {
		return endpoint.Func(func(ctx context.Context, in *endpoint.Input) endpoint.Result {
			tok := endpoint.Token(ctx)
			if tok == nil {
				return endpoint.Unauthorized()
			}
			return f(ctx, in, tok)
		})
	}
	return map[string]endpoint.Endpoint{
		RouteStart:        endpoint.Func(p.startRoute),
		RouteCallback:     endpoint.Func(p.callbackRoute),
		RouteCallbackPost: endpoint.Func(p.callbackRoute),
		RouteExchange:     endpoint.Func(p.exchangeRoute),
		RouteOneTap:       endpoint.Func(p.oneTapRoute),
		RouteAccounts:     authed(p.accountsRoute),
		RouteLink:         authed(p.linkRoute),
		RouteUnlink:       authed(p.unlinkRoute),
		RouteToken:        authed(p.tokenRoute),
	}
}

// answer answers err as its problem document (an unexpected error as a 500), else 200 with data.
func (p *Plugin) answer(ctx context.Context, data any, err error) endpoint.Result {
	if err == nil {
		return endpoint.Data(http.StatusOK, data)
	}
	r, ok := asRefusal(err)
	if !ok {
		p.g.Logger().ErrorContext(ctx, "polaris social: operation failed", "error", err)
		return endpoint.Error(http.StatusInternalServerError, "server_error", "The server could not complete the request.")
	}
	pr, known := problems[r.kind]
	if !known {
		return invalid(r.detail)
	}
	detail := pr.detail
	if detail == "" {
		detail = r.detail
	}
	return endpoint.Problem(pr.status, "social/"+string(r.kind), pr.title, detail, nil)
}

func invalid(message string) endpoint.Result {
	return endpoint.Problem(http.StatusUnprocessableEntity, "social/invalid_input", "Invalid input", message, map[string]any{"errors": []string{message}})
}

// inputText is a trimmed, non-empty string input ("" otherwise).
func inputText(in *endpoint.Input, field string) string { return strings.TrimSpace(in.String(field)) }

// startRoute answers POST /social/{provider}/start.
func (p *Plugin) startRoute(ctx context.Context, in *endpoint.Input) endpoint.Result {
	s, err := p.start(ctx, in.String("provider"), inputText(in, "redirect_uri"), in.Strings("scopes"), "")
	return p.started(ctx, in, s, err)
}

// linkRoute answers POST /social/{provider}/link: the same flow, linking to the caller.
func (p *Plugin) linkRoute(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result {
	s, err := p.start(ctx, in.String("provider"), inputText(in, "redirect_uri"), in.Strings("scopes"), tok.Subject())
	return p.started(ctx, in, s, err)
}

// started answers a started flow and binds it to the calling browser.
func (p *Plugin) started(ctx context.Context, in *endpoint.Input, s started, err error) endpoint.Result {
	if err != nil {
		return p.answer(ctx, nil, err)
	}
	return p.answer(ctx, s, nil).WithHeader("Set-Cookie", p.settings.bindingHeader(s.State, s.binding))
}

// callbackRoute answers GET and POST /social/{provider}/callback with a 302.
func (p *Plugin) callbackRoute(ctx context.Context, in *endpoint.Input) endpoint.Result {
	location, err := p.callback(ctx, in.String("provider"), callbackParams(in), in.Request, endpoint.Client(ctx))
	if err != nil {
		return p.answer(ctx, nil, err)
	}
	return endpoint.Result{Status: http.StatusFound}.WithHeader("Location", location)
}

// callbackParams is what the provider sent (query and body), without the route parameter.
// Cookies are never input, so a proxy forward never copies one into a URL.
func callbackParams(in *endpoint.Input) map[string]any {
	params := in.All()
	delete(params, "provider")
	return params
}

// exchangeRoute answers POST /social/exchange.
func (p *Plugin) exchangeRoute(ctx context.Context, in *endpoint.Input) endpoint.Result {
	code := inputText(in, "code")
	if code == "" {
		return invalid("code is required.")
	}
	outcome, err := p.exchange(ctx, code)
	return p.answer(ctx, outcome, err)
}

// oneTapRoute answers POST /social/google/one-tap.
func (p *Plugin) oneTapRoute(ctx context.Context, in *endpoint.Input) endpoint.Result {
	credential := inputText(in, "credential")
	if credential == "" {
		return invalid("credential is required.")
	}
	envelope, err := p.idTokenSignIn(ctx, "google", credential, endpoint.Client(ctx))
	return p.answer(ctx, envelope, err)
}

// accountsRoute answers GET /social/accounts: never the tokens.
func (p *Plugin) accountsRoute(ctx context.Context, _ *endpoint.Input, tok *token.Token) endpoint.Result {
	accounts, err := p.accountsOf(ctx, tok.Subject())
	data := make([]any, len(accounts))
	for i, a := range accounts {
		data[i] = a.wire()
	}
	return p.answer(ctx, data, err)
}

// unlinkRoute answers DELETE /social/{provider}.
func (p *Plugin) unlinkRoute(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result {
	err := p.unlink(ctx, tok.Subject(), in.String("provider"))
	return p.answer(ctx, map[string]any{"status": "unlinked"}, err)
}

// tokenRoute answers POST /social/{provider}/token.
func (p *Plugin) tokenRoute(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result {
	issued, err := p.providerToken(ctx, tok.Subject(), in.String("provider"))
	return p.answer(ctx, issued, err)
}
