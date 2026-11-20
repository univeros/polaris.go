package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/token"
)

// Route names.
const (
	RouteRegisterOptions     = "polaris.passkey.register-options"
	RouteRegisterVerify      = "polaris.passkey.register-verify"
	RouteAuthenticateOptions = "polaris.passkey.authenticate-options"
	RouteAuthenticateVerify  = "polaris.passkey.authenticate-verify"
	RouteList                = "polaris.passkey.list"
	RouteRename              = "polaris.passkey.rename"
	RouteDelete              = "polaris.passkey.delete"
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
	withUser := func(f func(ctx context.Context, in *endpoint.Input, u model.User) endpoint.Result) endpoint.Endpoint {
		return authed(func(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result {
			u, err := p.g.Repos.Users.Get(ctx, tok.Subject())
			if errors.Is(err, repository.ErrNotFound) {
				return endpoint.Unauthorized()
			}
			if err != nil {
				return p.answer(ctx, http.StatusOK, nil, err)
			}
			return f(ctx, in, u)
		})
	}
	return map[string]endpoint.Endpoint{
		RouteRegisterOptions: withUser(func(ctx context.Context, _ *endpoint.Input, u model.User) endpoint.Result {
			options, err := p.registerOptions(ctx, u)
			return p.answer(ctx, http.StatusOK, options, err)
		}),
		RouteRegisterVerify: withUser(p.registerVerify),
		RouteAuthenticateOptions: endpoint.Func(func(ctx context.Context, _ *endpoint.Input) endpoint.Result {
			options, err := p.authenticateOptions(ctx)
			return p.answer(ctx, http.StatusOK, options, err)
		}),
		RouteAuthenticateVerify: endpoint.Func(p.authenticateVerify),
		RouteList: authed(func(ctx context.Context, _ *endpoint.Input, tok *token.Token) endpoint.Result {
			all, err := p.forUser(ctx, tok.Subject())
			list := make([]any, len(all))
			for i, r := range all {
				list[i] = r.wire()
			}
			return p.answer(ctx, http.StatusOK, list, err)
		}),
		RouteRename: authed(func(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result {
			r, err := p.rename(ctx, tok.Subject(), in.String("id"), in.String("name"))
			if err != nil {
				return p.answer(ctx, http.StatusOK, nil, err)
			}
			return endpoint.Data(http.StatusOK, r.wire())
		}),
		RouteDelete: authed(func(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result {
			err := p.remove(ctx, tok.Subject(), in.String("id"))
			return p.answer(ctx, http.StatusOK, map[string]any{"status": "deleted"}, err)
		}),
	}
}

// registerVerify answers POST /passkey/register/verify: 201 with the passkey and recovery codes.
func (p *Plugin) registerVerify(ctx context.Context, in *endpoint.Input, u model.User) endpoint.Result {
	credential := credentialOf(in)
	if credential == "" {
		return invalid("credential is required.")
	}
	reg, err := p.register(ctx, u, credential, in.String("name"))
	return p.answer(ctx, http.StatusCreated, map[string]any{"passkey": reg.passkey.wire(), "recovery_codes": reg.recoveryCodes}, err)
}

// authenticateVerify answers POST /passkey/authenticate/verify.
func (p *Plugin) authenticateVerify(ctx context.Context, in *endpoint.Input) endpoint.Result {
	credential := credentialOf(in)
	if credential == "" {
		return invalid("credential is required.")
	}
	envelope, err := p.authenticate(ctx, credential, endpoint.Client(ctx))
	return p.answer(ctx, http.StatusOK, envelope, err)
}

// credentialOf is the PublicKeyCredential JSON, sent as an object or as its string.
func credentialOf(in *endpoint.Input) string {
	switch v := in.Value("credential").(type) {
	case map[string]any:
		raw, err := json.Marshal(v)
		if err == nil {
			return string(raw)
		}
	case string:
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// answer answers err as its problem document (an unexpected error as a 500), else status with data.
func (p *Plugin) answer(ctx context.Context, status int, data any, err error) endpoint.Result {
	if err == nil {
		return endpoint.Data(status, data)
	}
	r, ok := asRefusal(err)
	if !ok {
		p.g.Logger.ErrorContext(ctx, "polaris passkey: operation failed", "error", err)
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
	return endpoint.Problem(pr.status, "passkey/"+string(r.kind), pr.title, detail, nil)
}

func invalid(message string) endpoint.Result {
	return endpoint.Problem(http.StatusUnprocessableEntity, "passkey/invalid_input", "Invalid input", message, map[string]any{"errors": []string{message}})
}
