package passwordless

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/manifest"
	"github.com/univeros/polaris.go/token"
)

// Route names.
const (
	RouteMagicLinkSend        = "polaris.passwordless.magic-link-send"
	RouteMagicLinkVerify      = "polaris.passwordless.magic-link-verify"
	RouteMagicLinkExchange    = "polaris.passwordless.magic-link-exchange"
	RouteEmailOTPSend         = "polaris.passwordless.email-otp-send"
	RouteEmailOTPVerify       = "polaris.passwordless.email-otp-verify"
	RouteEmailOTPVerifyEmail  = "polaris.passwordless.email-otp-verify-email"
	RouteEmailOTPResetPasswd  = "polaris.passwordless.email-otp-reset-password"
	RoutePhoneSend            = "polaris.passwordless.phone-send"
	RoutePhoneVerify          = "polaris.passwordless.phone-verify"
	RoutePhoneAdd             = "polaris.passwordless.phone-add"
	RoutePhoneConfirm         = "polaris.passwordless.phone-confirm"
	RouteOneTimeTokenGenerate = "polaris.passwordless.one-time-token-generate"
	RouteOneTimeTokenVerify   = "polaris.passwordless.one-time-token-verify"
)

func (p *Plugin) endpoints() map[string]endpoint.Endpoint {
	v := p.svc
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
		RouteMagicLinkSend:        endpoint.Func(v.magicLinkSend),
		RouteMagicLinkVerify:      endpoint.Func(v.magicLinkVerify),
		RouteMagicLinkExchange:    endpoint.Func(v.magicLinkExchange),
		RouteEmailOTPSend:         endpoint.Func(v.emailOTPSend),
		RouteEmailOTPVerify:       endpoint.Func(v.emailOTPVerify),
		RouteEmailOTPVerifyEmail:  endpoint.Func(v.emailOTPVerifyEmail),
		RouteEmailOTPResetPasswd:  endpoint.Func(v.emailOTPResetPassword),
		RoutePhoneSend:            endpoint.Func(v.phoneSend),
		RoutePhoneVerify:          endpoint.Func(v.phoneVerify),
		RoutePhoneAdd:             authed(v.phoneAdd),
		RoutePhoneConfirm:         authed(v.phoneConfirm),
		RouteOneTimeTokenGenerate: authed(v.oneTimeTokenGenerate),
		RouteOneTimeTokenVerify:   endpoint.Func(v.oneTimeTokenVerify),
	}
}

// refuse answers a refused step as its problem document, any other error as a 500.
func (v *service) refuse(ctx context.Context, err error) endpoint.Result {
	var e *Error
	if !errors.As(err, &e) {
		v.g.Logger().ErrorContext(ctx, "polaris passwordless: operation failed", "error", err)
		return endpoint.Error(http.StatusInternalServerError, "server_error", "The server could not complete the request.")
	}
	var ext map[string]any
	if len(e.Errors) > 0 {
		ext = map[string]any{"errors": e.Errors}
	}
	problem := func(status int, title string) endpoint.Result {
		return endpoint.Problem(status, "passwordless/"+string(e.Kind), title, e.Detail, ext)
	}
	switch e.Kind {
	case KindRedirectNotAllowed:
		return problem(http.StatusUnprocessableEntity, "Redirect not allowed")
	case KindCodeInvalid:
		return problem(http.StatusUnprocessableEntity, "Invalid code")
	case KindTokenInvalid:
		return problem(http.StatusUnprocessableEntity, "Invalid token")
	case KindAccountDisabled:
		return problem(http.StatusForbidden, "Account disabled")
	case KindPasswordInvalid:
		return problem(http.StatusUnprocessableEntity, "Invalid password")
	case KindPhoneTaken:
		return problem(http.StatusConflict, "Phone taken")
	case KindSessionRequired:
		return problem(http.StatusForbidden, "Session required")
	}
	return problem(http.StatusUnprocessableEntity, "Invalid input")
}

func invalid(message string) endpoint.Result {
	return endpoint.Problem(http.StatusUnprocessableEntity, "passwordless/invalid_input", "Invalid input", message, map[string]any{"errors": []string{message}})
}

func sent() endpoint.Result {
	return endpoint.Data(http.StatusAccepted, map[string]any{"status": "sent"})
}

// text is a field trimmed as PHP's trim(); "" when absent, not a string or blank.
func text(in *endpoint.Input, field string) string {
	return strings.Trim(in.String(field), " \t\n\r\x00\x0B")
}

// email is the email field when it is a valid address, "" otherwise.
func email(in *endpoint.Input) string {
	if e := text(in, "email"); manifest.IsEmail(e) {
		return e
	}
	return ""
}

func (v *service) magicLinkSend(ctx context.Context, in *endpoint.Input) endpoint.Result {
	addr := email(in)
	if addr == "" {
		return invalid("A valid email address is required.")
	}
	if err := v.sendMagicLink(ctx, addr, text(in, "redirect_uri")); err != nil {
		return v.refuse(ctx, err)
	}
	return sent()
}

func (v *service) magicLinkVerify(ctx context.Context, in *endpoint.Input) endpoint.Result {
	tok := text(in, "token")
	if tok == "" {
		return invalid("token is required.")
	}
	location, err := v.verifyMagicLink(ctx, tok)
	if err != nil {
		return v.refuse(ctx, err)
	}
	return endpoint.Result{Status: http.StatusFound}.WithHeader("Location", location)
}

func (v *service) magicLinkExchange(ctx context.Context, in *endpoint.Input) endpoint.Result {
	code := text(in, "code")
	if code == "" {
		return invalid("code is required.")
	}
	e, err := v.exchange(ctx, code)
	if err != nil {
		return v.refuse(ctx, err)
	}
	return endpoint.Data(http.StatusOK, e)
}

func (v *service) emailOTPSend(ctx context.Context, in *endpoint.Input) endpoint.Result {
	addr := email(in)
	purpose := text(in, "purpose")
	if purpose == "" {
		purpose = PurposeSignIn
	}
	if addr == "" {
		return invalid("A valid email address is required.")
	}
	if _, ok := purposes[purpose]; !ok {
		return invalid("purpose must be one of sign-in, verify-email, reset-password.")
	}
	if err := v.sendEmailCode(ctx, addr, purpose); err != nil {
		return v.refuse(ctx, err)
	}
	return sent()
}

func (v *service) emailOTPVerify(ctx context.Context, in *endpoint.Input) endpoint.Result {
	addr, code := email(in), text(in, "code")
	if addr == "" || code == "" {
		return invalid("A valid email address and the code are required.")
	}
	e, err := v.signInWithEmailCode(ctx, addr, code)
	if err != nil {
		return v.refuse(ctx, err)
	}
	return endpoint.Data(http.StatusOK, e)
}

func (v *service) emailOTPVerifyEmail(ctx context.Context, in *endpoint.Input) endpoint.Result {
	addr, code := email(in), text(in, "code")
	if addr == "" || code == "" {
		return invalid("A valid email address and the code are required.")
	}
	if err := v.verifyEmail(ctx, addr, code); err != nil {
		return v.refuse(ctx, err)
	}
	return endpoint.Data(http.StatusOK, map[string]any{"status": "verified"})
}

func (v *service) emailOTPResetPassword(ctx context.Context, in *endpoint.Input) endpoint.Result {
	addr, code, password := email(in), text(in, "code"), in.String("password")
	if addr == "" || code == "" || password == "" {
		return invalid("A valid email address, the code and the new password are required.")
	}
	if err := v.resetPassword(ctx, addr, code, password); err != nil {
		return v.refuse(ctx, err)
	}
	return endpoint.Data(http.StatusOK, map[string]any{"status": "password_reset"})
}

func (v *service) phoneSend(ctx context.Context, in *endpoint.Input) endpoint.Result {
	phone := text(in, "phone")
	if phone == "" {
		return invalid("phone is required.")
	}
	if err := v.sendPhone(ctx, phone); err != nil {
		return v.refuse(ctx, err)
	}
	return sent()
}

func (v *service) phoneVerify(ctx context.Context, in *endpoint.Input) endpoint.Result {
	phone, code := text(in, "phone"), text(in, "code")
	if phone == "" || code == "" {
		return invalid("phone and code are required.")
	}
	e, err := v.signInWithPhone(ctx, phone, code)
	if err != nil {
		return v.refuse(ctx, err)
	}
	return endpoint.Data(http.StatusOK, e)
}

func (v *service) phoneAdd(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result {
	phone := text(in, "phone")
	if phone == "" {
		return invalid("phone is required.")
	}
	if err := v.addPhone(ctx, tok.Subject(), phone); err != nil {
		return v.refuse(ctx, err)
	}
	return sent()
}

func (v *service) phoneConfirm(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result {
	phone, code := text(in, "phone"), text(in, "code")
	if phone == "" || code == "" {
		return invalid("phone and code are required.")
	}
	e164, err := v.confirmPhone(ctx, tok.Subject(), phone, code)
	if err != nil {
		return v.refuse(ctx, err)
	}
	return endpoint.Data(http.StatusOK, map[string]any{"phone": e164, "verified": true})
}

func (v *service) oneTimeTokenGenerate(ctx context.Context, _ *endpoint.Input, tok *token.Token) endpoint.Result {
	generated, err := v.generateOneTimeToken(ctx, tok)
	if err != nil {
		return v.refuse(ctx, err)
	}
	return endpoint.Data(http.StatusCreated, generated)
}

func (v *service) oneTimeTokenVerify(ctx context.Context, in *endpoint.Input) endpoint.Result {
	value := text(in, "token")
	if value == "" {
		return invalid("token is required.")
	}
	e, err := v.verifyOneTimeToken(ctx, value)
	if err != nil {
		return v.refuse(ctx, err)
	}
	return endpoint.Data(http.StatusOK, e)
}
