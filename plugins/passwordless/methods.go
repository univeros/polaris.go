package passwordless

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/identity"
	"github.com/univeros/polaris-go/mfa"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/notify"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/token"
)

func seconds(d time.Duration) int { return int(d / time.Second) }

// deliver sends a link or code. A failure is logged, never answered: a send must answer the same
// whether the address is known (something was sent) or not.
func (v *service) deliver(ctx context.Context, send func() error) {
	if err := send(); err != nil {
		v.g.Logger.ErrorContext(ctx, "polaris passwordless: delivery failed", "error", err)
	}
}

// --- Magic links ---

type magicLinkData struct {
	Email       string `json:"email"`
	RedirectURI string `json:"redirect_uri"`
}

func (v *service) redirectURI(requested string) (string, error) {
	if requested == "" {
		if len(v.s.redirectURIs) == 0 {
			return "", &Error{Kind: KindRedirectNotAllowed, Detail: "No redirect_uri is configured; pass one of the allowed ones."}
		}
		return v.s.redirectURIs[0], nil
	}
	if !slices.Contains(v.s.redirectURIs, requested) {
		return "", &Error{Kind: KindRedirectNotAllowed, Detail: "redirect_uri is not one of the allowed ones."}
	}
	return requested, nil
}

// sendMagicLink emails a link when the address belongs to an active user, or to nobody and sign-up
// is on; the caller answers the same either way.
func (v *service) sendMagicLink(ctx context.Context, email, redirectURI string) error {
	redirectURI, err := v.redirectURI(redirectURI)
	if err != nil {
		return err
	}
	email = identity.NormalizeEmail(email)
	u, found, err := v.byEmail(ctx, email)
	if err != nil {
		return err
	}
	if (found && u.Status == model.UserStatusDisabled) || (!found && !v.s.signUp) {
		return nil
	}
	tok := newToken()
	if err := v.secrets.issueToken(ctx, kindMagicLink, email, u.ID, tok, v.s.magicLinkTTL, magicLinkData{Email: email, RedirectURI: redirectURI}); err != nil {
		return err
	}
	link := v.s.baseURL + "/magic-link/verify?token=" + url.QueryEscape(tok)
	v.deliver(ctx, func() error {
		return v.g.Mailer.Send(ctx, email, TemplateMagicLink, map[string]any{"link": link, "ttl": seconds(v.s.magicLinkTTL)})
	})
	return nil
}

// verifyMagicLink spends the link's token and opens the session; the application URL to redirect
// to, with the hand-off code.
func (v *service) verifyMagicLink(ctx context.Context, tok string) (string, error) {
	sec, ok, err := v.secrets.spendToken(ctx, kindMagicLink, tok)
	if err != nil {
		return "", err
	}
	var data magicLinkData
	if !ok || json.Unmarshal(sec.data, &data) != nil || data.Email == "" || data.RedirectURI == "" {
		return "", errTokenInvalid
	}
	u, err := v.forEmail(ctx, data.Email)
	if err != nil {
		return "", err
	}
	e, err := v.open(ctx, u, facts{amr: []string{AMRMagicLink}, gate: true})
	if err != nil {
		return "", err
	}
	code, err := v.handOff(ctx, e)
	if err != nil {
		return "", err
	}
	sep := "?"
	if strings.Contains(data.RedirectURI, "?") {
		sep = "&"
	}
	return data.RedirectURI + sep + "code=" + code, nil
}

// --- Email codes ---

var purposes = map[string]string{PurposeSignIn: kindEmailSignIn, PurposeVerifyEmail: kindEmailVerify, PurposeResetPassword: kindEmailReset}

// sendEmailCode emails a code when the purpose applies to the address: an active user, or nobody
// and sign-up on, to sign in; an unverified active user to verify; an active user to reset.
func (v *service) sendEmailCode(ctx context.Context, email, purpose string) error {
	email = identity.NormalizeEmail(email)
	u, found, err := v.byEmail(ctx, email)
	if err != nil {
		return err
	}
	active := found && u.Status != model.UserStatusDisabled
	applies := active
	switch purpose {
	case PurposeSignIn:
		applies = active || (!found && v.s.signUp)
	case PurposeVerifyEmail:
		applies = active && u.EmailVerifiedAt == nil
	}
	if !applies {
		return nil
	}
	code := newCode(v.s.otpLength)
	if err := v.secrets.issueCode(ctx, purposes[purpose], email, u.ID, code, v.s.otpTTL); err != nil {
		return err
	}
	v.deliver(ctx, func() error {
		return v.g.Mailer.Send(ctx, email, notify.TemplateOTPCode, map[string]any{"code": code, "ttl": seconds(v.s.otpTTL)})
	})
	return nil
}

func (v *service) signInWithEmailCode(ctx context.Context, email, code string) (envelope, error) {
	email = identity.NormalizeEmail(email)
	_, ok, err := v.secrets.spendCode(ctx, kindEmailSignIn, email, code)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errCodeInvalid
	}
	u, err := v.forEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return v.open(ctx, u, facts{amr: []string{AMREmailOTP}, gate: true})
}

// spendFor spends a code sent to an existing, enabled account.
func (v *service) spendFor(ctx context.Context, kind, email, code string) (model.User, error) {
	sec, ok, err := v.secrets.spendCode(ctx, kind, identity.NormalizeEmail(email), code)
	if err != nil {
		return model.User{}, err
	}
	if !ok || sec.userID == "" {
		return model.User{}, errCodeInvalid
	}
	u, found, err := v.user(ctx, sec.userID)
	if err != nil {
		return model.User{}, err
	}
	if !found || u.Status == model.UserStatusDisabled {
		return model.User{}, errCodeInvalid
	}
	return u, nil
}

func (v *service) verifyEmail(ctx context.Context, email, code string) error {
	u, err := v.spendFor(ctx, kindEmailVerify, email, code)
	if err != nil || u.EmailVerifiedAt != nil {
		return err
	}
	now := v.now()
	verified, err := v.g.DB.Update(ctx, "auth_users", store.Criteria{"id": u.ID, "email_verified_at": nil}, store.Data{"email_verified_at": now, "updated_at": now})
	if err == nil && verified == 1 {
		v.g.Events.Dispatch(ctx, event.UserEmailVerified{UserID: u.ID, Email: u.Email})
	}
	return err
}

// resetPassword sets a new password and ends every session, as core's reset does. A password
// failing the policy keeps the code.
func (v *service) resetPassword(ctx context.Context, email, code, password string) error {
	policy := identity.PasswordPolicy{MinLength: v.g.Auth.Password.MinLength, Breaches: v.g.Breaches}
	if violations := policy.Validate(ctx, password); len(violations) > 0 {
		return &Error{Kind: KindPasswordInvalid, Detail: violations[0], Errors: violations}
	}
	u, err := v.spendFor(ctx, kindEmailReset, email, code)
	if err != nil {
		return err
	}
	hash, err := v.g.Hasher.Hash(password)
	if err != nil {
		return err
	}
	now := v.now()
	data := store.Data{"password_hash": hash, "failed_login_count": 0, "failed_login_at": nil, "locked_until": nil, "updated_at": now}
	if u.Status == model.UserStatusLocked {
		data["status"] = model.UserStatusActive
	}
	if u.EmailVerifiedAt == nil {
		data["email_verified_at"] = now
	}
	err = v.g.DB.Tx(ctx, func(ctx context.Context) error {
		if _, err := v.g.DB.Update(ctx, "auth_users", store.Criteria{"id": u.ID}, data); err != nil {
			return err
		}
		_, err := v.g.Sessions.RevokeAll(ctx, u.ID, model.RevokedPasswordChange)
		return err
	})
	if err != nil {
		return err
	}
	v.g.Events.Dispatch(ctx, event.PasswordChanged{UserID: u.ID, Method: event.PasswordMethodReset})
	return nil
}

// --- Phones ---

var phoneNoise = regexp.MustCompile(`[\s().-]`)

const msgPhoneInvalid = "phone must be an E.164 number, +15551234567."

// normalizePhone is the number in E.164, spaces, dashes and parentheses removed.
func normalizePhone(phone string) (string, error) {
	e164 := phoneNoise.ReplaceAllString(phone, "")
	if !mfa.ValidE164(e164) {
		return "", &Error{Kind: KindInvalidInput, Detail: msgPhoneInvalid, Errors: []string{msgPhoneInvalid}}
	}
	return e164, nil
}

// phoneOwner is the user a verified number belongs to, "" for none.
func (v *service) phoneOwner(ctx context.Context, e164 string) (string, error) {
	row, err := v.g.DB.FindOne(ctx, TablePhones, store.Criteria{"e164": e164})
	if err != nil || row == nil {
		return "", err
	}
	return row.String("user_id"), nil
}

// phoneOf is the user's verified number, "" for none.
func (v *service) phoneOf(ctx context.Context, userID string) (string, error) {
	row, err := v.g.DB.FindOne(ctx, TablePhones, store.Criteria{"user_id": userID})
	if err != nil || row == nil {
		return "", err
	}
	return row.String("e164"), nil
}

// attachPhone sets the user's verified phone, replacing the one they had. The unique index on the
// number settles a race between two users confirming it.
func (v *service) attachPhone(ctx context.Context, userID, e164 string) error {
	owner, err := v.phoneOwner(ctx, e164)
	if err != nil {
		return err
	}
	if owner != "" && owner != userID {
		return errPhoneTaken
	}
	now := v.now()
	err = v.g.DB.Tx(ctx, func(ctx context.Context) error {
		if _, err := v.g.DB.Delete(ctx, TablePhones, store.Criteria{"user_id": userID}); err != nil {
			return err
		}
		return v.g.DB.Insert(ctx, TablePhones, store.Row{"user_id": userID, "e164": e164, "verified_at": now, "created_at": now})
	})
	if errors.Is(err, store.ErrDuplicate) {
		return errPhoneTaken
	}
	return err
}

func (v *service) sendPhoneCode(ctx context.Context, kind, e164, userID string) error {
	code := newCode(v.s.otpLength)
	if err := v.secrets.issueCode(ctx, kind, e164, userID, code, v.s.otpTTL); err != nil {
		return err
	}
	v.deliver(ctx, func() error { return v.g.SMS.Send(ctx, e164, "Your verification code is "+code+".") })
	return nil
}

// sendPhone texts a sign-in code when the number is an enabled user's verified phone.
func (v *service) sendPhone(ctx context.Context, phone string) error {
	e164, err := normalizePhone(phone)
	if err != nil {
		return err
	}
	owner, err := v.phoneOwner(ctx, e164)
	if err != nil || owner == "" {
		return err
	}
	u, found, err := v.user(ctx, owner)
	if err != nil || !found || u.Status == model.UserStatusDisabled {
		return err
	}
	return v.sendPhoneCode(ctx, kindPhoneSignIn, e164, u.ID)
}

func (v *service) signInWithPhone(ctx context.Context, phone, code string) (envelope, error) {
	e164, err := normalizePhone(phone)
	if err != nil {
		return nil, err
	}
	sec, ok, err := v.secrets.spendCode(ctx, kindPhoneSignIn, e164, code)
	if err != nil {
		return nil, err
	}
	if !ok || sec.userID == "" {
		return nil, errCodeInvalid
	}
	u, found, err := v.user(ctx, sec.userID)
	if err != nil {
		return nil, err
	}
	owner, err := v.phoneOwner(ctx, e164)
	if err != nil {
		return nil, err
	}
	if !found || owner != u.ID {
		return nil, errCodeInvalid
	}
	return v.open(ctx, u, facts{amr: []string{AMRPhone}, gate: true})
}

// addPhone texts a confirmation code to a number the user wants to add, unless another account
// has it; the caller answers the same either way.
func (v *service) addPhone(ctx context.Context, userID, phone string) error {
	e164, err := normalizePhone(phone)
	if err != nil {
		return err
	}
	owner, err := v.phoneOwner(ctx, e164)
	if err != nil || (owner != "" && owner != userID) {
		return err
	}
	return v.sendPhoneCode(ctx, kindPhoneAdd, e164, userID)
}

// confirmPhone attaches the number once its code is confirmed by the user who asked for it; a code
// confirmed by anyone else is spent (a code proves the phone once).
func (v *service) confirmPhone(ctx context.Context, userID, phone, code string) (string, error) {
	e164, err := normalizePhone(phone)
	if err != nil {
		return "", err
	}
	sec, ok, err := v.secrets.spendCode(ctx, kindPhoneAdd, e164, code)
	if err != nil {
		return "", err
	}
	if !ok || sec.userID != userID {
		return "", errCodeInvalid
	}
	return e164, v.attachPhone(ctx, userID, e164)
}

// --- One-time tokens ---

type oneTimeTokenData struct {
	AMR      []string `json:"amr"`
	Org      *string  `json:"org"`
	AuthTime *int64   `json:"auth_time"`
	MFA      bool     `json:"mfa"`
	SID      string   `json:"sid"`
}

// liveSession reports whether the session (refresh family) of userID has a live token.
func (v *service) liveSession(ctx context.Context, userID, sessionID string) (bool, error) {
	rt, err := v.g.Repos.RefreshTokens.ActiveInFamily(ctx, sessionID)
	if errors.Is(err, repository.ErrNotFound) {
		return false, nil
	}
	return err == nil && rt.UserID == userID, err
}

// generateOneTimeToken mints a token that opens a session like tok's elsewhere. Only a live
// session may (a token without sid, an impersonation, cannot).
func (v *service) generateOneTimeToken(ctx context.Context, tok *token.Token) (map[string]any, error) {
	userID := tok.Subject()
	sid, _ := tok.Claim("sid").(string)
	if sid == "" {
		return nil, errSessionRequired
	}
	live, err := v.liveSession(ctx, userID, sid)
	if err != nil {
		return nil, err
	}
	if !live {
		return nil, errSessionRequired
	}
	data := oneTimeTokenData{AMR: []string{}, SID: sid}
	if list, ok := tok.Claim("amr").([]any); ok {
		for _, m := range list {
			if s, ok := m.(string); ok {
				data.AMR = append(data.AMR, s)
			}
		}
	}
	if org := tok.Organization(); org != "" {
		data.Org = &org
	}
	if at, ok := tok.Claim("auth_time").(int64); ok {
		data.AuthTime = &at
	}
	data.MFA, _ = tok.Claim("mfa").(bool)
	value := newToken()
	if err := v.secrets.issueToken(ctx, kindOneTimeToken, userID, userID, value, v.s.oneTimeTokenTTL, data); err != nil {
		return nil, err
	}
	return map[string]any{"token": value, "expires_in": seconds(v.s.oneTimeTokenTTL)}, nil
}

// verifyOneTimeToken spends the token and opens a session inheriting the generating session's
// amr, mfa, auth_time and organization; it skips the MFA gate, which that session passed. The token
// dies with its session.
func (v *service) verifyOneTimeToken(ctx context.Context, value string) (envelope, error) {
	sec, ok, err := v.secrets.spendToken(ctx, kindOneTimeToken, value)
	if err != nil {
		return nil, err
	}
	var data oneTimeTokenData
	if !ok || sec.userID == "" || json.Unmarshal(sec.data, &data) != nil || data.SID == "" {
		return nil, errTokenInvalid
	}
	u, found, err := v.user(ctx, sec.userID)
	if err != nil {
		return nil, err
	}
	live, err := v.liveSession(ctx, sec.userID, data.SID)
	if err != nil {
		return nil, err
	}
	if !found || !live {
		return nil, errTokenInvalid
	}
	f := facts{amr: data.AMR, mfa: data.MFA, authTime: data.AuthTime}
	if len(f.amr) == 0 {
		f.amr = []string{AMROneTimeToken}
	}
	if data.Org != nil {
		f.organizationID = *data.Org
	}
	return v.open(ctx, u, f)
}
