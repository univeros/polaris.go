package passkey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/univeros/polaris-go/mfa"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/token"
)

// DefaultName names a passkey registered without one.
const DefaultName = "Passkey"

const (
	maxName      = 80
	challengeLen = 32
	register     = "register"
	authenticate = "authenticate"
)

// ceremony is what a challenge was issued for, in the cache under the challenge.
type ceremony struct {
	Purpose string `json:"purpose"`
	UserID  string `json:"user_id,omitempty"`
}

// registerOptions are the creation options for navigator.credentials.create(): a discoverable
// credential, the user's passkeys excluded.
func (p *Plugin) registerOptions(ctx context.Context, u model.User) (map[string]any, error) {
	existing, err := p.forUser(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	exclude := make([]string, len(existing))
	for i, r := range existing {
		exclude[i] = r.CredentialID
	}
	challenge := random(challengeLen)
	display := u.Email
	if u.DisplayName != nil && *u.DisplayName != "" {
		display = *u.DisplayName
	}
	if err := p.keep(ctx, challenge, ceremony{Purpose: register, UserID: u.ID}); err != nil {
		return nil, err
	}
	return p.settings.creationOptions(challenge, u.ID, u.Email, display, exclude), nil
}

// registered is a stored passkey and, for the user's first factor, core's recovery codes.
type registered struct {
	passkey       record
	recoveryCodes []string
}

// register stores the credential the browser created; when passkeys are factors, as a confirmed
// core factor too, in one transaction.
func (p *Plugin) register(ctx context.Context, u model.User, credential, name string) (registered, error) {
	name, err := checkName(name)
	if err != nil {
		return registered{}, err
	}
	c, err := p.clientData(credential, "webauthn.create")
	if err != nil {
		return registered{}, err
	}
	entry, err := p.take(ctx, c.clientData.Challenge, register)
	if err != nil {
		return registered{}, err
	}
	if entry.UserID != u.ID {
		return registered{}, &refusal{kindChallengeInvalid, "The challenge was issued to another user."}
	}
	att, err := p.settings.attest(c)
	if err != nil {
		return registered{}, err
	}
	dup, err := p.find(ctx, store.Criteria{"credential_id": att.credentialID})
	if err != nil {
		return registered{}, err
	}
	if dup != nil {
		return registered{}, errInvalid("this credential is already registered")
	}
	now := p.now()
	r := record{ID: repository.NewID(), UserID: u.ID, CredentialID: att.credentialID, PublicKey: att.publicKey, Counter: int64(att.counter),
		AAGUID: att.aaguid, Transports: att.transports, BackupEligible: att.backupEligible, BackedUp: att.backedUp, Name: name, CreatedAt: now}
	out := registered{passkey: r, recoveryCodes: []string{}}
	err = p.g.DB.Tx(ctx, func(ctx context.Context) error {
		if !p.settings.mfaFactor {
			return p.insert(ctx, r)
		}
		f := model.MFAFactor{ID: repository.NewID(), UserID: u.ID, Type: FactorType, Label: &name, CreatedAt: now, UpdatedAt: now}
		out.passkey.FactorID = f.ID
		if err := p.g.Repos.MFAFactors.Insert(ctx, f); err != nil {
			return err
		}
		if err := p.insert(ctx, out.passkey); err != nil {
			return err
		}
		confirmed, err := p.g.MFA.ConfirmFactor(ctx, f)
		out.recoveryCodes = confirmed.RecoveryCodes
		return err
	})
	if out.recoveryCodes == nil {
		out.recoveryCodes = []string{}
	}
	return out, err
}

// authenticateOptions are the request options for navigator.credentials.get(), discoverable.
func (p *Plugin) authenticateOptions(ctx context.Context) (map[string]any, error) {
	challenge := random(challengeLen)
	if err := p.keep(ctx, challenge, ceremony{Purpose: authenticate}); err != nil {
		return nil, err
	}
	return p.settings.requestOptions(challenge), nil
}

// authenticate signs in with an assertion: core's login envelope, or its mfa_required ticket.
func (p *Plugin) authenticate(ctx context.Context, credential string, client token.ClientContext) (map[string]any, error) {
	r, a, err := p.assert(ctx, credential, nil)
	if err != nil {
		return nil, err
	}
	u, err := p.g.Repos.Users.Get(ctx, r.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, errInvalid("the credential belongs to nobody")
	}
	if err != nil {
		return nil, err
	}
	return p.openSession(ctx, u, client, a.userVerified, r.FactorID)
}

// verifyFactor is the second-factor check core delegates: the assertion must be the passkey
// behind factor.
func (p *Plugin) verifyFactor(ctx context.Context, f model.MFAFactor, credential string) error {
	expected, err := p.find(ctx, store.Criteria{"factor_id": f.ID})
	if err != nil {
		return err
	}
	if expected == nil || expected.UserID != f.UserID {
		return errInvalid("no passkey backs this factor")
	}
	r, _, err := p.assert(ctx, credential, expected)
	if err != nil {
		return err
	}
	if r.ID != expected.ID {
		return errInvalid("another passkey answered")
	}
	return nil
}

// assert takes the challenge, finds the passkey the assertion names, verifies it for the user it
// is expected for (its owner when nil) and records the use.
func (p *Plugin) assert(ctx context.Context, credential string, expected *record) (record, asserted, error) {
	c, err := p.clientData(credential, "webauthn.get")
	if err != nil {
		return record{}, asserted{}, err
	}
	if _, err := p.take(ctx, c.clientData.Challenge, authenticate); err != nil {
		return record{}, asserted{}, err
	}
	found, err := p.find(ctx, store.Criteria{"credential_id": c.id})
	if err != nil {
		return record{}, asserted{}, err
	}
	if found == nil {
		return record{}, asserted{}, errInvalid("unknown credential")
	}
	owner := found.UserID
	if expected != nil {
		owner = expected.UserID
	}
	a, err := p.settings.assert(c, *found, owner)
	if err != nil {
		return record{}, asserted{}, err
	}
	if err := p.used(ctx, *found, a); err != nil {
		return record{}, asserted{}, err
	}
	return *found, a, nil
}

func (p *Plugin) owned(ctx context.Context, userID, id string) (record, error) {
	r, err := p.find(ctx, store.Criteria{"id": id})
	if err != nil {
		return record{}, err
	}
	if r == nil || r.UserID != userID {
		return record{}, &refusal{kindNotFound, "No such passkey."}
	}
	return *r, nil
}

// rename names the passkey and the factor it backs.
func (p *Plugin) rename(ctx context.Context, userID, id, name string) (record, error) {
	r, err := p.owned(ctx, userID, id)
	if err != nil {
		return record{}, err
	}
	if name, err = checkName(name); err != nil {
		return record{}, err
	}
	if _, err := p.g.DB.Update(ctx, TablePasskeys, store.Criteria{"id": r.ID}, store.Data{"name": name}); err != nil {
		return record{}, err
	}
	if r.FactorID != "" {
		// The factor may have gone under core's route; the passkey keeps its name.
		if _, err := p.g.MFA.UpdateFactor(ctx, userID, r.FactorID, &name, false); err != nil && !errors.Is(err, mfa.ErrFactorNotFound) {
			return record{}, err
		}
	}
	r.Name = name
	return r, nil
}

// remove deletes the passkey and the core factor it backs; last_factor when core's enforcement
// protects that factor.
func (p *Plugin) remove(ctx context.Context, userID, id string) error {
	r, err := p.owned(ctx, userID, id)
	if err != nil {
		return err
	}
	if r.FactorID != "" {
		err := p.g.MFA.RemoveFactor(ctx, userID, r.FactorID)
		switch {
		case errors.Is(err, mfa.ErrLastFactorProtected):
			return &refusal{kindLastFactor, "Enrol another factor before removing your last one."}
		case err != nil && !errors.Is(err, mfa.ErrFactorNotFound):
			return err
		}
	}
	_, err = p.g.DB.Delete(ctx, TablePasskeys, store.Criteria{"id": r.ID})
	return err
}

// clientData parses the credential and checks what the browser signed before anything is spent:
// the ceremony type and an origin of the plugin's.
func (p *Plugin) clientData(credential, ceremonyType string) (parsedCredential, error) {
	c, ok := parseCredential(credential)
	if !ok {
		return parsedCredential{}, &refusal{kindInvalidInput, "credential must be the PublicKeyCredential JSON the browser produced."}
	}
	if c.clientData.Type != ceremonyType {
		return parsedCredential{}, errInvalid("the credential is for another ceremony")
	}
	if !slices.Contains(p.settings.origins, c.clientData.Origin) {
		return parsedCredential{}, &refusal{kindOriginMismatch, "The credential was signed for an origin this relying party does not serve."}
	}
	return c, nil
}

// keep stores the ceremony under its challenge for ChallengeTTL.
func (p *Plugin) keep(ctx context.Context, challenge []byte, c ceremony) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return p.g.Cache.Set(ctx, challengeKey(b64(challenge)), raw, p.settings.challengeTTL)
}

// take consumes the ceremony a challenge was issued for, once: of concurrent takes, only the one
// that claims the single-use marker (an atomic Add) gets it.
func (p *Plugin) take(ctx context.Context, challenge, purpose string) (ceremony, error) {
	invalid := &refusal{kindChallengeInvalid, "The challenge is unknown, used or expired."}
	key := challengeKey(challenge)
	raw, ok, err := p.g.Cache.Get(ctx, key)
	if err != nil {
		return ceremony{}, err
	}
	if !ok {
		return ceremony{}, invalid
	}
	won, err := p.g.Cache.Add(ctx, key+".used", []byte{1}, p.settings.challengeTTL)
	if err != nil {
		return ceremony{}, err
	}
	if !won {
		return ceremony{}, invalid
	}
	if err := p.g.Cache.Delete(ctx, key); err != nil {
		return ceremony{}, err
	}
	var c ceremony
	if json.Unmarshal(raw, &c) != nil || c.Purpose != purpose {
		return ceremony{}, invalid
	}
	return c, nil
}

func challengeKey(challenge string) string {
	sum := sha256.Sum256([]byte(challenge))
	return "polaris.passkey.challenge." + hex.EncodeToString(sum[:])
}

func checkName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return DefaultName, nil
	}
	if utf8.RuneCountInString(name) > maxName {
		return "", &refusal{kindInvalidInput, "name may be at most 80 characters."}
	}
	return name, nil
}

func random(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	return b
}
