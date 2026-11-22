package sso

import "time"

// Provider types.
const (
	TypeSAML = "saml"
	TypeOIDC = "oidc"
)

// secretKey is the config member holding the OIDC client secret, encrypted at rest.
const secretKey = "client_secret"

// Provider is a SAML 2.0 or OIDC identity provider of one organization (polaris_sso_provider).
// Config holds the protocol settings (SAML: sso_url, slo_url, slo_response_url, certificate,
// idp_initiated; OIDC: issuer, client_id, client_secret encrypted at rest, scopes); Attributes maps
// email and name onto the provider's claim or attribute names; JIT says whether unknown users are
// created and which roles (slugs) a new member gets; RedirectURIs are the application URLs a
// sign-in may end on, the first being the default.
type Provider struct {
	ID             string
	OrganizationID string
	Type           string // TypeSAML or TypeOIDC
	Name           string
	Issuer         string // the SAML IdP entity id or the OIDC issuer URL
	Config         map[string]any
	Attributes     map[string]string
	JIT            JIT
	RedirectURIs   []string
	Enabled        bool
	CreatedBy      string // "" when unknown
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// JIT is a provider's just-in-time provisioning.
type JIT struct {
	Enabled bool
	Roles   []string // role slugs of the organization; "member" when empty
}

// Setting is a non-empty string member of Config, "" otherwise.
func (p Provider) Setting(key string) string {
	s, _ := p.Config[key].(string)
	return s
}

// Flag is a boolean member of Config that is exactly true.
func (p Provider) Flag(key string) bool { return p.Config[key] == true }

// Attribute is the claim or attribute name carrying field ("email", "name"); field itself by default.
func (p Provider) Attribute(field string) string {
	if v := p.Attributes[field]; v != "" {
		return v
	}
	return field
}

// Map is the provider as the API shows it: the configuration without the secret and, for OIDC,
// whether one is set.
func (p Provider) Map() map[string]any {
	config := make(map[string]any, len(p.Config)+1)
	for k, v := range p.Config {
		if k != secretKey {
			config[k] = v
		}
	}
	if p.Type == TypeOIDC {
		config["client_secret_set"] = p.Setting(secretKey) != ""
	}
	attributes := make(map[string]any, len(p.Attributes))
	for k, v := range p.Attributes {
		attributes[k] = v
	}
	return map[string]any{
		"id": p.ID, "organization_id": p.OrganizationID, "type": p.Type, "name": p.Name, "issuer": p.Issuer,
		"config": config, "attributes": attributes,
		"jit":           map[string]any{"enabled": p.JIT.Enabled, "roles": nonNil(p.JIT.Roles)},
		"redirect_uris": nonNil(p.RedirectURIs), "enabled": p.Enabled, "created_by": nullable(p.CreatedBy),
		"created_at": timestamp(p.CreatedAt), "updated_at": timestamp(p.UpdatedAt),
	}
}

// Domain verification: the DNS record name prefix and the well-known file path.
const (
	DNSRecord     = "_polaris"
	WellKnownPath = "/.well-known/polaris-sso.txt"
)

// Domain is a domain an organization claims for SSO routing (polaris_sso_domain): once verified,
// a sign-in with an email of that domain goes to the domain's provider.
type Domain struct {
	ID             string
	OrganizationID string
	ProviderID     string
	Domain         string // lower case
	Token          string // what the DNS record or the well-known file must carry
	VerifiedAt     *time.Time
	CreatedAt      time.Time
}

// Map is the domain as the API shows it, with the two ways to prove it.
func (d Domain) Map() map[string]any {
	var verifiedAt any
	if d.VerifiedAt != nil {
		verifiedAt = timestamp(*d.VerifiedAt)
	}
	return map[string]any{
		"id": d.ID, "organization_id": d.OrganizationID, "provider_id": d.ProviderID, "domain": d.Domain,
		"verification": map[string]any{
			"token": d.Token,
			"dns":   map[string]any{"record": DNSRecord + "." + d.Domain, "type": "TXT", "value": d.Token},
			"https": map[string]any{"url": "https://" + d.Domain + WellKnownPath, "body": d.Token},
		},
		"verified": d.VerifiedAt != nil, "verified_at": verifiedAt, "created_at": timestamp(d.CreatedAt),
	}
}

// timestamp is how the API writes a time: RFC 3339 in UTC, to the second ("…Z").
func timestamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
