package social

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// Definition is what makes an OAuth 2 provider: its endpoints, the scopes to ask for, how its
// client authenticates, whether it does PKCE and OpenID Connect, its quirks, and how its profile
// maps to a Profile. The catalog holds one per known provider; a host passes its own for any
// other server (Provider.Definition).
type Definition struct {
	Name             string
	AuthorizationURL string
	TokenURL         string
	// UserinfoURL is empty when the profile is in the id_token or the token response.
	UserinfoURL string
	// Scopes are the default scopes.
	Scopes []string
	// Profile maps the userinfo document (merged over the id_token claims, or the token response
	// with ProfileInTokenResponse) to a Profile; values are decoded JSON, numbers json.Number.
	Profile func(data map[string]any) Profile
	// NoPKCE turns PKCE off for a server that refuses it.
	NoPKCE bool
	// Issuer makes the provider OpenID Connect: id_tokens are verified against it (exactly, or
	// against IssuerPattern when the issuer varies, as Microsoft's tenants do).
	Issuer        string
	IssuerPattern *regexp.Regexp
	// JWKSURL is the key set, when the issuer has no discovery document.
	JWKSURL string
	// BasicAuth authenticates the client at the token endpoint with HTTP Basic, not form fields.
	BasicAuth bool
	// AuthorizationParams are extra query parameters of the authorization request.
	AuthorizationParams url.Values
	// ClientIDParam names the client id parameter; default client_id (TikTok: client_key).
	ClientIDParam string
	// UserinfoPOST fetches the profile with POST instead of GET.
	UserinfoPOST bool
	// UserinfoHeaders are extra headers of the profile request (a User-Agent is also sent to the
	// token endpoint).
	UserinfoHeaders map[string]string
	// ProfileInTokenResponse reads the profile from the token response (Notion).
	ProfileInTokenResponse bool
	// FormPost asks for response_mode=form_post (Apple).
	FormPost bool
	// ScopeSeparator joins the scopes; default a space (Facebook and TikTok: a comma).
	ScopeSeparator string
}

func (d Definition) oidc() bool { return d.Issuer != "" || d.IssuerPattern != nil }

// Profile is who the provider says the user is: its stable subject, the email it reports and
// whether it vouches for it, the display name, and what else is worth keeping (a picture, a handle).
type Profile struct {
	Subject       string
	Email         string // "" when the provider shares none
	EmailVerified bool
	Name          string
	Extra         map[string]any
}

// maxName bounds a profile name to core's display name.
const maxName = 120

// normalized trims the name to what core's display name holds.
func (p Profile) normalized() Profile {
	if utf8.RuneCountInString(p.Name) > maxName {
		p.Name = string([]rune(p.Name)[:maxName])
	}
	p.Name = strings.TrimSpace(p.Name)
	return p
}

// fields is the stored and answered profile: the name (null when none) and the extras.
func (p Profile) fields() map[string]any {
	out := map[string]any{"name": nil}
	for k, v := range p.Extra {
		out[k] = v
	}
	if p.Name != "" {
		out["name"] = p.Name
	}
	return out
}

// Catalog lists the providers known by id: they need only a client id and secret.
var Catalog = []string{"google", "apple", "microsoft", "github", "gitlab", "discord", "facebook", "x", "linkedin", "slack", "twitch", "spotify", "zoom", "notion", "dropbox", "reddit", "kick", "tiktok", "huggingface"}

var microsoftTenants = regexp.MustCompile(`^https://login\.microsoftonline\.com/[0-9a-f-]{36}/v2\.0$`)

// catalog returns the definition of a known provider; tenant is Microsoft's ("" is common).
func catalog(id, tenant string) (Definition, bool) {
	if tenant == "" {
		tenant = "common"
	}
	oidc := OIDCProfile
	switch id {
	case "google":
		return Definition{Name: "Google", AuthorizationURL: "https://accounts.google.com/o/oauth2/v2/auth", TokenURL: "https://oauth2.googleapis.com/token",
			UserinfoURL: "https://openidconnect.googleapis.com/v1/userinfo", Scopes: []string{"openid", "email", "profile"}, Profile: oidc,
			Issuer: "https://accounts.google.com", AuthorizationParams: url.Values{"access_type": {"offline"}, "prompt": {"select_account"}}}, true
	case "apple":
		return Definition{Name: "Apple", AuthorizationURL: "https://appleid.apple.com/auth/authorize", TokenURL: "https://appleid.apple.com/auth/token",
			Scopes: []string{"name", "email"}, Profile: oidc, NoPKCE: true, Issuer: "https://appleid.apple.com",
			JWKSURL: "https://appleid.apple.com/auth/keys", FormPost: true}, true
	case "microsoft":
		d := Definition{Name: "Microsoft", AuthorizationURL: "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/authorize",
			TokenURL: "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/token", UserinfoURL: "https://graph.microsoft.com/oidc/userinfo",
			Scopes: []string{"openid", "email", "profile", "offline_access"}, Profile: oidc,
			JWKSURL: "https://login.microsoftonline.com/" + tenant + "/discovery/v2.0/keys"}
		if slices.Contains([]string{"common", "organizations", "consumers"}, tenant) {
			d.IssuerPattern = microsoftTenants
		} else {
			d.Issuer = "https://login.microsoftonline.com/" + tenant + "/v2.0"
		}
		return d, true
	case "github":
		return Definition{Name: "GitHub", AuthorizationURL: "https://github.com/login/oauth/authorize", TokenURL: "https://github.com/login/oauth/access_token",
			UserinfoURL: "https://api.github.com/user", Scopes: []string{"read:user", "user:email"}, NoPKCE: true,
			UserinfoHeaders: map[string]string{"Accept": "application/vnd.github+json"},
			Profile: func(d map[string]any) Profile {
				return Profile{Subject: str(d["id"]), Email: text(d["email"]), EmailVerified: verifiedFlag(d["email_verified"]),
					Name: or(text(d["name"]), text(d["login"])), Extra: map[string]any{"login": d["login"], "picture": d["avatar_url"]}}
			}}, true
	case "gitlab":
		return Definition{Name: "GitLab", AuthorizationURL: "https://gitlab.com/oauth/authorize", TokenURL: "https://gitlab.com/oauth/token",
			UserinfoURL: "https://gitlab.com/oauth/userinfo", Scopes: []string{"openid", "email", "profile"}, Profile: oidc, Issuer: "https://gitlab.com"}, true
	case "discord":
		return Definition{Name: "Discord", AuthorizationURL: "https://discord.com/oauth2/authorize", TokenURL: "https://discord.com/api/oauth2/token",
			UserinfoURL: "https://discord.com/api/users/@me", Scopes: []string{"identify", "email"}, NoPKCE: true,
			Profile: func(d map[string]any) Profile {
				return Profile{Subject: str(d["id"]), Email: text(d["email"]), EmailVerified: verifiedFlag(d["verified"]),
					Name: or(text(d["global_name"]), text(d["username"])), Extra: map[string]any{"username": d["username"]}}
			}}, true
	case "facebook":
		return Definition{Name: "Facebook", AuthorizationURL: "https://www.facebook.com/v19.0/dialog/oauth", TokenURL: "https://graph.facebook.com/v19.0/oauth/access_token",
			UserinfoURL: "https://graph.facebook.com/me?fields=id,name,email,picture", Scopes: []string{"email", "public_profile"}, NoPKCE: true, ScopeSeparator: ",",
			Profile: func(d map[string]any) Profile {
				return Profile{Subject: str(d["id"]), Email: text(d["email"]), EmailVerified: text(d["email"]) != "",
					Name: text(d["name"]), Extra: map[string]any{"picture": at(d, "picture", "data", "url")}}
			}}, true
	case "x":
		return Definition{Name: "X", AuthorizationURL: "https://x.com/i/oauth2/authorize", TokenURL: "https://api.x.com/2/oauth2/token",
			UserinfoURL: "https://api.x.com/2/users/me?user.fields=profile_image_url,confirmed_email", Scopes: []string{"users.read", "tweet.read", "offline.access"}, BasicAuth: true,
			Profile: func(d map[string]any) Profile {
				email := text(at(d, "data", "confirmed_email"))
				return Profile{Subject: str(at(d, "data", "id")), Email: email, EmailVerified: email != "", Name: text(at(d, "data", "name")),
					Extra: map[string]any{"username": at(d, "data", "username"), "picture": at(d, "data", "profile_image_url")}}
			}}, true
	case "linkedin":
		return Definition{Name: "LinkedIn", AuthorizationURL: "https://www.linkedin.com/oauth/v2/authorization", TokenURL: "https://www.linkedin.com/oauth/v2/accessToken",
			UserinfoURL: "https://api.linkedin.com/v2/userinfo", Scopes: []string{"openid", "profile", "email"}, Profile: oidc, NoPKCE: true, Issuer: "https://www.linkedin.com/oauth"}, true
	case "slack":
		return Definition{Name: "Slack", AuthorizationURL: "https://slack.com/openid/connect/authorize", TokenURL: "https://slack.com/api/openid.connect.token",
			UserinfoURL: "https://slack.com/api/openid.connect.userInfo", Scopes: []string{"openid", "email", "profile"}, Profile: oidc, NoPKCE: true, Issuer: "https://slack.com"}, true
	case "twitch":
		return Definition{Name: "Twitch", AuthorizationURL: "https://id.twitch.tv/oauth2/authorize", TokenURL: "https://id.twitch.tv/oauth2/token",
			UserinfoURL: "https://id.twitch.tv/oauth2/userinfo", Scopes: []string{"openid", "user:read:email"}, Profile: oidc, NoPKCE: true, Issuer: "https://id.twitch.tv/oauth2",
			AuthorizationParams: url.Values{"claims": {`{"userinfo":{"email":null,"email_verified":null,"preferred_username":null,"picture":null}}`}}}, true
	case "spotify":
		return Definition{Name: "Spotify", AuthorizationURL: "https://accounts.spotify.com/authorize", TokenURL: "https://accounts.spotify.com/api/token",
			UserinfoURL: "https://api.spotify.com/v1/me", Scopes: []string{"user-read-email", "user-read-private"},
			Profile: func(d map[string]any) Profile {
				return Profile{Subject: str(d["id"]), Email: text(d["email"]), Name: text(d["display_name"]), Extra: map[string]any{"picture": at(d, "images", 0, "url")}}
			}}, true
	case "zoom":
		return Definition{Name: "Zoom", AuthorizationURL: "https://zoom.us/oauth/authorize", TokenURL: "https://zoom.us/oauth/token",
			UserinfoURL: "https://api.zoom.us/v2/users/me", Scopes: []string{"user:read:user"}, BasicAuth: true,
			Profile: func(d map[string]any) Profile {
				return Profile{Subject: str(d["id"]), Email: text(d["email"]), EmailVerified: verifiedFlag(d["verified"]), Name: text(d["display_name"]),
					Extra: map[string]any{"picture": d["pic_url"]}}
			}}, true
	case "notion":
		return Definition{Name: "Notion", AuthorizationURL: "https://api.notion.com/v1/oauth/authorize", TokenURL: "https://api.notion.com/v1/oauth/token",
			Scopes: []string{}, NoPKCE: true, BasicAuth: true, AuthorizationParams: url.Values{"owner": {"user"}}, ProfileInTokenResponse: true,
			Profile: func(d map[string]any) Profile {
				email := text(at(d, "owner", "user", "person", "email"))
				return Profile{Subject: str(at(d, "owner", "user", "id")), Email: email, EmailVerified: email != "", Name: text(at(d, "owner", "user", "name")),
					Extra: map[string]any{"workspace": d["workspace_name"], "picture": at(d, "owner", "user", "avatar_url")}}
			}}, true
	case "dropbox":
		return Definition{Name: "Dropbox", AuthorizationURL: "https://www.dropbox.com/oauth2/authorize", TokenURL: "https://api.dropboxapi.com/oauth2/token",
			UserinfoURL: "https://api.dropboxapi.com/2/users/get_current_account", Scopes: []string{"account_info.read"},
			AuthorizationParams: url.Values{"token_access_type": {"offline"}}, UserinfoPOST: true,
			Profile: func(d map[string]any) Profile {
				return Profile{Subject: str(d["account_id"]), Email: text(d["email"]), EmailVerified: verifiedFlag(d["email_verified"]), Name: text(at(d, "name", "display_name"))}
			}}, true
	case "reddit":
		return Definition{Name: "Reddit", AuthorizationURL: "https://www.reddit.com/api/v1/authorize", TokenURL: "https://www.reddit.com/api/v1/access_token",
			UserinfoURL: "https://oauth.reddit.com/api/v1/me", Scopes: []string{"identity"}, NoPKCE: true, BasicAuth: true,
			AuthorizationParams: url.Values{"duration": {"permanent"}}, UserinfoHeaders: map[string]string{"User-Agent": "polaris-social/1.0"},
			Profile: func(d map[string]any) Profile {
				return Profile{Subject: str(d["id"]), Name: text(d["name"]), Extra: map[string]any{"username": d["name"], "picture": d["icon_img"]}}
			}}, true
	case "kick":
		return Definition{Name: "Kick", AuthorizationURL: "https://id.kick.com/oauth/authorize", TokenURL: "https://id.kick.com/oauth/token",
			UserinfoURL: "https://api.kick.com/public/v1/users", Scopes: []string{"user:read"},
			Profile: func(d map[string]any) Profile {
				email := text(at(d, "data", 0, "email"))
				return Profile{Subject: str(at(d, "data", 0, "user_id")), Email: email, EmailVerified: email != "", Name: text(at(d, "data", 0, "name")),
					Extra: map[string]any{"picture": at(d, "data", 0, "profile_picture")}}
			}}, true
	case "tiktok":
		return Definition{Name: "TikTok", AuthorizationURL: "https://www.tiktok.com/v2/auth/authorize/", TokenURL: "https://open.tiktokapis.com/v2/oauth/token/",
			UserinfoURL: "https://open.tiktokapis.com/v2/user/info/?fields=open_id,display_name,avatar_url", Scopes: []string{"user.info.basic"},
			ClientIDParam: "client_key", ScopeSeparator: ",",
			Profile: func(d map[string]any) Profile {
				return Profile{Subject: str(at(d, "data", "user", "open_id")), Name: text(at(d, "data", "user", "display_name")),
					Extra: map[string]any{"picture": at(d, "data", "user", "avatar_url")}}
			}}, true
	case "huggingface":
		return Definition{Name: "Hugging Face", AuthorizationURL: "https://huggingface.co/oauth/authorize", TokenURL: "https://huggingface.co/oauth/token",
			UserinfoURL: "https://huggingface.co/oauth/userinfo", Scopes: []string{"openid", "profile", "email"}, Profile: oidc, Issuer: "https://huggingface.co"}, true
	}
	return Definition{}, false
}

// OIDCProfile maps the standard OpenID Connect claims (sub, email, email_verified, name or
// preferred_username, picture) to a Profile; use it as Definition.Profile for an OIDC server.
func OIDCProfile(d map[string]any) Profile {
	subject, ok := d["sub"]
	if !ok || subject == nil {
		subject = d["id"]
	}
	return Profile{Subject: str(subject), Email: text(d["email"]), EmailVerified: verifiedFlag(d["email_verified"]),
		Name: or(text(d["name"]), text(d["preferred_username"])), Extra: map[string]any{"picture": d["picture"]}}
}

// at walks decoded JSON: a string steps into an object, an int into a list; nil when absent.
func at(v any, path ...any) any {
	for _, step := range path {
		switch k := step.(type) {
		case string:
			m, ok := v.(map[string]any)
			if !ok {
				return nil
			}
			v = m[k]
		case int:
			l, ok := v.([]any)
			if !ok || k >= len(l) {
				return nil
			}
			v = l[k]
		}
	}
	return v
}

// str reads an identifier or a message from a provider's JSON as text: a string as is, a number
// as its JSON text (providers send numeric ids). Anything else (a boolean, null, a list or an
// object) names nothing and reads as "", so a subject is never made up from a non-identifier.
func str(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return fmt.Sprint(v)
	}
	return ""
}

// text is a string with something besides white space in it, else "".
func text(v any) string {
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return ""
	}
	return s
}

// verifiedFlag reads a provider's email_verified (or verified) claim: true only for the JSON
// true, the strings "true" (any case) or "1", or the number 1. Everything else, "false" and other
// strings, other numbers, lists, objects and null, is unverified: a wrong true lets a trusted
// provider claim an existing account, so the reading fails closed.
func verifiedFlag(v any) bool {
	switch v := v.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true") || v == "1"
	case json.Number:
		return v.String() == "1"
	case float64:
		return v == 1
	}
	return false
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
