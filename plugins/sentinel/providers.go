package sentinel

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// BotVerifier verifies a token the client obtained from a captcha (Turnstile, hCaptcha). With one
// configured, enforce mode answers the challenge band with sentinel/challenge_required.
type BotVerifier interface {
	Verify(ctx context.Context, token, ip string) bool
}

// The siteverify endpoints of the bundled verifiers.
const (
	TurnstileEndpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	HCaptchaEndpoint  = "https://api.hcaptcha.com/siteverify"
)

// SiteVerifier speaks the siteverify protocol Turnstile and hCaptcha share: a form POST with the
// secret, the token and the client address, a JSON "success". A transport failure, a non-200
// answer or an unreadable body is a failed verification.
type SiteVerifier struct {
	Endpoint string
	Secret   string
	Client   *http.Client // nil means http.DefaultClient
}

// Turnstile is Cloudflare Turnstile's verifier.
func Turnstile(secret string) *SiteVerifier {
	return &SiteVerifier{Endpoint: TurnstileEndpoint, Secret: secret}
}

// HCaptcha is hCaptcha's verifier.
func HCaptcha(secret string) *SiteVerifier {
	return &SiteVerifier{Endpoint: HCaptchaEndpoint, Secret: secret}
}

// Verify implements BotVerifier.
func (v *SiteVerifier) Verify(ctx context.Context, token, ip string) bool {
	form := url.Values{"secret": {v.Secret}, "response": {token}}
	if ip != "" {
		form.Set("remoteip", ip)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.Endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := v.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var body struct {
		Success bool `json:"success"`
	}
	return resp.StatusCode == http.StatusOK && json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body) == nil && body.Success
}

// GeoPoint is a location in decimal degrees.
type GeoPoint struct{ Latitude, Longitude float64 }

const earthRadiusKm = 6371.0

// DistanceTo is the great-circle distance in kilometres (haversine).
func (p GeoPoint) DistanceTo(o GeoPoint) float64 {
	rad := math.Pi / 180
	// Explicit conversions round each product, so no fused multiply-add skews a zero distance.
	lat1, lat2 := float64(p.Latitude*rad), float64(o.Latitude*rad)
	dLat, dLon := lat2-lat1, (o.Longitude-p.Longitude)*rad
	a := math.Pow(math.Sin(dLat/2), 2) + math.Cos(lat1)*math.Cos(lat2)*math.Pow(math.Sin(dLon/2), 2)
	return 2 * earthRadiusKm * math.Asin(math.Sqrt(a))
}

// GeoResolver tells where an address is; ok is false when unknown (a private range, no data).
// With one configured the impossible-travel signal runs and sign-ins record their location.
//
// Polaris ships no geo database. Plug MaxMind (github.com/oschwald/geoip2-golang) or any other
// source with a few lines in the host:
//
//	type maxmind struct{ db *geoip2.Reader }
//
//	func (m maxmind) Resolve(_ context.Context, ip string) (sentinel.GeoPoint, bool) {
//		rec, err := m.db.City(net.ParseIP(ip))
//		if err != nil || (rec.Location.Latitude == 0 && rec.Location.Longitude == 0) {
//			return sentinel.GeoPoint{}, false
//		}
//		return sentinel.GeoPoint{Latitude: rec.Location.Latitude, Longitude: rec.Location.Longitude}, true
//	}
type GeoResolver interface {
	Resolve(ctx context.Context, ip string) (GeoPoint, bool)
}

// NoGeo resolves nothing: the impossible-travel signal stays silent. It is the default.
type NoGeo struct{}

// Resolve implements GeoResolver.
func (NoGeo) Resolve(context.Context, string) (GeoPoint, bool) { return GeoPoint{}, false }

// DomainList holds the domains of disposable mailboxes.
type DomainList interface {
	Contains(domain string) bool
}

// Domains is a DomainList: lower-cased domains.
type Domains map[string]struct{}

// Contains implements DomainList, ignoring case.
func (d Domains) Contains(domain string) bool {
	_, ok := d[strings.ToLower(domain)]
	return ok
}

// ParseDomains reads one domain per line ("#" starts a comment line, blank lines skipped), plus
// extra domains.
func ParseDomains(r io.Reader, extra ...string) (Domains, error) {
	d := Domains{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if line := strings.ToLower(strings.TrimSpace(sc.Text())); line != "" && !strings.HasPrefix(line, "#") {
			d[line] = struct{}{}
		}
	}
	for _, e := range extra {
		d[strings.ToLower(strings.TrimSpace(e))] = struct{}{}
	}
	return d, sc.Err()
}

// bundledList is the disposable-email-domains list (CC0) shipped with the plugin,
// refreshed per release.
//
//go:embed disposable-domains.txt
var bundledList string

var bundled = sync.OnceValue(func() Domains {
	d, _ := ParseDomains(strings.NewReader(bundledList))
	return d
})

// BundledDomains is the bundled disposable-domain list, parsed on first use.
func BundledDomains() Domains { return bundled() }

// withExtra is the bundled list plus the host's domains.
type withExtra struct {
	base  DomainList
	extra Domains
}

func (w withExtra) Contains(domain string) bool {
	return w.extra.Contains(domain) || w.base.Contains(domain)
}
