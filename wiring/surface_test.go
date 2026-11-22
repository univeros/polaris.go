package wiring

import (
	"reflect"
	"strings"
	"testing"
)

// The plugin SDK is stable (API.md §2), so a Graph accessor may only hand out what is stable too:
// a type of a stable package, a narrow interface declared here, or a stable host interface. A
// concrete service of a "public but not stable" package (identity.Service, session.Service, …)
// would freeze its whole method set.
func TestGraphAccessorsReturnOnlyStableTypes(t *testing.T) {
	const module = "github.com/univeros/polaris.go/"
	stablePackages := map[string]bool{"wiring": true, "endpoint": true, "manifest": true, "event": true, "token": true, "config": true, "store": true}
	stableTypes := map[string]bool{
		// Host-implemented interfaces (API.md §1).
		"security.PasswordHasher": true, "security.BreachedPasswordCheck": true, "notify.Mailer": true,
		"notify.SMSSender": true, "clock.Clock": true, "cache.Cache": true, "ratelimit.Store": true,
		"metrics.Metrics": true,
		// Already a narrow interface; its payload format is frozen (stored data must decrypt).
		"security.Encrypter": true,
		// Declared exceptions (API.md §2): the table builder plugins declare their schema with, the
		// core repositories, the pipeline a plugin mounts.
		"schema.Model": true, "repository.Repos": true, "pipeline.Pipeline": true,
	}
	g := reflect.TypeFor[*Graph]()
	for i := range g.NumMethod() {
		m := g.Method(i)
		for j := range m.Type.NumOut() {
			out := m.Type.Out(j)
			for out.Kind() == reflect.Pointer || out.Kind() == reflect.Slice || out.Kind() == reflect.Map {
				if out.Kind() == reflect.Map {
					out = out.Elem() // the key is a string everywhere
					continue
				}
				out = out.Elem()
			}
			pkg, ok := strings.CutPrefix(out.PkgPath(), module)
			if !ok || stablePackages[pkg] {
				continue
			}
			if name := pkg + "." + out.Name(); !stableTypes[name] {
				t.Errorf("Graph.%s returns %s: return a narrow interface declared in wiring", m.Name, name)
			}
		}
	}
}
