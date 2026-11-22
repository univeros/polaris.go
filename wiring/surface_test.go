package wiring

import (
	"reflect"
	"strings"
	"testing"
)

// Every exported name outside internal/ is the v1 API (API.md), so a Graph accessor may only hand
// out a type a plugin can name: one of a public package. A concrete service (internal/identity's
// Service, internal/session's, …) would be a value a plugin can call but not declare, and would
// freeze its whole method set; return a narrow interface declared in this package instead.
func TestGraphAccessorsReturnOnlyPublicTypes(t *testing.T) {
	const module = "github.com/univeros/polaris.go/"
	g := reflect.TypeFor[*Graph]()
	for i := range g.NumMethod() {
		m := g.Method(i)
		for j := range m.Type.NumOut() {
			out := m.Type.Out(j)
			for out.Kind() == reflect.Pointer || out.Kind() == reflect.Slice || out.Kind() == reflect.Map {
				out = out.Elem() // a map's key is a string everywhere
			}
			if pkg, ok := strings.CutPrefix(out.PkgPath(), module); ok && strings.HasPrefix(pkg, "internal/") {
				t.Errorf("Graph.%s returns %s.%s: return a narrow interface declared in wiring", m.Name, pkg, out.Name())
			}
		}
	}
}
