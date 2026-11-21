package httpapi_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/internal/contracttest"
)

// TestEveryCoreFixtureHasAGoTest fails while an upstream core fixture has no Go test: a test claims
// a fixture when a _test.go file in this package names both its PHP class ("LoginEndpointTest") and
// its method ("testValidLogin…") as string literals.
func TestEveryCoreFixtureHasAGoTest(t *testing.T) {
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	var src strings.Builder
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src.Write(b)
	}
	dir := contracttest.Fixtures(t, "core")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var covered []string
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".json")
		parts := strings.Split(name, ".")
		if len(parts) < 2 {
			continue
		}
		class, method := parts[len(parts)-2], parts[len(parts)-1]
		if strings.Contains(src.String(), `"`+class+`"`) && strings.Contains(src.String(), `"`+method+`"`) {
			covered = append(covered, name)
		}
	}
	missing, err := contracttest.Uncovered(dir, covered)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range missing {
		t.Errorf("no Go test for fixture %s", m)
	}
}
