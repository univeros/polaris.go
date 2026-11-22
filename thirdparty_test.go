package polaris_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The plugin SDK is what a plugin outside this module can import (API.md). The in-tree plugins
// cannot prove it: they may import internal/ packages. testdata/thirdparty/notes is a plugin that
// uses every part of the SDK (tables, routes, a permission, a listener, a bearer resolver, an MFA
// factor type, an access eraser, the narrow services of the Graph); it is type-checked here as a
// module of its own, against this checkout through a replace directive. It fails when a signature
// of the SDK names something a third party cannot reach.
//
// Its own test (notes_test.go, run by hand with `go test` in a copy made the same way) boots it
// with polaristest.
func TestAThirdPartyPluginBuildsOutsideTheModule(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the go command")
	}
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(filepath.Join(root, "testdata", "thirdparty", "notes"))); err != nil {
		t.Fatal(err)
	}
	sum, err := os.ReadFile("go.sum")
	if err != nil {
		t.Fatal(err)
	}
	// The fixture requires what Polaris requires, so its (pruned) module graph is the one this
	// module already resolved: nothing beyond the module cache CI and developers already hold.
	gomod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	mod := "module example.com/notes\n\ngo 1.26.0\n\nrequire github.com/univeros/polaris.go v0.0.0\n\n" +
		requireBlocks(string(gomod)) +
		"replace github.com/univeros/polaris.go => " + root + "\n"
	for name, data := range map[string][]byte{"go.mod": []byte(mod), "go.sum": sum} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Every dependency is one of this module's, so the module cache already holds it.
	vet := func() (string, error) {
		cmd := exec.Command("go", "vet", "-mod=mod", "./...")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOFLAGS=", "GOPROXY=off", "GOWORK=off")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := vet(); err != nil {
		t.Fatalf("a third-party plugin does not build on the public packages: %v\n%s", err, out)
	}

	// And the other half of the promise: what is internal cannot be imported from there.
	leak := "package notes\n\nimport _ \"github.com/univeros/polaris.go/internal/services\"\n"
	if err := os.WriteFile(filepath.Join(dir, "leak.go"), []byte(leak), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := vet(); err == nil || !strings.Contains(out, "use of internal package") {
		t.Fatalf("internal/services is importable from outside the module: %v\n%s", err, out)
	}
}

// requireBlocks returns the require directives of a go.mod file, verbatim.
func requireBlocks(gomod string) string {
	var b strings.Builder
	in := false
	for _, line := range strings.Split(gomod, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case in:
			b.WriteString(line + "\n")
			if trimmed == ")" {
				in = false
				b.WriteString("\n")
			}
		case trimmed == "require (":
			in = true
			b.WriteString(line + "\n")
		case strings.HasPrefix(trimmed, "require "):
			b.WriteString(line + "\n\n")
		}
	}
	return b.String()
}
