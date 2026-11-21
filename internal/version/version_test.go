package version

import (
	"runtime/debug"
	"testing"
)

func TestOfBuildInfo(t *testing.T) {
	dep := func(path, v string, replace *debug.Module) *debug.Module {
		return &debug.Module{Path: path, Version: v, Replace: replace}
	}
	for name, c := range map[string]struct {
		bi   *debug.BuildInfo
		ok   bool
		want string
	}{
		"no build info":          {nil, false, Devel},
		"a host's dependency":    {&debug.BuildInfo{Main: debug.Module{Path: "example.com/app", Version: "v1.0.0"}, Deps: []*debug.Module{dep(module, "v0.3.0", nil)}}, true, "v0.3.0"},
		"a replaced dependency":  {&debug.BuildInfo{Main: debug.Module{Path: "example.com/app"}, Deps: []*debug.Module{dep(module, "v0.3.0", dep("../polaris.go", "", nil))}}, true, Devel},
		"this module, stamped":   {&debug.BuildInfo{Main: debug.Module{Path: module, Version: "v0.4.1"}}, true, "v0.4.1"},
		"this module, unstamped": {&debug.BuildInfo{Main: debug.Module{Path: module, Version: "(devel)"}}, true, Devel},
		"not a dependency":       {&debug.BuildInfo{Main: debug.Module{Path: "example.com/app", Version: "v1.0.0"}}, true, Devel},
	} {
		if got := of(c.bi, c.ok); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
	if Module() != Devel {
		t.Errorf("a test binary is unstamped: %q", Module())
	}
}
