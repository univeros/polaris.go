// Package version reports which release of Polaris is running, from the build information the Go
// toolchain records: the version of github.com/univeros/polaris.go a host's go.mod requires, or of
// this module when it is the one being built. Nothing to bump at release time.
package version

import (
	"runtime/debug"
	"sync"
)

// Devel is the version of a build that records none: tests, a replaced module, go run in a checkout.
const Devel = "devel"

const module = "github.com/univeros/polaris.go"

// Module returns the running Polaris release ("v0.3.0"), or Devel.
var Module = sync.OnceValue(func() string { return of(debug.ReadBuildInfo()) })

func of(bi *debug.BuildInfo, ok bool) string {
	if !ok || bi == nil {
		return Devel
	}
	if bi.Main.Path == module {
		return stamped(bi.Main.Version)
	}
	for _, dep := range bi.Deps {
		if dep.Path == module {
			if dep.Replace != nil {
				return stamped(dep.Replace.Version)
			}
			return stamped(dep.Version)
		}
	}
	return Devel
}

func stamped(v string) string {
	if v == "" || v == "(devel)" {
		return Devel
	}
	return v
}
