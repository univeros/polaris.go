package manifest_test

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"

	"github.com/univeros/polaris-go/internal/upstream"
	"github.com/univeros/polaris-go/manifest"
)

func Example() {
	core, err := fs.Sub(upstream.API, "api/core")
	if err != nil {
		log.Fatal(err)
	}
	audit, err := fs.Sub(upstream.API, "api/audit")
	if err != nil {
		log.Fatal(err)
	}
	m, err := manifest.Load(core, audit)
	if err != nil {
		log.Fatal(err)
	}

	login, _ := m.Named("polaris.auth.login")
	fmt.Println(login.Pattern(), login.Auth, login.RateLimit)
	me, _ := m.Find("GET", "/audit/me")
	fmt.Println(me.Name, me.Plugin)

	if err := login.Validate(map[string]any{"email": "ada@example.com"}); err != nil {
		body, _ := json.Marshal(err) // the 422 body
		fmt.Println(string(body))
	}
	// Output:
	// POST /auth/login public login
	// polaris.audit.me audit
	// {"errors":["password is required."]}
}
