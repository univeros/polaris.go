package cli_test

import (
	"context"
	"fmt"
	"log"
	"os"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/cli"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store/memstore"
)

// A host's own binary runs the CLI over its instance, so its plugins' tables, routes and
// commands are seen. In a real main: os.Exit(cli.Run(ctx, p, os.Args[1:], os.Stdout, os.Stderr)).
func ExampleRun() {
	private, public := contracttest.TestRSAKeyPEM() // test keys; a host reads its own
	auth := config.Defaults()
	auth.Issuer = "https://auth.example.com"
	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: contracttest.AppKey, JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth,
		DB:      memstore.New(schema.Core()...), // sqlstore.Open(...) in production
	})
	if err != nil {
		log.Fatal(err)
	}
	code := cli.Run(context.Background(), p, []string{"schema:export", "--target=sql:sqlite", "--drop"}, os.Stdout, os.Stderr)
	fmt.Println("exit", code)
	// Output:
	// DROP TABLE IF EXISTS "auth_membership_roles";
	//
	// DROP TABLE IF EXISTS "auth_users";
	//
	// DROP TABLE IF EXISTS "auth_role_permissions";
	//
	// DROP TABLE IF EXISTS "auth_roles";
	//
	// DROP TABLE IF EXISTS "auth_refresh_tokens";
	//
	// DROP TABLE IF EXISTS "auth_recovery_codes";
	//
	// DROP TABLE IF EXISTS "auth_permissions";
	//
	// DROP TABLE IF EXISTS "auth_password_resets";
	//
	// DROP TABLE IF EXISTS "auth_otp_challenges";
	//
	// DROP TABLE IF EXISTS "auth_organizations";
	//
	// DROP TABLE IF EXISTS "auth_mfa_factors";
	//
	// DROP TABLE IF EXISTS "auth_memberships";
	//
	// DROP TABLE IF EXISTS "auth_invitations";
	//
	// DROP TABLE IF EXISTS "auth_email_verifications";
	//
	// DROP TABLE IF EXISTS "auth_audit_log";
	// exit 0
}
