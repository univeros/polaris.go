package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/univeros/polaris.go/token"
)

// check is one doctor finding.
type check struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // pass, fail or skip
	Message string `json:"message"`
	Remedy  string `json:"remedy,omitempty"`
}

func doctor(a *app, _ *flag.FlagSet) runFunc {
	return func(ctx context.Context) (report, error) {
		var checks []check
		add := func(name, okMessage string, err error) bool {
			c := check{Name: name, Status: "pass", Message: okMessage}
			if err != nil {
				c.Status, c.Message, c.Remedy = "fail", err.Error(), "run `polaris doctor` again after fixing the message's cause"
				var ce *cliError
				if errors.As(err, &ce) {
					c.Remedy = ce.remedy
				}
			}
			checks = append(checks, c)
			return err == nil
		}
		skip := func(name, why string) { checks = append(checks, check{Name: name, Status: "skip", Message: why}) }

		secrets, auth, err := a.src.config()
		configOK := add("config", fmt.Sprintf("APP_KEY, the JWT key pair and issuer %q are set", auth.Issuer), err)
		if configOK {
			_, err = token.New(token.Config{
				Algorithm: token.Algorithm(auth.AccessToken.Signer), PublicKey: secrets.JWTPublicKey, PrivateKey: secrets.JWTPrivateKey,
				KeyID: secrets.KeyID(), Issuer: auth.Issuer, TTL: auth.AccessToken.TTL,
				PreviousPublicKey: secrets.JWTPreviousPublicKey, PreviousKeyID: secrets.PreviousKeyID(),
			})
			if err != nil {
				err = fail(err.Error(), "replace the key pair: `polaris init --force` writes a fresh RS256 pair to .env")
			}
			add("keys", fmt.Sprintf("the %s key pair parses (kid %s)", auth.AccessToken.Signer, secrets.KeyID()), err)
		} else {
			skip("keys", "needs config")
		}

		if m, err := a.src.manifest(); err != nil {
			add("manifest", "", err)
		} else {
			add("manifest", fmt.Sprintf("%d routes load", len(m.Routes())), nil)
		}

		db, err := a.src.database(ctx)
		connected := ""
		if err == nil {
			connected = fmt.Sprintf("connected (%s)", db.Dialect())
			if err = db.DB().PingContext(ctx); err != nil {
				err = fail(err.Error(), "check that the database is running and reachable")
			}
		}
		dbOK := add("database", connected, err)

		if configOK && dbOK {
			p, err := a.src.instance(ctx)
			var ids []string
			if err == nil {
				for _, pl := range p.Graph().Plugins() {
					ids = append(ids, pl.ID())
				}
			}
			add("instance", fmt.Sprintf("polaris.New succeeds (plugins: %s)", orNone(ids)), err)
		} else {
			skip("instance", "needs config and database")
		}

		if dbOK {
			if models, err := a.src.models(); err != nil {
				add("schema", "", err)
			} else if diffs, err := db.Diff(ctx, models); err != nil {
				add("schema", "", fail(err.Error(), "check that the database user may read the catalog"))
			} else if len(diffs) > 0 {
				add("schema", "", fail(fmt.Sprintf("%d difference(s) from the Polaris schema (polaris schema:diff lists them)", len(diffs)), remedyDiff))
			} else {
				add("schema", "the database matches the Polaris schema", nil)
			}
		} else {
			skip("schema", "needs database")
		}

		return doctorReport(checks)
	}
}

func doctorReport(checks []check) (report, error) {
	var b strings.Builder
	ready := true
	for _, c := range checks {
		label := map[string]string{"pass": "ok  ", "fail": "FAIL", "skip": "skip"}[c.Status]
		fmt.Fprintf(&b, " %s  %s: %s\n", label, c.Name, c.Message)
		if c.Status == "fail" {
			ready = false
			fmt.Fprintf(&b, "       fix: %s\n", c.Remedy)
		}
	}
	data := map[string]any{"ready": ready, "checks": checks}
	if !ready {
		b.WriteString("Polaris is not ready.\n")
		return report{text: b.String(), data: data}, fail("Polaris is not ready: a check failed", "apply each failing check's fix, then run `polaris doctor` again")
	}
	b.WriteString("Polaris is ready.\n")
	return report{text: b.String(), data: data}, nil
}

func orNone(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ", ")
}
