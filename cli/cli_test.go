package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/internal/contracttest"
)

// result is one command's outcome.
type result struct {
	code           int
	stdout, stderr string
}

func (r result) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &m); err != nil {
		t.Fatalf("stdout is not one JSON object: %v\n%s", err, r.stdout)
	}
	return m
}

func (r result) want(t *testing.T, code int, contains ...string) {
	t.Helper()
	if r.code != code {
		t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", r.code, code, r.stdout, r.stderr)
	}
	for _, s := range contains {
		if !strings.Contains(r.stdout+r.stderr, s) {
			t.Errorf("output lacks %q\nstdout: %s\nstderr: %s", s, r.stdout, r.stderr)
		}
	}
}

var envKeys = []string{"APP_KEY", "AUTH_JWT_PRIVATE_KEY", "AUTH_JWT_PUBLIC_KEY", "AUTH_JWT_KID", "AUTH_ISSUER", "AUTH_AUDIENCE",
	"AUTH_JWT_PREVIOUS_PUBLIC_KEY", "AUTH_JWT_PREVIOUS_KID", "DATABASE_URL", "POLARIS_PLUGINS", "POLARIS_MCP_TOKEN"}

// cleanEnv empties every variable the CLI reads (empty counts as unset).
func cleanEnv(t *testing.T) {
	t.Helper()
	for _, k := range envKeys {
		t.Setenv(k, "")
	}
}

// configuredEnv sets valid secrets and a fresh SQLite database; it returns the database URL.
func configuredEnv(t *testing.T) string {
	t.Helper()
	cleanEnv(t)
	private, public := contracttest.TestRSAKeyPEM()
	t.Setenv("APP_KEY", contracttest.AppKey)
	t.Setenv("AUTH_JWT_PRIVATE_KEY", private)
	t.Setenv("AUTH_JWT_PUBLIC_KEY", public)
	t.Setenv("AUTH_ISSUER", contracttest.Issuer)
	url := "sqlite:" + filepath.Join(t.TempDir(), "polaris.db")
	t.Setenv("DATABASE_URL", url)
	return url
}

// standalone runs args as cmd/polaris does, reading the .env file envFile.
func standalone(t *testing.T, envFile string, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	src := &source{envFile: envFile, stderr: &errb}
	defer src.close()
	code := run(context.Background(), &app{src: src, stdout: &out, stderr: &errb}, args)
	return result{code, out.String(), errb.String()}
}

func noEnvFile(t *testing.T) string { return filepath.Join(t.TempDir(), ".env") }

// hosted runs args through Run over p; stdin feeds the mcp command.
func hosted(t *testing.T, p *polaris.Polaris, stdin io.Reader, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), &app{src: &source{host: p, stderr: &errb}, stdin: stdin, stdout: &out, stderr: &errb}, args)
	return result{code, out.String(), errb.String()}
}

func TestUsageAndFailuresNameTheRemedy(t *testing.T) {
	cleanEnv(t)
	cases := []struct {
		name string
		args []string
		code int
		want []string
	}{
		{"no command", nil, exitUsage, []string{"usage: polaris"}},
		{"help", []string{"help"}, exitOK, []string{"schema:export", "anonymous:prune"}},
		{"unknown command", []string{"nope"}, exitUsage, []string{`unknown command "nope"`, "remedy: run `polaris help`"}},
		{"unknown flag", []string{"schema:export", "--bogus"}, exitUsage, []string{"-bogus", "polaris schema:export -h"}},
		{"command help", []string{"schema:export", "-h"}, exitOK, []string{"usage: polaris schema:export", "-target"}},
		{"extra argument", []string{"schema:export", "extra"}, exitUsage, []string{"takes 0 argument(s), got 1"}},
		{"missing argument", []string{"admin:grant", "a@example.com"}, exitUsage, []string{"takes 2 argument(s), got 1"}},
		{"bad target", []string{"schema:export", "--target=sql:oracle"}, exitUsage, []string{`unknown target "sql:oracle"`, "--target=sql:postgres"}},
		{"drop needs force", []string{"schema:drop"}, exitUsage, []string{"rerun with --force"}},
		{"bad algorithm", []string{"keys:generate", "--alg=HS256"}, exitUsage, []string{"--alg=RS256"}},
		{"bad format", []string{"manifest", "--format=yaml"}, exitUsage, []string{"--format=openapi"}},
		{"unknown plugin", []string{"schema:export", "--plugins=audit,nope"}, exitUsage, []string{`unknown plugin "nope"`, "audit, admin, apikeys"}},
		{"no database", []string{"schema:diff"}, exitFail, []string{"DATABASE_URL are empty", "remedy: set DATABASE_URL"}},
		{"bad database URL", []string{"schema:diff", "--dsn=oracle://x"}, exitUsage, []string{"unrecognized database URL"}},
		{"unreachable database", []string{"schema:diff", "--dsn=sqlite:" + filepath.Join(t.TempDir(), "missing", "x.db")}, exitFail, []string{"check that the database is running"}},
		{"no secrets", []string{"migrate", "--dsn=sqlite:" + filepath.Join(t.TempDir(), "p.db")}, exitFail, []string{"APP_KEY", "run `polaris init`"}},
		{"bad role", []string{"admin:grant", "a@example.com", "god"}, exitUsage, []string{`unknown role "god"`}},
		{"bad expiry", []string{"admin:grant", "a@example.com", "admin", "--expires=soon"}, exitUsage, []string{"ISO 8601"}},
		{"bad allowlist", []string{"admin:key", "ops", "admin", "--allow=10.0.0.0/99"}, exitUsage, []string{"not an address or a CIDR block"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			standalone(t, noEnvFile(t), c.args...).want(t, c.code, c.want...)
		})
	}
}

func TestJSONFailuresAreOneObjectWithTheRemedy(t *testing.T) {
	cleanEnv(t)
	for _, args := range [][]string{{"nope", "--json"}, {"schema:export", "--json", "--target=x"}, {"schema:diff", "--json"}} {
		r := standalone(t, noEnvFile(t), args...)
		if r.code == exitOK || r.stderr != "" {
			t.Fatalf("%v: exit %d, stderr %q", args, r.code, r.stderr)
		}
		if m := r.json(t); m["error"] == "" || m["remedy"] == "" {
			t.Errorf("%v: %v", args, m)
		}
	}
	m := standalone(t, noEnvFile(t), "help", "--json").json(t)
	if len(m["commands"].([]any)) != len(commands()) {
		t.Errorf("help --json: %v", m)
	}
}

func TestEntryPoints(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Run(context.Background(), nil, []string{"doctor"}, &out, &errb); code != exitUsage || !strings.Contains(errb.String(), "polaris.New") {
		t.Errorf("Run(nil): %d %q", code, errb.String())
	}
	if code := Main(context.Background(), []string{"help"}, &out, &errb); code != exitOK || !strings.Contains(out.String(), "doctor") {
		t.Errorf("Main help: %d", code)
	}
	if code := Run(context.Background(), &polaris.Polaris{}, []string{"keys:generate", "--json"}, io.Discard, io.Discard); code != exitOK {
		t.Errorf("Run keys:generate: %d", code)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
