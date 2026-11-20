package cli

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/polaristest"
	"github.com/univeros/polaris-go/token"
)

func lookupIn(values map[string]string) config.LookupFunc {
	return func(k string) (string, bool) { v, ok := values[k]; return v, ok }
}

func TestInitWritesOnlyWhatIsMissing(t *testing.T) {
	cleanEnv(t)
	dir := t.TempDir()
	env, mine := filepath.Join(dir, ".env"), "# mine\nDATABASE_URL=sqlite:"+filepath.Join(dir, "p.db")+"\n"
	if err := os.WriteFile(env, []byte(mine), 0o600); err != nil {
		t.Fatal(err)
	}

	r := standalone(t, env, "init", "--plugins=audit,admin", "--json")
	r.want(t, exitOK)
	m := r.json(t)
	if len(m["added"].([]any)) != 4 || len(m["replaced"].([]any)) != 0 {
		t.Errorf("first run: %v", m)
	}
	if s := m["snippet"].(string); !strings.Contains(s, "polaris.FromEnv(db, audit.New(audit.Config{}), admin.New(admin.Config{}))") || !strings.Contains(s, `"github.com/univeros/polaris-go/plugins/admin"`) {
		t.Errorf("snippet: %s", s)
	}
	file, err := readDotenv(env)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(readFile(t, env), mine) {
		t.Error("existing lines were not kept")
	}
	if _, _, err := config.FromLookup(lookupIn(file.values)); err != nil {
		t.Fatalf("the written file does not configure Polaris: %v", err)
	}
	if info, _ := os.Stat(env); info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", info.Mode().Perm())
	}

	// Idempotent: a second run changes nothing.
	before := readFile(t, env)
	standalone(t, env, "init").want(t, exitOK, "nothing changed")
	if readFile(t, env) != before {
		t.Error("a second run rewrote the file")
	}

	// --force replaces the secrets but keeps the issuer unless one is given.
	r = standalone(t, env, "init", "--force", "--json")
	r.want(t, exitOK)
	if got := r.json(t)["replaced"].([]any); len(got) != 3 {
		t.Errorf("--force replaced %v", got)
	}
	again, _ := readDotenv(env)
	if again.values["APP_KEY"] == file.values["APP_KEY"] || again.values["AUTH_ISSUER"] != "http://localhost:8080" {
		t.Error("--force did not replace the secrets, or replaced the issuer")
	}
	standalone(t, env, "init", "--force", "--issuer=https://auth.example.com").want(t, exitOK, "replaced APP_KEY, AUTH_JWT_PRIVATE_KEY, AUTH_JWT_PUBLIC_KEY, AUTH_ISSUER")
	if again, _ = readDotenv(env); again.values["AUTH_ISSUER"] != "https://auth.example.com" {
		t.Errorf("issuer %q", again.values["AUTH_ISSUER"])
	}

	// The standalone binary reads what init wrote.
	standalone(t, env, "migrate").want(t, exitOK)
	standalone(t, env, "doctor", "--json").want(t, exitOK, `"ready": true`)
}

func TestInitRefusesHalfAKeyPair(t *testing.T) {
	cleanEnv(t)
	env := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(env, []byte("AUTH_JWT_PUBLIC_KEY=\"x\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	standalone(t, env, "init").want(t, exitFail, "half of the JWT key pair", "--force")
	if err := os.WriteFile(env, []byte("BROKEN\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	standalone(t, env, "init").want(t, exitFail, ".env:1: expected KEY=value")
	standalone(t, filepath.Join(t.TempDir(), "missing", ".env"), "init").want(t, exitFail, "writable")
}

func TestInitInAHostBinary(t *testing.T) {
	srv := polaristest.New(t)
	env := filepath.Join(t.TempDir(), "app.env")
	hosted(t, srv.Polaris, nil, "init", "--env-file="+env).want(t, exitOK, "Wrote "+env, "polaris.FromEnv(db)")
}

func TestKeysGenerate(t *testing.T) {
	cleanEnv(t)
	r := standalone(t, noEnvFile(t), "keys:generate", "--json")
	r.want(t, exitOK)
	env := r.json(t)["env"].(map[string]any)
	if len(env["APP_KEY"].(string)) < config.MinAppKeyBytes {
		t.Error("APP_KEY too short")
	}
	if _, err := token.New(token.Config{PublicKey: env["AUTH_JWT_PUBLIC_KEY"].(string), PrivateKey: env["AUTH_JWT_PRIVATE_KEY"].(string), Issuer: "x", TTL: time.Minute}); err != nil {
		t.Errorf("RS256 pair: %v", err)
	}

	r = standalone(t, noEnvFile(t), "keys:generate", "--alg=EdDSA", "--json")
	r.want(t, exitOK)
	env = r.json(t)["env"].(map[string]any)
	priv, _ := base64.StdEncoding.DecodeString(env["AUTH_JWT_PRIVATE_KEY"].(string))
	pub, _ := base64.StdEncoding.DecodeString(env["AUTH_JWT_PUBLIC_KEY"].(string))
	if _, err := token.New(token.Config{Algorithm: token.EdDSA, PublicKey: string(pub), PrivateKey: string(priv), Issuer: "x", TTL: time.Minute}); err != nil {
		t.Errorf("EdDSA pair: %v", err)
	}

	standalone(t, noEnvFile(t), "keys:generate").want(t, exitOK, "APP_KEY=\"", "-----BEGIN PRIVATE KEY-----", "-----BEGIN PUBLIC KEY-----")
	standalone(t, noEnvFile(t), "keys:generate", "--alg=EdDSA").want(t, exitOK, "# EdDSA keys are base64")
}

func TestDotenv(t *testing.T) {
	data := strings.Join([]string{
		"# comment",
		"",
		"export A=plain value # trailing comment",
		"B='single $literal \\n'",
		`C="line\nbreak \"quoted\" back\\slash"`,
		`PEM="-----BEGIN-----`,
		"abc",
		`-----END-----"`,
		`EMPTY=""`,
		"LAST=1",
	}, "\n")
	d, err := parseDotenv(".env", data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"A": "plain value", "B": `single $literal \n`, "C": "line\nbreak \"quoted\" back\\slash",
		"PEM": "-----BEGIN-----\nabc\n-----END-----", "EMPTY": "", "LAST": "1",
	}
	for k, v := range want {
		if d.values[k] != v {
			t.Errorf("%s = %q, want %q", k, d.values[k], v)
		}
	}

	path := filepath.Join(t.TempDir(), ".env")
	if err := d.write(path, map[string]string{"PEM": "new\npem", "C": "c", "NEW": `x"y`}); err != nil {
		t.Fatal(err)
	}
	back, err := readDotenv(path)
	if err != nil {
		t.Fatal(err)
	}
	if back.values["PEM"] != "new\npem" || back.values["C"] != "c" || back.values["NEW"] != `x"y` || back.values["LAST"] != "1" || back.values["A"] != "plain value" {
		t.Errorf("round trip: %v", back.values)
	}

	for _, bad := range []string{"NOEQUALS", "A B=1", `X="never closed`, "Y='never closed"} {
		if _, err := parseDotenv(".env", bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}
