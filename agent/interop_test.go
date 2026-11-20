package agent

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestPHPVerifiesWhatGoSigns hands Go-signed request JWTs, client assertions and exported keys to
// upstream's PHP verifiers (testdata/interop.php verify): the server's RequestJwt, the OAuth
// provider's assertion checks and the PHP SDK's AgentKey. It runs when php and polaris-core's
// vendor directory (../polaris-core, or $POLARIS_CORE) are present, and is skipped otherwise.
func TestPHPVerifiesWhatGoSigns(t *testing.T) {
	core := os.Getenv("POLARIS_CORE")
	if core == "" {
		core = filepath.Join("..", "..", "polaris-core")
	}
	php, err := exec.LookPath("php")
	if err != nil {
		t.Skip("php is not installed")
	}
	if _, err := os.Stat(filepath.Join(core, "vendor", "autoload.php")); err != nil {
		t.Skipf("no polaris-core vendor at %s (set POLARIS_CORE)", core)
	}

	type request struct {
		AgentID      string   `json:"agent_id"`
		JWK          JWK      `json:"jwk"`
		JWT          string   `json:"jwt"`
		Method       string   `json:"method"`
		URL          string   `json:"url"`
		Body         string   `json:"body"`
		Capabilities []string `json:"capabilities"`
		Tamper       bool     `json:"tamper"`
	}
	type assertion struct {
		AgentID       string `json:"agent_id"`
		JWK           JWK    `json:"jwk"`
		JWT           string `json:"jwt"`
		TokenEndpoint string `json:"token_endpoint"`
	}
	type stored struct {
		Stored string `json:"stored"`
		JWK    JWK    `json:"jwk"`
	}
	var cases struct {
		Requests   []request   `json:"requests"`
		Assertions []assertion `json:"assertions"`
		StoredKeys []stored    `json:"stored_keys"`
	}
	const execute = "https://auth.polaris.test/agents/execute"
	const endpoint = "https://auth.polaris.test/oauth2/token"
	for _, alg := range []Algorithm{ES256, EdDSA} {
		key, err := GenerateKey(alg)
		if err != nil {
			t.Fatal(err)
		}
		sign := func(method, url string, body []byte, only []string) string {
			jwt, err := signRequest(key, "agent-1", method, url, body, only, DefaultRequestTTL, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			return jwt
		}
		body := []byte(`{"capability":"demo.echo","arguments":{"note":"café/✓ <b>"}}`)
		cases.Requests = append(cases.Requests,
			request{"agent-1", key.PublicJWK(), sign("POST", execute, body, nil), "POST", execute, string(body), nil, false},
			request{"agent-1", key.PublicJWK(), sign("POST", execute+"?trace=1", body, []string{"demo.echo"}), "POST", execute + "?trace=1", string(body), []string{"demo.echo"}, false},
			request{"agent-1", key.PublicJWK(), sign("GET", "https://auth.polaris.test/agents/session", nil, nil), "GET", "https://auth.polaris.test/agents/session", "", nil, false},
			request{"agent-1", key.PublicJWK(), sign("POST", execute, body, nil), "POST", execute, string(body) + " ", nil, true},
			request{"agent-1", key.PublicJWK(), sign("POST", execute, body, nil), "POST", "https://auth.polaris.test/agents/grants/request", string(body), nil, true},
		)
		a, err := signAssertion(key, "agent-1", endpoint, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		cases.Assertions = append(cases.Assertions, assertion{"agent-1", key.PublicJWK(), a, endpoint})
		exported, err := key.Export()
		if err != nil {
			t.Fatal(err)
		}
		cases.StoredKeys = append(cases.StoredKeys, stored{string(exported), key.PublicJWK()})
	}
	input, _ := json.Marshal(cases)
	cmd := exec.Command(php, filepath.Join("testdata", "interop.php"), "verify")
	cmd.Env = append(os.Environ(), "POLARIS_CORE="+core)
	cmd.Stdin = bytes.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("PHP refused what Go signed: %v\n%s", err, stderr.String())
	}
	var verdict struct {
		OK      int      `json:"ok"`
		PHPKeys []stored `json:"php_keys"`
	}
	if err := json.Unmarshal(out, &verdict); err != nil || verdict.OK != len(cases.Requests)+len(cases.Assertions)+len(cases.StoredKeys) {
		t.Fatalf("PHP answered %s (%v)", out, err)
	}
	for _, k := range verdict.PHPKeys {
		key, err := ImportKey([]byte(k.Stored))
		if err != nil {
			t.Fatalf("a key the PHP SDK stored: %v", err)
		}
		if key.PublicJWK() != k.JWK {
			t.Fatalf("Go reads %+v, PHP %+v", key.PublicJWK(), k.JWK)
		}
	}
}
