package main

import (
	"os/exec"
	"testing"
)

// The server runs its command with the URL it serves, and answers the command's exit status.
func TestRunServesTheCommand(t *testing.T) {
	t.Setenv("POLARIS_DEV", "1")
	for _, name := range []string{"APP_KEY", "AUTH_JWT_PRIVATE_KEY", "AUTH_JWT_PUBLIC_KEY", "AUTH_ISSUER"} {
		t.Setenv(name, "") // DevEnv sets them; restored afterwards
	}
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("needs curl")
	}
	status, err := run(t.Context(), []string{"sh", "-c", curl + ` -fsS "$AGENT_AUTH_URL/.well-known/agent-configuration" | grep -q '"/capability/list"' && exit 3; exit 1`})
	if err != nil || status != 3 {
		t.Errorf("status %d, %v", status, err)
	}
	if _, err := run(t.Context(), []string{"no-such-command-" + t.Name()}); err == nil {
		t.Error("a command that cannot start is an error")
	}
}
