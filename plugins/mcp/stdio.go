package mcp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/wiring"
)

// StdioEnv is the environment variable a stdio host reads the credential from, as upstream's
// `polaris mcp` does.
const StdioEnv = "POLARIS_MCP_TOKEN"

// stdioVersions are the handshake-era revisions the stdio transport negotiates, newest first.
var stdioVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

// StdioOptions configures [ServeStdio].
type StdioOptions struct {
	// Credential is who to act as: a session token, an API key, an OAuth access token, an operator
	// key; "" serves the public tools alone. Hosts read it from StdioEnv.
	Credential string
	// In and Out carry the newline-delimited JSON-RPC messages; default os.Stdin and os.Stdout.
	In  io.Reader
	Out io.Writer
	// Tools are served over stdio only, beside the routes: the hook for cmd/polaris's read-only
	// commands (polaris.schema.export, polaris.schema.diff, polaris.manifest, polaris.doctor).
	Tools []wiring.Tool
}

// ServeStdio serves Polaris as an MCP server over stdio for a local coding agent, as the principal
// opts.Credential resolves to, until In ends or ctx is done. The mcp plugin must be registered. It
// speaks the handshake (initialize) every stdio client sends.
//
//	err := mcp.ServeStdio(ctx, p, mcp.StdioOptions{Credential: os.Getenv(mcp.StdioEnv)})
func ServeStdio(ctx context.Context, p *polaris.Polaris, opts StdioOptions) error {
	plugin := Of(p.Graph())
	if plugin == nil {
		return errNoPlugin
	}
	r, _ := http.NewRequestWithContext(ctx, http.MethodPost, plugin.resource, http.NoBody)
	r.Header.Set("Authorization", "Bearer "+opts.Credential)
	c, err := plugin.callerOf(r, opts.Credential)
	if err != nil {
		return fmt.Errorf("mcp: %w (set %s to a session token, API key, OAuth access token or operator key)", err, StdioEnv)
	}
	in, out := opts.In, opts.Out
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}
	s := plugin.session(c, opts.Tools)
	lines := bufio.NewScanner(in)
	lines.Buffer(make([]byte, 64<<10), maxBodySize)
	for lines.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if reply := s.stdio(ctx, lines.Bytes()); reply != nil {
			if _, err := out.Write(append(reply, '\n')); err != nil {
				return err
			}
		}
	}
	return lines.Err()
}

// stdio answers one handshake-era message; nil for a notification.
func (s *session) stdio(ctx context.Context, line []byte) []byte {
	if len(line) == 0 {
		return nil
	}
	msg, id, method, rerr := parseMessage(line)
	if rerr != nil {
		return errorMessage(id, rerr)
	}
	if _, has := msg["id"]; !has || msg["id"] == nil {
		return nil
	}
	params, _ := msg["params"].(map[string]any)
	var result map[string]any
	switch method {
	case "initialize":
		version, _ := params["protocolVersion"].(string)
		if !slices.Contains(stdioVersions, version) {
			version = stdioVersions[0]
		}
		result = map[string]any{"protocolVersion": version, "capabilities": capabilities(),
			"serverInfo": s.p.serverInfo(), "instructions": instructions}
	case "ping":
		result = map[string]any{}
	default:
		result, rerr = s.handle(ctx, method, params)
	}
	if rerr != nil {
		return errorMessage(id, rerr)
	}
	return resultMessage(id, result)
}
