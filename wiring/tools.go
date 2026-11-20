package wiring

import (
	"context"

	"github.com/univeros/polaris.go/token"
)

// ToolResult is what an MCP tool answers: what the equivalent HTTP route would answer.
type ToolResult struct {
	Status int // HTTP status; >= 400 makes the MCP result isError
	Body   any // decoded JSON body (nil for none)
}

// Tool is one MCP tool a plugin contributes to Polaris's MCP server (plugins/mcp).
type Tool struct {
	Name         string
	Description  string
	InputSchema  any  // JSON Schema object; nil means {"type":"object"}
	OutputSchema any  // optional
	ReadOnly     bool // annotations.readOnlyHint
	Destructive  bool // annotations.destructiveHint
	// Call runs the tool; an error is a JSON-RPC internal error, a refusal is a ToolResult >= 400.
	Call func(ctx context.Context, arguments map[string]any) (ToolResult, error)
}

// ToolProvider is implemented by a plugin that exposes MCP tools (agents' capabilities). caller is
// nil without a credential; a tool the caller may not use is simply not returned.
type ToolProvider interface {
	MCPTools(ctx context.Context, caller *token.Token) ([]Tool, error)
}
