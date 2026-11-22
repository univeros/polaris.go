package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/univeros/polaris.go/internal/version"
	"net/http"
	"slices"
	"strings"

	"github.com/univeros/polaris.go/wiring"
)

// The server's identity; its version is the running Polaris release (internal/version).
const (
	serverDescription = "Polaris for Go: every endpoint and CLI command as a tool, under the caller's own permissions."
	instructions      = "Tools are named polaris.<route> and answer {status, body}: what the HTTP route answers for the same request. A 4xx or 5xx status is an error result."
)

// ToolsPageSize is the most tools one tools/list result carries; a longer list continues at its
// nextCursor.
const ToolsPageSize = 100

// JSON-RPC and MCP error codes.
const (
	codeParse              = -32700
	codeInvalidRequest     = -32600
	codeMethodNotFound     = -32601
	codeInvalidParams      = -32602
	codeInternal           = -32603
	codeResourceNotFound   = -32002
	codeHeaderMismatch     = -32020
	codeUnsupportedVersion = -32022
)

const (
	metaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	metaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
	metaServerInfo         = "io.modelcontextprotocol/serverInfo"
	base64Prefix           = "=?base64?"
	base64Suffix           = "?="
)

// removedMethods are the handshake-era methods the 2026-07-28 profile dropped.
var removedMethods = []string{"initialize", "notifications/initialized", "ping", "logging/setLevel",
	"resources/subscribe", "resources/unsubscribe", "notifications/roots/list_changed"}

// cacheable results carry the cache hints (ttlMs, cacheScope) in the 2026-07-28 profile.
var cacheable = []string{"server/discover", "tools/list", "prompts/list", "resources/list", "resources/templates/list", "resources/read"}

// rpcError is a JSON-RPC error and the HTTP status the stateless profile answers it with.
type rpcError struct {
	code    int
	message string
	data    any
	status  int
}

func (e *rpcError) Error() string { return e.message }

func newError(code int, status int, format string, args ...any) *rpcError {
	return &rpcError{code: code, message: fmt.Sprintf(format, args...), status: status}
}

func errorMessage(id any, e *rpcError) []byte {
	body := map[string]any{"code": e.code, "message": e.message}
	if e.data != nil {
		body["data"] = e.data
	}
	msg := map[string]any{"jsonrpc": "2.0", "error": body}
	if id != nil {
		msg["id"] = id
	}
	return encodeJSON(msg)
}

func resultMessage(id any, result map[string]any) []byte {
	return encodeJSON(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

// session is one caller's view of the server: the tools they may call (and, over stdio, the
// extra tools the host passes).
type session struct {
	p      *Plugin
	caller caller
	extra  []wiring.Tool
}

func (p *Plugin) session(c caller, extra []wiring.Tool) *session {
	return &session{p: p, caller: c, extra: extra}
}

// stateless answers one HTTP message of the 2026-07-28 profile: the status and the body (nil for
// none).
func (p *Plugin) stateless(ctx context.Context, body []byte, h http.Header, c caller) (int, []byte) {
	if len(body) > maxBodySize {
		return http.StatusRequestEntityTooLarge, errorMessage(nil, newError(codeInvalidRequest, 0, "Request body exceeds the maximum allowed size of %d bytes.", maxBodySize))
	}
	msg, id, method, rerr := parseMessage(body)
	if rerr != nil {
		return rerr.status, errorMessage(id, rerr)
	}
	if _, has := msg["id"]; !has || msg["id"] == nil {
		if slices.Contains(removedMethods, method) {
			return http.StatusBadRequest, nil
		}
		return http.StatusAccepted, nil
	}
	if id == nil {
		return http.StatusBadRequest, errorMessage(nil, newError(codeInvalidRequest, 0, "A JSON-RPC request id must be a string or a number."))
	}
	params, _ := msg["params"].(map[string]any)
	if rerr := checkEnvelope(method, params, h); rerr != nil {
		return rerr.status, errorMessage(id, rerr)
	}
	var result map[string]any
	switch {
	case method == "server/discover":
		result = map[string]any{"supportedVersions": []string{ProtocolVersion}, "capabilities": capabilities(), "instructions": instructions}
	case slices.Contains(removedMethods, method):
		rerr = newError(codeMethodNotFound, http.StatusNotFound, "Method \"%s\" does not exist in protocol version %s.", method, ProtocolVersion)
	default:
		result, rerr = p.session(c, nil).handle(ctx, method, params)
	}
	if rerr != nil {
		return rerr.status, errorMessage(id, rerr)
	}
	return http.StatusOK, resultMessage(id, p.stamp(method, result))
}

// parseMessage decodes a JSON-RPC message; id is nil when absent or not a string or integer.
func parseMessage(body []byte) (msg map[string]any, id any, method string, err *rpcError) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if e := dec.Decode(&v); e != nil || dec.More() {
		return nil, nil, "", newError(codeParse, http.StatusBadRequest, "Invalid JSON: %v", e)
	}
	msg, ok := v.(map[string]any)
	if !ok {
		return nil, nil, "", newError(codeInvalidRequest, http.StatusBadRequest, "A JSON-RPC message must be a JSON object.")
	}
	switch raw := msg["id"].(type) {
	case string:
		id = raw
	case json.Number:
		if _, e := raw.Int64(); e == nil {
			id = raw
		}
	}
	method, _ = msg["method"].(string)
	if method == "" {
		return nil, id, "", newError(codeInvalidRequest, http.StatusBadRequest, "A JSON-RPC message must carry a \"method\".")
	}
	return msg, id, method, nil
}

// checkEnvelope validates the profile's _meta and the transport headers (SEP-2243).
func checkEnvelope(method string, params map[string]any, h http.Header) *rpcError {
	meta, ok := params["_meta"].(map[string]any)
	if !ok {
		return newError(codeInvalidParams, http.StatusBadRequest, "Request is missing the required \"params._meta\" member.")
	}
	version, _ := meta[metaProtocolVersion].(string)
	if version == "" {
		return newError(codeInvalidParams, http.StatusBadRequest, "Request \"_meta\" is missing the required \"%s\" member.", metaProtocolVersion)
	}
	if _, ok := meta[metaClientCapabilities].(map[string]any); !ok {
		return newError(codeInvalidParams, http.StatusBadRequest, "Request \"_meta\" is missing the required \"%s\" member.", metaClientCapabilities)
	}
	switch header := h.Get("MCP-Protocol-Version"); {
	case header == "":
		return newError(codeHeaderMismatch, http.StatusBadRequest, "Missing required MCP-Protocol-Version header (_meta declares \"%s\").", version)
	case header != version:
		return newError(codeHeaderMismatch, http.StatusBadRequest, "MCP-Protocol-Version header \"%s\" contradicts the \"%s\" declared in _meta.", header, version)
	case version != ProtocolVersion:
		e := newError(codeUnsupportedVersion, http.StatusBadRequest, "Unsupported protocol version")
		e.data = map[string]any{"requested": version, "supported": []string{ProtocolVersion}}
		return e
	}
	switch declared := strings.TrimSpace(h.Get("Mcp-Method")); {
	case declared == "":
		return newError(codeHeaderMismatch, http.StatusBadRequest, "Missing required Mcp-Method header (body method is \"%s\").", method)
	case declared != method:
		return newError(codeHeaderMismatch, http.StatusBadRequest, "Mcp-Method header \"%s\" does not match the body method \"%s\".", declared, method)
	}
	var expected string
	switch method {
	case "tools/call", "prompts/get":
		expected, _ = params["name"].(string)
	case "resources/read":
		expected, _ = params["uri"].(string)
	}
	if expected == "" {
		return nil
	}
	declared := strings.TrimSpace(h.Get("Mcp-Name"))
	if declared == "" {
		return newError(codeHeaderMismatch, http.StatusBadRequest, "Missing required Mcp-Name header (body carries \"%s\").", expected)
	}
	name, ok := decodeHeader(declared)
	if !ok {
		return newError(codeHeaderMismatch, http.StatusBadRequest, "Mcp-Name header is not a well-formed Base64 wrapper.")
	}
	if name != expected {
		return newError(codeHeaderMismatch, http.StatusBadRequest, "Mcp-Name header \"%s\" does not match the body value \"%s\".", name, expected)
	}
	return nil
}

// decodeHeader unwraps a "=?base64?…?=" header value strictly; a plain value is returned as is.
func decodeHeader(v string) (string, bool) {
	inner, ok := strings.CutPrefix(v, base64Prefix)
	if !ok || !strings.HasSuffix(inner, base64Suffix) {
		return v, true
	}
	b, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSuffix(inner, base64Suffix))
	return string(b), err == nil
}

func capabilities() map[string]any {
	return map[string]any{"tools": map[string]any{}, "resources": map[string]any{}}
}

func (p *Plugin) serverInfo() map[string]any {
	return map[string]any{"name": p.cfg.ServerName, "version": version.Module(), "description": serverDescription}
}

// stamp adds what the 2026-07-28 profile puts on every result: resultType, the cache hints on a
// cacheable one (nothing is fresh, nothing is shared) and the server's identity.
func (p *Plugin) stamp(method string, result map[string]any) map[string]any {
	result["resultType"] = "complete"
	if slices.Contains(cacheable, method) {
		result["ttlMs"], result["cacheScope"] = 0, "private"
	}
	result["_meta"] = map[string]any{metaServerInfo: p.serverInfo()}
	return result
}

// handle runs one request method common to both transports.
func (s *session) handle(ctx context.Context, method string, params map[string]any) (map[string]any, *rpcError) {
	switch method {
	case "tools/list":
		tools, err := s.tools(ctx)
		if err != nil {
			return nil, s.internal(ctx, method, err)
		}
		return toolsPage(tools, params)
	case "tools/call":
		return s.callTool(ctx, params)
	case "resources/list":
		return map[string]any{"resources": s.p.resources()}, nil
	case "resources/templates/list":
		return map[string]any{"resourceTemplates": []any{problemTemplate}}, nil
	case "resources/read":
		uri, _ := params["uri"].(string)
		return s.p.readResource(ctx, uri)
	}
	return nil, newError(codeMethodNotFound, http.StatusNotFound, "No handler found for method \"%s\".", method)
}

// toolsPage is one tools/list result: at most ToolsPageSize tools, starting after the tool the
// cursor names, and the nextCursor naming the last one when more follow. The cursor is opaque to
// the client (base64url of a tool name) and grants nothing: it must name one of the caller's own
// tools, listed again under the caller's permissions, or the request is invalid params.
func toolsPage(tools []wiring.Tool, params map[string]any) (map[string]any, *rpcError) {
	start := 0
	if raw, has := params["cursor"]; has {
		cursor, _ := raw.(string)
		name, err := base64.RawURLEncoding.DecodeString(cursor)
		i := slices.IndexFunc(tools, func(t wiring.Tool) bool { return t.Name == string(name) })
		if cursor == "" || err != nil || i < 0 {
			return nil, newError(codeInvalidParams, http.StatusBadRequest, "Invalid cursor.")
		}
		start = i + 1
	}
	end := min(start+ToolsPageSize, len(tools))
	list := make([]any, 0, end-start)
	for _, t := range tools[start:end] {
		list = append(list, definition(t))
	}
	result := map[string]any{"tools": list}
	if end < len(tools) {
		result["nextCursor"] = base64.RawURLEncoding.EncodeToString([]byte(tools[end-1].Name))
	}
	return result, nil
}

func (s *session) tools(ctx context.Context) ([]wiring.Tool, error) {
	tools, err := s.p.tools(ctx, s.caller)
	return append(tools, s.extra...), err
}

func (s *session) internal(ctx context.Context, method string, err error) *rpcError {
	s.p.g.Logger().ErrorContext(ctx, "polaris mcp: "+method+" failed", "error", err)
	return newError(codeInternal, http.StatusInternalServerError, "Internal server error.")
}

func (s *session) callTool(ctx context.Context, params map[string]any) (map[string]any, *rpcError) {
	name, _ := params["name"].(string)
	args := map[string]any{}
	switch a := params["arguments"].(type) {
	case nil:
	case map[string]any:
		args = a
	default:
		return nil, newError(codeInvalidParams, http.StatusBadRequest, "Invalid parameters for tool '%s': arguments must be an object.", name)
	}
	tools, err := s.tools(ctx)
	if err != nil {
		return nil, s.internal(ctx, "tools/call", err)
	}
	i := slices.IndexFunc(tools, func(t wiring.Tool) bool { return t.Name == name })
	if i < 0 {
		return nil, newError(codeInvalidParams, http.StatusBadRequest, "Tool not found: \"%s\".", name)
	}
	res, err := tools[i].Call(ctx, args)
	if err != nil {
		return nil, s.internal(ctx, "tools/call", err)
	}
	return map[string]any{
		"content":           []any{map[string]any{"type": "text", "text": text(res.Body)}},
		"isError":           res.Status >= 400,
		"structuredContent": map[string]any{"status": res.Status, "body": res.Body},
	}, nil
}

// text is a tool result's text content: the body as indented JSON, unless it already is text.
func text(body any) string {
	if s, ok := body.(string); ok {
		return s
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "    ")
	if err := enc.Encode(body); err != nil {
		return fmt.Sprint(body)
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

// definition is a tool as tools/list lists it.
func definition(t wiring.Tool) map[string]any {
	input := t.InputSchema
	if input == nil {
		input = map[string]any{"type": "object"}
	}
	d := map[string]any{
		"name":        t.Name,
		"inputSchema": input,
		"description": t.Description,
		"annotations": map[string]any{"readOnlyHint": t.ReadOnly, "destructiveHint": t.Destructive},
	}
	if t.OutputSchema != nil {
		d["outputSchema"] = t.OutputSchema
	}
	return d
}

var errNoPlugin = errors.New("mcp: the mcp plugin is not registered: add mcp.New(mcp.Config{BaseURL: ...}) to polaris.Config.Plugins")
