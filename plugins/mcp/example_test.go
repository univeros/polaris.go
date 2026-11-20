package mcp_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/plugins/mcp"
	"github.com/univeros/polaris.go/plugins/oauth"
)

type deployArgs struct {
	Service string `json:"service"`
}

// Protect an MCP server built with the official Go MCP SDK, in a service of its own, with
// access tokens a remote Polaris issued: in production set JWKSURL to the issuer's JWK Set; here a
// local key stands in for it so the example runs.
func ExampleProtect() {
	server := sdk.NewServer(&sdk.Implementation{Name: "deploy-tools", Version: "1.0.0"}, nil)
	sdk.AddTool(server, &sdk.Tool{Name: "deploy", Description: "Deploy a service"},
		func(ctx context.Context, _ *sdk.CallToolRequest, in deployArgs) (*sdk.CallToolResult, any, error) {
			claims := mcp.Claims(ctx) // the verified access token: sub, scope, client_id, act, ...
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: fmt.Sprintf("%v deployed %s", claims["sub"], in.Service)}}}, nil, nil
		})
	sdkHandler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, nil)

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	protected, err := mcp.Protect(sdkHandler, mcp.ProtectConfig{
		Resource: "https://tools.example.com/mcp",
		Issuer:   "https://auth.example.com",
		// JWKSURL: "https://auth.example.com/auth/.well-known/jwks.json", // a remote Polaris
		Keys:         map[string]crypto.PublicKey{"k1": &key.PublicKey},
		Scopes:       []string{"deploy"},
		ResourceName: "Deploy tools",
	})
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", protected) // serves /mcp and /.well-known/oauth-protected-resource/mcp

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://tools.example.com/mcp", nil))
	fmt.Println(rec.Code, rec.Header().Get("WWW-Authenticate"))
	// Output: 401 Bearer resource_metadata="https://tools.example.com/.well-known/oauth-protected-resource/mcp"
}

// Serve Polaris itself as an MCP server: POST /mcp for remote agents (tokens from the oauth
// plugin, minted for the /mcp resource), and stdio for a local coding agent.
func ExampleNew() {
	var cfg polaris.Config // polaris.FromEnv(db) in a real host
	cfg.PathPrefix = "/auth"
	cfg.Plugins = []polaris.Plugin{
		oauth.New(oauth.Config{BaseURL: "https://app.example.com/auth", Audiences: []string{"https://app.example.com/auth/mcp"}}),
		mcp.New(mcp.Config{BaseURL: "https://app.example.com/auth"}),
	}
	p, err := polaris.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	http.Handle("/auth/", p.Handler()) // POST /auth/mcp is the MCP server

	// `yourapp mcp`: a local coding agent's stdio server, as the credential's principal.
	if len(os.Args) > 1 && os.Args[1] == "mcp" {
		if err := mcp.ServeStdio(context.Background(), p, mcp.StdioOptions{Credential: os.Getenv(mcp.StdioEnv)}); err != nil {
			log.Fatal(err)
		}
	}
}
