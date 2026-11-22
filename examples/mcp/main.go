// Command mcp protects an MCP server of the host's own with Polaris-issued tokens, and mounts
// Polaris's own MCP endpoint beside it.
//
//   - POST /tools/mcp: the host's MCP server, built with the official Go MCP SDK (one tool,
//     "deploy"), behind mcp.Protect. A token must name this resource (aud) and hold the
//     "deploy.run" scope; mcp.Claims gives the tool the verified token.
//   - POST /mcp: Polaris as an MCP server (plugins/mcp): every Polaris route the caller may call
//     is a tool (polaris.auth.me, polaris.orgs.members.list, …).
//
// Tokens come from Polaris's OAuth provider (plugins/oauth): a client exchanges a user's session
// for a token bound to one resource (RFC 8693 token exchange with the resource parameter). The
// README walks through it with curl.
//
//	go run ./examples/mcp
//
// Zero setup: SQLite in a temporary directory, and APP_KEY, AUTH_JWT_PRIVATE_KEY,
// AUTH_JWT_PUBLIC_KEY and AUTH_ISSUER generated when the environment lacks them. ADDR (default
// localhost:8080) is where it listens. It creates one user, ada@example.com, owner of "Acme".
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/plugins/mcp"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/sqlstore"
)

// The demo user; sign in as them to follow the README.
const (
	demoEmail    = "ada@example.com"
	demoPassword = "correct horse battery staple"
)

func main() {
	ctx := context.Background()
	addr := envOr("ADDR", "localhost:8080")
	baseURL := "http://" + addr
	if err := devEnv(baseURL); err != nil {
		log.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "polaris-mcp-")
	if err != nil {
		log.Fatal(err)
	}
	db, err := sqlstore.Open(ctx, store.SQLite, "file:"+filepath.Join(dir, "polaris.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		log.Fatal(err)
	}
	h, p, err := newServer(ctx, db, baseURL)
	if err != nil {
		log.Fatal(err)
	}
	orgID, err := seed(ctx, p)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s; sign in as %s / %q (organization %s)", baseURL, demoEmail, demoPassword, orgID)
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

// newServer mounts Polaris (with the OAuth provider and its MCP server) and the host's own MCP
// server behind mcp.Protect.
func newServer(ctx context.Context, db store.Adapter, baseURL string) (http.Handler, *polaris.Polaris, error) {
	toolsURL := baseURL + "/tools/mcp" // the host MCP server's resource: the aud its tokens carry
	cfg, err := polaris.FromEnv(db,
		// Audiences: the resources Polaris's tokens may be minted for (the resource parameter).
		oauth.New(oauth.Config{BaseURL: baseURL, Audiences: []string{baseURL + "/mcp", toolsURL}}),
		mcp.New(mcp.Config{BaseURL: baseURL}),
	)
	if err != nil {
		return nil, nil, err
	}
	// The host's own permission: it is also the OAuth scope the MCP server requires.
	cfg.Permissions = map[string]string{"deploy.run": "Deploy a service"}
	// Every organization's owner holds it, so the owner can delegate the deploy.run scope.
	cfg.RolePermissions = map[string][]string{"owner": {"deploy.run"}}
	p, err := polaris.New(cfg)
	if err != nil {
		return nil, nil, err
	}
	if _, err := p.Migrate(ctx); err != nil {
		return nil, nil, err
	}

	// The host's MCP server: any http.Handler; here the official Go SDK's, stateless JSON.
	server := sdk.NewServer(&sdk.Implementation{Name: "deploy-tools", Version: "1.0.0"}, nil)
	sdk.AddTool(server, &sdk.Tool{Name: "deploy", Description: "Deploy a service"}, deploy)
	tools := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server },
		&sdk.StreamableHTTPOptions{Stateless: true, JSONResponse: true})

	protected, err := mcp.Protect(tools, mcp.ProtectConfig{
		Resource:     toolsURL,
		Graph:        p.Graph(), // Polaris in this process; a remote Polaris: JWKSURL
		Scopes:       []string{"deploy.run"},
		ResourceName: "Deploy tools",
	})
	if err != nil {
		return nil, nil, err
	}

	mux := http.NewServeMux()
	mux.Handle("/", p.Handler()) // /auth/*, /orgs/*, /oauth2/*, POST /mcp, /.well-known/*
	mux.Handle("/tools/mcp", protected)
	// The RFC 9728 metadata a 401 points clients at; Protect serves it.
	mux.Handle("GET /.well-known/oauth-protected-resource/tools/mcp", protected)
	return mux, p, nil
}

type deployArgs struct {
	Service string `json:"service" jsonschema:"the service to deploy"`
}

// deploy is the tool. mcp.Claims is the verified access token: sub, scope, client_id, act, …
func deploy(ctx context.Context, _ *sdk.CallToolRequest, in deployArgs) (*sdk.CallToolResult, any, error) {
	claims := mcp.Claims(ctx)
	text := fmt.Sprintf("%s deployed by user %v through client %v", in.Service, claims["sub"], claims["client_id"])
	return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: text}}}, nil, nil
}

// seed creates the demo user and their organization; its owner role holds deploy.run
// (Config.RolePermissions).
func seed(ctx context.Context, p *polaris.Polaris) (string, error) {
	ada, err := p.Users().Create(ctx, polaris.NewUser{Email: demoEmail, Password: demoPassword, EmailVerified: true})
	if err != nil {
		return "", err
	}
	org, err := p.Orgs().Create(ctx, ada.ID, "Acme", "")
	if err != nil {
		return "", err
	}
	return org.ID, nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// devEnv sets what polaris.FromEnv reads and the environment lacks, so the example runs with zero
// setup: a random APP_KEY, a fresh RS256 key pair, AUTH_ISSUER. Tokens signed with a generated key
// die with the process; in production set the variables (`polaris init` writes them to .env).
func devEnv(issuer string) error {
	if os.Getenv("APP_KEY") == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		if err := os.Setenv("APP_KEY", base64.StdEncoding.EncodeToString(b)); err != nil {
			return err
		}
	}
	if os.Getenv("AUTH_JWT_PRIVATE_KEY") == "" {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		priv, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return err
		}
		if err := os.Setenv("AUTH_JWT_PRIVATE_KEY", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}))); err != nil {
			return err
		}
		if err := os.Setenv("AUTH_JWT_PUBLIC_KEY", string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))); err != nil {
			return err
		}
		log.Print("generated a throwaway JWT key pair (set AUTH_JWT_PRIVATE_KEY and AUTH_JWT_PUBLIC_KEY to keep tokens across restarts)")
	}
	if os.Getenv("AUTH_ISSUER") == "" {
		return os.Setenv("AUTH_ISSUER", issuer)
	}
	return nil
}
