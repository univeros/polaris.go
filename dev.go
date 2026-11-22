package polaris

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
)

// EnvDev is the environment variable DevEnv requires set to "1": the deliberate, per-shell
// statement that this process is a development one.
const EnvDev = "POLARIS_DEV"

// DevEnv fills in, for local development only, what FromEnv reads and the environment lacks: a
// random APP_KEY, a fresh RS256 key pair (AUTH_JWT_PRIVATE_KEY, AUTH_JWT_PUBLIC_KEY) and
// AUTH_ISSUER = issuer. A variable already set is kept. Each value it generates is logged as a
// warning: tokens signed with a generated key die with the process, and anything encrypted with
// a generated APP_KEY (MFA secrets) is unreadable after a restart.
//
// It refuses (an error, nothing set) unless POLARIS_DEV=1 is in the environment, so a binary that
// still calls it cannot boot in production on throwaway secrets by accident:
//
//	POLARIS_DEV=1 go run ./cmd/app
//
// In production, remove the call and set the variables (`polaris init` writes them to .env).
func DevEnv(issuer string) error {
	if os.Getenv(EnvDev) != "1" {
		return fmt.Errorf("polaris: DevEnv generates throwaway secrets and runs only with %s=1 in the environment; "+
			"in production remove the DevEnv call and set APP_KEY, AUTH_JWT_PRIVATE_KEY, AUTH_JWT_PUBLIC_KEY and AUTH_ISSUER "+
			"(`polaris init` writes them to .env)", EnvDev)
	}
	set := func(name, value, warning string) error {
		if err := os.Setenv(name, value); err != nil {
			return fmt.Errorf("polaris: DevEnv: %w", err)
		}
		slog.Warn("polaris: DEVELOPMENT ONLY: "+warning, "variable", name, "flag", EnvDev+"=1")
		return nil
	}
	if os.Getenv("APP_KEY") == "" {
		key := make([]byte, 32)
		_, _ = rand.Read(key) // never fails (crypto/rand)
		if err := set("APP_KEY", base64.StdEncoding.EncodeToString(key), "generated a throwaway APP_KEY; what it encrypts is unreadable after a restart"); err != nil {
			return err
		}
	}
	if os.Getenv("AUTH_JWT_PRIVATE_KEY") == "" && os.Getenv("AUTH_JWT_PUBLIC_KEY") == "" {
		private, public, err := devRSAPair()
		if err != nil {
			return err
		}
		if err := set("AUTH_JWT_PRIVATE_KEY", private, "generated a throwaway JWT key pair; its tokens die with the process"); err != nil {
			return err
		}
		if err := set("AUTH_JWT_PUBLIC_KEY", public, "generated a throwaway JWT key pair; its tokens die with the process"); err != nil {
			return err
		}
	}
	if os.Getenv("AUTH_ISSUER") == "" {
		return set("AUTH_ISSUER", issuer, "AUTH_ISSUER set to "+issuer)
	}
	return nil
}

// devRSAPair is a fresh RSA 2048 key pair as PKCS#8 and PKIX PEM.
func devRSAPair() (private, public string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("polaris: DevEnv: %w", err)
	}
	priv, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("polaris: DevEnv: %w", err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("polaris: DevEnv: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})), nil
}
