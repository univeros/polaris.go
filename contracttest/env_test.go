package contracttest

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestTestRSAKeyPEM(t *testing.T) {
	private, public := TestRSAKeyPEM()
	block, _ := pem.Decode([]byte(private))
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatal("private key is not PKCS#8 PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil || !TestRSAKey().Equal(key) || TestRSAKey().N.BitLen() != RSAKeyBits {
		t.Fatalf("private key: %v", err)
	}
	block, _ = pem.Decode([]byte(public))
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatal("public key is not PKIX PEM")
	}
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil || !TestRSAKey().PublicKey.Equal(pub) {
		t.Fatalf("public key: %v", err)
	}
}

func TestEnvironment(t *testing.T) {
	if len(AppKey) < 32 {
		t.Fatal("APP_KEY must be at least 32 bytes")
	}
	limits := RateLimits()
	if len(limits) != 9 || limits["login"] != (RateLimit{10, 5 * time.Minute}) || limits["authenticated"].Limit != 600 {
		t.Fatalf("rate limits: %v", limits)
	}
	clk := NewRateClock()
	first := clk.Now()
	time.Sleep(time.Millisecond)
	if !clk.Now().Equal(first) {
		t.Fatal("the rate clock moves")
	}
}
