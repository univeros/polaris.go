package mfa

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestRendersDataAsAnSVGDocument(t *testing.T) {
	svg, err := SVGQRCode{}.SVG("otpauth://totp/Univeros:ada@example.com?secret=ABC&issuer=Univeros")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(svg, "<?xml") || !strings.Contains(svg, "<svg") {
		t.Fatalf("not SVG markup: %.80s", svg)
	}
	if err := xml.Unmarshal([]byte(svg), new(struct{})); err != nil {
		t.Fatalf("not well-formed XML: %v", err)
	}
}

func TestRefusesDataTooLongForAQRCode(t *testing.T) {
	if _, err := (SVGQRCode{}).SVG(strings.Repeat("x", 5000)); err == nil {
		t.Fatal("want an error")
	}
}
