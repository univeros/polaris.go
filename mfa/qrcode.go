package mfa

import (
	"fmt"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

// QRRenderer renders data, typically an otpauth:// provisioning URI, as a QR code. data must be a
// trusted value: a QR encodes whatever it is given.
type QRRenderer interface {
	// SVG returns a standalone SVG document.
	SVG(data string) (string, error)
}

// SVGQRCode is the default QRRenderer: medium error correction, 4-module quiet zone, scalable
// SVG markup. The image differs from upstream's byte for byte; the shape (an SVG document) does not.
type SVGQRCode struct{}

// SVG implements QRRenderer.
func (SVGQRCode) SVG(data string) (string, error) {
	code, err := qrcode.New(data, qrcode.Medium)
	if err != nil {
		return "", fmt.Errorf("mfa: render QR code: %w", err)
	}
	bitmap := code.Bitmap()
	n := len(bitmap)

	var b strings.Builder
	fmt.Fprintf(&b, `<?xml version="1.0"?>`+"\n"+`<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="320px" height="320px" viewBox="0 0 %d %d" shape-rendering="crispEdges">`, n, n)
	fmt.Fprintf(&b, `<rect x="0" y="0" width="%d" height="%d" fill="#ffffff"/><path fill="#000000" d="`, n, n)
	for y, row := range bitmap {
		for x := 0; x < len(row); {
			if !row[x] {
				x++
				continue
			}
			start := x
			for x < len(row) && row[x] {
				x++
			}
			fmt.Fprintf(&b, "M%d,%dh%dv1h-%dz", start, y, x-start, x-start)
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String(), nil
}
