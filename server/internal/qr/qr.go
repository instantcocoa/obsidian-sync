// Package qr renders a QR code as inline SVG (for the admin page) or as
// half-block characters (for a terminal). The content is an
// `obsidian://obsync-join?link=…` URL, which a phone camera opens in
// Obsidian; the plugin there asks before doing anything with it.
package qr

import (
	"fmt"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

// SVG returns a self-contained <svg> element. Modules are drawn as one path
// in the current text colour so the page's theme applies; the quiet zone is
// four modules, as the standard asks.
func SVG(content string) (string, error) {
	q, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return "", err
	}
	q.DisableBorder = true
	bm := q.Bitmap()
	n := len(bm)
	const quiet = 4
	size := n + 2*quiet
	var d strings.Builder
	for y, row := range bm {
		for x, on := range row {
			if on {
				fmt.Fprintf(&d, "M%d %dh1v1h-1z", x+quiet, y+quiet)
			}
		}
	}
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges" role="img" aria-label="QR code"><rect width="%d" height="%d" fill="#fff"/><path d="%s" fill="#000"/></svg>`,
		size, size, size, size, d.String()), nil
}

// Terminal returns the code as lines of half-block characters, two modules
// per character cell, dark on the terminal's background. A one-module quiet
// zone of spaces is included; terminals rarely need the full four.
func Terminal(content string) (string, error) {
	q, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return "", err
	}
	q.DisableBorder = true
	bm := q.Bitmap()
	n := len(bm)
	at := func(x, y int) bool {
		if x < 0 || y < 0 || x >= n || y >= n {
			return false
		}
		return bm[y][x]
	}
	var b strings.Builder
	for y := -2; y < n+2; y += 2 {
		b.WriteString("  ")
		for x := -2; x < n+2; x++ {
			top, bot := at(x, y), at(x, y+1)
			switch {
			case top && bot:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bot:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}
