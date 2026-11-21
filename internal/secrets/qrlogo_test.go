// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"bytes"
	"image/png"
	"testing"
)

// TestQRLogoPNG: the code carries the mark in its centre, on a white tile,
// and the corners keep their finder patterns.
func TestQRLogoPNG(t *testing.T) {
	const link = "privasys-wallet://vault-approval?vault_op=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&issuer=https%3A%2F%2Fprivasys.id"
	raw, err := qrLogoPNG(link, 4)
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	b := img.Bounds()
	if b.Dx() != b.Dy() || b.Dx()%4 != 0 {
		t.Fatalf("image is %dx%d, want a square of whole modules", b.Dx(), b.Dy())
	}
	mid := b.Dx() / 2
	// The diagonal through the centre is the white band between the shapes.
	if r, g, bl, _ := img.At(mid, mid).RGBA(); r>>8 != 0xff || g>>8 != 0xff || bl>>8 != 0xff {
		t.Errorf("centre is %02x%02x%02x, want white", r>>8, g>>8, bl>>8)
	}
	off := b.Dx() / 20
	if r, g, bl, _ := img.At(mid-off, mid-off).RGBA(); !(g > r && g > bl) {
		t.Errorf("above the diagonal is %02x%02x%02x, want green", r>>8, g>>8, bl>>8)
	}
	if r, g, bl, _ := img.At(mid+off, mid+off).RGBA(); !(bl > r && bl > g) {
		t.Errorf("below the diagonal is %02x%02x%02x, want blue", r>>8, g>>8, bl>>8)
	}
	// A finder pattern's corner: the first module after the quiet zone.
	if r, _, _, _ := img.At(4*4+1, 4*4+1).RGBA(); r != 0 {
		t.Errorf("finder corner is not dark")
	}
	if len(raw) > 1400 {
		t.Errorf("PNG is %d bytes; keep the page URL small", len(raw))
	}
}
