// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package secrets

import (
	"bytes"
	"image"
	"image/color"
	"image/png"

	"github.com/skip2/go-qrcode"
)

const (
	// qrLogoShare is the logo's side as a share of the code's, quiet zone
	// excluded. The same share is used wherever Privasys shows a QR code.
	qrLogoShare = 0.24
	// qrLogoShades is how many shades each of the mark's two gradients is
	// drawn in. With black and white that makes a 16-colour image, which
	// keeps the PNG at four bits a pixel.
	qrLogoShades = 7
)

// qrLogoPalette is white, black, then the mark's green and blue gradients.
var qrLogoPalette = func() color.Palette {
	p := color.Palette{color.RGBA{0xff, 0xff, 0xff, 0xff}, color.RGBA{0, 0, 0, 0xff}}
	p = append(p, shades(color.RGBA{0x34, 0xe8, 0x9e, 0xff}, color.RGBA{0x12, 0xb0, 0x6e, 0xff})...)
	p = append(p, shades(color.RGBA{0x00, 0xbc, 0xf2, 0xff}, color.RGBA{0x00, 0xa0, 0xeb, 0xff})...)
	return p
}()

func shades(from, to color.RGBA) []color.Color {
	out := make([]color.Color, qrLogoShades)
	mix := func(a, b uint8, t float64) uint8 { return uint8(float64(a) + (float64(b)-float64(a))*t + 0.5) }
	for i := range out {
		t := float64(i) / float64(qrLogoShades-1)
		out[i] = color.RGBA{mix(from.R, to.R, t), mix(from.G, to.G, t), mix(from.B, to.B, t), 0xff}
	}
	return out
}

// qrLogoPNG renders content as a QR code with the Privasys logo in its centre,
// scale pixels a module, as a PNG. The code is made at the highest
// error-correction level (H, up to 30% recovered), so the modules under the
// logo are read back from the rest.
func qrLogoPNG(content string, scale int) ([]byte, error) {
	qr, err := qrcode.New(content, qrcode.High)
	if err != nil {
		return nil, err
	}
	bits := qr.Bitmap() // includes the quiet zone
	n := len(bits)
	img := image.NewPaletted(image.Rect(0, 0, n*scale, n*scale), qrLogoPalette)
	for y := 0; y < n*scale; y++ {
		for x := 0; x < n*scale; x++ {
			if bits[y/scale][x/scale] {
				img.SetColorIndex(x, y, 1)
			}
		}
	}

	// The modules start where the first dark one is: the corner of a finder.
	quiet := 0
	for quiet < n && !bits[quiet][quiet] {
		quiet++
	}
	side := float64((n-2*quiet)*scale) * qrLogoShare
	at := (float64(n*scale) - side) / 2
	drawQRLogo(img, at, side)

	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// drawQRLogo draws the Privasys mark on a white rounded tile, side pixels
// wide with its corner at (at, at). The tile gives the mark a clear edge
// against the modules.
func drawQRLogo(img *image.Paletted, at, side float64) {
	radius := side * 0.18
	inset := side * 0.14
	mark := side - 2*inset
	for y := int(at); float64(y) < at+side; y++ {
		for x := int(at); float64(x) < at+side; x++ {
			// The pixel's centre, within the tile.
			px, py := float64(x)+0.5-at, float64(y)+0.5-at
			if px < 0 || py < 0 || px > side || py > side || outsideCorner(px, py, side, radius) {
				continue
			}
			img.SetColorIndex(x, y, qrMarkColor((px-inset)/mark*500, (py-inset)/mark*500))
		}
	}
}

// outsideCorner reports whether (x, y) falls in the part of a side-wide square
// that rounding its corners by radius cuts off.
func outsideCorner(x, y, side, radius float64) bool {
	cx, cy := x, y
	if cx > side/2 {
		cx = side - cx
	}
	if cy > side/2 {
		cy = side - cy
	}
	if cx >= radius || cy >= radius {
		return false
	}
	dx, dy := radius-cx, radius-cy
	return dx*dx+dy*dy > radius*radius
}

// qrMarkColor is the palette index of the mark at (u, v) on its 500 by 500
// canvas: a green shape above the diagonal, a blue one below, white between
// them and around.
func qrMarkColor(u, v float64) uint8 {
	if u < 0 || v < 0 || u > 500 || v > 500 {
		return 0
	}
	shade := func(t float64) uint8 {
		// Both gradients run from 21% to 42% of their length.
		t = (t - 0.21) / 0.21
		if t < 0 {
			t = 0
		} else if t > 1 {
			t = 1
		}
		return uint8(t*float64(qrLogoShades-1) + 0.5)
	}
	switch {
	case u+v <= 450:
		if u < 100 && v < 100 && (100-u)*(100-u)+(100-v)*(100-v) > 100*100 {
			return 0
		}
		return 2 + shade((u+v)/900)
	case u+v >= 550:
		if u > 400 && v > 400 && (u-400)*(u-400)+(v-400)*(v-400) > 100*100 {
			return 0
		}
		return 2 + qrLogoShades + shade((1000-u-v)/900)
	}
	return 0
}
