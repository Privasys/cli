// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package output

import (
	"fmt"
	"io"
	"os"
)

// Brand colours (24-bit truecolor) from the Privasys palette.
const (
	cGreen = "\033[38;2;52;232;158m"
	cBlue  = "\033[38;2;0;188;242m"
	cSlate = "\033[38;2;100;116;139m"
	cWhite = "\033[97m"
	cBold  = "\033[1m"
	cReset = "\033[0m"
)

// useColor is true only when stdout is an interactive terminal and the user
// hasn't opted out — so agents, pipes, and --format json never see escape
// codes.
var useColor = detectColor()

func detectColor() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("PRIVASYS_NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func paint(code, s string) string {
	if !useColor {
		return s
	}
	return code + s + cReset
}

// IsTTY reports whether w is an interactive terminal (a char device). Used to
// gate live, in-place rendering (spinners, \r updates) so pipes, agents, and
// captured output get plain, one-line-per-change output instead.
func IsTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// Green/Blue/Slate/Bold colourise a string for human terminals (no-ops when
// colour is disabled).
func Green(s string) string { return paint(cGreen, s) }
func Blue(s string) string  { return paint(cBlue, s) }
func Slate(s string) string { return paint(cSlate, s) }
func Bold(s string) string  { return paint(cBold, s) }

// Check returns a light brand-green check mark (plain ASCII when colour is off).
func Check() string {
	if useColor {
		return cGreen + "✓" + cReset
	}
	return "OK"
}

// Success writes a "✔ <message>" line (to stderr by convention, so stdout
// stays the data channel for piping).
func Success(w io.Writer, format string, a ...interface{}) {
	fmt.Fprintf(w, "%s %s\n", Check(), fmt.Sprintf(format, a...))
}

// Wordmark returns the "privasys" wordmark in bold white (the brand colours
// stay on the logo mark, not the name).
func Wordmark() string {
	if !useColor {
		return "privasys"
	}
	return cBold + cWhite + "privasys" + cReset
}
