// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package output renders command results as a human table or as machine JSON
// or YAML, selected by the --format flag. Agents pass --format json for a
// stable, parseable surface.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"gopkg.in/yaml.v3"
)

// Table is a set of column headers and rows.
type Table struct {
	Headers []string
	Rows    [][]string
}

// Emit writes v in the requested format. For "table" it calls tableFn to build
// the columns; for "json"/"yaml" it marshals v directly. tableFn may be nil
// when only structured output makes sense.
func Emit(format string, v interface{}, tableFn func() Table) error {
	switch format {
	case "json":
		return writeJSON(os.Stdout, v)
	case "yaml":
		return writeYAML(os.Stdout, v)
	default:
		if tableFn == nil {
			return writeJSON(os.Stdout, v)
		}
		return writeTable(os.Stdout, tableFn())
	}
}

func writeJSON(w io.Writer, v interface{}) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func writeYAML(w io.Writer, v interface{}) error {
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	defer enc.Close()
	return enc.Encode(v)
}

func writeTable(w io.Writer, t Table) error {
	if len(t.Rows) == 0 {
		fmt.Fprintln(w, "No items.")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 2, 3, ' ', 0)
	if len(t.Headers) > 0 {
		for i, h := range t.Headers {
			if i > 0 {
				fmt.Fprint(tw, "\t")
			}
			fmt.Fprint(tw, h)
		}
		fmt.Fprintln(tw)
	}
	for _, row := range t.Rows {
		for i, c := range row {
			if i > 0 {
				fmt.Fprint(tw, "\t")
			}
			fmt.Fprint(tw, c)
		}
		fmt.Fprintln(tw)
	}
	return tw.Flush()
}

// Str returns a string field from a generic record, or "" if absent.
func Str(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok && v != nil {
		switch t := v.(type) {
		case string:
			return t
		default:
			return fmt.Sprintf("%v", t)
		}
	}
	return ""
}
