// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// allowedCallersDocument composes the {"entries":[...],"platforms":[...]}
// document from 'callers' (an entry array or a document), any_attested and
// platforms. It mirrors the CLI's --data / --any-attested / --platform, so a
// tool call and the flags mean the same thing.
func allowedCallersDocument(callers string, anyAttested bool, platforms []string) (json.RawMessage, error) {
	doc := struct {
		Entries   []json.RawMessage `json:"entries"`
		Platforms []string          `json:"platforms,omitempty"`
	}{Entries: []json.RawMessage{}}
	if s := strings.TrimSpace(callers); s != "" {
		var entries []json.RawMessage
		if err := json.Unmarshal([]byte(s), &entries); err == nil {
			doc.Entries = entries
		} else if err := json.Unmarshal([]byte(s), &doc); err != nil {
			return nil, fmt.Errorf("callers: expected an entry array or {\"entries\":[...]}: %w", err)
		}
	}
	if anyAttested {
		doc.Entries = append(doc.Entries, json.RawMessage(`{"app_id":"*"}`))
	}
	doc.Platforms = append(doc.Platforms, platforms...)
	// The server refuses the wildcard without platforms too; say it here in
	// the words of the tool.
	if anyAttested && len(doc.Platforms) == 0 {
		return nil, errors.New("any_attested needs at least one platform (platforms, or \"platforms\" in callers): the machines callers may run on")
	}
	return json.Marshal(doc)
}
