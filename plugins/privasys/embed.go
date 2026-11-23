// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package privasys carries the Claude Code plugin's files into the CLI binary,
// so `privasys agents init` can install the same skill for every agent harness.
// The plugin folder stays the single source of the skill.
package privasys

import "embed"

// Skills holds skills/<name>/SKILL.md and its references.
//
//go:embed skills
var Skills embed.FS
