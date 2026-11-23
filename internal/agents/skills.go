// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package agents

import (
	"io/fs"
	"path"

	plugin "github.com/Privasys/cli/plugins/privasys"
)

// SkillName is the folder the Privasys skill is installed under.
const SkillName = "privasys"

// SkillFile is one file of the Privasys skill, its path relative to the skill
// folder (SKILL.md, references/manifest.md, ...).
type SkillFile struct {
	Path    string
	Content []byte
}

// SkillFiles returns the Privasys skill as shipped in the Claude Code plugin,
// which is the single source for every harness.
func SkillFiles() ([]SkillFile, error) {
	root := path.Join("skills", SkillName)
	var out []SkillFile
	err := fs.WalkDir(plugin.Skills, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(plugin.Skills, p)
		if err != nil {
			return err
		}
		rel := p[len(root)+1:]
		out = append(out, SkillFile{Path: rel, Content: b})
		return nil
	})
	return out, err
}

// SkillDirs returns the distinct skill folders the harnesses read, in the
// order first seen, so a skill shared by several harnesses is written once.
func SkillDirs(hs []Harness) []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range hs {
		if h.SkillsDir == "" || seen[h.SkillsDir] {
			continue
		}
		seen[h.SkillsDir] = true
		out = append(out, h.SkillsDir)
	}
	return out
}
