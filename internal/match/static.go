package match

import (
	"path/filepath"
	"strings"
)

// StaticIndex is an in-memory Index built from a fixed skill list. Tests in
// other packages use it in place of the on-disk index.
type StaticIndex struct {
	skills  []IndexedSkill
	needles []string
}

// NewStaticIndex builds an index whose needles are computed by
// BuildNeedles(home, skills).
func NewStaticIndex(home string, skills ...IndexedSkill) *StaticIndex {
	return &StaticIndex{skills: skills, needles: BuildNeedles(home, skills)}
}

func (s *StaticIndex) Skills() []IndexedSkill { return s.skills }
func (s *StaticIndex) Needles() []string      { return s.needles }

// BuildNeedles returns the needle set for a skill list: every root and alias
// as written, its ~/, $HOME/ and ${HOME}/ spellings when it lies under home,
// and GenericNeedles. Duplicates and empty strings are dropped.
func BuildNeedles(home string, skills []IndexedSkill) []string {
	home = filepath.Clean(home)
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		if n == "" || seen[n] {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	for _, s := range skills {
		for _, p := range append([]string{s.Dir}, s.Aliases...) {
			if p == "" {
				continue
			}
			p = filepath.Clean(p)
			add(p)
			if home != "" && home != "." && home != "/" {
				if rel, ok := strings.CutPrefix(p, home+string(filepath.Separator)); ok {
					add("~/" + rel)
					add("$HOME/" + rel)
					add("${HOME}/" + rel)
				}
			}
		}
	}
	for _, n := range GenericNeedles {
		add(n)
	}
	return out
}
