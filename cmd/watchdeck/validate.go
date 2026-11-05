package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/skillmd"
)

// cmdValidate checks a PERMISSIONS.yaml, or a skill directory's manifest and
// SKILL.md frontmatter. Exit 1 on an invalid manifest.
func cmdValidate(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: watchdeck validate <PERMISSIONS.yaml | skill-dir>")
		return 3
	}
	target := args[0]
	st, err := os.Stat(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "watchdeck validate:", err)
		return 2
	}
	rc := 0
	if st.IsDir() {
		if fm, err := skillmd.Parse(filepath.Join(target, "SKILL.md")); err != nil {
			fmt.Printf("SKILL.md: %v\n", err)
		} else {
			for _, p := range fm.Problems {
				fmt.Printf("SKILL.md: warning: %s\n", p)
			}
		}
		target = filepath.Join(target, "PERMISSIONS.yaml")
		if _, err := os.Stat(target); err != nil {
			fmt.Println("PERMISSIONS.yaml: none (default profile applies)")
			return rc
		}
	}
	m, err := manifest.Parse(target)
	if err != nil {
		fmt.Printf("%s: %v\n", target, err)
		return 1
	}
	eff, ungranted := manifest.Clip(m, manifest.Default())
	fmt.Printf("%s: ok\n", target)
	fmt.Printf("  under the default grant: %s\n", eff.Summary())
	for _, u := range ungranted {
		fmt.Printf("  requests beyond the default grant: %s\n", u)
	}
	return rc
}
