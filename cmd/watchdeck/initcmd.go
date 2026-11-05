package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/inventory"
	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/scan"
	"github.com/Panda-Taps-LLC/watchdeck/internal/skills"
)

// cmdInit writes a PERMISSIONS.yaml request for a skill from what its
// scripts reference. The file is a request: the user grants with
// `watchdeck allow`.
func cmdInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	force := fs.Bool("force", false, "overwrite an existing PERMISSIONS.yaml")
	dir := fs.String("dir", "", "skill directory (instead of looking the name up among installed skills)")
	if err := fs.Parse(args); err != nil {
		return 3
	}
	root := *dir
	name := ""
	if root == "" {
		if fs.NArg() != 1 {
			fmt.Fprintln(os.Stderr, "usage: watchdeck init <skill> [--force]  |  watchdeck init --dir <path>")
			return 3
		}
		name = fs.Arg(0)
		found, err := findSkill(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, "watchdeck init:", err)
			return 2
		}
		root = found.RealRoot
	} else {
		if r, err := filepath.EvalSymlinks(root); err == nil {
			root = r
		}
		name = filepath.Base(root)
	}
	out := filepath.Join(root, "PERMISSIONS.yaml")
	if _, err := os.Stat(out); err == nil && !*force {
		fmt.Fprintf(os.Stderr, "watchdeck init: %s exists; use --force to overwrite\n", out)
		return 1
	}
	text, err := draftManifest(name, root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "watchdeck init:", err)
		return 2
	}
	if _, err := manifest.ParseBytes([]byte(text)); err != nil {
		fmt.Fprintln(os.Stderr, "watchdeck init: generated manifest does not validate (bug):", err)
		return 2
	}
	if err := os.WriteFile(out, []byte(text), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "watchdeck init:", err)
		return 2
	}
	fmt.Printf("wrote %s\n", out)
	return 0
}

func findSkill(name string) (skills.Skill, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return skills.Skill{}, err
	}
	cwd, _ := os.Getwd()
	found, err := skills.Scan(skills.Roots{Home: home, Cwd: cwd, All: true})
	if err != nil {
		return skills.Skill{}, err
	}
	var matches []skills.Skill
	for _, s := range found {
		if s.Name == name {
			matches = append(matches, s)
		}
	}
	switch len(matches) {
	case 0:
		return skills.Skill{}, fmt.Errorf("no installed skill named %q (try --dir <path>)", name)
	case 1:
		return matches[0], nil
	default:
		var roots []string
		for _, m := range matches {
			roots = append(roots, m.Root)
		}
		return skills.Skill{}, fmt.Errorf("%d skills named %q: %s; use --dir <path>", len(matches), name, strings.Join(roots, ", "))
	}
}

// draftManifest builds the YAML text with explanatory comments.
func draftManifest(name, root string) (string, error) {
	scripts, err := inventory.Scripts(root, nil)
	if err != nil {
		return "", err
	}
	hits, err := scan.Dir(root)
	if err != nil {
		return "", err
	}
	// scripts globs: default plus a glob per directory (or file) holding scripts outside scripts/
	globs := []string{"scripts/**"}
	seen := map[string]bool{}
	for _, s := range scripts {
		if s.InGlob {
			continue
		}
		g := s.Rel
		if d := filepath.Dir(s.Rel); d != "." {
			g = strings.SplitN(d, "/", 2)[0] + "/**"
		}
		if !seen[g] {
			seen[g] = true
			globs = append(globs, g)
		}
	}
	sort.Strings(globs[1:])

	var netHit *scan.Hit
	var credHits []scan.Hit
	for i := range hits {
		h := hits[i]
		switch h.Category {
		case scan.Network:
			if netHit == nil {
				netHit = &h
			}
		case scan.Credential:
			credHits = append(credHits, h)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# PERMISSIONS.yaml for skill %q, drafted by `watchdeck init` from a static scan.\n", name)
	b.WriteString("# This file is a REQUEST. The owner grants it (or not) with `watchdeck allow`.\n")
	b.WriteString("# Edit freely; `watchdeck validate` checks it.\n")
	b.WriteString("version: 1\n")
	b.WriteString("scripts: [" + quoteList(globs) + "]   # files that count as this skill's code\n")
	b.WriteString("filesystem:\n")
	b.WriteString("  read:  [\"${SKILL_DIR}\", \"${CWD}\"]\n")
	b.WriteString("  write: [\"${CWD}\", \"${TMP}\"]\n")
	b.WriteString("  # deny: the built-in list always applies; list it only to extend it\n")
	if netHit != nil {
		fmt.Fprintf(&b, "network: all          # requested: %s:%d references the network; granted only via: watchdeck allow %s --network all\n", netHit.File, netHit.Line, name)
	} else {
		b.WriteString("network: none         # the scan found no network use\n")
	}
	b.WriteString("exec: any\n")
	b.WriteString("env: [\"PATH\", \"HOME\", \"LANG\", \"TMPDIR\"]\n")
	if len(credHits) > 0 {
		b.WriteString("# credential-looking references found; the built-in deny list keeps them unreadable:\n")
		for i, h := range credHits {
			if i == 3 {
				b.WriteString("#   ...\n")
				break
			}
			fmt.Fprintf(&b, "#   %s:%d %s\n", h.File, h.Line, h.Snippet)
		}
	}
	b.WriteString("notes: \"\"\n")
	return b.String(), nil
}

func quoteList(xs []string) string {
	q := make([]string, len(xs))
	for i, x := range xs {
		q[i] = fmt.Sprintf("%q", x)
	}
	return strings.Join(q, ", ")
}
