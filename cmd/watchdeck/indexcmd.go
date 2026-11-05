package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Panda-Taps-LLC/watchdeck/internal/index"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/skills"
)

// cmdIndex shows or rebuilds the discovery cache the hook reads.
func cmdIndex(args []string) int {
	if len(args) > 0 && args[0] == "sessions" {
		return cmdIndexSessions(args[1:], os.Stdout, os.Stderr)
	}
	fs := flag.NewFlagSet("index", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	rebuild := fs.Bool("rebuild", false, "rebuild the cache now")
	asJSON := fs.Bool("json", false, "print the index as JSON")
	if err := fs.Parse(args); err != nil {
		return 3
	}
	hp, _, err := hostPaths()
	if err != nil {
		fmt.Fprintln(os.Stderr, "watchdeck index:", err)
		return 2
	}
	cwd, _ := os.Getwd()
	path := hp.IndexFile()
	roots := skills.Roots{Home: hp.Home, Cwd: cwd}
	var ix *index.Index
	rebuilt := false
	if *rebuild {
		ix, err = index.Build(roots, hp.ConfigDir)
		if err == nil {
			err = ix.Save(path)
		}
		rebuilt = true
	} else {
		ix, rebuilt, err = index.LoadOrBuild(path, roots, hp.ConfigDir)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "watchdeck index:", err)
		return 2
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(ix)
		return 0
	}
	fmt.Printf("%s\n", path)
	fmt.Printf("  built:    %s", ix.BuiltAt.Local().Format("2006-01-02 15:04:05"))
	if rebuilt {
		fmt.Print("  (rebuilt now)")
	}
	fmt.Println()
	fmt.Printf("  project:  %s\n", orDash(ix.ProjectRoot))
	enabled := 0
	withManifest := 0
	for _, e := range ix.Entries {
		if e.Enabled {
			enabled++
		}
		if e.Manifest != "" {
			withManifest++
		}
	}
	fmt.Printf("  skills:   %d (%d enabled, %d with PERMISSIONS.yaml)\n", len(ix.Entries), enabled, withManifest)
	fmt.Printf("  needles:  %d\n", len(ix.NeedleList))
	fmt.Printf("  fresh:    %v\n", ix.Fresh(paths.ProjectRoot(cwd, hp.Home)))
	return 0
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
