package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/policy"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
)

const allowUsage = `usage: watchdeck allow <skill|*> [--network none|localhost|all] [--write PATH]... [--remove-write PATH]... [--caches|--no-caches] [--auto|--no-auto] [--reset] [--show] [--for DURATION]

Edits the grant for a skill ("*" = every skill) in the user overrides file
(~/.config/watchdeck/overrides.yaml). --network all|localhost, --write,
--caches and --auto widen; --network none, --remove-write, --no-caches,
--no-auto take back; --reset deletes the skill's whole block. Only the user
file can grant beyond the project; a project .watchdeck.yaml is clipped.
--show prints the file. --for 1h (at most 8h) widens the grant for that
long only: it is written as a timed entry that ends by itself (watchdeck
rules pause --list shows it, rules resume ends it early), never with
--auto, and only with flags that widen. The result is re-parsed strictly and written
atomically, so the file can never be left invalid. The file is written as
policy file v2; the previous file is kept beside it as overrides.yaml.bak-<ts>.
`

// cmdAllow maps the flags onto a manifest.Edit and applies it through
// policy.Apply + policy.Save. The dashboard takes the same path, so the two
// never disagree about what a grant means.
func cmdAllow(args []string) int {
	fs := flag.NewFlagSet("allow", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, allowUsage)
	}
	network := fs.String("network", "", "none | localhost | all")
	var writes, removeWrites multiFlag
	fs.Var(&writes, "write", "extra writable path (repeatable)")
	fs.Var(&removeWrites, "remove-write", "take a writable path back (repeatable)")
	caches := fs.Bool("caches", false, "allow interpreter cache dirs (~/Library/Caches, ~/.cache, ~/.npm/_cacache)")
	noCaches := fs.Bool("no-caches", false, "take the cache dirs back")
	auto := fs.Bool("auto", false, "run this skill's scripts without asking")
	noAuto := fs.Bool("no-auto", false, "ask again for this skill")
	reset := fs.Bool("reset", false, "delete the skill's whole override block")
	show := fs.Bool("show", false, "print the overrides file and exit")
	forDur := fs.String("for", "", "widen for this long only (at most 8h)")
	pos, flagArgs := splitAllowArgs(args)
	if err := fs.Parse(flagArgs); err != nil {
		return 3 // unknown flag, bad value or -h; the flag package has printed why
	}
	hp, _, err := hostPaths()
	if err != nil {
		fmt.Fprintln(os.Stderr, "watchdeck allow:", err)
		return 2
	}
	path := hp.OverridesFile()
	if *show {
		b, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("%s: none\n", path)
			return 0
		}
		fmt.Print(string(b))
		return 0
	}
	if len(pos) != 1 || fs.NArg() > 0 {
		fmt.Fprint(os.Stderr, allowUsage)
		return 3
	}
	skill := pos[0]
	if !manifest.ValidSkillName(skill) {
		fmt.Fprintf(os.Stderr, "watchdeck allow: invalid skill name %q (%s)\n", skill, manifest.SkillNameRule)
		return 3
	}
	if *caches && *noCaches {
		fmt.Fprintln(os.Stderr, "watchdeck allow: --caches and --no-caches are exclusive")
		return 3
	}
	if *auto && *noAuto {
		fmt.Fprintln(os.Stderr, "watchdeck allow: --auto and --no-auto are exclusive")
		return 3
	}

	var e manifest.Edit
	if *network != "" {
		n, err := manifest.ParseNetwork(*network)
		if err != nil {
			fmt.Fprintln(os.Stderr, "watchdeck allow:", err)
			return 3
		}
		e.Network = &n
	}
	e.AddWrite = []string(writes)
	e.RemoveWrite = []string(removeWrites)
	if *caches || *noCaches {
		v := *caches
		e.Caches = &v
	}
	if *auto || *noAuto {
		v := *auto
		e.AutoAllow = &v
	}
	e.Reset = *reset
	if *forDur != "" {
		return allowFor(skill, *forDur, e, hp)
	}
	// Compare grants on real paths too, so /Users/me/.ssh (or a symlink to
	// it) is refused like ~/.ssh.
	e.Home = hp.Home
	if e.Empty() {
		fmt.Fprint(os.Stderr, allowUsage)
		return 3
	}

	f, _, err := policy.LoadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "watchdeck allow:", err)
		return 2
	}
	changed, err := policy.Apply(&f, policy.Edit{Kind: policy.KindSkill, Name: skill, Grant: e})
	if err != nil {
		fmt.Fprintln(os.Stderr, "watchdeck allow:", err)
		return 3
	}
	if changed {
		// Saved as policy file v2; the previous file is kept as .bak-<ts>.
		if _, err := policy.Save(path, f); err != nil {
			fmt.Fprintln(os.Stderr, "watchdeck allow:", err)
			return 2
		}
		fmt.Printf("updated %s\n", path)
	} else {
		fmt.Printf("%s: no change\n", path)
	}
	eff, _ := manifest.Grant(skill, f.SkillOverrides(), manifest.Overrides{})
	fmt.Printf("  %s: %s", skill, eff.Summary())
	if eff.AutoAllow {
		fmt.Print(" auto_allow")
	}
	fmt.Println()
	return 0
}

// allowTakesValue reports whether an allow flag is followed by a separate
// value, so the positional skill name can be told apart from one.
func allowTakesValue(arg string) bool {
	name := strings.TrimLeft(arg, "-")
	if strings.Contains(name, "=") {
		return false // --network=all carries its value
	}
	switch name {
	case "network", "write", "remove-write", "for":
		return true
	}
	return false
}

// splitAllowArgs separates positional arguments (the skill name, which may
// come before or after the flags) from the flags and their values. Only the
// first positional is removed; a second one stays in flagArgs so flag.Parse
// stops there and the caller reports a usage error.
func splitAllowArgs(args []string) (pos, flagArgs []string) {
	dropped := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "-" {
			pos = append(pos, a)
			if !dropped {
				dropped = true
				continue
			}
		}
		flagArgs = append(flagArgs, a)
		if allowTakesValue(a) && i+1 < len(args) {
			flagArgs = append(flagArgs, args[i+1])
			i++
		}
	}
	return pos, flagArgs
}

// allowFor is allow --for: the widening flags of e become a timed grant
// (rulebook.GrantFor). Anything that narrows, auto_allow and "*" are
// usage errors (exit 3); nothing is written then.
func allowFor(skill, spec string, e manifest.Edit, hp paths.Paths) int {
	d, err := time.ParseDuration(spec)
	if err != nil || d <= 0 || d > rulebook.MaxGrantFor {
		fmt.Fprintln(os.Stderr, "watchdeck allow: --for takes a duration up to 8h, such as 1h")
		return 3
	}
	switch {
	case skill == "*":
		fmt.Fprintln(os.Stderr, "watchdeck allow: --for widens one skill, not *")
		return 3
	case e.AutoAllow != nil || e.ClearAutoAllow:
		fmt.Fprintln(os.Stderr, "watchdeck allow: --for never sets auto_allow (a timed grant still asks)")
		return 3
	case e.Reset || len(e.RemoveWrite) > 0 || e.ClearNetwork || (e.Caches != nil && !*e.Caches) || (e.Network != nil && *e.Network == manifest.NetNone):
		fmt.Fprintln(os.Stderr, "watchdeck allow: --for only widens (--network localhost|all, --write, --caches)")
		return 3
	}
	var edits []rulebook.UngrantedEdit
	if e.Network != nil {
		edits = append(edits, rulebook.UngrantedEdit{Skill: skill, Field: "network", Value: e.Network.String()})
	}
	for _, w := range e.AddWrite {
		edits = append(edits, rulebook.UngrantedEdit{Skill: skill, Field: "write", Value: w})
	}
	if e.Caches != nil && *e.Caches {
		edits = append(edits, rulebook.UngrantedEdit{Skill: skill, Field: "caches", Value: "true"})
	}
	if len(edits) == 0 {
		fmt.Fprint(os.Stderr, allowUsage)
		return 3
	}
	t, err := rulebook.GrantFor(rulebook.Input{Paths: hp}, skill, edits, d)
	if err != nil {
		fmt.Fprintln(os.Stderr, "watchdeck allow:", err)
		return 3
	}
	for _, v := range rulebook.ListTemporaries(rulebook.Input{Paths: hp}) {
		if v.ID == t.ID {
			fmt.Printf("%s until %s (%s; end it early with: %s rules resume %s)\n", v.Sentence, localTime(v.Until), t.ID, paths.BinaryName, t.ID)
			return 0
		}
	}
	fmt.Printf("granted %s for %s (%s)\n", skill, d, t.ID)
	return 0
}
