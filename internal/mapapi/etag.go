package mapapi

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/mapmodel"
)

// buildVersion changes whenever this package or mapmodel changes what a
// Graph looks like for the same inputs; it is hashed into every ETag.
const buildVersion = "mapapi-5" // 4: totals.blocked_calls (Plan 05 Task 6); 5: it counts a person's "No" and unrecognised rejections (Plan 05 fix wave)

// inputs is every file a session's Graph was built from, by path. It is
// recorded after a full build and re-Stat'ed on the next request: when the
// hash of those Stat results equals the client's If-None-Match the answer is
// 304 and nothing is opened (Spec B §4).
//
// Any file whose content decides which other files are inputs (the activity
// log decides the session's skills, hence the manifests; the transcript too)
// is itself an input, so a stale record can never yield a false 304. The one
// change it does not see is a skill being installed or removed on disk
// without any input changing; the next activity record or grant refreshes it.
type inputs struct {
	view          string
	hideNone      bool
	authorities   string // the sorted authority filter, comma-joined; "all" when none
	noTranscripts bool

	transcript string   // the resolved main transcript, "" when none was found
	subagents  string   // <dir>/<id>/subagents next to it (unresolved), "" when none
	root       string   // the projects dir, symlinks resolved: subagents must resolve under it
	candidates []string // transcript paths the activity log names that were not usable (missing, outside the projects dir): Stat only
	activity   string   // paths.Activity ("" when the log is off); its ".1" is hashed too
	overrides  []string // the user overrides.yaml and the project .watchdeck.yaml
	manifests  []string // each resolved skill's PERMISSIONS.yaml, present or not
}

// etag hashes the Stat of every input with the view, the hide-none toggle,
// the authority filter, a liveness bit and the build version, and returns the first 16 hex characters.
//
// The liveness bit (newest input mtime younger than mapmodel.LiveWindow)
// keeps a quiet session from answering 304 forever with live:true: once the
// files stop changing for LiveWindow the bit flips and the next poll gets a
// fresh Graph with live:false.
func (a *api) etag(in *inputs) string {
	h := sha256.New()
	var newest time.Time
	fmt.Fprintf(h, "build %s %s\nview %s hide %t authority %s nt %t\n", buildVersion, a.d.Version, in.view, in.hideNone, in.authorities, in.noTranscripts)
	stat := func(label, p string) {
		if p == "" {
			fmt.Fprintf(h, "%s -\n", label)
			return
		}
		fi, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(h, "%s %q absent\n", label, p)
			return
		}
		writeStat(h, label, p, fi.Size(), fi.ModTime())
		if fi.ModTime().After(newest) {
			newest = fi.ModTime()
		}
	}
	stat("transcript", in.transcript)
	if in.subagents != "" {
		// Resolved and prefix-checked as transcript.Load does before it reads
		// the dir: a subagents dir (or <id> dir) that is a symlink leading out
		// of the projects dir is never listed, only noted. Every file is
		// hashed, not the directory: a directory's mtime changes when an
		// agent file is created or removed, not when it grows.
		switch dir, err := filepath.EvalSymlinks(in.subagents); {
		case err != nil:
			fmt.Fprintf(h, "subagents absent\n")
		case in.root == "" || !strings.HasPrefix(dir, in.root+string(filepath.Separator)):
			fmt.Fprintf(h, "subagents-outside\n")
		default:
			entries, err := os.ReadDir(dir)
			if err != nil {
				fmt.Fprintf(h, "subagents unreadable\n")
			}
			sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
			for _, e := range entries {
				fi, err := e.Info() // Lstat: a symlinked entry is not regular and is skipped
				if err != nil || !fi.Mode().IsRegular() {
					continue
				}
				writeStat(h, "subagent", e.Name(), fi.Size(), fi.ModTime())
				if fi.ModTime().After(newest) {
					newest = fi.ModTime()
				}
			}
		}
	}
	for _, p := range in.candidates {
		stat("candidate", p)
	}
	stat("activity", in.activity)
	if in.activity != "" {
		stat("activity.1", in.activity+".1")
	}
	for _, p := range in.overrides {
		stat("overrides", p)
	}
	for _, p := range in.manifests {
		stat("manifest", p)
	}
	live := !newest.IsZero() && a.d.Now().Sub(newest) < mapmodel.LiveWindow
	fmt.Fprintf(h, "live %t\n", live)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func writeStat(w io.Writer, label, p string, size int64, mtime time.Time) {
	fmt.Fprintf(w, "%s %q %d %d\n", label, p, size, mtime.UnixNano())
}

// quoted is the ETag header value for a tag.
func quoted(tag string) string { return `"` + tag + `"` }

// notModified reports whether an If-None-Match header names tag: "*", or
// any listed entity tag equal to it after dropping a weak "W/" prefix and
// the quotes (weak comparison, RFC 9110 §13.1.2).
func notModified(header, tag string) bool {
	if header == "" || tag == "" {
		return false
	}
	for _, t := range strings.Split(header, ",") {
		t = strings.TrimSpace(t)
		if t == "*" {
			return true
		}
		t = strings.TrimPrefix(t, "W/")
		if strings.Trim(t, `"`) == tag {
			return true
		}
	}
	return false
}
