package activity

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// JoinWindow is how long after a decision a run may still attach to it.
const JoinWindow = 10 * time.Minute

// tailBytes is how much of the log Correlate reads (comfortably more than
// ten minutes of a busy session).
const tailBytes = 256 << 10

// Join attaches run records to the decision that caused them, in place, and
// returns the same slice. Records are walked in slice order (file order; the
// caller never sorts by Offset, since offsets of the rotated and the current
// file overlap). For each run:
//
//  1. A run that already carries a tool_use_id (write-time correlation) is
//     trusted: the decision with that id is consumed before the walk starts,
//     so no other run can take it. If an earlier run already carries the same
//     id (two runs raced at write time), the later run's ids are cleared and
//     it falls through to the heuristic.
//  2. Otherwise the candidates are the earlier, unconsumed decisions that were
//     rewritten, have equal sorted skills, equal command (the decision's
//     original text against the run's -c payload), equal cwd (after Clean,
//     then EvalSymlinks when still unequal: /var/tmp and /private/var/tmp name
//     one directory on macOS) and a timestamp within JoinWindow before the
//     run's. The NEWEST candidate wins: with a declined decision followed by
//     the same command approved, the run belongs to the approval. Its ids are
//     copied, the decision is consumed and joined_by becomes "heuristic".
//  3. A decision joins at most one run; a run with no candidate stays unjoined.
//
// skill_invoked and denied records are untouched.
func Join(recs []Record) []Record {
	consumed := make([]bool, len(recs))
	// owner maps a tool_use_id to the first run that carries it. A decision
	// owned by a write-time run is never offered to the heuristic, even to a
	// run that appears before its owner.
	owner := map[string]int{}
	for i := range recs {
		if recs[i].Kind == KindRun && recs[i].ToolUseID != "" {
			if _, ok := owner[recs[i].ToolUseID]; !ok {
				owner[recs[i].ToolUseID] = i
			}
		}
	}
	for i := range recs {
		if recs[i].Kind == KindDecision && recs[i].ToolUseID != "" {
			if _, ok := owner[recs[i].ToolUseID]; ok {
				consumed[i] = true
			}
		}
	}
	for i := range recs {
		r := &recs[i]
		if r.Kind != KindRun {
			continue
		}
		if r.ToolUseID != "" {
			if owner[r.ToolUseID] == i {
				continue
			}
			clearIDs(r) // a later run raced for the same decision at write time
		}
		j := candidate(recs, i, consumed)
		if j < 0 {
			continue
		}
		copyIDs(r, recs[j])
		r.JoinedBy = JoinedByHeuristic
		consumed[j] = true
	}
	return recs
}

// candidate returns the index of the newest qualifying decision before run
// index ri, or -1.
func candidate(recs []Record, ri int, consumed []bool) int {
	run := recs[ri]
	rt, ok := parseTS(run.TS)
	if !ok {
		return -1
	}
	for j := ri - 1; j >= 0; j-- {
		d := recs[j]
		if d.Kind != KindDecision || consumed[j] || d.Rewritten == "" {
			continue
		}
		if !sameKey(d, run) {
			continue
		}
		dt, ok := parseTS(d.TS)
		if !ok {
			continue
		}
		if delta := rt.Sub(dt); delta < 0 || delta > JoinWindow {
			continue
		}
		return j
	}
	return -1
}

// sameKey compares sorted skills, command bytes and cwd.
func sameKey(d, run Record) bool {
	if d.Command != run.Command || !sameSkills(d.Skills, run.Skills) || subjectKey(d) != subjectKey(run) {
		return false
	}
	return sameDir(d.Cwd, run.Cwd)
}

// subjectKey is "kind:name" for a non-skill subject and "" otherwise: a
// command subject's run has no skills (M6.4), skill subjects join on Skills.
func subjectKey(r Record) string {
	if r.Subject == nil || r.Subject.Kind == "skill" {
		return ""
	}
	return r.Subject.Kind + ":" + r.Subject.Name
}

func sameSkills(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]string(nil), a...)
	bs := append([]string(nil), b...)
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

func sameDir(a, b string) bool {
	if a == "" || b == "" {
		return a == b
	}
	a, b = filepath.Clean(a), filepath.Clean(b)
	if a == b {
		return true
	}
	ra, err1 := filepath.EvalSymlinks(a)
	rb, err2 := filepath.EvalSymlinks(b)
	return err1 == nil && err2 == nil && ra == rb
}

func copyIDs(dst *Record, src Record) {
	dst.SessionID = src.SessionID
	dst.ToolUseID = src.ToolUseID
	dst.Transcript = src.Transcript
	dst.AgentID = src.AgentID
	dst.AgentType = src.AgentType
	dst.PermMode = src.PermMode
}

func clearIDs(r *Record) {
	r.SessionID, r.ToolUseID, r.Transcript, r.AgentID, r.AgentType, r.PermMode = "", "", "", "", "", ""
	r.JoinedBy = ""
}

// Correlate is the write-time half of the join: right before the runner
// appends run, it reads the tail (tailBytes) of the current file, and the tail
// of <path>.1 as well when the current file is shorter than that (a decision
// may have just rotated), runs Join over tail+run and returns run with the ids
// of the decision it attached to and joined_by "write". It never errors and
// returns run unchanged when nothing qualified, the file is absent, the log is
// off, or run already carries ids.
func Correlate(path string, run Record) Record {
	if path == "" || run.Kind != KindRun || run.ToolUseID != "" {
		return run
	}
	cur, size := readTail(path)
	var recs []Record
	if size < tailBytes {
		rot, _ := readTail(path + ".1")
		recs = append(recs, parseLines(rot)...)
	}
	recs = append(recs, parseLines(cur)...)
	if len(recs) == 0 {
		return run
	}
	recs = append(recs, run)
	Join(recs)
	got := recs[len(recs)-1]
	if got.JoinedBy != JoinedByHeuristic {
		return run
	}
	got.JoinedBy = JoinedByWrite
	return got
}

// readTail returns the last tailBytes of path, cut at the first newline when
// it did not start at the beginning, and the file's size (0 when absent).
func readTail(path string) ([]byte, int64) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, 0
	}
	size := fi.Size()
	start := size - tailBytes
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, size
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, size
	}
	if start > 0 {
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		} else {
			b = nil
		}
	}
	return b, size
}

// parseLines decodes complete lines, skipping torn or unparseable ones.
func parseLines(b []byte) []Record {
	var out []Record
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			break // torn last line
		}
		line := bytes.TrimSpace(b[:i])
		b = b[i+1:]
		if len(line) == 0 {
			continue
		}
		var rec Record
		if json.Unmarshal(line, &rec) == nil && rec.Kind != "" {
			rec.Harness = DefaultHarness(rec.Harness)
			out = append(out, rec)
		}
	}
	return out
}
