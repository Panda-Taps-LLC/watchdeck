package sessionindex

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Panda-Taps-LLC/watchdeck/internal/leakscan"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/transcript"
)

// row is the tolerant shape of one transcript row, the fields the index
// reads. Unknown fields are ignored.
type row struct {
	Type        string          `json:"type"`
	UUID        string          `json:"uuid"`
	Timestamp   string          `json:"timestamp"`
	IsMeta      bool            `json:"isMeta"`
	IsSidechain bool            `json:"isSidechain"`
	Cwd         string          `json:"cwd"`
	Version     string          `json:"version"`
	GitBranch   string          `json:"gitBranch"`
	Entrypoint  string          `json:"entrypoint"`
	Summary     string          `json:"summary"`
	Message     *rowMessage     `json:"message"`
	Attachment  *rowAttachment  `json:"attachment"`
	Content     json.RawMessage `json:"content"` // system rows carry a string here
}

type rowMessage struct {
	Model   string          `json:"model"`
	Content json.RawMessage `json:"content"` // a string or an array of blocks
}

type rowAttachment struct {
	Type      string          `json:"type"`
	HookEvent string          `json:"hookEvent"`
	Stdout    string          `json:"stdout"`
	Content   json.RawMessage `json:"content"`
}

type block struct {
	Type      string          `json:"type"`
	ID        string          `json:"id"`          // tool_use
	ToolUseID string          `json:"tool_use_id"` // tool_result
	Text      string          `json:"text"`
	Thinking  string          `json:"thinking"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	Content   json.RawMessage `json:"content"` // tool_result: string or []{type,text}
}

// hookOut is the part of a PreToolUse hook's JSON the index reads: the
// rewritten command, which names the skills of a watchdeck run.
type hookOut struct {
	HookSpecificOutput struct {
		UpdatedInput struct {
			Command string `json:"command"`
		} `json:"updatedInput"`
	} `json:"hookSpecificOutput"`
}

// sink appends text parts, one per line, to the session's text file and
// stops at the per-session cap. Newlines inside a part become spaces so a
// line is always one part. A nil w counts and caps but writes nothing.
type sink struct {
	w      *bufio.Writer
	n      int64
	cap    int64
	capped bool
}

func (s *sink) part(t string) {
	t = strings.TrimSpace(t)
	if t == "" || s.capped {
		return
	}
	room := s.cap - s.n - 1
	if room <= 0 {
		s.capped = true
		return
	}
	if int64(len(t)) > room {
		t = cutRunes(t, int(room))
		s.capped = true
		if t == "" {
			return
		}
	}
	if s.w != nil {
		for i := 0; i < len(t); i++ {
			c := t[i]
			if c == '\n' || c == '\r' {
				c = ' '
			}
			s.w.WriteByte(c)
		}
		s.w.WriteByte('\n')
	}
	s.n += int64(len(t)) + 1
}

// builder accumulates one session's entry across its files. tools maps
// the tool use ids this pass has read to their tool and target, for the
// findings on their results; agent is the subagent id of the file being
// read ("" for the main file).
type builder struct {
	e       *Entry
	s       *sink
	maxLine int
	maxRead int64
	headCap int64
	tools   map[string]toolRef
	agent   string
}

type toolRef struct {
	tool, target string
	cut          bool // target is the first maxTarget bytes of a longer one
}

// toolUnknown is a result's tool when its tool use was read in an earlier
// pass (an incremental append resumed past it).
const toolUnknown = "unknown"

const maxTarget = 120

// readFile streams one file from offset from and returns the new resume
// offset. A file read from 0 that is larger than maxRead is read as head
// (metadata only, main file) plus its last maxRead bytes, and the entry is
// marked TailRead.
func (b *builder) readFile(path string, isMain bool, from int64) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return from, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return from, err
	}
	size := st.Size()
	base := from
	discard := false
	if from == 0 && size > b.maxRead {
		tailStart := size - b.maxRead
		if isMain {
			head := b.headCap
			if head > tailStart {
				head = tailStart
			}
			b.scan(transcript.NewLineReader(bufio.NewReaderSize(io.LimitReader(f, head), 64<<10), b.maxLine), isMain, true)
		}
		base = tailStart
		discard = true
		b.e.TailRead = true
	}
	if from > size {
		return from, errShrunk
	}
	if _, err := f.Seek(base, io.SeekStart); err != nil {
		return from, err
	}
	lr := transcript.NewLineReader(bufio.NewReaderSize(f, 64<<10), b.maxLine)
	if discard {
		lr.Next() // the partial first line of the tail
	}
	b.scan(lr, isMain, false)
	return base + lr.Consumed, nil
}

func (b *builder) scan(lr *transcript.LineReader, isMain, metaOnly bool) {
	for {
		line, tooLong, partial, ok := lr.Next()
		if !ok || partial {
			return // a final line without a newline is read again next time
		}
		if tooLong {
			if !metaOnly {
				b.e.SkippedLines++
			}
			continue
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var r row
		if json.Unmarshal(line, &r) != nil {
			if !metaOnly {
				b.e.SkippedLines++
			}
			continue
		}
		b.row(&r, isMain, metaOnly)
	}
}

func (b *builder) row(r *row, isMain, metaOnly bool) {
	e := b.e
	if ts := parseTS(r.Timestamp); !ts.IsZero() {
		if e.FirstTS.IsZero() || ts.Before(e.FirstTS) {
			e.FirstTS = ts
		}
		if ts.After(e.LastTS) {
			e.LastTS = ts
		}
	}
	if isMain {
		if e.Cwd == "" && r.Cwd != "" {
			e.Cwd = r.Cwd
		}
		if r.GitBranch != "" {
			e.GitBranch = r.GitBranch // the latest wins: a session can switch branches
		}
		if e.CCVersion == "" && r.Version != "" {
			e.CCVersion = r.Version
		}
		if e.Entrypoint == "" && r.Entrypoint != "" {
			e.Entrypoint = r.Entrypoint
		}
	}
	switch r.Type {
	case "user":
		b.userRow(r, isMain, metaOnly)
	case "assistant":
		if !metaOnly {
			b.assistantRow(r)
		}
	case "attachment":
		if !metaOnly && r.Attachment != nil {
			b.attachmentRow(r.Attachment)
		}
	case "summary":
		if !metaOnly {
			b.s.part(r.Summary)
		}
	case "system":
		if !metaOnly {
			b.s.part(rawString(r.Content))
		}
	}
}

func (b *builder) userRow(r *row, isMain, metaOnly bool) {
	if r.Message == nil {
		return
	}
	c := bytes.TrimSpace(r.Message.Content)
	if len(c) == 0 {
		return
	}
	var texts []string
	hasResult := false
	switch c[0] {
	case '"':
		texts = append(texts, rawString(c))
	case '[':
		var blocks []block
		if json.Unmarshal(c, &blocks) != nil {
			return
		}
		for i := range blocks {
			switch blocks[i].Type {
			case "text":
				texts = append(texts, blocks[i].Text)
			case "tool_result":
				hasResult = true
				if !metaOnly {
					t := resultText(blocks[i].Content)
					ref := blocks[i].ToolUseID
					tr, ok := b.tools[ref]
					if !ok {
						tr = toolRef{tool: toolUnknown}
					}
					b.leaks(t, WhereResult, rowRef(ref, r), tr, r.Timestamp)
					b.s.part(t)
				}
			}
		}
	}
	if !metaOnly {
		for _, t := range texts {
			b.s.part(t)
		}
	}
	if !isMain || hasResult || r.IsMeta || r.IsSidechain {
		return
	}
	text := strings.TrimSpace(strings.Join(texts, "\n"))
	if text == "" || isCommandText(text) {
		return
	}
	if !metaOnly {
		b.e.Turns++
	}
	if b.e.Title == "" {
		b.e.Title = cutRunes(strings.Join(strings.Fields(text), " "), titleLen)
	}
}

// isCommandText reports text Claude Code writes into a user row for a slash
// command, a local command or shell mode, rather than a typed prompt.
func isCommandText(t string) bool {
	for _, p := range []string{"<command-", "<local-command-", "<bash-input>", "<bash-stdout>", "<bash-stderr>", "<user-memory-input>", "Caveat: The messages below were generated by the user while running local commands"} {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

func (b *builder) assistantRow(r *row) {
	if r.Message == nil {
		return
	}
	if m := r.Message.Model; m != "" && m != "<synthetic>" {
		b.e.Models = addUnique(b.e.Models, m)
	}
	c := bytes.TrimSpace(r.Message.Content)
	if len(c) == 0 {
		return
	}
	replyRef := rowRef(r.UUID, r)
	if c[0] == '"' {
		t := rawString(c)
		b.leaks(t, WhereReply, replyRef, toolRef{}, r.Timestamp)
		b.s.part(t)
		return
	}
	var blocks []block
	if c[0] != '[' || json.Unmarshal(c, &blocks) != nil {
		return
	}
	for i := range blocks {
		bl := &blocks[i]
		switch bl.Type {
		case "text":
			b.leaks(bl.Text, WhereReply, replyRef, toolRef{}, r.Timestamp)
			b.s.part(bl.Text)
		case "thinking":
			b.s.part(bl.Thinking) // plain-text thinking when present; redacted thinking has none
		case "tool_use":
			b.e.ToolCalls++
			var in any
			if len(bl.Input) > 0 && json.Unmarshal(bl.Input, &in) == nil {
				if bl.Name == "Skill" {
					if m, ok := in.(map[string]any); ok {
						if s, ok := m["skill"].(string); ok && s != "" {
							b.e.Skills = addUnique(b.e.Skills, s)
						}
					}
				}
				var parts []string
				collectStrings(in, &parts, 0)
				m, _ := in.(map[string]any)
				target, cut := toolTarget(bl.Name, m)
				tr := toolRef{tool: bl.Name, target: target, cut: cut}
				if bl.ID != "" {
					b.tools[bl.ID] = tr
				}
				for _, p := range parts {
					b.leaks(p, WhereInput, rowRef(bl.ID, r), tr, r.Timestamp)
				}
				b.s.part(bl.Name + " " + strings.Join(parts, " "))
			} else {
				if bl.ID != "" {
					b.tools[bl.ID] = toolRef{tool: bl.Name}
				}
				b.s.part(bl.Name)
			}
		}
	}
}

func (b *builder) attachmentRow(a *rowAttachment) {
	if a.Type == "hook_success" && a.HookEvent == "PreToolUse" {
		if s := strings.TrimSpace(a.Stdout); strings.HasPrefix(s, "{") {
			var h hookOut
			if json.Unmarshal([]byte(s), &h) == nil {
				for _, sk := range rewriteSkills(h.HookSpecificOutput.UpdatedInput.Command) {
					b.e.Skills = addUnique(b.e.Skills, sk)
				}
			}
		}
	}
	b.s.part(a.Stdout)
	b.s.part(rawString(a.Content))
}

// leaks adds a finding for each pattern leak watch finds in text, at most
// once per (pattern, ref, where) and at most MaxFindings per entry.
func (b *builder) leaks(text, where, ref string, tr toolRef, ts string) {
	if text == "" {
		return
	}
	hits := leakscan.Scan(text)
	if len(hits) == 0 {
		return
	}
	at := parseTS(ts)
	for _, h := range hits {
		b.addFinding(Finding{Pattern: h.ID, Label: h.Label, Where: where, Tool: tr.tool, Target: tr.target, TargetCut: tr.cut, Ref: ref, Agent: b.agent, TS: at})
	}
}

func (b *builder) addFinding(f Finding) {
	e := b.e
	for i := range e.Findings {
		if x := &e.Findings[i]; x.Pattern == f.Pattern && x.Ref == f.Ref && x.Where == f.Where {
			return
		}
	}
	if len(e.Findings) >= MaxFindings {
		e.FindingsCapped = true
		return
	}
	e.Findings = append(e.Findings, f)
}

// rowRef is ref, else "ts:" and the row's timestamp, so findings on rows
// without an id do not all share one.
func rowRef(ref string, r *row) string {
	if ref != "" {
		return ref
	}
	return "ts:" + r.Timestamp
}

// toolTarget names what a tool call touched, for a finding: the file path
// for the file tools (Grep and Glob: their path), the program for Bash, the
// host for WebFetch, else "". It is cut to 120 bytes (cut reports that it
// was), and a target that is secret-shaped before or after the cut is
// dropped.
func toolTarget(tool string, in map[string]any) (target string, cut bool) {
	str := func(k string) string {
		s, _ := in[k].(string)
		return s
	}
	t := ""
	switch tool {
	case "Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Grep", "Glob":
		t = str("file_path")
		if t == "" && tool == "NotebookEdit" {
			t = str("notebook_path")
		}
		if t == "" && (tool == "Grep" || tool == "Glob") {
			t = str("path")
		}
	case "Bash":
		t = argv0(str("command"))
	case "WebFetch":
		if u, err := url.Parse(str("url")); err == nil {
			t = u.Hostname()
		}
	}
	// Check the whole target as well as the cut one: a cut can leave a key's
	// prefix that no longer matches on its own.
	if len(leakscan.Scan(t)) > 0 {
		return "", false
	}
	cut = len(t) > maxTarget
	t = cutRunes(t, maxTarget)
	if len(leakscan.Scan(t)) > 0 {
		return "", false
	}
	return t, cut
}

// argv0 is the base name of a command's first word that is not a
// VAR=value assignment, quotes trimmed, at most 64 bytes (the inbox's rule).
func argv0(cmd string) string {
	w := ""
	for _, x := range strings.Fields(cmd) {
		if !strings.Contains(x, "=") {
			w = x
			break
		}
	}
	if w == "" {
		return ""
	}
	return cutRunes(filepath.Base(strings.Trim(w, `'"`)), 64)
}

// agentOf is the subagent id of agent-<id>.jsonl.
func agentOf(name string) string {
	return strings.TrimSuffix(strings.TrimPrefix(name, "agent-"), ".jsonl")
}

// rewriteSkills extracts the --skill names of a hook rewrite of the form
// `watchdeck run --skill <n> [--skill <n>] -c '<original>'` (the binary
// may be named by an absolute path). Anything else yields nil.
func rewriteSkills(cmd string) []string {
	f := strings.Fields(cmd)
	run := -1
	for i := 0; i+1 < len(f); i++ {
		if (f[i] == paths.BinaryName || strings.HasSuffix(f[i], "/"+paths.BinaryName)) && f[i+1] == "run" {
			run = i + 2
			break
		}
	}
	if run < 0 {
		return nil
	}
	var out []string
	for i := run; i < len(f); i++ {
		switch {
		case f[i] == "-c" || f[i] == "--":
			return out
		case f[i] == "--skill" && i+1 < len(f):
			i++
			if s := strings.Trim(f[i], `'"`); s != "" {
				out = append(out, s)
			}
		case strings.HasPrefix(f[i], "--skill="):
			if s := strings.Trim(strings.TrimPrefix(f[i], "--skill="), `'"`); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// collectStrings appends every string value of a decoded JSON value, depth
// first, map keys in no particular order.
func collectStrings(v any, out *[]string, depth int) {
	if depth > 32 {
		return
	}
	switch x := v.(type) {
	case string:
		if x != "" {
			*out = append(*out, x)
		}
	case []any:
		for _, y := range x {
			collectStrings(y, out, depth+1)
		}
	case map[string]any:
		for _, y := range x {
			collectStrings(y, out, depth+1)
		}
	}
}

// resultText returns a tool_result's text: the string itself or the joined
// text blocks.
func resultText(c json.RawMessage) string {
	c = bytes.TrimSpace(c)
	if len(c) == 0 {
		return ""
	}
	switch c[0] {
	case '"':
		return rawString(c)
	case '[':
		var blocks []block
		if json.Unmarshal(c, &blocks) != nil {
			return ""
		}
		var parts []string
		for _, bl := range blocks {
			if bl.Type == "text" && bl.Text != "" {
				parts = append(parts, bl.Text)
			}
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

func rawString(c json.RawMessage) string {
	c = bytes.TrimSpace(c)
	if len(c) == 0 || c[0] != '"' {
		return ""
	}
	var s string
	if json.Unmarshal(c, &s) != nil {
		return ""
	}
	return s
}

func parseTS(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func addUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

// cutRunes cuts s to at most n bytes on a rune boundary.
func cutRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
