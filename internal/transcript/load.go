package transcript

import (
	"bufio"
	"bytes"
	"encoding/json"
	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Options controls Load.
type Options struct {
	ProjectsDir   string // required: the dir every transcript must resolve under
	MaxBytes      int64  // per file; when a file is larger only its last MaxBytes are read (default DefaultMaxBytes)
	MaxLine       int    // lines longer than this are skipped and counted (default DefaultMaxLine)
	SkipSubagents bool   // do not read <session>/subagents/
}

const (
	// DefaultMaxBytes is the per-file tail read size, 32 MiB.
	DefaultMaxBytes int64 = 32 << 20
	// DefaultMaxLine is the longest line accepted, 2 MiB. tool_result rows
	// carry whole files, so bufio.Scanner's 64 KiB default is not enough.
	DefaultMaxLine = 2 << 20

	readerBuf  = 256 << 10
	snippetLen = 240
	errTextLen = 160
	commandLen = 512
	descLen    = 120
	nameLen    = 60
	summaryLen = 120
	reasonLen  = 240
)

// Load reads one session: the main file at path, then (unless
// o.SkipSubagents) every <dir>/<id>/subagents/agent-*.jsonl next to it.
//
// Path safety comes first: o.ProjectsDir must be set, path must end in
// ".jsonl" with a ValidID stem, and after filepath.EvalSymlinks it must be
// exactly <projects>/<escaped cwd>/<id>.jsonl. Agent ids from file names are
// checked the same way before the file is opened.
//
// Degradation is never fatal: a file larger than MaxBytes is read from its
// tail (Truncated=true; the first prompt and early spawns may be missing, and
// a subagent whose spawn was not seen is reported with SpawnLink ""); lines
// that are not JSON, longer than MaxLine, or a final line without a newline
// (a write in progress) are skipped and counted; unknown row types and
// unknown fields are ignored.
func Load(path string, o Options) (*Session, error) {
	if o.MaxBytes <= 0 {
		o.MaxBytes = DefaultMaxBytes
	}
	if o.MaxLine <= 0 {
		o.MaxLine = DefaultMaxLine
	}
	if o.ProjectsDir == "" {
		return nil, ErrNoProjectsDir
	}
	root, err := resolveRoot(o.ProjectsDir)
	if err != nil {
		return nil, err
	}
	resolved, err := resolveSessionPath(root, path)
	if err != nil {
		return nil, err
	}
	abs, _ := filepath.Abs(path)
	stem := strings.TrimSuffix(filepath.Base(resolved), ".jsonl")
	ld := newLoader(o, root, stem, filepath.Clean(abs))
	if err := ld.readFile(resolved, MainAgentID, true); err != nil {
		return nil, err
	}
	if !o.SkipSubagents {
		ld.readSubagents(filepath.Join(filepath.Dir(resolved), stem, "subagents"))
	}
	return ld.finish(), nil
}

// rawEntry is the tolerant shape of one transcript row. Unknown fields are
// ignored by encoding/json; everything here is optional.
type rawEntry struct {
	Type             string          `json:"type"`
	Subtype          string          `json:"subtype"`
	UUID             string          `json:"uuid"`
	ParentUUID       string          `json:"parentUuid"`
	Timestamp        string          `json:"timestamp"`
	IsSidechain      bool            `json:"isSidechain"`
	IsMeta           bool            `json:"isMeta"`
	Cwd              string          `json:"cwd"`
	Version          string          `json:"version"`
	AgentID          string          `json:"agentId"`
	AttributionAgent string          `json:"attributionAgent"`
	Message          *rawMessage     `json:"message"`
	ToolUseResult    json.RawMessage `json:"toolUseResult"`
	Attachment       *rawAttachment  `json:"attachment"`

	PermissionDecision *rawPermissionDecision `json:"permissionDecision"`
	ToolDenialKind     string                 `json:"toolDenialKind"`
}

type rawPermissionDecision struct {
	Decision   string `json:"decision"`
	Source     string `json:"source"`
	ReasonType string `json:"reasonType"`
}

type rawMessage struct {
	Role    string          `json:"role"`
	Model   string          `json:"model"`
	Content json.RawMessage `json:"content"` // a string or an array of blocks
}

type rawAttachment struct {
	Type      string `json:"type"`
	HookName  string `json:"hookName"`
	HookEvent string `json:"hookEvent"`
	ToolUseID string `json:"toolUseID"`
	Stdout    string `json:"stdout"`
}

type rawBlock struct {
	Type      string          `json:"type"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"`
	Content   json.RawMessage `json:"content"` // string or []{type,text}
	IsError   bool            `json:"is_error"`
	Text      string          `json:"text"`
}

// rawAgentResult is the subset of toolUseResult read for every tool_result
// row; it is only kept when AgentID is set (an Agent call's result).
type rawAgentResult struct {
	AgentID       string `json:"agentId"`
	AgentType     string `json:"agentType"`
	ResolvedModel string `json:"resolvedModel"`
}

// hookOut is the JSON a deciding PreToolUse hook prints. The top-level
// decision/reason pair is the older output format.
type hookOut struct {
	HookSpecificOutput struct {
		PermissionDecision       string         `json:"permissionDecision"`
		PermissionDecisionReason string         `json:"permissionDecisionReason"`
		UpdatedInput             map[string]any `json:"updatedInput"`
	} `json:"hookSpecificOutput"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// agentMeta is agent-<id>.meta.json (observed keys, 2026-10-12).
type agentMeta struct {
	AgentType   string `json:"agentType"`
	Description string `json:"description"`
	ToolUseID   string `json:"toolUseId"`
}

type spawnRef struct {
	tc  *ToolCall
	ts  time.Time
	seq int
}

type loader struct {
	o    Options
	root string // resolved projects dir; every file opened must resolve under it
	sess *Session
	seq  int

	agents     map[string]*Agent
	agentOrder []string
	calls      map[string]*ToolCall
	hooks      map[string][]string  // tool_use id -> PreToolUse hook_success stdout strings, file order
	authority  map[string]Authority // tool_use id -> verdict on its result row
	pending    map[string]string    // tool_use id -> result snippet, applied in finish when the call is Bash
	resultIdx  map[string]int       // tool_use id -> index in sess.Events of its tool_result
	results    map[string]rawAgentResult
	spawnCalls []spawnRef
	meta       map[string]*agentMeta
	scParent   map[string]string // legacy sidechain rows in the main file: uuid -> parentUuid
}

func newLoader(o Options, root, id, path string) *loader {
	ld := &loader{
		o:         o,
		root:      root,
		sess:      &Session{ID: id, Harness: activity.HarnessClaudeCode, Path: path},
		agents:    map[string]*Agent{},
		calls:     map[string]*ToolCall{},
		hooks:     map[string][]string{},
		pending:   map[string]string{},
		authority: map[string]Authority{},
		resultIdx: map[string]int{},
		results:   map[string]rawAgentResult{},
		meta:      map[string]*agentMeta{},
		scParent:  map[string]string{},
	}
	ld.agent(MainAgentID).Kind = "main"
	return ld
}

func (ld *loader) agent(id string) *Agent {
	if a, ok := ld.agents[id]; ok {
		return a
	}
	a := &Agent{ID: id, Kind: "subagent"}
	ld.agents[id] = a
	ld.agentOrder = append(ld.agentOrder, id)
	return a
}

// readSubagents reads every agent-<id>.jsonl in dir. The dir and each file
// are resolved through EvalSymlinks and must stay under the projects dir; a
// subagent file that resolves elsewhere is skipped and counted, never opened.
func (ld *loader) readSubagents(dir string) {
	rdir, ok := ld.inside(dir)
	if !ok {
		if _, err := os.Lstat(dir); err == nil {
			ld.sess.SkippedFiles++ // a subagents dir that leads outside the projects dir
		}
		return // no subagents is the normal case
	}
	entries, err := os.ReadDir(rdir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		id, ok := subagentID(e.Name())
		if !ok {
			if strings.HasSuffix(e.Name(), ".jsonl") {
				ld.sess.SkippedFiles++
			}
			continue
		}
		file, ok := ld.inside(filepath.Join(rdir, e.Name()))
		if !ok {
			ld.sess.SkippedFiles++
			continue
		}
		if mp, ok := ld.inside(filepath.Join(rdir, "agent-"+id+".meta.json")); ok {
			if m := readMeta(mp); m != nil {
				ld.meta[id] = m
				a := ld.agent(id)
				a.Type, a.Name = m.AgentType, truncate(m.Description, nameLen)
			}
		}
		if err := ld.readFile(file, id, false); err != nil {
			ld.sess.SkippedFiles++
		}
	}
}

// inside resolves p through EvalSymlinks and reports whether the result sits
// under the projects dir. A missing p is reported as not inside.
func (ld *loader) inside(p string) (string, bool) { return underRoot(ld.root, p) }

func readMeta(path string) *agentMeta {
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 64<<10 {
		return nil
	}
	var m agentMeta
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return &m
}

// readFile streams one transcript file with a tail read and a line cap.
func (ld *loader) readFile(path, agentID string, isMain bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	a := ld.agent(agentID)
	a.File = path
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() > ld.o.MaxBytes {
		if _, err := f.Seek(st.Size()-ld.o.MaxBytes, io.SeekStart); err != nil {
			return err
		}
		ld.sess.Truncated = true
	}
	lr := NewLineReader(bufio.NewReaderSize(f, readerBuf), ld.o.MaxLine)
	if st.Size() > ld.o.MaxBytes {
		lr.Next() // discard the partial first line
	}
	for {
		line, tooLong, partial, ok := lr.Next()
		if !ok {
			return nil
		}
		if tooLong || partial {
			ld.sess.SkippedLines++
			continue
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue // blank lines are not rows and are not counted
		}
		var e rawEntry
		if err := json.Unmarshal(line, &e); err != nil {
			ld.sess.SkippedLines++
			continue
		}
		ld.row(&e, agentID, isMain)
	}
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

func (ld *loader) nextSeq() int {
	ld.seq++
	return ld.seq
}

func (ld *loader) row(e *rawEntry, fileAgent string, isMain bool) {
	ts := parseTS(e.Timestamp)
	agentID := fileAgent
	if isMain {
		if ld.sess.Cwd == "" && e.Cwd != "" {
			ld.sess.Cwd = e.Cwd
		}
		if ld.sess.Version == "" && e.Version != "" {
			ld.sess.Version = e.Version
		}
		if e.IsSidechain && e.UUID != "" {
			agentID = ld.sidechainAgent(e)
		}
	}
	a := ld.agent(agentID)
	if !ts.IsZero() {
		if a.SpawnTS.IsZero() || ts.Before(a.SpawnTS) {
			a.SpawnTS = ts
		}
		if ts.After(a.EndTS) {
			a.EndTS = ts
		}
		if ts.After(ld.sess.LastEvent) {
			ld.sess.LastEvent = ts
		}
		if agentID == MainAgentID && (e.Type == "user" || e.Type == "assistant") && (ld.sess.Started.IsZero() || ts.Before(ld.sess.Started)) {
			ld.sess.Started = ts
		}
	}
	switch e.Type {
	case "user":
		ld.userRow(e, agentID, ts)
	case "assistant":
		ld.assistantRow(e, a, ts)
	case "attachment":
		ld.attachmentRow(e)
	}
	// system, summary, queue-operation, file-history-snapshot, cost-state,
	// atis-latch, last-prompt and anything newer carry nothing the map uses.
}

// sidechainAgent keys a legacy isSidechain row in the main file by the uuid
// of its chain's first row, found by walking parentUuid through sidechain rows.
func (ld *loader) sidechainAgent(e *rawEntry) string {
	ld.scParent[e.UUID] = e.ParentUUID
	root := e.UUID
	for i := 0; i < 100000; i++ {
		p, ok := ld.scParent[root]
		if !ok || p == "" {
			break
		}
		if _, isSC := ld.scParent[p]; !isSC {
			break
		}
		root = p
	}
	a := ld.agent(root)
	a.Sidechain = true
	return root
}

func (ld *loader) userRow(e *rawEntry, agentID string, ts time.Time) {
	if e.Message == nil || len(e.Message.Content) == 0 {
		return
	}
	c := bytes.TrimSpace(e.Message.Content)
	switch {
	case len(c) > 0 && c[0] == '"':
		var s string
		if json.Unmarshal(c, &s) == nil {
			ld.prompt(e, agentID, ts, s)
		}
	case len(c) > 0 && c[0] == '[':
		var blocks []rawBlock
		if json.Unmarshal(c, &blocks) != nil {
			return
		}
		var texts []string
		hasResult := false
		for i := range blocks {
			switch blocks[i].Type {
			case "tool_result":
				hasResult = true
				ld.toolResult(e, &blocks[i], agentID, ts)
			case "text":
				texts = append(texts, blocks[i].Text)
			}
		}
		if !hasResult && len(texts) > 0 {
			ld.prompt(e, agentID, ts, strings.Join(texts, "\n"))
		}
	}
}

func (ld *loader) prompt(e *rawEntry, agentID string, ts time.Time, text string) {
	if agentID != MainAgentID || e.IsMeta || strings.TrimSpace(text) == "" {
		return
	}
	ld.sess.Prompts = append(ld.sess.Prompts, Prompt{TS: ts, Summary: truncate(text, summaryLen)})
	ld.sess.Events = append(ld.sess.Events, Event{Seq: ld.nextSeq(), TS: ts, Agent: agentID, Kind: "prompt"})
}

func (ld *loader) toolResult(e *rawEntry, b *rawBlock, agentID string, ts time.Time) {
	if b.ToolUseID == "" {
		return
	}
	var auth Authority
	if pd := e.PermissionDecision; pd != nil {
		auth.Decision, auth.Source, auth.ReasonType = pd.Decision, pd.Source, pd.ReasonType
	}
	auth.DenialKind = e.ToolDenialKind
	var errText string
	text := resultText(b.Content)
	if b.IsError {
		errText = truncate(text, errTextLen)
	}
	if auth.Known() {
		ld.authority[b.ToolUseID] = auth
	}
	ld.resultIdx[b.ToolUseID] = len(ld.sess.Events)
	ld.sess.Events = append(ld.sess.Events, Event{Seq: ld.nextSeq(), TS: ts, Agent: agentID, Kind: "tool_result", ResultFor: b.ToolUseID, IsError: b.IsError, ErrorText: errText, Authority: auth})
	if text != "" {
		ld.pending[b.ToolUseID] = truncate(text, snippetLen)
	}
	if len(e.ToolUseResult) > 0 {
		var r rawAgentResult
		if json.Unmarshal(e.ToolUseResult, &r) == nil && r.AgentID != "" {
			ld.results[b.ToolUseID] = r
		}
	}
}

// resultText returns a tool_result's text: the string itself or the joined
// text blocks. Only the first snippetLen bytes are retained by the caller.
func resultText(c json.RawMessage) string {
	c = bytes.TrimSpace(c)
	if len(c) == 0 {
		return ""
	}
	if c[0] == '"' {
		var s string
		if json.Unmarshal(c, &s) == nil {
			return s
		}
		return ""
	}
	if c[0] == '[' {
		var blocks []rawBlock
		if json.Unmarshal(c, &blocks) != nil {
			return ""
		}
		var parts []string
		for _, b := range blocks {
			if b.Type == "text" && b.Text != "" {
				parts = append(parts, b.Text)
			}
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

func (ld *loader) assistantRow(e *rawEntry, a *Agent, ts time.Time) {
	if e.Message == nil {
		return
	}
	if e.Message.Model != "" {
		a.Model = e.Message.Model
	}
	if a.Type == "" && a.Kind == "subagent" && e.AttributionAgent != "" {
		a.Type = e.AttributionAgent
	}
	c := bytes.TrimSpace(e.Message.Content)
	if len(c) == 0 || c[0] != '[' {
		return
	}
	var blocks []rawBlock
	if json.Unmarshal(c, &blocks) != nil {
		return
	}
	for i := range blocks {
		if blocks[i].Type == "tool_use" && blocks[i].ID != "" {
			ld.toolUse(&blocks[i], a, ts)
		}
	}
}

func (ld *loader) toolUse(b *rawBlock, a *Agent, ts time.Time) {
	tc := &ToolCall{ID: b.ID, Name: b.Name}
	var in map[string]any
	if len(b.Input) > 0 {
		_ = json.Unmarshal(b.Input, &in) // a malformed input leaves the call with id and name only
	}
	str := func(k string) string {
		s, _ := in[k].(string)
		return s
	}
	kind := "tool_use"
	switch b.Name {
	case "Bash":
		tc.Command = truncate(str("command"), commandLen)
	case "Read", "Edit", "Write", "MultiEdit":
		tc.Path = str("file_path")
	case "NotebookEdit":
		tc.Path = str("notebook_path")
	case "Grep", "Glob":
		tc.Pattern = str("pattern")
		tc.Path = str("path")
	case "WebFetch":
		tc.URL = hostOf(str("url"))
	case "Skill":
		tc.Skill = str("skill")
		kind = "skill_invoked"
	case "Agent", "Task":
		tc.Spawn = &Spawn{SubagentType: str("subagent_type"), Description: truncate(str("description"), descLen), Model: str("model")}
		kind = "spawn"
	default:
		if strings.HasPrefix(b.Name, "mcp__") {
			rest := b.Name[len("mcp__"):]
			if i := strings.Index(rest, "__"); i > 0 {
				tc.MCPServer, tc.MCPTool = rest[:i], rest[i+2:]
			}
		}
	}
	a.Calls++
	ld.calls[b.ID] = tc
	seq := ld.nextSeq()
	ld.sess.Events = append(ld.sess.Events, Event{Seq: seq, TS: ts, Agent: a.ID, Kind: kind, ToolCall: tc})
	if tc.Spawn != nil {
		ld.spawnCalls = append(ld.spawnCalls, spawnRef{tc: tc, ts: ts, seq: seq})
	}
}

// attachmentRow keeps the stdout of PreToolUse hook_success rows that look
// like JSON; they are parsed in finish, once per call, when the call exists.
func (ld *loader) attachmentRow(e *rawEntry) {
	at := e.Attachment
	if at == nil || at.Type != "hook_success" || at.ToolUseID == "" || at.HookEvent != "PreToolUse" {
		return
	}
	s := strings.TrimSpace(at.Stdout)
	if !strings.HasPrefix(s, "{") {
		return
	}
	ld.hooks[at.ToolUseID] = append(ld.hooks[at.ToolUseID], s)
}

func (ld *loader) finish() *Session {
	s := ld.sess
	// hook decisions onto calls: the first PreToolUse hook_success row for a
	// call whose stdout is a decision wins (several hooks may answer one call).
	for id, outs := range ld.hooks {
		tc := ld.calls[id]
		if tc == nil {
			continue
		}
		for _, raw := range outs {
			var h hookOut
			if json.Unmarshal([]byte(raw), &h) != nil {
				continue
			}
			hs := h.HookSpecificOutput
			if hs.PermissionDecision != "" || hs.UpdatedInput != nil {
				tc.HookDecision = hs.PermissionDecision
				tc.HookReason = truncate(hs.PermissionDecisionReason, reasonLen)
				if cmd, ok := hs.UpdatedInput["command"].(string); ok {
					tc.HookRewrite = truncate(cmd, commandLen)
				}
				break
			}
			if h.Decision != "" {
				switch h.Decision {
				case "approve":
					tc.HookDecision = "allow"
				case "block":
					tc.HookDecision = "deny"
				default:
					tc.HookDecision = h.Decision
				}
				tc.HookReason = truncate(h.Reason, reasonLen)
				break
			}
		}
	}
	// results: snippets for Bash only; Agent results become "return" events,
	// recognised by the call or, when a tail read dropped the call, by the
	// result row's toolUseResult.agentId.
	for id, idx := range ld.resultIdx {
		tc := ld.calls[id]
		if tc != nil && tc.Name == "Bash" {
			s.Events[idx].Snippet = ld.pending[id]
		}
		if _, agentResult := ld.results[id]; (tc != nil && tc.Spawn != nil) || agentResult {
			s.Events[idx].Kind = "return"
		}
	}
	for id, a := range ld.authority {
		if tc := ld.calls[id]; tc != nil {
			tc.Authority = a
		}
	}
	ld.linkSpawns()

	for _, id := range ld.agentOrder {
		a := ld.agents[id]
		if a.Model == "" {
			if r, ok := ld.resultByAgent(id); ok && r.ResolvedModel != "" {
				a.Model = r.ResolvedModel
			} else {
				a.Model = "unknown"
			}
		}
		if a.Type == "" && a.Kind == "subagent" {
			if r, ok := ld.resultByAgent(id); ok {
				a.Type = r.AgentType
			}
		}
	}
	s.Agents = make([]Agent, 0, len(ld.agentOrder))
	s.Agents = append(s.Agents, *ld.agents[MainAgentID])
	var subs []*Agent
	for _, id := range ld.agentOrder {
		if id != MainAgentID {
			subs = append(subs, ld.agents[id])
		}
	}
	sort.SliceStable(subs, func(i, j int) bool { return tsLess(subs[i].SpawnTS, subs[j].SpawnTS, subs[i].ID < subs[j].ID) })
	for _, a := range subs {
		s.Agents = append(s.Agents, *a)
	}
	sort.SliceStable(s.Events, func(i, j int) bool {
		return tsLess(s.Events[i].TS, s.Events[j].TS, s.Events[i].Seq < s.Events[j].Seq)
	})
	return s
}

// resultByAgent finds the parent's Agent result that names this agent id.
func (ld *loader) resultByAgent(agentID string) (rawAgentResult, bool) {
	for _, r := range ld.results {
		if r.AgentID == agentID {
			return r, true
		}
	}
	return rawAgentResult{}, false
}

// tsLess orders timestamps ascending with zero (missing) last; tie is the fallback.
func tsLess(a, b time.Time, tie bool) bool {
	switch {
	case a.IsZero() && b.IsZero():
		return tie
	case a.IsZero():
		return false
	case b.IsZero():
		return true
	case a.Equal(b):
		return tie
	default:
		return a.Before(b)
	}
}
