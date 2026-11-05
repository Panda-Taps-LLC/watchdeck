package sessionindex

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Leak watch (Plan 08 D2, DESIGN §14 "Leak watch"). Key-shaped values are
// built by concatenation, as internal/rules/rules_test.go does, so no file
// in the repo holds a whole one.
var (
	fakeSlack  = "xoxb" + "-" + strings.Repeat("0", 10) + "-FAKE"
	fakeGitHub = "ghp" + "_" + "FAKE" + strings.Repeat("0", 32)
	fakeStripe = "sk" + "_live_" + "FAKE" + strings.Repeat("0", 16)
	fakeAnth   = "sk" + "-ant-" + "api03-" + "FAKE" + strings.Repeat("0", 32)
	fakeAWSID  = "AKIA" + "IOSFODNN7" + "EXAMPLE"
	fakePEM    = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"
	fakeOpenAI = "sk" + "-proj-" + "FAKE" + strings.Repeat("0", 32)
	fakeAWSSec = "FAKE" + strings.Repeat("0", 36)
)

func allFakes() []string {
	return []string{fakeSlack, fakeGitHub, fakeStripe, fakeAnth, fakeAWSID, fakePEM, fakeOpenAI, fakeAWSSec}
}

// reply is an assistant text row with a uuid, as Claude Code writes them.
func reply(i int, uuid, text string) string {
	return jsonLine(map[string]any{
		"type": "assistant", "timestamp": ts(i), "uuid": uuid,
		"message": map[string]any{"role": "assistant", "model": modelTest, "content": []any{
			map[string]any{"type": "text", "text": text},
		}},
	})
}

func findingsOf(t *testing.T, ix *Index, id string) Entry {
	t.Helper()
	en, ok := ix.Get(id)
	if !ok {
		t.Fatalf("no entry %s", id)
	}
	return en
}

func TestFindingsFromResultReplyAndInput(t *testing.T) {
	e := newEnv(t)
	// A typed prompt is not scanned (D5); neither are thinking and hook output.
	content := userPrompt(0, "/p", "my key is "+fakeAnth+", keep it") +
		assistantTool(1, modelTest, "toolu_read", "Read", map[string]any{"file_path": "/p/config/app.env"}) +
		toolResult(2, "toolu_read", "SLACK="+fakeSlack+"\nPORT=8080") +
		reply(3, "uuid-reply-1", "The file holds the token "+fakeGitHub+".") +
		assistantTool(4, modelTest, "toolu_bash", "Bash", map[string]any{"command": "curl -H 'Authorization: Bearer " + fakeStripe + "' https://api.example.test/v1"}) +
		toolResult(5, "toolu_bash", "ok") +
		// Neither thinking nor hook output is scanned.
		jsonLine(map[string]any{"type": "assistant", "timestamp": ts(6), "uuid": "uuid-think",
			"message": map[string]any{"role": "assistant", "model": modelTest, "content": []any{
				map[string]any{"type": "thinking", "thinking": "the key " + fakeOpenAI + " is in scope"}}}}) +
		jsonLine(map[string]any{"type": "attachment", "timestamp": ts(7),
			"attachment": map[string]any{"type": "hook_success", "hookEvent": "PostToolUse", "stdout": "saw " + fakeAWSID}})
	writeSession(t, e.projects, "-p", sid(1), content)
	ix, _ := e.update(t)
	en := findingsOf(t, ix, sid(1))
	want := []Finding{
		{Pattern: "slack-token", Label: "Slack token", Where: WhereResult, Tool: "Read", Target: "/p/config/app.env", Ref: "toolu_read", TS: tsBase.Add(2 * time.Second)},
		{Pattern: "github-token", Label: "GitHub token", Where: WhereReply, Ref: "uuid-reply-1", TS: tsBase.Add(3 * time.Second)},
		{Pattern: "stripe-live", Label: "Stripe live key", Where: WhereInput, Tool: "Bash", Target: "curl", Ref: "toolu_bash", TS: tsBase.Add(4 * time.Second)},
	}
	if !reflect.DeepEqual(en.Findings, want) {
		t.Fatalf("findings:\n got %+v\nwant %+v", en.Findings, want)
	}
	if en.FindingsCapped {
		t.Error("capped")
	}
	// meta.json round trip: a fresh Open reads the same findings.
	en2 := findingsOf(t, e.open(t), sid(1))
	if !reflect.DeepEqual(en2.Findings, want) {
		t.Fatalf("after reload: %+v", en2.Findings)
	}
}

func TestReplyFindingsHaveDistinctRefs(t *testing.T) {
	e := newEnv(t)
	writeSession(t, e.projects, "-p", sid(1), userPrompt(0, "/p", "hi")+
		reply(1, "uuid-a", "first "+fakeSlack)+
		reply(2, "uuid-b", "second "+fakeSlack))
	ix, _ := e.update(t)
	en := findingsOf(t, ix, sid(1))
	if len(en.Findings) != 2 || en.Findings[0].Ref != "uuid-a" || en.Findings[1].Ref != "uuid-b" {
		t.Fatalf("findings: %+v", en.Findings)
	}
	for _, f := range en.Findings {
		if f.Where != WhereReply || f.Tool != "" || f.Pattern != "slack-token" {
			t.Errorf("finding %+v", f)
		}
	}
}

func TestFindingsDedupeAndCap(t *testing.T) {
	e := newEnv(t)
	// One tool use whose results carry the token 60 times: one finding.
	var b strings.Builder
	b.WriteString(userPrompt(0, "/p", "hi"))
	b.WriteString(assistantTool(1, modelTest, "toolu_one", "Read", map[string]any{"file_path": "/p/a"}))
	for i := 0; i < 60; i++ {
		b.WriteString(toolResult(2+i, "toolu_one", fakeSlack+" "+fakeSlack))
	}
	writeSession(t, e.projects, "-p", sid(1), b.String())
	// Sixty tool uses with a token each: capped at MaxFindings distinct.
	b.Reset()
	b.WriteString(userPrompt(0, "/q", "hi"))
	for i := 0; i < 60; i++ {
		id := "toolu_" + strings.Repeat("x", 3) + string(rune('A'+i%26)) + string(rune('a'+i/26))
		b.WriteString(assistantTool(1+2*i, modelTest, id, "Read", map[string]any{"file_path": "/q/f"}))
		b.WriteString(toolResult(2+2*i, id, fakeSlack))
	}
	writeSession(t, e.projects, "-q", sid(2), b.String())
	ix, _ := e.update(t)
	one := findingsOf(t, ix, sid(1))
	if len(one.Findings) != 1 || one.FindingsCapped {
		t.Fatalf("one ref: %d findings, capped %v", len(one.Findings), one.FindingsCapped)
	}
	many := findingsOf(t, ix, sid(2))
	if len(many.Findings) != MaxFindings || !many.FindingsCapped {
		t.Fatalf("many refs: %d findings, capped %v", len(many.Findings), many.FindingsCapped)
	}
	seen := map[string]bool{}
	for _, f := range many.Findings {
		if seen[f.Ref] {
			t.Fatalf("ref %s twice", f.Ref)
		}
		seen[f.Ref] = true
	}
}

func TestFindingsSurviveIncrementalAppend(t *testing.T) {
	e := newEnv(t)
	p := writeSession(t, e.projects, "-p", sid(1), userPrompt(0, "/p", "hi")+
		assistantTool(1, modelTest, "toolu_1", "Read", map[string]any{"file_path": "/p/one"})+
		toolResult(2, "toolu_1", fakeSlack)+
		assistantTool(3, modelTest, "toolu_2", "WebFetch", map[string]any{"url": "https://docs.example.test/page?q=1", "prompt": "read"}))
	ix, _ := e.update(t)
	if en := findingsOf(t, ix, sid(1)); len(en.Findings) != 1 {
		t.Fatalf("first pass: %+v", en.Findings)
	}
	// A result for the tool use read in the first pass (its tool is not
	// known to this pass), then a new call and its result.
	appendFile(t, p, toolResult(4, "toolu_2", "page text "+fakeGitHub)+
		assistantTool(5, modelTest, "toolu_3", "Grep", map[string]any{"pattern": "x", "path": "/p/src"})+
		toolResult(6, "toolu_3", "src/a.go: "+fakeAWSID))
	bumpMtime(t, p, time.Second)
	ix, st := e.update(t)
	if st.Appended != 1 {
		t.Fatalf("stats: %+v", st)
	}
	got := findingsOf(t, ix, sid(1)).Findings
	if len(got) != 3 {
		t.Fatalf("after append: %+v", got)
	}
	if got[0].Ref != "toolu_1" || got[0].Tool != "Read" {
		t.Errorf("kept: %+v", got[0])
	}
	if got[1].Ref != "toolu_2" || got[1].Tool != "unknown" || got[1].Target != "" || got[1].Pattern != "github-token" {
		t.Errorf("resumed past the tool use: %+v", got[1])
	}
	if got[2].Ref != "toolu_3" || got[2].Tool != "Grep" || got[2].Target != "/p/src" || got[2].Pattern != "aws-access-key-id" {
		t.Errorf("new: %+v", got[2])
	}
	// A rebuild knows every tool: WebFetch's target is the host.
	ix = e.open(t)
	if _, err := ix.Rebuild(); err != nil {
		t.Fatal(err)
	}
	got = findingsOf(t, ix, sid(1)).Findings
	if len(got) != 3 || got[1].Tool != "WebFetch" || got[1].Target != "docs.example.test" {
		t.Errorf("rebuilt: %+v", got)
	}
}

func TestFindingsAgentFromSubagentFile(t *testing.T) {
	e := newEnv(t)
	writeSession(t, e.projects, "-p", sid(1), userPrompt(0, "/p", "hi")+
		assistantTool(1, modelTest, "toolu_main", "Bash", map[string]any{"command": "echo " + fakeSlack}))
	sub := filepath.Join(e.projects, "-p", sid(1), "subagents")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "agent-a1b2.jsonl"), []byte(
		assistantTool(2, modelTest, "toolu_sub", "Read", map[string]any{"file_path": "/p/.env"})+
			toolResult(3, "toolu_sub", "TOKEN="+fakeGitHub)), 0o600); err != nil {
		t.Fatal(err)
	}
	ix, _ := e.update(t)
	got := findingsOf(t, ix, sid(1)).Findings
	if len(got) != 2 {
		t.Fatalf("findings: %+v", got)
	}
	if got[0].Agent != "" || got[0].Ref != "toolu_main" || got[0].Target != "echo" {
		t.Errorf("main: %+v", got[0])
	}
	if got[1].Agent != "a1b2" || got[1].Ref != "toolu_sub" || got[1].Tool != "Read" || got[1].Target != "/p/.env" {
		t.Errorf("subagent: %+v", got[1])
	}
}

// TestMetaVersionFourRebuilds: a version-3 meta.json (no findings field)
// loads empty, and the next Update rebuilds the session with its findings.
func TestMetaVersionFourRebuilds(t *testing.T) {
	e := newEnv(t)
	writeSession(t, e.projects, "-p", sid(1), userPrompt(0, "/p", "hi")+
		assistantTool(1, modelTest, "toolu_1", "Read", map[string]any{"file_path": "/p/x"})+
		toolResult(2, "toolu_1", fakeSlack))
	if err := os.MkdirAll(e.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	v3 := `{"version":3,"sessions":{"` + sid(1) + `":{"id":"` + sid(1) + `","harness":"claude-code","project_dir":"-p","path":"x"}}}`
	if err := os.WriteFile(filepath.Join(e.dir, "meta.json"), []byte(v3), 0o600); err != nil {
		t.Fatal(err)
	}
	ix := e.open(t)
	if n := len(ix.Entries()); n != 0 {
		t.Fatalf("a version-3 index loaded %d entries", n)
	}
	st, err := ix.Update()
	if err != nil {
		t.Fatal(err)
	}
	if st.Rebuilt != 1 {
		t.Fatalf("stats: %+v", st)
	}
	if en := findingsOf(t, ix, sid(1)); len(en.Findings) != 1 {
		t.Fatalf("findings after the rebuild: %+v", en.Findings)
	}
	b, err := os.ReadFile(filepath.Join(e.dir, "meta.json"))
	if err != nil || !strings.Contains(string(b), `"version":4`) {
		t.Fatalf("meta.json version: %v %.80s", err, b)
	}
}

// TestLeakFindingsCarryNoSecret: neither meta.json nor any Finding field
// holds a key-shaped value, even when the key is the Bash program or part
// of a file path.
func TestLeakFindingsCarryNoSecret(t *testing.T) {
	e := newEnv(t)
	content := userPrompt(0, "/p", "hi") +
		assistantTool(1, modelTest, "toolu_a", "Bash", map[string]any{"command": fakeStripe + " --help"}) +
		toolResult(2, "toolu_a", fakeAnth) +
		assistantTool(3, modelTest, "toolu_b", "Read", map[string]any{"file_path": "/tmp/" + fakeGitHub + ".txt"}) +
		toolResult(4, "toolu_b", fakePEM+"\n"+fakeOpenAI) +
		reply(5, "uuid-r", "found "+fakeAWSID+" and aws_secret_access_key = "+fakeAWSSec) +
		assistantTool(6, modelTest, "toolu_c", "Write", map[string]any{"file_path": "/p/notes.md", "content": "slack: " + fakeSlack})
	writeSession(t, e.projects, "-p", sid(1), content)
	ix, _ := e.update(t)
	got := findingsOf(t, ix, sid(1)).Findings
	patterns := map[string]bool{}
	for _, f := range got {
		patterns[f.Pattern] = true
		for _, field := range []string{f.Pattern, f.Label, f.Where, f.Tool, f.Target, f.Ref, f.Agent} {
			for _, k := range allFakes() {
				if strings.Contains(field, k) {
					t.Errorf("finding %+v holds a key-shaped value", f)
				}
			}
		}
	}
	if len(patterns) != 8 {
		t.Errorf("want all eight patterns found, got %v", patterns)
	}
	for _, f := range got {
		if f.Ref == "toolu_a" && f.Target != "" || f.Ref == "toolu_b" && f.Where == WhereInput && f.Target != "" {
			t.Errorf("a key-shaped target was kept: %+v", f)
		}
	}
	b, err := os.ReadFile(filepath.Join(e.dir, "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range allFakes() {
		if strings.Contains(string(b), k) {
			t.Errorf("meta.json holds a key-shaped value (%d bytes)", len(k))
		}
	}
}

// TestFindingTargetCutFlag (Task 5 fix round 1): a target longer than 120
// bytes is cut and the finding says so, so a fix is never built from the
// cut path; a target of exactly 120 bytes is whole.
func TestFindingTargetCutFlag(t *testing.T) {
	e := newEnv(t)
	long := "/p/" + strings.Repeat("d", 130) + "/app.env"
	whole := "/p/" + strings.Repeat("e", 117) // 120 bytes
	content := assistantTool(1, modelTest, "toolu_long", "Read", map[string]any{"file_path": long}) +
		toolResult(2, "toolu_long", "SLACK="+fakeSlack) +
		assistantTool(3, modelTest, "toolu_whole", "Read", map[string]any{"file_path": whole}) +
		toolResult(4, "toolu_whole", "SLACK="+fakeSlack)
	writeSession(t, e.projects, "-p", sid(1), content)
	ix, _ := e.update(t)
	en := findingsOf(t, ix, sid(1))
	if len(en.Findings) != 2 {
		t.Fatalf("findings %+v", en.Findings)
	}
	cut, ok := en.Findings[0], en.Findings[1]
	if !cut.TargetCut || len(cut.Target) != 120 || !strings.HasPrefix(long, cut.Target) {
		t.Errorf("long target: cut %v, %d bytes", cut.TargetCut, len(cut.Target))
	}
	if ok.TargetCut || ok.Target != whole {
		t.Errorf("120-byte target: %+v", ok)
	}
	if en2 := findingsOf(t, e.open(t), sid(1)); !en2.Findings[0].TargetCut {
		t.Error("target_cut lost in meta.json")
	}
}
