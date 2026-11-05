package profile

import (
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
)

func TestBwrapArgs(t *testing.T) {
	r := Resolved{
		SkillDirs: []string{"/home/u/.claude/skills/pdf"},
		CWD:       "/home/u/proj", Tmp: "/tmp/u", Home: "/home/u",
		Write:        []string{"/home/u/.cache"},
		DenyPaths:    []string{"/home/u/.ssh", "/home/u/.aws", "/home/u/.claude"},
		DenyFiles:    []string{"/run/docker.sock", "/home/u/.netrc"},
		DenyPatterns: []string{"**/.env"},
		Network:      manifest.NetLocalhost, ExecAny: false, ExecAllow: []string{"/usr/bin/python3"},
	}
	text, warnings, err := BwrapArgs(r)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(strings.Split(text, "\n"), " ")
	for _, want := range []string{"--ro-bind / /", "--tmpfs /home/u/.aws", "--tmpfs /home/u/.ssh", "--tmpfs /home/u/.claude", "--bind /home/u/.cache /home/u/.cache", "--bind /home/u/proj /home/u/proj", "--bind /tmp/u /tmp/u", "--ro-bind /home/u/.claude/skills/pdf /home/u/.claude/skills/pdf", "--ro-bind /dev/null /home/u/.netrc", "--ro-bind /dev/null /run/docker.sock", "--unshare-all", "--clearenv", "--die-with-parent", "--new-session"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %q", want, joined)
		}
	}
	if strings.Contains(joined, "--share-net") {
		t.Error("localhost must not share the network namespace")
	}
	// order: every --bind before every --tmpfs, and the skill ro-bind after the tmpfs that would hide it
	lastBind := strings.LastIndex(joined, "--bind ")
	firstTmpfs := strings.Index(joined, "--tmpfs ")
	skillBind := strings.Index(joined, "--ro-bind /home/u/.claude/skills/pdf")
	claudeDeny := strings.Index(joined, "--tmpfs /home/u/.claude")
	lastTmpfs := strings.LastIndex(joined, "--tmpfs ")
	firstNull := strings.Index(joined, "--ro-bind /dev/null ")
	lastNull := strings.LastIndex(joined, "--ro-bind /dev/null ")
	if lastBind > firstTmpfs || skillBind < claudeDeny || firstNull < lastTmpfs || lastNull > skillBind {
		t.Errorf("mount order wrong: %q", joined)
	}
	if strings.Contains(joined, "--tmpfs /run/docker.sock") || strings.Contains(joined, "--tmpfs /home/u/.netrc") {
		t.Errorf("files must not be tmpfs mount points: %q", joined)
	}
	if len(warnings) != 3 {
		t.Errorf("warnings = %q", warnings)
	}

	all, _, _ := BwrapArgs(Resolved{CWD: "/home/u/p", Tmp: "/tmp/u", Network: manifest.NetAll, ExecAny: true})
	if !strings.Contains(all, "--share-net") {
		t.Error("network=all should share the network namespace")
	}
	if _, _, err := BwrapArgs(Resolved{CWD: "/", Tmp: "/tmp"}); err == nil {
		t.Error("CWD=/ should be refused")
	}
	if _, _, err := BwrapArgs(Resolved{CWD: "/home/u/p", Tmp: "/tmp", SkillDirs: []string{"/home/u"}, DenyPaths: []string{"/home/u/.ssh"}}); err == nil {
		t.Error("a skill dir covering a deny path should be refused")
	}
	if _, _, err := BwrapArgs(Resolved{CWD: "/home/u/p", Tmp: "/tmp", SkillDirs: []string{"/home/u"}, DenyFiles: []string{"/home/u/.netrc"}}); err == nil {
		t.Error("a skill dir covering a deny file should be refused")
	}
	if _, _, err := BwrapArgs(Resolved{CWD: "/home/u/p", Tmp: "/tmp", DenyFiles: []string{"/dev/null"}}); err == nil {
		t.Error("hiding /dev/null with itself should be refused")
	}
	_, w, _ := BwrapArgs(Resolved{CWD: "/home/u/.ssh/x", Tmp: "/tmp", DenyPaths: []string{"/home/u/.ssh"}})
	if len(w) == 0 || !strings.Contains(w[0], "will be hidden") {
		t.Errorf("writable-under-deny should warn: %q", w)
	}
}
