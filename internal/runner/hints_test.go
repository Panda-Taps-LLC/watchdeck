package runner

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
)

func TestHintsTable(t *testing.T) {
	type want struct {
		kind   string
		errno  int
		stream string
		label  string
	}
	cases := []struct {
		name           string
		stdout, stderr string
		exit           int
		execAny        bool
		want           []want
	}{
		{
			name: "traceback: connect four lines above the errno line",
			stderr: `Traceback (most recent call last):
  File "/x/net.py", line 3, in fetch
    sock.connect(sa)
  File "/x/wrap.py", line 9, in inner
    raise wrapped
  File "/x/wrap.py", line 12, in outer
PermissionError: [Errno 1] Operation not permitted`,
			exit: 1, execAny: true,
			want: []want{{activity.HintNetwork, 1, "stderr", ""}},
		},
		{
			name:   "darwin ENETUNREACH",
			stderr: "OSError: [Errno 51] Network is unreachable",
			want:   []want{{activity.HintNetwork, 51, "stderr", ""}},
		},
		{
			name:   "linux ENETUNREACH",
			stderr: "OSError: [Errno 101] Network is unreachable",
			want:   []want{{activity.HintNetwork, 101, "stderr", ""}},
		},
		{
			name:   "EROFS",
			stderr: "OSError: [Errno 30] Read-only file system: '/home/u/out.txt'",
			want:   []want{{activity.HintWrite, 30, "stderr", ""}},
		},
		{
			name:   "bad interpreter",
			stderr: "/bin/bash: ./run.sh: /usr/local/bin/python3: bad interpreter: Operation not permitted",
			exit:   126,
			want:   []want{{activity.HintExec, 0, "stderr", ""}},
		},
		{
			name:   "ENOENT on a deny path",
			stderr: "FileNotFoundError: [Errno 2] No such file or directory: '/home/u/.ssh/id_fake'",
			want:   []want{{activity.HintRead, 2, "stderr", ""}},
		},
		{
			name:   "ENOENT elsewhere is not a hint",
			stderr: "FileNotFoundError: [Errno 2] No such file or directory: 'data.csv'",
		},
		{
			name: "EPERM on a write, os.environ above is not a deny path",
			stderr: `  File "/x/probe.py", line 30, in write_home
    with open(os.path.join(os.environ["HOME"], ".canary-write"), "w") as f:
PermissionError: [Errno 1] Operation not permitted: '/Users/you/.canary-write'`,
			want: []want{{activity.HintWrite, 1, "stderr", ""}},
		},
		{
			name:   "EPERM on a deny path read",
			stderr: "PermissionError: [Errno 1] Operation not permitted: '/Users/you/.ssh/id_fake'",
			want:   []want{{activity.HintRead, 1, "stderr", ""}},
		},
		{
			name:   "EACCES keeps its errno",
			stderr: "PermissionError: [Errno 13] Permission denied: '/Users/you/.aws/credentials'",
			want:   []want{{activity.HintRead, 13, "stderr", ""}},
		},
		{
			name:   "bare EPERM",
			stderr: "chflags: x: Operation not permitted",
			want:   []want{{activity.HintUnknown, 1, "stderr", ""}},
		},
		{
			name:   "probe --strict stderr line",
			stderr: "probe net: socket connect to 192.0.2.1:80 refused: PermissionError: [Errno 1] Operation not permitted",
			want:   []want{{activity.HintNetwork, 1, "stderr", ""}},
		},
		{
			name:   "canary markers on stdout",
			stdout: "shell: started\nnet: DENIED(1)\nwrite-cwd: ALLOWED\nwrite-home: DENIED(1)\nread-secret: DENIED(1)\nsubprocess: DENIED(1)\nlocalhost: DENIED(1)\nenv: SCRUBBED\n",
			want: []want{
				{activity.HintNetwork, 1, "stdout", "net"},
				{activity.HintWrite, 1, "stdout", "write-home"},
				{activity.HintRead, 1, "stdout", "read-secret"},
				{activity.HintExec, 1, "stdout", "subprocess"},
				{activity.HintNetwork, 1, "stdout", "localhost"},
			},
		},
		{
			name:   "linux canary marker",
			stdout: "net: DENIED(101)\n",
			want:   []want{{activity.HintNetwork, 101, "stdout", "net"}},
		},
		{
			name:   "stderr before stdout, duplicates dropped",
			stdout: "net: DENIED(1)\nnet: DENIED(1)\n",
			stderr: "OSError: [Errno 30] Read-only file system\nOSError: [Errno 30] Read-only file system\n",
			want:   []want{{activity.HintWrite, 30, "stderr", ""}, {activity.HintNetwork, 1, "stdout", "net"}},
		},
		{
			name:   "exit 126 under an exec allow-list",
			stderr: "/bin/bash: line 1: /usr/bin/git: Operation not permitted",
			exit:   126,
			want:   []want{{activity.HintExec, 1, "stderr", ""}},
		},
		{
			name:   "exit 126 with nothing matched still names exec, line not stored",
			stderr: "some unrelated output\n",
			exit:   126,
			want:   []want{{activity.HintExec, 0, "stderr", ""}},
		},
		{
			name:    "exit 126 with exec any is not exec",
			stderr:  "/bin/bash: line 1: ./x: Operation not permitted",
			exit:    126,
			execAny: true,
			want:    []want{{activity.HintUnknown, 1, "stderr", ""}},
		},
		{
			name:   "stdout error message still counts",
			stdout: "PermissionError: [Errno 1] Operation not permitted: '/Users/you/.ssh/id_x'",
			want:   []want{{activity.HintRead, 1, "stdout", ""}},
		},
		{
			name:   "stdout bare EPERM token is not a hint",
			stdout: "except PermissionError as e:\nerr = errno.EPERM\n",
		},
		{
			name:   "ordinary output",
			stdout: "rows: 42\nwrite-cwd: ALLOWED\n",
			stderr: "warning: deprecated option\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scanHints([]byte(c.stdout), []byte(c.stderr), c.exit, c.execAny)
			if len(got) != len(c.want) {
				t.Fatalf("got %d hints %+v, want %d", len(got), got, len(c.want))
			}
			for i, w := range c.want {
				h := got[i]
				if h.Kind != w.kind || h.Errno != w.errno || h.Stream != w.stream || h.Label != w.label {
					t.Errorf("hint %d = %+v, want %+v", i, h, w)
				}
				if !h.Heuristic || h.Text == "" || len(h.Line) > maxHintLine || strings.Contains(h.Line, "unrelated") {
					t.Errorf("hint %d fields: %+v", i, h)
				}
			}
		})
	}
}

func TestHintTexts(t *testing.T) {
	for _, c := range []struct {
		kind  string
		errno int
		want  string
	}{
		{activity.HintNetwork, 1, "network access refused by the OS (EPERM)"},
		{activity.HintNetwork, 101, "network access refused by the OS (ENETUNREACH, no network namespace)"},
		{activity.HintWrite, 1, "write outside the allowed paths refused (EPERM)"},
		{activity.HintWrite, 30, "write outside the allowed paths refused (EROFS, read-only bind)"},
		{activity.HintRead, 1, "read of a protected path refused (EPERM)"},
		{activity.HintRead, 2, "read of a protected path refused (hidden by the sandbox, ENOENT)"},
		{activity.HintExec, 0, "program not on the exec allow-list (bad interpreter / exit 126)"},
		{activity.HintUnknown, 1, "operation not permitted by the sandbox (EPERM)"},
	} {
		if got := hintText(c.kind, c.errno); got != c.want {
			t.Errorf("%s/%d: %q", c.kind, c.errno, got)
		}
	}
}

func TestHintsCapAndTrim(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&b, "PermissionError: [Errno 1] Operation not permitted: '/x/%d'\n", i)
	}
	if got := scanHints(nil, []byte(b.String()), 1, true); len(got) != maxHints {
		t.Fatalf("cap: %d hints", len(got))
	}
	long := "PermissionError: [Errno 1] Operation not permitted: '" + strings.Repeat("é", 300) + "'"
	got := scanHints(nil, []byte(long), 1, true)
	if len(got) != 1 || len(got[0].Line) > maxHintLine || !utf8.ValidString(got[0].Line) || !strings.HasPrefix(got[0].Line, "PermissionError") {
		t.Fatalf("trim: %+v", got)
	}
}

func TestTailWriterKeepsTail(t *testing.T) {
	var dst bytes.Buffer
	w := newTailWriter(&dst, 1024)
	var all strings.Builder
	for i := 0; i < 500; i++ {
		line := fmt.Sprintf("line %04d %s\n", i, strings.Repeat("x", 20))
		all.WriteString(line)
		if n, err := w.Write([]byte(line)); n != len(line) || err != nil {
			t.Fatalf("write: %d %v", n, err)
		}
	}
	if dst.String() != all.String() {
		t.Fatal("forwarded bytes differ from the input")
	}
	tail := string(w.Tail())
	if len(tail) > 1024 || !strings.HasPrefix(tail, "line ") || !strings.HasSuffix(tail, "line 0499 "+strings.Repeat("x", 20)+"\n") {
		t.Fatalf("tail (%d bytes): %q", len(tail), tail)
	}
	// a short stream is kept whole
	w = newTailWriter(&bytes.Buffer{}, 1024)
	w.Write([]byte("partial"))
	if string(w.Tail()) != "partial" {
		t.Fatalf("short tail %q", w.Tail())
	}
}

// A command that prints a script's source before running it (seen in the
// 2026-10-13 dogfood: cat probe.py && python3 probe.py net) must yield the
// probe's marker only, not its comments and except clauses.
func TestStdoutSourceListingIsNotAHint(t *testing.T) {
	stdout := strings.Join([]string{
		"except PermissionError as e:",
		"# EPERM/EACCES (Seatbelt), EROFS (bwrap read-only root), ENETUNREACH (bwrap unshared net)",
		"# EPERM for a present one (measured 2026-10-12), so ENOENT alone proves",
		"# nothing on macOS. stat of the directory is EPERM when it is denied.",
		"// write: Operation not permitted when the sandbox denies it",
		"except PermissionError as pe:",
		`raise PermissionError(pe.errno, "directory denied by the sandbox") from e`,
		`raise PermissionError(e.errno, "hidden by the sandbox") from e`,
		"----",
		"net: DENIED(1)",
	}, "\n")
	got := scanHints([]byte(stdout), nil, 0, true)
	if len(got) != 1 || got[0].Label != "net" || got[0].Kind != activity.HintNetwork {
		t.Fatalf("got %+v, want the net marker only", got)
	}
}

func TestCanaryMarkerSurvivesCap(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&b, "PermissionError: [Errno 1] Operation not permitted: '/x/%d'\n", i)
	}
	got := scanHints([]byte("net: DENIED(1)\n"), []byte(b.String()), 1, true)
	if len(got) != maxHints {
		t.Fatalf("cap: %d hints", len(got))
	}
	if got[len(got)-1].Label != "net" {
		t.Fatalf("marker evicted by the cap: %+v", got)
	}
}
