package runner

import (
	"io"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/Panda-Taps-LLC/watchdeck/internal/activity"
)

// Limits for denial hints.
const (
	tailKeep     = 64 << 10 // bytes of each stream kept for the scan
	maxHints     = 8
	maxHintLine  = 200 // bytes of a matched line kept in a hint
	hintLookback = 6   // lines above a match that classify it (a traceback's call site)
)

// tailWriter forwards every write to dst unchanged and keeps the last keep
// bytes for the hint scan.
type tailWriter struct {
	dst  io.Writer
	keep int
	mu   sync.Mutex
	buf  []byte
	cut  bool // bytes were dropped from the front
}

func newTailWriter(dst io.Writer, keep int) *tailWriter {
	return &tailWriter{dst: dst, keep: keep}
}

func (w *tailWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.buf = append(w.buf, p...)
	if len(w.buf) > 2*w.keep {
		w.buf = append(w.buf[:0], w.buf[len(w.buf)-w.keep:]...)
		w.cut = true
	}
	w.mu.Unlock()
	return w.dst.Write(p)
}

// Tail returns the kept bytes, starting at a line boundary when the front
// was cut.
func (w *tailWriter) Tail() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	b := w.buf
	cut := w.cut
	if len(b) > w.keep {
		b = b[len(b)-w.keep:]
		cut = true
	}
	if cut {
		if i := strings.IndexByte(string(b), '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	return append([]byte(nil), b...)
}

// scanHints looks for lines that read like a sandbox denial in the child's
// stderr and stdout tails. Only matched lines are kept (trimmed, at most
// maxHintLine bytes), at most maxHints in all, duplicates dropped; canary
// markers are kept before other matches when the cap bites. stdout is
// scanned strictly (see classify), since it may hold anything the command
// printed, source listings included. Hints are heuristic: a floor, never a
// ceiling. exit and execAny add the exec rule: exit 126 under an exec
// allow-list is a refused exec.
func scanHints(stdout, stderr []byte, exit int, execAny bool) []activity.Hint {
	var hs []activity.Hint
	hs = scanStream(hs, "stderr", stderr, false)
	hs = scanStream(hs, "stdout", stdout, true)
	hs = capHints(hs)
	if exit == 126 && !execAny {
		found := false
		for i := range hs {
			if hs[i].Kind == activity.HintUnknown && hs[i].Stream == "stderr" {
				hs[i].Kind = activity.HintExec
				hs[i].Text = hintText(activity.HintExec, hs[i].Errno)
			}
			found = found || hs[i].Kind == activity.HintExec
		}
		if !found && len(hs) < maxHints {
			// No line matched: Line stays empty (only matched lines are ever stored).
			hs = append(hs, activity.Hint{
				Kind: activity.HintExec, Stream: "stderr",
				Text: hintText(activity.HintExec, 0), Heuristic: true,
			})
		}
	}
	return hs
}

// scanStream appends the hints found in b. It collects up to maxHints
// labelled and maxHints unlabelled hints in all; capHints trims the rest.
func scanStream(hs []activity.Hint, stream string, b []byte, strict bool) []activity.Hint {
	if len(b) == 0 {
		return hs
	}
	labelled, other := 0, 0
	for _, h := range hs {
		if h.Label != "" {
			labelled++
		} else {
			other++
		}
	}
	lines := strings.Split(string(b), "\n")
	for i := range lines {
		if labelled >= maxHints && other >= maxHints {
			break
		}
		h, ok := classify(lines, i, strict)
		if !ok || h.Label == "" && other >= maxHints || h.Label != "" && labelled >= maxHints {
			continue
		}
		h.Stream = stream
		h.Line = trimLine(lines[i])
		h.Text = hintText(h.Kind, h.Errno)
		h.Heuristic = true
		dup := false
		for _, o := range hs {
			if o.Stream == h.Stream && o.Line == h.Line {
				dup = true
				break
			}
		}
		if !dup {
			hs = append(hs, h)
			if h.Label != "" {
				labelled++
			} else {
				other++
			}
		}
	}
	return hs
}

// capHints keeps at most maxHints, labelled (canary marker) hints first, in
// their original order.
func capHints(hs []activity.Hint) []activity.Hint {
	if len(hs) <= maxHints {
		return hs
	}
	keep := make([]bool, len(hs))
	n := 0
	for pass := 0; pass < 2; pass++ {
		for i, h := range hs {
			if n < maxHints && !keep[i] && (pass == 1 || h.Label != "") {
				keep[i] = true
				n++
			}
		}
	}
	out := hs[:0:0]
	for i, h := range hs {
		if keep[i] {
			out = append(out, h)
		}
	}
	return out
}

// classify applies the rules to line i, most specific first. It returns
// Kind, Errno and Label only. strict (stdout) accepts, beyond the canary
// marker, only lines carrying an OS error message, and never a comment line:
// a bare EPERM or PermissionError there is as likely source code as an error.
func classify(lines []string, i int, strict bool) (activity.Hint, bool) {
	line := strings.TrimSpace(lines[i])
	if line == "" {
		return activity.Hint{}, false
	}
	// The canary probes' marker: "<label>: DENIED(<errno>)".
	if label, errno, ok := canaryMarker(line); ok {
		return activity.Hint{Kind: labelKind(label), Errno: errno, Label: label}, true
	}
	if strict && (isComment(line) || !containsAny(line, "Operation not permitted", "Network is unreachable",
		"Read-only file system", "No such file or directory", "bad interpreter")) {
		return activity.Hint{}, false
	}
	errno := bracketErrno(line)
	switch {
	case strings.Contains(line, "bad interpreter"):
		return activity.Hint{Kind: activity.HintExec, Errno: errno}, true
	case strings.Contains(line, "Network is unreachable") || errno == 51 || errno == 101 || strings.Contains(line, "ENETUNREACH"):
		if errno != 51 && errno != 101 {
			errno = 101
			if runtime.GOOS == "darwin" {
				errno = 51
			}
		}
		return activity.Hint{Kind: activity.HintNetwork, Errno: errno}, true
	case strings.Contains(line, "Read-only file system") || errno == 30 || strings.Contains(line, "EROFS"):
		return activity.Hint{Kind: activity.HintWrite, Errno: 30}, true
	case strings.Contains(line, "No such file or directory") && namesDenyPath(line):
		return activity.Hint{Kind: activity.HintRead, Errno: 2}, true
	case strings.Contains(line, "Operation not permitted") || errno == 1 || strings.Contains(line, "EPERM") || strings.Contains(line, "PermissionError"):
		if errno == 0 {
			errno = 1
		}
		lo := i - hintLookback
		if lo < 0 {
			lo = 0
		}
		window := strings.Join(lines[lo:i+1], "\n")
		return activity.Hint{Kind: windowKind(window), Errno: errno}, true
	}
	return activity.Hint{}, false
}

// windowKind classifies an EPERM by the matched line and the lines above it.
func windowKind(w string) string {
	switch {
	case containsAny(w, "connect", "socket", "urlopen", "getaddrinfo", "HTTPConnection", "Network"):
		return activity.HintNetwork
	case namesDenyPath(w):
		return activity.HintRead
	case containsAny(w, "subprocess", "posix_spawn", "execve", "exec of"):
		return activity.HintExec
	case containsAny(w, "open", "write", "mkdir", "rename", "unlink", "chmod", "Read-only"):
		return activity.HintWrite
	}
	return activity.HintUnknown
}

// namesDenyPath reports whether s mentions one of the built-in deny paths.
// ".env" counts only as a whole name, so os.environ in a traceback does not.
func namesDenyPath(s string) bool {
	if containsAny(s, ".ssh", ".aws", ".gnupg", ".claude", ".netrc", "gcloud", "docker/config.json") {
		return true
	}
	for i := strings.Index(s, ".env"); i >= 0; {
		end := i + len(".env")
		if end == len(s) || !isIdent(s[end]) {
			return true
		}
		j := strings.Index(s[end:], ".env")
		if j < 0 {
			break
		}
		i = end + j
	}
	return false
}

// isComment reports whether a trimmed line starts like a source comment.
func isComment(line string) bool {
	for _, p := range []string{"#", "//", "/*", "*", "--", ";"} {
		if strings.HasPrefix(line, p) {
			return true
		}
	}
	return false
}

func isIdent(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// canaryMarker parses "<label>: DENIED(<n>)" at the start of a line, label
// made of [a-z0-9-].
func canaryMarker(line string) (label string, errno int, ok bool) {
	i := strings.Index(line, ": DENIED(")
	if i <= 0 {
		return "", 0, false
	}
	label = line[:i]
	for _, c := range label {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return "", 0, false
		}
	}
	rest := line[i+len(": DENIED("):]
	j := strings.IndexByte(rest, ')')
	if j < 0 {
		return "", 0, false
	}
	n, err := strconv.Atoi(rest[:j])
	if err != nil {
		return "", 0, false
	}
	return label, n, true
}

func labelKind(label string) string {
	switch {
	case label == "net" || label == "localhost":
		return activity.HintNetwork
	case strings.HasPrefix(label, "write-"):
		return activity.HintWrite
	case strings.HasPrefix(label, "read-"):
		return activity.HintRead
	case label == "subprocess":
		return activity.HintExec
	}
	return activity.HintUnknown
}

// bracketErrno reads Python's "[Errno N]"; 0 when absent.
func bracketErrno(line string) int {
	i := strings.Index(line, "[Errno ")
	if i < 0 {
		return 0
	}
	rest := line[i+len("[Errno "):]
	j := strings.IndexByte(rest, ']')
	if j < 0 {
		return 0
	}
	n, err := strconv.Atoi(rest[:j])
	if err != nil {
		return 0
	}
	return n
}

func errnoName(n int) string {
	switch n {
	case 1:
		return "EPERM"
	case 2:
		return "ENOENT"
	case 13:
		return "EACCES"
	case 30:
		return "EROFS"
	case 51, 101:
		return "ENETUNREACH"
	}
	return "errno " + strconv.Itoa(n)
}

// hintText is the one sentence the dashboard and the in-session mod print.
func hintText(kind string, errno int) string {
	switch kind {
	case activity.HintNetwork:
		if errno == 51 || errno == 101 {
			return "network access refused by the OS (ENETUNREACH, no network namespace)"
		}
		return "network access refused by the OS (" + errnoName(orEPERM(errno)) + ")"
	case activity.HintWrite:
		if errno == 30 {
			return "write outside the allowed paths refused (EROFS, read-only bind)"
		}
		return "write outside the allowed paths refused (" + errnoName(orEPERM(errno)) + ")"
	case activity.HintRead:
		if errno == 2 {
			return "read of a protected path refused (hidden by the sandbox, ENOENT)"
		}
		return "read of a protected path refused (" + errnoName(orEPERM(errno)) + ")"
	case activity.HintExec:
		if errno == 0 {
			return "program not on the exec allow-list (bad interpreter / exit 126)"
		}
		return "program not on the exec allow-list (" + errnoName(errno) + ")"
	}
	return "operation not permitted by the sandbox (" + errnoName(orEPERM(errno)) + ")"
}

func orEPERM(n int) int {
	if n == 0 {
		return 1
	}
	return n
}

// trimLine trims space and cuts to maxHintLine bytes on a rune boundary.
func trimLine(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxHintLine {
		return s
	}
	cut := maxHintLine
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
