package runner

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Panda-Taps-LLC/watchdeck/internal/manifest"
)

// TestToResolvedDropsCaseVariants: on every OS, a write entry that is a case
// variant of a built-in deny path (~/.SSH, ~/.Ssh/x, an absolute <home>/.AWS)
// or whose last element is a case variant of a deny name (.ENV) is dropped
// and warned about. Ordinary entries, including look-alikes such as .envrc
// and .sshx, are kept. Nothing is created on disk.
func TestToResolvedDropsCaseVariants(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir()) // /var → /private/var on macOS
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	cwd := filepath.Join(root, "proj")
	tmp := filepath.Join(root, "tmp")
	eff := manifest.Default()
	eff.Write = append(eff.Write, "~/.SSH", "~/.Ssh/x", home+"/.AWS/config", "${CWD}/.ENV", "${CWD}/sub/.Env",
		"~/.ſſh", "~/.ſsh/x", "~/.awſ", "~/.doc\u212Aer/config.json",
		"${CWD}/out", "${CWD}/.envrc", "~/.sshx", "~/proj/.env-example")
	res, dropped, droppedWrites, err := toResolved(eff, nil, home, cwd, tmp, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"~/.SSH", "~/.Ssh/x", home + "/.AWS/config", "${CWD}/.ENV", "${CWD}/sub/.Env",
		"~/.ſſh", "~/.ſsh/x", "~/.awſ", "~/.doc\u212Aer/config.json"}
	if strings.Join(droppedWrites, "|") != strings.Join(want, "|") {
		t.Fatalf("droppedWrites = %q, want %q", droppedWrites, want)
	}
	for i, w := range want {
		if msg := "write " + w + " ignored: under a protected path"; dropped[i] != msg {
			t.Errorf("dropped[%d] = %q, want %q", i, dropped[i], msg)
		}
	}
	for _, keep := range []string{cwd + "/out", cwd + "/.envrc", home + "/.sshx", home + "/proj/.env-example"} {
		found := false
		for _, w := range res.Write {
			if w == keep {
				found = true
			}
		}
		if !found {
			t.Errorf("res.Write lacks %q: %q", keep, res.Write)
		}
	}
	for _, w := range res.Write {
		l := strings.ToLower(w)
		if strings.HasPrefix(l, strings.ToLower(home)+"/.ssh/") || l == strings.ToLower(home)+"/.ssh" || strings.HasSuffix(l, "/.env") {
			t.Errorf("protected path kept as a write allow: %q", w)
		}
	}
}
