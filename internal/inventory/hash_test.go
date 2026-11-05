package inventory

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// nodePort is a faithful port of computeSkillFolderHash from
// vercel-labs/skills src/local-lock.ts, with the sort comparator selectable:
// "locale" is the upstream localeCompare sort, "byte" is a code-unit sort
// (identical to Go's byte order for ASCII paths).
const nodePort = `
const { createHash } = require('crypto');
const fs = require('fs');
const path = require('path');
function collectFiles(baseDir, currentDir, results) {
  for (const entry of fs.readdirSync(currentDir, { withFileTypes: true })) {
    const fullPath = path.join(currentDir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === '.git' || entry.name === 'node_modules') continue;
      collectFiles(baseDir, fullPath, results);
    } else if (entry.isFile()) {
      results.push({
        relativePath: path.relative(baseDir, fullPath).split('\\').join('/'),
        content: fs.readFileSync(fullPath),
      });
    }
  }
}
function computeSkillFolderHash(skillDir, mode) {
  const files = [];
  collectFiles(skillDir, skillDir, files);
  if (mode === 'locale') {
    files.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
  } else {
    files.sort((a, b) => (a.relativePath < b.relativePath ? -1 : a.relativePath > b.relativePath ? 1 : 0));
  }
  const hash = createHash('sha256');
  for (const file of files) {
    hash.update(file.relativePath);
    hash.update(file.content);
  }
  return hash.digest('hex');
}
const [dir, mode] = process.argv.slice(-2);
process.stdout.write(computeSkillFolderHash(dir, mode));
`

func nodeHash(t *testing.T, node, dir, mode string) string {
	t.Helper()
	out, err := exec.Command(node, "-e", nodePort, "--", dir, mode).Output()
	if err != nil {
		t.Fatalf("node port failed: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func TestHashDeterministicAndSkips(t *testing.T) {
	h1, err := Hash("testdata/hash-lower")
	if err != nil {
		t.Fatal(err)
	}
	if len(h1) != 64 {
		t.Fatalf("hash %q is not a hex sha256", h1)
	}
	h2, err := Hash("testdata/hash-lower")
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("not deterministic: %s vs %s", h1, h2)
	}

	// A copy with .git, node_modules and a symlink added hashes the same.
	cp := copyTree(t, "testdata/hash-lower")
	mustWrite(t, filepath.Join(cp, ".git", "HEAD"), "ref: refs/heads/main\n")
	mustWrite(t, filepath.Join(cp, "node_modules", "dep", "index.js"), "module.exports = 1\n")
	if err := os.Symlink(filepath.Join(cp, "a.md"), filepath.Join(cp, "link.md")); err != nil {
		t.Fatal(err)
	}
	h3, err := Hash(cp)
	if err != nil {
		t.Fatal(err)
	}
	if h3 != h1 {
		t.Fatalf(".git/node_modules/symlink changed the hash: %s vs %s", h3, h1)
	}

	// Other dotfiles, lockfiles and nested dirs DO count (vercel skips only
	// .git and node_modules).
	cp2 := copyTree(t, "testdata/hash-lower")
	mustWrite(t, filepath.Join(cp2, "uv.lock"), "lock\n")
	h4, err := Hash(cp2)
	if err != nil {
		t.Fatal(err)
	}
	if h4 == h1 {
		t.Fatal("adding uv.lock did not change the hash")
	}

	// Content changes are detected.
	cp3 := copyTree(t, "testdata/hash-lower")
	mustWrite(t, filepath.Join(cp3, "a.md"), "alpha changed\n")
	h5, err := Hash(cp3)
	if err != nil {
		t.Fatal(err)
	}
	if h5 == h1 {
		t.Fatal("content change did not change the hash")
	}

	// A symlinked root works.
	link := filepath.Join(t.TempDir(), "linked")
	abs, _ := filepath.Abs("testdata/hash-lower")
	if err := os.Symlink(abs, link); err != nil {
		t.Fatal(err)
	}
	h6, err := Hash(link)
	if err != nil {
		t.Fatal(err)
	}
	if h6 != h1 {
		t.Fatalf("symlinked root hash differs: %s vs %s", h6, h1)
	}
}

func TestHashErrors(t *testing.T) {
	if _, err := Hash(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing root accepted")
	}
	f := filepath.Join(t.TempDir(), "f")
	mustWrite(t, f, "x")
	if _, err := Hash(f); err == nil {
		t.Fatal("file root accepted")
	}
}

// TestHashMatchesNodeLowercase: on an all-lowercase-ASCII tree the Go hash
// equals the upstream (localeCompare) hash byte for byte.
func TestHashMatchesNodeLowercase(t *testing.T) {
	node := requireNode(t)
	want := nodeHash(t, node, "testdata/hash-lower", "locale")
	got, err := Hash("testdata/hash-lower")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("Go hash %s != node localeCompare hash %s on lowercase fixture", got, want)
	}
}

// TestHashMixedCaseDivergence documents the known divergence from
// vercel-labs/skills on the canonical skill layout (SKILL.md + scripts/).
//
// Upstream sorts relative paths with String.prototype.localeCompare, which
// under ICU compares letters case-insensitively at primary strength, so
// "scripts/x.py" sorts BEFORE "SKILL.md" ('c' < 'k'). Go's byte order puts
// "SKILL.md" first ('S' 0x53 < 's' 0x73). Same files, different feed order,
// different digest. Two assertions:
//
//  1. The node port with a code-unit (byte-order) comparator equals Hash, so
//     the per-file feed (relpath then content, sha256, hex) is ported
//     faithfully even on mixed case.
//  2. The node port with localeCompare differs from Hash whenever node's ICU
//     orders the two paths differently from byte order. If a node build ever
//     sorted them identically (no full ICU), both values are logged and the
//     test does not fail, because then there is no divergence to document.
func TestHashMixedCaseDivergence(t *testing.T) {
	node := requireNode(t)
	got, err := Hash("testdata/hash-mixed")
	if err != nil {
		t.Fatal(err)
	}
	byteOrder := nodeHash(t, node, "testdata/hash-mixed", "byte")
	if got != byteOrder {
		t.Fatalf("Go hash %s != node byte-order hash %s: port is not faithful", got, byteOrder)
	}
	locale := nodeHash(t, node, "testdata/hash-mixed", "locale")
	t.Logf("hash-mixed: go/byte-order=%s node/localeCompare=%s", got, locale)

	// Does this node's localeCompare actually reorder the fixture paths?
	out, err := exec.Command(node, "-e", `process.stdout.write(String("scripts/x.py".localeCompare("SKILL.md")))`).Output()
	if err != nil {
		t.Fatal(err)
	}
	reorders := strings.TrimSpace(string(out)) == "-1"
	switch {
	case reorders && locale == got:
		t.Fatalf("node localeCompare reorders the paths yet the hashes agree: %s", got)
	case reorders:
		t.Logf("divergence confirmed: upstream lock hash for a SKILL.md + scripts/ tree differs from Hash")
	default:
		t.Logf("this node build does not reorder SKILL.md vs scripts/ (no full ICU?); divergence not reproducible here")
	}
}

func requireNode(t *testing.T) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not on PATH; skipping cross-check against the vercel-labs/skills port")
	}
	return node
}

func copyTree(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func mustWrite(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
