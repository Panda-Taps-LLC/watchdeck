package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// hashSkipDir mirrors vercel-labs/skills: only these two directory names are
// skipped, everything else (lockfiles, images, dotfiles) is hashed.
func hashSkipDir(name string) bool { return name == ".git" || name == "node_modules" }

// Hash computes the vercel-labs/skills folder hash of root: every regular file
// below root except under `.git` and `node_modules`, relative paths sorted in
// byte order, one SHA-256 over `relpath` then `content` for each file, hex
// encoded. root may be a symlink. Symlinks inside the tree are ignored, as
// they are by the reference implementation's isFile()/isDirectory() checks.
//
// Caveat: the reference sorts with JavaScript localeCompare, so this value
// equals the vercel lock hash only for all-lowercase-ASCII trees. It is still
// a stable content fingerprint for change detection.
func Hash(root string) (string, error) {
	real, err := realDir(root)
	if err != nil {
		return "", err
	}
	var files []string
	err = filepath.WalkDir(real, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if p != real && hashSkipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(real, p)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("inventory: hash: %w", err)
	}
	sort.Strings(files)
	h := sha256.New()
	for _, rel := range files {
		if err := hashFile(h, rel, filepath.Join(real, filepath.FromSlash(rel))); err != nil {
			return "", fmt.Errorf("inventory: hash: %w", err)
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashFile(h io.Writer, rel, p string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.WriteString(h, rel); err != nil {
		return err
	}
	_, err = io.Copy(h, f)
	return err
}
