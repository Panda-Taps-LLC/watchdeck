// Package settings edits Claude Code settings.json files for `watchdeck enforce`.
//
// Files are parsed into an order-preserving Object so that a round trip
// (install, then uninstall) reproduces the user's file byte for byte when it
// was written with two-space indentation, which is how Claude Code writes it.
package settings

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/safeio"
)

// Object is a JSON object that remembers key order.
type Object struct {
	keys []string
	vals map[string]any
}

// NewObject returns an empty object.
func NewObject() *Object { return &Object{vals: map[string]any{}} }

// Keys returns the keys in document order.
func (o *Object) Keys() []string { return append([]string(nil), o.keys...) }

// Get returns a value and whether it exists.
func (o *Object) Get(k string) (any, bool) {
	v, ok := o.vals[k]
	return v, ok
}

// Set assigns a value, appending the key if it is new.
func (o *Object) Set(k string, v any) {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

// Delete removes a key.
func (o *Object) Delete(k string) {
	if _, ok := o.vals[k]; !ok {
		return
	}
	delete(o.vals, k)
	for i, kk := range o.keys {
		if kk == k {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

// Len returns the number of keys.
func (o *Object) Len() int { return len(o.keys) }

// Object returns the child object at k, creating it when create is true.
func (o *Object) Object(k string, create bool) *Object {
	if v, ok := o.vals[k]; ok {
		if child, ok := v.(*Object); ok {
			return child
		}
		return nil
	}
	if !create {
		return nil
	}
	child := NewObject()
	o.Set(k, child)
	return child
}

// Array returns the child array at k (nil when absent or not an array).
func (o *Object) Array(k string) ([]any, bool) {
	v, ok := o.vals[k]
	if !ok {
		return nil, false
	}
	arr, ok := v.([]any)
	return arr, ok
}

// marshalRaw encodes v without HTML escaping, so "Bash(a && b)" stays as
// written instead of becoming "Bash(a \u0026\u0026 b)". Nested *Object
// values reach their own MarshalJSON and chain the same way.
func marshalRaw(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}

// MarshalJSON writes keys in document order, without HTML escaping.
func (o *Object) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := marshalRaw(k)
		if err != nil {
			return nil, err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := marshalRaw(o.vals[k])
		if err != nil {
			return nil, err
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// UnmarshalJSON parses an object preserving key order. Numbers stay json.Number.
func (o *Object) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return err
	}
	obj, ok := v.(*Object)
	if !ok {
		return fmt.Errorf("settings: expected a JSON object")
	}
	*o = *obj
	return nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := NewObject()
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, ok := kt.(string)
				if !ok {
					return nil, fmt.Errorf("settings: object key is not a string")
				}
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				obj.Set(k, v)
			}
			if _, err := dec.Token(); err != nil { // '}'
				return nil, err
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			if _, err := dec.Token(); err != nil { // ']'
				return nil, err
			}
			return arr, nil
		}
		return nil, fmt.Errorf("settings: unexpected delimiter %v", t)
	default:
		return tok, nil // string, json.Number, bool, nil
	}
}

// Load reads a settings file. A missing file yields an empty object and existed=false.
// The read never blocks and is capped (safeio.ReadRegular): a project's
// .claude/settings.json comes with the repository and may be a FIFO or a
// symlink to /dev/tty or /dev/zero.
func Load(path string) (obj *Object, existed bool, err error) {
	b, err := safeio.ReadRegular(path, safeio.MaxJSON, false)
	if errors.Is(err, fs.ErrNotExist) {
		return NewObject(), false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return NewObject(), true, nil
	}
	obj = NewObject()
	if err := json.Unmarshal(b, obj); err != nil {
		return nil, true, fmt.Errorf("settings: parse %s: %w", path, err)
	}
	return obj, true, nil
}

// Encode renders the object the way Claude Code writes settings: two-space
// indent, trailing newline, and &, < and > kept literal (json.MarshalIndent
// would escape them, so a round trip would change the person's bytes).
func Encode(obj *Object) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(obj); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil // Encoder.Encode already ends with '\n'
}

// backupNow is the clock for backup names; tests pin it.
var backupNow = time.Now

// maxBackupsPerSecond bounds the -2, -3, … suffixes tried for one timestamp.
const maxBackupsPerSecond = 1000

// Save writes obj to path atomically. When backup is true and the file exists,
// a copy is written first to <path>.bak-<unix seconds>, or to
// <path>.bak-<unix seconds>-2, -3, … when that name is taken: an existing
// backup is never overwritten, so an install and an uninstall in the same
// second keep the original bytes. Returns the backup path (or "").
// A symlinked path (a dotfiles setup may link settings.json) is resolved
// first, so the real file is replaced, the backup sits beside it and the
// link survives. Any other path is kept as given.
func Save(path string, obj *Object, backup bool) (string, error) {
	return save(path, obj, backup, false)
}

// SaveSync is Save plus fsync: the backup, the new file and the parent
// directory are synced before it returns, so a crash cannot leave an empty
// or missing settings file. It is for CLI and dashboard writes; the hook
// path keeps Save, which never pays for an fsync.
func SaveSync(path string, obj *Object, backup bool) (string, error) {
	return save(path, obj, backup, true)
}

func save(path string, obj *Object, backup, sync bool) (string, error) {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		if r, err := filepath.EvalSymlinks(path); err == nil {
			path = r
		}
	}
	out, err := Encode(obj)
	if err != nil {
		return "", err
	}
	backupPath := ""
	if backup {
		if orig, err := safeio.ReadRegular(path, safeio.MaxJSON, false); err == nil {
			if backupPath, err = writeBackup(path, orig, sync); err != nil {
				return "", err
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".settings-*.tmp")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	if _, err := io.Copy(tmp, bytes.NewReader(out)); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return "", err
	}
	if sync {
		if err := tmp.Sync(); err != nil {
			tmp.Close()
			os.Remove(tmpName)
			return "", err
		}
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return "", err
	}
	if st, err := os.Stat(path); err == nil {
		_ = os.Chmod(tmpName, st.Mode().Perm())
	} else {
		_ = os.Chmod(tmpName, 0o644)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return "", err
	}
	if sync {
		if err := syncDir(filepath.Dir(path)); err != nil {
			return backupPath, err
		}
	}
	return backupPath, nil
}

// syncDir fsyncs a directory so a rename into it is durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// writeBackup writes data to the first free <path>.bak-<unix seconds>[-N]
// name, created exclusively so that no existing file is replaced.
func writeBackup(path string, data []byte, sync bool) (string, error) {
	base := fmt.Sprintf("%s.bak-%d", path, backupNow().Unix())
	for n := 1; n <= maxBackupsPerSecond; n++ {
		name := base
		if n > 1 {
			name = fmt.Sprintf("%s-%d", base, n)
		}
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			os.Remove(name)
			return "", err
		}
		if sync {
			if err := f.Sync(); err != nil {
				f.Close()
				os.Remove(name)
				return "", err
			}
		}
		if err := f.Close(); err != nil {
			os.Remove(name)
			return "", err
		}
		return name, nil
	}
	return "", fmt.Errorf("settings: no free backup name for %s (%d taken)", base, maxBackupsPerSecond)
}
