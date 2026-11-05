package activity

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
)

// TailWindow is how many bytes from the end of a file LastOfKind reads. A
// variable so tests can lower it.
var TailWindow int64 = 64 << 10

// LastOfKind returns the newest complete record of the given kind in the last
// TailWindow bytes of the current file. Only when that window covered the
// whole current file (it is small, or absent: just rotated) and held no such
// record does it read the last TailWindow bytes of <path>.1; a record beyond
// the window of a larger current file is reported as absent (ok == false),
// never replaced by an older one from <path>.1. It never reads a whole file.
// A torn last line is ignored. An absent file, or path == "", is
// (Record{}, false, nil). Offset is not set.
func LastOfKind(path, kind string) (Record, bool, error) {
	if path == "" {
		return Record{}, false, nil
	}
	r, ok, whole, err := lastOfKind(path, kind)
	if ok || err != nil || !whole {
		return r, ok, err
	}
	r, ok, _, err = lastOfKind(path+".1", kind)
	return r, ok, err
}

// lastOfKind scans one file's tail; whole reports that the window covered
// the entire file (true for an absent file).
func lastOfKind(path, kind string) (Record, bool, bool, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, false, true, nil
	}
	if err != nil {
		return Record{}, false, false, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return Record{}, false, false, err
	}
	r, found, err := scanTail(f, fi.Size(), kind)
	return r, found, fi.Size() <= TailWindow, err
}

// scanTail returns the newest record of kind in the last TailWindow bytes of
// f, whose size is size.
func scanTail(f *os.File, size int64, kind string) (Record, bool, error) {
	start := size - TailWindow
	if start < 0 {
		start = 0
	}
	buf := make([]byte, size-start)
	if _, err := f.ReadAt(buf, start); err != nil && !errors.Is(err, io.EOF) {
		return Record{}, false, err
	}
	// Drop a torn last line, and a partial first line when the window
	// starts mid-file.
	i := bytes.LastIndexByte(buf, '\n')
	if i < 0 {
		return Record{}, false, nil
	}
	buf = buf[:i]
	if start > 0 {
		j := bytes.IndexByte(buf, '\n')
		if j < 0 {
			return Record{}, false, nil
		}
		buf = buf[j+1:]
	}
	needle := []byte(`"` + kind + `"`)
	for len(buf) > 0 {
		line := buf
		if k := bytes.LastIndexByte(buf, '\n'); k >= 0 {
			line, buf = buf[k+1:], buf[:k]
		} else {
			buf = nil
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 || !bytes.Contains(line, needle) {
			continue
		}
		var rec Record
		if json.Unmarshal(line, &rec) == nil && rec.Kind == kind {
			rec.Harness = DefaultHarness(rec.Harness)
			return rec, true, nil
		}
	}
	return Record{}, false, nil
}
