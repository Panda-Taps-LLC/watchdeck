package activity

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"
)

// ReadOptions selects what Read returns.
type ReadOptions struct {
	After     int64     // byte offset in the current file; 0 = from the start (then the rotated .1 file is included first)
	Limit     int       // 0 = all; records are returned oldest first. On Reset it keeps the newest Limit instead, like Tail
	Tail      int       // only with After == 0: return the newest N records instead (page first load); Next is at EOF
	Kinds     []string  // nil = all
	SessionID string    // "" = all; applied after Join so write-time or reader-joined runs match too
	Since     time.Time // zero = all; records with ts >= Since
}

// Result is what Read returns.
type Result struct {
	Records []Record
	// Next is the offset after the last complete line read from the current
	// file; pass it back as After. With Limit it is the offset after the last
	// record returned when that record came from the current file, and 0 when
	// the limit cut inside the rotated file's records. On Reset it is always
	// the end of the current file (0 when it is absent).
	Next int64
	// Reset is true when the current file is shorter than After (rotated or
	// truncated). The records are then the newest ones (at most Limit) from
	// the rotated file and the current one, as a Tail read would return, and
	// Next is at the current file's end, so a reader that drops what it held
	// and continues from Next sees neither the oldest records nor duplicates.
	Reset bool
	// Skipped counts unparseable lines (torn writes) that were passed over.
	Skipped int
}

type item struct {
	rec Record
	rot bool  // from <path>.1
	end int64 // offset after the line, in its own file
}

// Read returns the records at or after o.After in the current file, joined
// (see Join) and filtered. Records from <path>.1 carry Offset relative to that
// file and are returned only when After == 0 (or on Reset). A torn last line
// is skipped and Next stops before it, so the next poll re-reads it whole. An
// absent file, or path == "", yields an empty Result and no error.
func Read(path string, o ReadOptions) (Result, error) {
	var res Result
	if path == "" {
		return res, nil
	}
	after := o.After
	if after < 0 {
		after = 0
	}
	var items []item
	cur, err := os.Open(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// Between a rotation and the next append only .1 exists.
		if after > 0 {
			res.Reset = true
			after = 0
		}
	case err != nil:
		return res, err
	default:
		defer cur.Close()
		fi, err := cur.Stat()
		if err != nil {
			return res, err
		}
		if after > fi.Size() {
			res.Reset = true
			after = 0
		}
	}
	if after == 0 {
		rot, skipped := readRotated(path + ".1")
		items = append(items, rot...)
		res.Skipped += skipped
	}
	res.Next = after
	if cur != nil {
		if _, err := cur.Seek(after, io.SeekStart); err != nil {
			return res, err
		}
		recs, next, skipped := scan(cur, after, true)
		res.Skipped += skipped
		res.Next = next
		for _, r := range recs {
			items = append(items, item{rec: r.rec, end: r.end})
		}
	}

	recs := make([]Record, len(items))
	for i := range items {
		recs[i] = items[i].rec
	}
	Join(recs)

	var kinds map[string]bool
	if o.Kinds != nil {
		kinds = make(map[string]bool, len(o.Kinds))
		for _, k := range o.Kinds {
			kinds[k] = true
		}
	}
	keep := items[:0]
	for i, it := range items {
		r := recs[i]
		if kinds != nil && !kinds[r.Kind] {
			continue
		}
		if o.SessionID != "" && r.SessionID != o.SessionID {
			continue
		}
		if !o.Since.IsZero() {
			if t, ok := parseTS(r.TS); ok && t.Before(o.Since) {
				continue
			}
		}
		it.rec = r
		keep = append(keep, it)
	}
	items = keep

	switch {
	case res.Reset:
		if o.Limit > 0 && len(items) > o.Limit {
			items = items[len(items)-o.Limit:]
		}
	case o.Tail > 0 && o.After <= 0:
		if len(items) > o.Tail {
			items = items[len(items)-o.Tail:]
		}
	case o.Limit > 0 && len(items) > o.Limit:
		items = items[:o.Limit]
		last := items[len(items)-1]
		if last.rot {
			res.Next = 0
		} else {
			res.Next = last.end
		}
	}
	res.Records = make([]Record, len(items))
	for i := range items {
		res.Records[i] = items[i].rec
	}
	return res, nil
}

// readRotated reads every parseable record of a rotated file; a torn last
// line there will never be completed and counts as skipped.
func readRotated(path string) ([]item, int) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0
	}
	defer f.Close()
	recs, _, skipped := scan(f, 0, false)
	items := make([]item, len(recs))
	for i, r := range recs {
		items[i] = item{rec: r.rec, rot: true, end: r.end}
	}
	return items, skipped
}

type scanned struct {
	rec Record
	end int64
}

// scan parses lines from r, which is positioned at offset start. It returns
// the records, the offset after the last complete line, and the number of
// unparseable complete lines. A final line without a newline is torn: when
// keepTorn is true it is left for the next poll (not counted), otherwise it
// counts as skipped.
func scan(r io.Reader, start int64, keepTorn bool) ([]scanned, int64, int) {
	br := bufio.NewReaderSize(r, 64<<10)
	var out []scanned
	skipped := 0
	pos := start
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			if err == io.EOF && len(line) > 0 && !keepTorn {
				skipped++
			}
			break
		}
		next := pos + int64(len(line))
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 {
			var rec Record
			if json.Unmarshal(trimmed, &rec) == nil && rec.Kind != "" {
				rec.Harness = DefaultHarness(rec.Harness)
				rec.Offset = pos
				out = append(out, scanned{rec: rec, end: next})
			} else {
				skipped++
			}
		}
		pos = next
	}
	return out, pos, skipped
}

// ReadFrom returns the records after byte offset in the current file,
// joined within what it read: Read(path, ReadOptions{After: offset}). It is
// how a poller (the dashboard's session catalog, M5.5) reads only what was
// appended since its last call: pass Result.Next back as the next offset. On
// Result.Reset (the file was rotated or truncated) the records are the whole
// rotated file plus the current one, so a caller that counts must drop its
// counts and recount from them. Offset 0 reads <path>.1 first.
//
// Join is per call: a run read in a later call than its decision is matched
// to it only when it was joined at write time (joined_by "write"), which
// carries the session id and tool_use_id on the run itself.
func ReadFrom(path string, offset int64) (Result, error) {
	return Read(path, ReadOptions{After: offset})
}
