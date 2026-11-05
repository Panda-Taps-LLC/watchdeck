package sessionindex

import (
	"bytes"
	"context"
	"io"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Panda-Taps-LLC/watchdeck/internal/transcript"
)

const (
	// DefaultSearchLimit is the hit count Search returns when limit <= 0.
	DefaultSearchLimit = 50
	// SnippetLen is the longest snippet, in bytes.
	SnippetLen = 240

	searchChunk   = 1 << 20
	snippetBefore = 100
	maxWorkers    = 8
)

// Hit is the first match of a query in one session's text.
type Hit struct {
	SessionID string `json:"session_id"`
	Snippet   string `json:"snippet"` // at most SnippetLen bytes around the match, newlines as spaces
	Offset    int64  `json:"offset"`  // byte offset of the match in the session's text file
}

// matcher finds q in a window: ASCII queries by a byte-wise ASCII fold and
// bytes.Index, others with a (?i) regexp compiled per search (RE2, linear).
type matcher struct {
	q    []byte         // lowered, ASCII path
	re   *regexp.Regexp // non-ASCII path
	span int            // longest match in bytes, for the chunk overlap
}

func newMatcher(q string) (*matcher, error) {
	ascii := true
	for i := 0; i < len(q); i++ {
		if q[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return &matcher{q: lowerASCII(nil, []byte(q)), span: len(q)}, nil
	}
	re, err := regexp.Compile("(?i)" + regexp.QuoteMeta(q))
	if err != nil {
		return nil, err
	}
	return &matcher{re: re, span: 4 * len(q)}, nil
}

// find returns the start and end of the first match in w at or after from.
func (m *matcher) find(w, low []byte, from int) (int, int, []byte) {
	if m.re != nil {
		loc := m.re.FindIndex(w[from:])
		if loc == nil {
			return -1, -1, low
		}
		return from + loc[0], from + loc[1], low
	}
	low = lowerASCII(low[:0], w)
	i := bytes.Index(low[from:], m.q)
	if i < 0 {
		return -1, -1, low
	}
	return from + i, from + i + len(m.q), low
}

func lowerASCII(dst, src []byte) []byte {
	if cap(dst) < len(src) {
		dst = make([]byte, len(src))
	}
	dst = dst[:len(src)]
	for i, c := range src {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst[i] = c
	}
	return dst
}

// Search finds q (case-insensitive substring) in every session's text and
// returns at most limit hits, one per session, newest session first. It is
// a bounded parallel scan: at most 8 workers, each reading its file in 1 MiB
// chunks. An empty query returns nothing; NoTranscripts returns ErrDisabled.
func (ix *Index) Search(q string, limit int) ([]Hit, error) {
	return ix.SearchContext(context.Background(), q, limit)
}

// SearchContext is Search that stops when ctx is done: no new session is
// dispatched, each worker checks ctx between files and between chunks, and
// the answer is ctx.Err() with no hits. The dashboard passes the request's
// context, so a search the page aborts (a newer keystroke) stops reading.
func (ix *Index) SearchContext(ctx context.Context, q string, limit int) ([]Hit, error) {
	if ix.o.NoTranscripts {
		return nil, ErrDisabled
	}
	q = strings.TrimSpace(q)
	if q == "" {
		return nil, nil
	}
	if limit <= 0 {
		limit = DefaultSearchLimit
	}
	m, err := newMatcher(q)
	if err != nil {
		return nil, err
	}
	entries := ix.Entries()
	workers := runtime.GOMAXPROCS(0)
	if workers > maxWorkers {
		workers = maxWorkers
	}
	if workers > len(entries) {
		workers = len(entries)
	}
	type result struct {
		order int
		hit   Hit
	}
	var (
		mu    sync.Mutex
		found []result
		nhit  atomic.Int64
		wg    sync.WaitGroup
		jobs  = make(chan int)
	)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sc := &scanner{m: m, ctx: ctx}
			for i := range jobs {
				if ctx.Err() != nil {
					continue // drain
				}
				id := entries[i].ID
				if !transcript.ValidID(id) {
					continue
				}
				if h, ok := sc.scan(ix.textPath(id)); ok {
					h.SessionID = id
					mu.Lock()
					found = append(found, result{i, h})
					mu.Unlock()
					nhit.Add(1)
				}
			}
		}()
	}
	// Sessions are dispatched in order; once limit hits are in, every
	// undispatched session is older than all of them, so stopping is exact.
	for i := range entries {
		if nhit.Load() >= int64(limit) || ctx.Err() != nil {
			break
		}
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sort.Slice(found, func(i, j int) bool { return found[i].order < found[j].order })
	if len(found) > limit {
		found = found[:limit]
	}
	out := make([]Hit, len(found))
	for i, r := range found {
		out[i] = r.hit
	}
	return out, nil
}

// scanner holds one worker's buffers.
type scanner struct {
	ctx context.Context // nil: never cancelled
	m   *matcher
	buf []byte
	low []byte
}

// scan returns the first match in the file at path.
func (sc *scanner) scan(path string) (Hit, bool) {
	f, err := os.Open(path)
	if err != nil {
		return Hit{}, false
	}
	defer f.Close()
	chunk := searchChunk
	if st, err := f.Stat(); err == nil && st.Size() < int64(chunk) {
		chunk = int(st.Size()) + 1 // a small file is read in one call that sees EOF
	}
	keep := sc.m.span - 1 + snippetBefore
	if cap(sc.buf) < chunk+keep+SnippetLen {
		sc.buf = make([]byte, 0, chunk+keep+SnippetLen)
	}
	w := sc.buf[:0]
	var base int64 // file offset of w[0]
	carried := 0   // bytes at the start of w kept from the previous window
	for {
		if sc.ctx != nil && sc.ctx.Err() != nil {
			return Hit{}, false
		}
		n, rerr := io.ReadFull(f, w[len(w):len(w)+chunk])
		w = w[:len(w)+n]
		from := carried - (sc.m.span - 1)
		if from < 0 {
			from = 0
		}
		if len(w) > from {
			var s, e int
			s, e, sc.low = sc.m.find(w, sc.low, from)
			if s >= 0 {
				if len(w)-e < SnippetLen && rerr == nil {
					// read a little more so the snippet can extend past the chunk
					m, _ := io.ReadFull(f, w[len(w):len(w)+SnippetLen])
					w = w[:len(w)+m]
				}
				return Hit{Snippet: snippet(w, s, e), Offset: base + int64(s)}, true
			}
		}
		if rerr != nil { // io.EOF or io.ErrUnexpectedEOF: the file is done
			return Hit{}, false
		}
		if len(w) > keep {
			drop := len(w) - keep
			copy(w, w[drop:])
			w = w[:keep]
			base += int64(drop)
		}
		carried = len(w)
	}
}

// snippet returns at most SnippetLen bytes of w around [s,e), cut on rune
// boundaries, with newlines as spaces and invalid UTF-8 replaced.
func snippet(w []byte, s, e int) string {
	start := s - snippetBefore
	if start < 0 {
		start = 0
	}
	end := start + SnippetLen
	if end > len(w) {
		end = len(w)
	}
	if e > end { // a match longer than the window after start
		start = e - SnippetLen
		if start < 0 {
			start = 0
		}
		end = e
	}
	for start < end && start > 0 && !isRuneStart(w[start]) {
		start++
	}
	for end > start && end < len(w) && !isRuneStart(w[end]) {
		end--
	}
	out := strings.ToValidUTF8(string(w[start:end]), "�")
	out = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, out)
	return cutRunes(out, SnippetLen)
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }
