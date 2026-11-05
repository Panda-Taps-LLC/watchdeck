package ui

import (
	"net/http"
	"strconv"
	"time"
)

// Event is one server-sent event on GET /api/events (M5.5). Name is the SSE
// event name ("session", "activity", "index"); Data is one line of JSON.
// Events are nudges: the page reacts by refetching through the ordinary
// routes, so a dropped event costs a little latency, never data.
type Event struct {
	Name string
	Data []byte
}

// EventSource feeds GET /api/events. Subscribe returns a channel of events
// and a cancel func that must be called once when the stream ends; after
// cancel the source never sends on the channel again. The session catalog
// (internal/sessionsapi) implements it.
type EventSource interface {
	Subscribe() (<-chan Event, func())
}

// Stream bounds. Init-free constants.
const (
	maxEventStreams   = 8
	eventsKeepalive   = 25 * time.Second
	eventWriteTimeout = 10 * time.Second
	eventsMaxAge      = time.Hour
)

type eventsRouter interface{ eventsRoutes() []route }

func (s *Server) eventsRoutes() []route {
	if s.opts.Events == nil {
		return nil
	}
	return []route{{"GET /api/events", http.HandlerFunc(s.handleEvents)}}
}

// Streams is the number of open GET /api/events streams (tests).
func (s *Server) Streams() int { return int(s.streams.Load()) }

// handleEvents is GET /api/events: text/event-stream, read by the page with
// fetch and a streaming body reader so the token travels in the
// Authorization header like every other API call (EventSource cannot send
// one, and the token is never put in a URL). The guard has already checked
// Host and the bearer before this runs.
//
//   - At most 8 streams are open at once; the 9th gets 429 and the page
//     keeps polling.
//   - A comment line ": keepalive" every 25 s keeps proxies and the browser
//     from timing the stream out, and touches the idle clock, so an open
//     page keeps a manual-mode server alive as polling did.
//   - The server's 60 s write timeout and 30 s read timeout are lifted for
//     the stream; each write gets its own 10 s deadline instead. A client
//     that stops reading is dropped only once the socket buffers between
//     us are full and a write then stalls for 10 s, which can take a long
//     time at a few hundred bytes per event; the lifetime cap below bounds
//     it regardless.
//   - A stream lives at most 1 h (EventsMaxAge); the page reconnects.
//   - The stream ends when the client goes away (request context), when the
//     server shuts down, at the lifetime cap, or on a write error; the
//     subscription is cancelled and the stream count released in every
//     case.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		return
	}
	for {
		n := s.streams.Load()
		if n >= maxEventStreams {
			w.Header().Set("Retry-After", "30")
			writeError(w, http.StatusTooManyRequests, "too many event streams (at most "+strconv.Itoa(maxEventStreams)+"); polling continues")
			return
		}
		if s.streams.CompareAndSwap(n, n+1) {
			break
		}
	}
	defer s.streams.Add(-1)

	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("X-Accel-Buffering", "no")

	ch, cancel := s.opts.Events.Subscribe()
	defer cancel()

	write := func(b []byte) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(eventWriteTimeout))
		if _, err := w.Write(b); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	w.WriteHeader(http.StatusOK)
	keep := s.opts.EventsKeepalive
	if keep <= 0 {
		keep = eventsKeepalive
	}
	if !write([]byte("retry: 5000\nevent: hello\ndata: {\"keepalive_ms\":" + strconv.FormatInt(keep.Milliseconds(), 10) + "}\n\n")) {
		return
	}
	t := time.NewTicker(keep)
	defer t.Stop()
	maxAge := s.opts.EventsMaxAge
	if maxAge <= 0 {
		maxAge = eventsMaxAge
	}
	deadline := time.NewTimer(maxAge)
	defer deadline.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-deadline.C:
			return // the page reconnects
		case <-s.closing:
			return
		case <-s.stop:
			return
		case <-t.C:
			s.touch()
			if !write([]byte(": keepalive\n\n")) {
				return
			}
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if !write(frame(ev)) {
				return
			}
		}
	}
}

// frame encodes one event. Name and Data are produced by the server, never
// by a client; a newline in either is dropped so a frame cannot be split.
func frame(ev Event) []byte {
	b := make([]byte, 0, len(ev.Name)+len(ev.Data)+16)
	b = append(b, "event: "...)
	for i := 0; i < len(ev.Name); i++ {
		if c := ev.Name[i]; c != '\n' && c != '\r' {
			b = append(b, c)
		}
	}
	b = append(b, "\ndata: "...)
	for _, c := range ev.Data {
		if c != '\n' && c != '\r' {
			b = append(b, c)
		}
	}
	return append(b, "\n\n"...)
}
