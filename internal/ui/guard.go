package ui

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/Panda-Taps-LLC/watchdeck/internal/uiproof"
)

// CSP is the Content-Security-Policy sent on every response. style-src and
// script-src 'self' forbid inline styles, inline scripts and on* handlers;
// the static pages are written for that (static_test.go guards it). No
// font-src: the pages use the system fonts and load no font file.
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// securityHeaders go on every response, rejections included. A slice of
// constant pairs, not a map: no init work.
var securityHeaders = [...][2]string{
	{"Content-Security-Policy", CSP},
	{"X-Content-Type-Options", "nosniff"},
	{"Referrer-Policy", "no-referrer"},
	{"Cache-Control", "no-store"},
	{"X-Frame-Options", "DENY"},
	{"Cross-Origin-Opener-Policy", "same-origin"},
	{"Cross-Origin-Resource-Policy", "same-origin"},
}

// guard runs every request through, in this order:
//  1. security headers on the response;
//  2. Host must be 127.0.0.1:<port> or localhost:<port> (403; stops DNS
//     rebinding, since an attacker's hostname fails here);
//  3. outside /api/ only GET and HEAD exist (405 with Allow: GET, HEAD;
//     this also answers "OPTIONS *");
//  4. methods other than GET/HEAD: Origin must equal "http://"+Host (absent
//     403), Sec-Fetch-Site when present must be same-origin or none (403),
//     the media type must be application/json, parameters allowed (415),
//     the body is capped at 1 MiB (413);
//  5. /api/ paths need "Authorization: Bearer <token>", compared in
//     constant time (401). Static files need none: nothing in them is
//     sensitive and the token lives in the URL fragment, never sent;
//  6. only an authenticated /api/ request has side effects: an unsafe
//     method drops the /api/skills cache, and every one touches the idle
//     clock (static and refused requests never keep the server alive; an
//     open page polls /api/ and does).
//
// The guard never reads request headers beyond these, never rewrites a
// handler's response (a handler's 304 and ETag pass through) and logs
// nothing.
func (s *Server) guard(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	for _, kv := range securityHeaders {
		h.Set(kv[0], kv[1])
	}

	port := s.port.Load()
	if port == 0 || !hostAllowed(r.Host, strconv.Itoa(int(port))) {
		writeError(w, http.StatusForbidden, "forbidden host")
		return
	}

	unsafe := r.Method != http.MethodGet && r.Method != http.MethodHead
	api := strings.HasPrefix(r.URL.Path, apiPrefix)
	if unsafe && !api {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if unsafe {
		if origin := r.Header.Get("Origin"); origin == "" || origin != "http://"+r.Host {
			writeError(w, http.StatusForbidden, "cross-origin request refused")
			return
		}
		if site := r.Header.Values("Sec-Fetch-Site"); len(site) > 0 && site[0] != "same-origin" && site[0] != "none" {
			writeError(w, http.StatusForbidden, "cross-site request refused")
			return
		}
		ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
		if !strings.EqualFold(strings.TrimSpace(ct), "application/json") {
			writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
			return
		}
		if r.ContentLength > maxBodyBytes {
			writeError(w, http.StatusRequestEntityTooLarge, "request body over 1 MiB")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	}

	if !api {
		s.serveStatic(w, r)
		return
	}
	if !s.authorized(r.Header.Get("Authorization")) {
		// Proof of identity for health probes (uiproof): an unauthenticated
		// GET /api/status with a well-formed challenge gets
		// HMAC(token, challenge) on its 401, so a client can tell this
		// dashboard from a look-alike before it sends the bearer. It reveals
		// nothing about the token and has no side effect.
		if r.Method == http.MethodGet && r.URL.Path == "/api/status" {
			if c := r.Header.Get(uiproof.ChallengeHeader); uiproof.ValidChallenge(c) {
				if tok := s.Token(); tok != "" {
					w.Header().Set(uiproof.ProofHeader, uiproof.Proof(tok, int(s.port.Load()), c))
				}
			}
		}
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	// Side effects only after the token check: any local process can
	// forge Origin, so an unauthenticated request must neither force
	// audit rebuilds nor keep an idle server alive.
	if unsafe {
		s.invalidateSkills()
	}
	s.touch()
	s.api.ServeHTTP(w, r)
}

// hostAllowed reports whether host is exactly 127.0.0.1:<port> or
// localhost:<port>.
func hostAllowed(host, port string) bool {
	return host == "127.0.0.1:"+port || host == "localhost:"+port
}

// authorized checks "Bearer <token>" with a constant-time compare.
func (s *Server) authorized(header string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	want := s.Token()
	if want == "" {
		return false // a token source that cannot read the token refuses everything
	}
	return subtle.ConstantTimeCompare([]byte(header[len(prefix):]), []byte(want)) == 1
}

// staticFiles serves the embedded static/ tree.
type staticFiles struct{ fsys fs.FS }

func newStaticFiles() (*staticFiles, error) {
	sub, err := fs.Sub(StaticFS, "static")
	if err != nil {
		return nil, err
	}
	return &staticFiles{fsys: sub}, nil
}

// serveStatic answers GET/HEAD for embedded files with an explicit
// Content-Type (no package mime, no http.FileServer: no sniffing, no
// directory listings, no redirects). "/" is index.html.
func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	name := "index.html"
	if r.URL.Path != "/" {
		name = strings.TrimPrefix(r.URL.Path, "/")
		if path.Clean("/"+name) != "/"+name || !fs.ValidPath(name) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
	}
	b, err := fs.ReadFile(s.files.fsys, name)
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Content-Type", ContentType(name))
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(b)
	}
}

// writeJSON writes v as JSON with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		status, b = http.StatusInternalServerError, []byte(`{"error":"encoding the response failed"}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	w.Write(append(b, '\n'))
}

// writeError writes {"error": msg}, the error body everywhere.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// readJSON decodes one JSON value from the (guard-capped) body into v,
// refusing unknown fields and trailing data. On failure it has already
// written 413 (body over the cap) or 400 and returns false.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil {
		if _, terr := dec.Token(); terr != io.EOF {
			err = terr // a MaxBytesError past the first value lands here
			if err == nil {
				err = errors.New("unexpected data after the JSON value")
			}
		}
	}
	if err == nil {
		return true
	}
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		writeError(w, http.StatusRequestEntityTooLarge, "request body over 1 MiB")
		return false
	}
	if errors.Is(err, io.EOF) {
		err = errors.New("empty body")
	}
	writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
	return false
}
