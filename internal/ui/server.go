package ui

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Panda-Taps-LLC/watchdeck/internal/hook"
	"github.com/Panda-Taps-LLC/watchdeck/internal/paths"
	"github.com/Panda-Taps-LLC/watchdeck/internal/rulebook"
)

// Options configures a Server. Paths, Cwd and Environ are the injected host
// state (tests point them at temp dirs); nothing in this package asks the OS
// for the home directory or the environment.
//
// Cwd is optional (M5.3): a server started in auto or service mode has no
// working directory. Then project-scoped routes (/api/status, /api/skills,
// /api/skills/{name}, the grant route's row, /api/enforce) work in user
// scope only, unless a request names a project with ?project=<abs root>,
// which must be the cwd, its git root or one of ProjectRoots
// (projectscope.Resolve); anything else is 400.
type Options struct {
	Paths   paths.Paths
	Cwd     string
	Environ map[string]string
	Version string
	Binary  string        // absolute self path, for settings.Install (api_enforce.go)
	Idle    time.Duration // 0 = never exit on idle

	// NoTranscripts is reported by /api/status; cmd/watchdeck/ui.go also
	// hands it to Phase B's route constructor.
	NoTranscripts bool

	// Routes adds handlers under /api/ (Phase B). Keys are Go 1.22 mux
	// patterns "METHOD /api/...", e.g. "GET /api/sessions/{id}/map". New
	// rejects a key without a method, a path outside /api/, a nil handler
	// or a pattern that conflicts with another route. Every extra route sits
	// behind the guard (headers, Host, Origin, bearer token).
	Routes map[string]http.Handler

	// Token is the bearer token; "" makes a fresh random one (tests, and
	// every server before M5.3). cmd/watchdeck passes the token kept in
	// <stateDir>/ui.token.
	Token string
	// TokenSource, when set, is asked for the current token on every
	// /api/ request (uistate.TokenWatcher re-reads ui.token when it
	// changes, so `ui --rotate-token` takes effect without a restart). An
	// empty answer refuses every request.
	TokenSource func() string
	// Mode is reported by /api/status: "manual", "auto" or "service".
	Mode string
	// ProjectRoots lists the projects a ?project= value may name, besides
	// Cwd and its git root.
	ProjectRoots func() []string

	// Events, when set, serves GET /api/events (M5.5, api_events.go): an
	// authenticated text/event-stream of session, activity and index
	// nudges. EventsKeepalive is the keepalive period (0: 25 s) and
	// EventsMaxAge a stream's longest life (0: 1 h); both are for tests.
	Events          EventSource
	EventsKeepalive time.Duration
	EventsMaxAge    time.Duration

	// Leaks, when set, lists the leak watch findings at or after since
	// (zero: all) for the inbox (Plan 08 D4; sessionsapi.Catalog.Leaks).
	// nil under --no-transcripts. Leak items are listed even with the
	// activity log off.
	Leaks func(since time.Time) []rulebook.Leak

	Now      func() time.Time              // tests; default time.Now
	Settings func() (user, project string) // tests; default ClaudeSettings() and the project root's .claude/settings.json ("" when no project)
}

// Server is the dashboard's HTTP server. Build it with New, bind with
// Listen, run it with Serve.
type Server struct {
	opts  Options
	token string
	port  atomic.Int32 // the listener's port, recorded by Serve; 0 = not serving (every request 403s)
	api   *http.ServeMux
	files *staticFiles

	lastHit atomic.Int64 // UnixNano of the last authenticated /api/ request (the idle clock)

	// stop is closed by RequestStop (POST /api/shutdown); Serve then
	// shuts down gracefully, as on ctx cancel.
	stop     chan struct{}
	stopOnce sync.Once

	// closing is closed when Serve starts shutting down, before it waits
	// for handlers, so long-lived event streams end instead of holding the
	// graceful shutdown for its whole timeout. streams counts open ones.
	closing     chan struct{}
	closingOnce sync.Once
	streams     atomic.Int32

	// customSettings: Options.Settings came from the caller (tests), so
	// it is used as is instead of being derived per request.
	customSettings bool

	// mu serialises overrides edits: each grant POST re-reads the file,
	// applies the edit and saves it while holding mu.
	mu sync.Mutex

	// Reserved for api_enforce.go (WP5): one-use nonces and their issue
	// times, guarded by nonceMu.
	nonceMu sync.Mutex
	nonces  map[string]time.Time

	skillsMu    sync.Mutex
	skillsCache map[string][]byte // encoded /api/skills body per cwd; absent = rebuild on next GET

	// stats is GET /api/rules/stats's fold of the activity log, by offset
	// (api_stats.go, Plan 08 Task 4).
	stats statsFold

	// explain is what POST /api/rules/try runs (api_try.go): hook.Explain,
	// set by New; tests swap in a slow one before serving (R15).
	explain func(hook.Input, hook.Env) (*hook.Output, hook.Explanation)
	tryGate chan struct{} // the try mutex: one slot, so a wait can time out
}

// route is one API handler and its mux pattern ("METHOD /api/...").
type route struct {
	pattern string
	handler http.Handler
}

// Optional route files of this package implement these on *Server, and New
// mounts whatever they return. This is the registration hook for
// api_activity.go (WP3 step 3, after WP2) and api_enforce.go (WP5): each
// defines its method on *Server in its own file and server.go stays as is.
// A method set is resolved at compile time, so there is no init work and no
// package-level registry.
type (
	activityRouter interface{ activityRoutes() []route }
	enforceRouter  interface{ enforceRoutes() []route }
	rulesRouter    interface{ rulesRoutes() []route }
	needsRouter    interface{ needsRoutes() []route }
	recentRouter   interface{ recentRoutes() []route }
	mcpRouter      interface{ mcpRoutes() []route }
	statsRouter    interface{ statsRoutes() []route }
	tryRouter      interface{ tryRoutes() []route }
)

// Init-free: everything below is a constant. Package-level maps, errors.New
// or log.New would run at init, and internal/ui is linked into the hook
// binary (CONTRIBUTING; checked with GODEBUG=inittrace=1).
const (
	tokenBytes      = 32
	maxBodyBytes    = 1 << 20
	maxHeaderBytes  = 64 << 10
	idleTickMax     = 10 * time.Second
	idleTickMin     = 10 * time.Millisecond
	shutdownTimeout = 5 * time.Second
	apiPrefix       = "/api/"
)

// New builds a Server: a fresh 32-byte token and the API mux with the core
// routes, the optional route files and Options.Routes.
func New(o Options) (*Server, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	custom := o.Settings != nil
	if o.Settings == nil {
		p, cwd := o.Paths, o.Cwd
		o.Settings = func() (string, string) { return settingsFor(p, cwd) }
	}
	tok := o.Token
	if tok == "" {
		var err error
		if tok, err = newToken(); err != nil {
			return nil, err
		}
	}
	s := &Server{opts: o, token: tok, nonces: map[string]time.Time{}, stop: make(chan struct{}), closing: make(chan struct{}), customSettings: custom,
		explain: hook.Explain, tryGate: make(chan struct{}, 1)}
	files, err := newStaticFiles()
	if err != nil {
		return nil, err
	}
	s.files = files

	routes := s.coreRoutes()
	if m, ok := any(s).(activityRouter); ok {
		routes = append(routes, m.activityRoutes()...)
	}
	if m, ok := any(s).(enforceRouter); ok {
		routes = append(routes, m.enforceRoutes()...)
	}
	if m, ok := any(s).(configRouter); ok {
		routes = append(routes, m.configRoutes()...)
	}
	if m, ok := any(s).(eventsRouter); ok {
		routes = append(routes, m.eventsRoutes()...)
	}
	if m, ok := any(s).(rulesRouter); ok {
		routes = append(routes, m.rulesRoutes()...)
	}
	if m, ok := any(s).(needsRouter); ok {
		routes = append(routes, m.needsRoutes()...)
	}
	if m, ok := any(s).(recentRouter); ok {
		routes = append(routes, m.recentRoutes()...)
	}
	if m, ok := any(s).(mcpRouter); ok {
		routes = append(routes, m.mcpRoutes()...)
	}
	if m, ok := any(s).(statsRouter); ok {
		routes = append(routes, m.statsRoutes()...)
	}
	if m, ok := any(s).(tryRouter); ok {
		routes = append(routes, m.tryRoutes()...)
	}
	keys := make([]string, 0, len(o.Routes))
	for k := range o.Routes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		routes = append(routes, route{k, o.Routes[k]})
	}
	mux, err := buildMux(routes)
	if err != nil {
		return nil, err
	}
	s.api = mux
	return s, nil
}

// coreRoutes are Phase A's routes in this package's own files.
func (s *Server) coreRoutes() []route {
	return []route{
		{"GET /api/status", http.HandlerFunc(s.handleStatus)},
		{"GET /api/skills", http.HandlerFunc(s.handleSkills)},
		{"GET /api/skills/{name}", http.HandlerFunc(s.handleSkill)},
		{"POST /api/skills/{name}/grant", http.HandlerFunc(s.handleGrant)},
		{"GET /api/overrides", http.HandlerFunc(s.handleOverrides)},
		{"GET /api/shutdown", http.HandlerFunc(s.handleShutdownGet)},
		{"POST /api/shutdown", http.HandlerFunc(s.handleShutdownPost)},
	}
}

// settingsFor is the user settings file and, when cwd is inside a git
// repository below home, that project's settings file ("" otherwise).
func settingsFor(p paths.Paths, cwd string) (user, project string) {
	if root := paths.ProjectRoot(cwd, p.Home); root != "" {
		project = paths.ProjectSettings(root)
	}
	return p.ClaudeSettings(), project
}

// buildMux validates every pattern and registers it. For each distinct path
// it also registers the method-less pattern answering 405 with Allow, and
// "/api/" answers 404, so every API error body is JSON (the mux's own 404
// and 405 are text/plain). A conflicting pattern makes the mux panic; that is
// turned into an error.
func buildMux(routes []route) (mux *http.ServeMux, err error) {
	defer func() {
		if r := recover(); r != nil {
			mux, err = nil, fmt.Errorf("ui: route: %v", r)
		}
	}()
	mux = http.NewServeMux()
	allow := map[string][]string{}
	var order []string
	for _, rt := range routes {
		method, path, ok := strings.Cut(rt.pattern, " ")
		path = strings.TrimLeft(path, " \t")
		switch {
		case !ok || method == "" || strings.ContainsAny(method, "/{"):
			return nil, fmt.Errorf("ui: route %q: want \"METHOD /api/...\"", rt.pattern)
		case !strings.HasPrefix(path, apiPrefix) || len(path) == len(apiPrefix):
			return nil, fmt.Errorf("ui: route %q: path must start with %s", rt.pattern, apiPrefix)
		case rt.handler == nil:
			return nil, fmt.Errorf("ui: route %q: nil handler", rt.pattern)
		}
		mux.Handle(method+" "+path, rt.handler)
		if _, seen := allow[path]; !seen {
			order = append(order, path)
		}
		allow[path] = append(allow[path], method)
		if method == http.MethodGet {
			allow[path] = append(allow[path], http.MethodHead)
		}
	}
	for _, path := range order {
		methods := strings.Join(allow[path], ", ")
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Allow", methods)
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		})
	}
	mux.HandleFunc(apiPrefix, func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})
	return mux, nil
}

func newToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("ui: token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Listen binds 127.0.0.1:<port> over IPv4 only (port 0 = ephemeral). It never
// binds any other address.
func Listen(port int) (net.Listener, error) {
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("ui: port %d out of range", port)
	}
	return net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
}

// Handler is the guarded handler. The Host check needs the listener's port,
// which Serve records, so before Serve every request is refused with 403.
func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.guard) }

// Serve answers on ln until ctx is done or, with Options.Idle > 0, no
// authenticated /api/ request has arrived for that long. Both return nil. The server
// logs nothing: its error log is discarded and no handler logs URLs,
// headers or the token.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	tcp, ok := ln.Addr().(*net.TCPAddr)
	if !ok || !tcp.IP.IsLoopback() {
		return fmt.Errorf("ui: refusing to serve on %s: loopback TCP only", ln.Addr())
	}
	s.port.Store(int32(tcp.Port))
	defer s.port.Store(0)
	s.touch()

	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    maxHeaderBytes,
		// "OPTIONS *" goes through the guard (security headers, 405)
		// instead of net/http's built-in answer.
		DisableGeneralOptionsHandler: true,
		ErrorLog:                     log.New(io.Discard, "", 0),
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.watch(ctx, stop)
		s.closingOnce.Do(func() { close(s.closing) })
		sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	err := srv.Serve(ln)
	close(stop)
	<-done
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// watch returns when ctx is done, when Serve stopped on its own (stop), or
// when the idle limit passed. The tick is Idle/4 clamped to [10ms, 10s], so
// a 30-minute limit is checked every 10 s and a test's 50 ms limit promptly.
func (s *Server) watch(ctx context.Context, stop <-chan struct{}) {
	idle := s.opts.Idle
	if idle <= 0 {
		select {
		case <-ctx.Done():
		case <-stop:
		case <-s.stop:
		}
		return
	}
	tick := min(max(idle/4, idleTickMin), idleTickMax)
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-s.stop:
			return
		case <-t.C:
			if s.opts.Now().UnixNano()-s.lastHit.Load() > int64(idle) {
				return
			}
		}
	}
}

func (s *Server) touch() { s.lastHit.Store(s.opts.Now().UnixNano()) }

// URL is the launch URL, http://127.0.0.1:<port>/#t=<token>. The token is in
// the fragment, which browsers never send; print it once and nowhere else.
func (s *Server) URL(ln net.Listener) string {
	port := 0
	if tcp, ok := ln.Addr().(*net.TCPAddr); ok {
		port = tcp.Port
	}
	return "http://127.0.0.1:" + strconv.Itoa(port) + "/#t=" + s.Token()
}

// Token is the bearer token (TokenSource's answer when set). Tests use it;
// nothing logs it.
func (s *Server) Token() string {
	if s.opts.TokenSource != nil {
		return s.opts.TokenSource()
	}
	return s.token
}

// RequestStop makes Serve shut down gracefully, as a cancelled ctx does.
// It is safe to call more than once and before Serve.
func (s *Server) RequestStop() { s.stopOnce.Do(func() { close(s.stop) }) }

// Stopped reports whether RequestStop was called (POST /api/shutdown), so
// a caller can tell that exit from an idle exit or a signal.
func (s *Server) Stopped() bool {
	select {
	case <-s.stop:
		return true
	default:
		return false
	}
}
