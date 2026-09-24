package lab

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

//go:embed web
var webFS embed.FS

// ServerOptions configures the configuration UI and its API.
type ServerOptions struct {
	LabPath   string
	DeployDir string
	RepoRoot  string
	Listen    string
	Logger    *slog.Logger
}

// Server owns the lab definition and serialises edits to it.
type Server struct {
	opts ServerOptions
	log  *slog.Logger

	mu  sync.Mutex
	lab *Lab
}

// Serve starts the configuration UI. It blocks until the process is stopped.
func Serve(opts ServerOptions) error {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	def, err := Load(opts.LabPath)
	if err != nil {
		return err
	}
	srv := &Server{opts: opts, log: opts.Logger, lab: def}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/healthz", srv.handleHealth)
	mux.HandleFunc("GET /api/v1/lab", srv.handleGetLab)
	mux.HandleFunc("PUT /api/v1/lab", srv.handlePutLab)
	mux.HandleFunc("GET /api/v1/lab/{section}", srv.handleGetSection)
	mux.HandleFunc("PUT /api/v1/lab/{section}", srv.handlePutSection)
	mux.HandleFunc("POST /api/v1/render", srv.handleRender)
	mux.HandleFunc("GET /api/v1/render/status", srv.handleRenderStatus)

	ui, err := fs.Sub(webFS, "web")
	if err != nil {
		return fmt.Errorf("lab: cannot open the embedded UI: %w", err)
	}
	mux.Handle("GET /", http.FileServer(http.FS(ui)))

	httpSrv := &http.Server{
		Addr:              opts.Listen,
		Handler:           logRequests(opts.Logger, mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	opts.Logger.Info("labctl: configuration UI listening",
		"address", opts.Listen, "lab", opts.LabPath)

	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("lab: %w", err)
	}
	return nil
}

func logRequests(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only the API is worth logging; the UI assets are noise.
		if len(r.URL.Path) >= 4 && r.URL.Path[:4] == "/api" {
			log.Debug("labctl: request", "method", r.Method, "path", r.URL.Path)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"lab":    s.opts.LabPath,
	})
}

func (s *Server) handleGetLab(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeJSON(w, http.StatusOK, s.lab)
}

// handlePutLab replaces the whole definition. The UI sends the full document,
// which keeps the browser and the file from drifting apart.
func (s *Server) handlePutLab(w http.ResponseWriter, r *http.Request) {
	var incoming Lab
	if err := decodeJSON(r, &incoming); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := incoming.Validate(); err != nil {
		s.writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := incoming.Save(s.opts.LabPath); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.lab = &incoming
	s.log.Info("labctl: lab definition updated", "path", s.opts.LabPath)
	s.writeJSON(w, http.StatusOK, map[string]any{"saved": true, "lab": s.lab})
}

// handleGetSection returns one top level section, which is what each UI panel
// loads on its own.
func (s *Server) handleGetSection(w http.ResponseWriter, r *http.Request) {
	section := r.PathValue("section")
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.section(section)
	if !ok {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("unknown section %q", section))
		return
	}
	s.writeJSON(w, http.StatusOK, value)
}

// handlePutSection replaces one top level section in place.
func (s *Server) handlePutSection(w http.ResponseWriter, r *http.Request) {
	section := r.PathValue("section")
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "cannot read the request body")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Work on a copy so a rejected edit cannot leave a half applied state.
	next := *s.lab
	if err := json.Unmarshal(body, s.target(&next, section)); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("cannot parse the %s section: %v", section, err))
		return
	}
	if err := next.Validate(); err != nil {
		s.writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := next.Save(s.opts.LabPath); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.lab = &next
	s.log.Info("labctl: lab section updated", "section", section)
	s.writeJSON(w, http.StatusOK, map[string]any{"saved": true, "section": section})
}

// section returns the value for a section name.
func (s *Server) section(name string) (any, bool) {
	switch name {
	case "network":
		return &s.lab.Network, true
	case "plmn":
		return &s.lab.PLMN, true
	case "credentials":
		return &s.lab.Credentials, true
	case "epdg":
		return &s.lab.EPDG, true
	case "open5gs":
		return &s.lab.Open5GS, true
	case "enb":
		return &s.lab.ENB, true
	default:
		return nil, false
	}
}

// target returns the address of a section within a lab copy for unmarshalling.
func (s *Server) target(l *Lab, name string) any {
	switch name {
	case "network":
		return &l.Network
	case "plmn":
		return &l.PLMN
	case "credentials":
		return &l.Credentials
	case "epdg":
		return &l.EPDG
	case "open5gs":
		return &l.Open5GS
	case "enb":
		return &l.ENB
	default:
		return nil
	}
}

// handleRender regenerates deploy/.env and deploy/runtime from the current
// definition, which is what makes the containers pick up a change.
func (s *Server) handleRender(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Re-read from disk if the file was edited by hand, so the render always
	// reflects what is actually stored.
	if def, err := Load(s.opts.LabPath); err == nil {
		s.lab = def
	}

	renderer := NewRenderer(s.opts.RepoRoot, s.opts.DeployDir, s.lab)
	result, err := renderer.Render()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.log.Info("labctl: rendered the lab", "files", len(result.Files))
	s.writeJSON(w, http.StatusOK, map[string]any{
		"env":      result.EnvFile,
		"files":    result.Files,
		"profiles": renderer.profiles(),
	})
}

// handleRenderStatus reports whether the rendered tree is older than the lab
// definition, which the UI shows as "restart needed".
func (s *Server) handleRenderStatus(w http.ResponseWriter, _ *http.Request) {
	labInfo, err := os.Stat(s.opts.LabPath)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	runtimeDir := filepath.Join(s.opts.DeployDir, "runtime")
	var newest time.Time
	if err := filepath.Walk(runtimeDir, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
		return nil
	}); err != nil && !os.IsNotExist(err) {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	stale := labInfo.ModTime().After(newest)
	s.writeJSON(w, http.StatusOK, map[string]any{
		"lab_modified":    labInfo.ModTime().Format(time.RFC3339),
		"rendered_at":     formatOrEmpty(newest),
		"render_required": stale,
		"runtime_dir":     runtimeDir,
	})
}

func formatOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func decodeJSON(r *http.Request, target any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return fmt.Errorf("cannot parse the request body: %w", err)
	}
	return nil
}

func (s *Server) writeError(w http.ResponseWriter, code int, message string) {
	s.writeJSON(w, code, map[string]string{"error": message})
}

func (s *Server) writeJSON(w http.ResponseWriter, code int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		s.log.Error("labctl: cannot encode the response", "error", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}
