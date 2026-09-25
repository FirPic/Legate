package http

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/FirPic/acme-dns-httpreq-proxy/internal/provider"
	"github.com/FirPic/acme-dns-httpreq-proxy/internal/tracker"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server handles incoming HTTP requests for ACME DNS-01 challenges.
type Server struct {
	allowedDomain string
	dnsProvider   provider.DNSProvider
	tracker       *tracker.Tracker
	auth          *Authenticator
	metrics       *Metrics
	mux           *http.ServeMux
	handler       http.Handler
}

// NewServer builds and configures a new Server instance.
func NewServer(
	allowedDomain string,
	users map[string]string,
	dnsProvider provider.DNSProvider,
	tr *tracker.Tracker,
	m *Metrics,
) *Server {
	s := &Server{
		allowedDomain: allowedDomain,
		dnsProvider:   dnsProvider,
		tracker:       tr,
		auth:          NewAuthenticator(users),
		metrics:       m,
		mux:           http.NewServeMux(),
	}

	s.routes()
	s.handler = s.loggingMiddleware(s.recovererMiddleware(s.mux))
	return s
}

func (s *Server) routes() {
	// Public liveness / health probe
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)

	// Prometheus metrics
	if s.metrics != nil {
		s.mux.Handle("GET /metrics", promhttp.HandlerFor(s.metrics.Registry(), promhttp.HandlerOpts{}))
	}

	// Protected Lego httpreq challenge endpoints
	s.mux.Handle("POST /present", s.auth.Middleware(http.HandlerFunc(s.handlePresent)))
	s.mux.Handle("POST /cleanup", s.auth.Middleware(http.HandlerFunc(s.handleCleanup)))
}

// ServeHTTP delegates request handling to the configured middleware pipeline.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// statusWriter wraps http.ResponseWriter to intercept HTTP response status codes.
type statusWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *statusWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(sw, r)

		duration := time.Since(start)
		user, _, ok := r.BasicAuth()
		if !ok || user == "" {
			user = "anonymous"
		}

		// Omit verbose logs for repetitive /healthz or /metrics polling unless debug enabled
		if r.URL.Path == "/healthz" || r.URL.Path == "/metrics" {
			slog.Debug("http request completed",
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.statusCode,
				"duration_ms", duration.Milliseconds(),
				"remote_addr", r.RemoteAddr,
			)
			return
		}

		logAttrs := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.statusCode,
			"user", user,
			"duration_ms", duration.Milliseconds(),
			"remote_addr", r.RemoteAddr,
		}

		if sw.statusCode >= 500 {
			slog.Error("http request error", logAttrs...)
		} else if sw.statusCode >= 400 {
			slog.Warn("http request warning", logAttrs...)
		} else {
			slog.Info("http request completed", logAttrs...)
		}
	})
}

func (s *Server) recovererMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("recovered from panic in http handler",
					"error", rec,
					"path", r.URL.Path,
					"method", r.Method,
				)
				http.Error(w, `{"status":"error","error":"internal server error"}`, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
