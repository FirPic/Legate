package http

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/FirPic/acme-dns-httpreq-proxy/internal/config"
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
	rateLimiter   *RateLimiter
	mux           *http.ServeMux
	handler       http.Handler
}

// NewServer builds and configures a new Server instance for challenge operations.
func NewServer(
	allowedDomain string,
	users map[string]config.UserConfig,
	dnsProvider provider.DNSProvider,
	tr *tracker.Tracker,
	m *Metrics,
	rateLimitPerMinute int,
) *Server {
	rl := NewRateLimiter(rateLimitPerMinute)

	s := &Server{
		allowedDomain: allowedDomain,
		dnsProvider:   dnsProvider,
		tracker:       tr,
		auth:          NewAuthenticator(users),
		metrics:       m,
		rateLimiter:   rl,
		mux:           http.NewServeMux(),
	}

	s.routes()
	s.handler = s.loggingMiddleware(s.recovererMiddleware(s.mux))
	return s
}

func (s *Server) routes() {
	// Protected Lego httpreq challenge endpoints with Basic Auth and Rate Limiting
	presentChain := s.rateLimiter.Middleware(s.auth.Middleware(http.HandlerFunc(s.handlePresent)))
	cleanupChain := s.rateLimiter.Middleware(s.auth.Middleware(http.HandlerFunc(s.handleCleanup)))

	s.mux.Handle("POST /present", presentChain)
	s.mux.Handle("POST /cleanup", cleanupChain)
}

// ServeHTTP delegates request handling to the configured middleware pipeline.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// AdminHandler returns an http.Handler serving /healthz and /metrics on the dedicated admin port.
func (s *Server) AdminHandler() http.Handler {
	return NewAdminServer(s.allowedDomain, s.tracker, s.metrics)
}

// NewAdminServer creates an isolated http.Handler serving operational endpoints (/healthz and /metrics).
func NewAdminServer(allowedDomain string, tr *tracker.Tracker, m *Metrics) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":          "ok",
			"tracked_records": tr.Count(),
			"allowed_domain":  allowedDomain,
		})
	})

	if m != nil {
		mux.Handle("GET /metrics", promhttp.HandlerFor(m.Registry(), promhttp.HandlerOpts{}))
	}

	return mux
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
