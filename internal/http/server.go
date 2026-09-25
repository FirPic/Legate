package http

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/FirPic/legate/internal/config"
	"github.com/FirPic/legate/internal/provider"
	"github.com/FirPic/legate/internal/tracker"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server handles incoming HTTP requests for ACME DNS-01 challenges.
type Server struct {
	registry    *provider.Registry
	tracker     *tracker.Tracker
	auth        *Authenticator
	metrics         *Metrics
	userRateLimiter *RateLimiter
	ipRateLimiter   *RateLimiter
	mux             *http.ServeMux
	handler         http.Handler
}

// NewServer builds and configures a new Server instance using a multi-domain provider Registry.
func NewServer(
	reg *provider.Registry,
	users map[string]config.UserConfig,
	tr *tracker.Tracker,
	m *Metrics,
	rateLimitPerMinute int,
) *Server {
	ipLimit := rateLimitPerMinute * 2
	if ipLimit < 120 {
		ipLimit = 120
	}
	return NewServerWithRateLimits(reg, users, tr, m, rateLimitPerMinute, ipLimit)
}

// NewServerWithRateLimits allows explicitly specifying both user and IP rate limits.
func NewServerWithRateLimits(
	reg *provider.Registry,
	users map[string]config.UserConfig,
	tr *tracker.Tracker,
	m *Metrics,
	userRateLimitPerMinute int,
	ipRateLimitPerMinute int,
) *Server {
	userRL := NewRateLimiter(userRateLimitPerMinute)
	ipRL := NewRateLimiter(ipRateLimitPerMinute)

	s := &Server{
		registry:        reg,
		tracker:         tr,
		auth:            NewAuthenticator(users),
		metrics:         m,
		userRateLimiter: userRL,
		ipRateLimiter:   ipRL,
		mux:             http.NewServeMux(),
	}

	s.routes()
	s.handler = s.securityHeadersMiddleware(s.loggingMiddleware(s.recovererMiddleware(s.mux)))
	return s
}

// Close gracefully terminates background rate limiter cleanup goroutines.
func (s *Server) Close() {
	if s.userRateLimiter != nil {
		s.userRateLimiter.Stop()
	}
	if s.ipRateLimiter != nil {
		s.ipRateLimiter.Stop()
	}
}

// NewSingleProviderServer creates a Server for a single domain and provider (convenience & backward compatibility).
func NewSingleProviderServer(
	allowedDomain string,
	users map[string]config.UserConfig,
	dnsProvider provider.DNSProvider,
	tr *tracker.Tracker,
	m *Metrics,
	rateLimitPerMinute int,
) *Server {
	reg := provider.NewRegistry()
	_ = reg.Register(allowedDomain, dnsProvider)
	return NewServer(reg, users, tr, m, rateLimitPerMinute)
}

func (s *Server) routes() {
	// Defense in depth:
	// 1. IP rate limiting (pre-auth) to prevent brute-force attacks and volumetric DoS
	// 2. HTTP Basic Authentication
	// 3. User rate limiting (post-auth) to isolate per-user quotas
	presentChain := s.ipRateLimiter.IPMiddleware(s.auth.Middleware(s.userRateLimiter.UserMiddleware(http.HandlerFunc(s.handlePresent))))
	cleanupChain := s.ipRateLimiter.IPMiddleware(s.auth.Middleware(s.userRateLimiter.UserMiddleware(http.HandlerFunc(s.handleCleanup))))

	s.mux.Handle("POST /present", presentChain)
	s.mux.Handle("POST /cleanup", cleanupChain)
}

// ServeHTTP delegates request handling to the configured middleware pipeline.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// AdminHandler returns an http.Handler serving /healthz and /metrics on the dedicated admin port.
func (s *Server) AdminHandler() http.Handler {
	return NewAdminServer(s.registry.RegisteredDomains(), s.tracker, s.metrics)
}

// NewAdminServer creates an isolated http.Handler serving operational endpoints (/healthz and /metrics).
func NewAdminServer(domains []string, tr *tracker.Tracker, m *Metrics) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := map[string]any{
			"status":          "ok",
			"tracked_records": tr.Count(),
			"domains_count":   len(domains),
		}
		_ = json.NewEncoder(w).Encode(resp)
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

func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		next.ServeHTTP(w, r)
	})
}
