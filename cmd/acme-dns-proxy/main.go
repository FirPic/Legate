package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/FirPic/acme-dns-httpreq-proxy/internal/config"
	httpinternal "github.com/FirPic/acme-dns-httpreq-proxy/internal/http"
	"github.com/FirPic/acme-dns-httpreq-proxy/internal/tracker"
)

var (
	// Version is populated during build via -ldflags
	Version = "1.0.0"
	// Commit is populated during build via -ldflags
	Commit = "dev"
	// Date is populated during build via -ldflags
	Date = "unknown"
)

func main() {
	showVersion := flag.Bool("version", false, "Print version information and exit")
	configPath := flag.String("config", "", "Path to YAML configuration file (optional, defaults to environment variables)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("acme-dns-proxy version %s (commit: %s, built at: %s)\n", Version, Commit, Date)
		os.Exit(0)
	}

	// 1. Load configuration (fail-fast: YAML with env expansion or pure env vars)
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	// 2. Setup structured logging
	initLogger(cfg.LogLevel)

	slog.Info("starting acme-dns-proxy",
		"version", Version,
		"commit", Commit,
		"bind_addr", cfg.BindAddr,
		"port", cfg.Port,
		"admin_port", cfg.AdminPort,
		"rate_limit_per_min", cfg.RateLimitPerMinute,
		"providers_count", len(cfg.Providers),
		"domains_count", len(cfg.Domains),
		"users_count", len(cfg.Users),
		"log_level", cfg.LogLevel,
	)

	// 3. Initialize record tracker with background TTL eviction (VULN-05)
	tr := tracker.New()
	gcStopCh := make(chan struct{})
	defer close(gcStopCh)
	tr.StartGC(5*time.Minute, 15*time.Minute, gcStopCh)

	// 4. Initialize Prometheus metrics
	metrics := httpinternal.NewMetrics(nil, func() float64 {
		return float64(tr.Count())
	})

	// 5. Initialize Multi-domain DNS Provider Registry
	dnsRegistry, err := cfg.BuildRegistry(metrics)
	if err != nil {
		slog.Error("failed to initialize dns provider registry", "error", err)
		os.Exit(1)
	}
	slog.Info("registered dns provider domains", "domains", dnsRegistry.RegisteredDomains())

	// 6. Build HTTP challenge server
	appServer := httpinternal.NewServer(dnsRegistry, cfg.Users, tr, metrics, cfg.RateLimitPerMinute)

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr(),
		Handler:           appServer,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      35 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MiB
	}

	serverErrCh := make(chan error, 2)

	// Start main challenge HTTP server
	go func() {
		slog.Info("listening for challenge requests", "address", cfg.ListenAddr())
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrCh <- fmt.Errorf("main server listener: %w", err)
		}
	}()

	// 7. Build and start separate admin HTTP server for /healthz and /metrics (VULN-02)
	var adminServer *http.Server
	if cfg.AdminPort != "" {
		adminServer = &http.Server{
			Addr:              cfg.AdminListenAddr(),
			Handler:           appServer.AdminHandler(),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    1 << 20,
		}

		go func() {
			slog.Info("listening for admin metrics/healthz requests", "address", cfg.AdminListenAddr())
			if err := adminServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				serverErrCh <- fmt.Errorf("admin server listener: %w", err)
			}
		}()
	}

	// 8. Wait for OS signal or unexpected server listener errors
	shutdownSigCh := make(chan os.Signal, 1)
	signal.Notify(shutdownSigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-shutdownSigCh:
		slog.Info("shutdown signal received", "signal", sig.String())
	case srvErr := <-serverErrCh:
		slog.Error("critical server listener failure", "error", srvErr)
	}

	// 9. Graceful shutdown sequence
	slog.Info("initiating graceful shutdown...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if adminServer != nil {
		if err := adminServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("error during admin server shutdown", "error", err)
		} else {
			slog.Info("admin server stopped")
		}
	}

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("error during main server shutdown", "error", err)
	} else {
		slog.Info("main server stopped")
	}

	slog.Info("server shutdown complete")
}

func initLogger(level string) {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: lvl,
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, opts))
	slog.SetDefault(logger)
}
