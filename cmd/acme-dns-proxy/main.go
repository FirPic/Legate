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
	"github.com/FirPic/acme-dns-httpreq-proxy/internal/provider/cloudflare"
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
	flag.Parse()

	if *showVersion {
		fmt.Printf("acme-dns-proxy version %s (commit: %s, built at: %s)\n", Version, Commit, Date)
		os.Exit(0)
	}

	// 1. Load configuration (fail-fast)
	cfg, err := config.LoadFromEnv()
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
		"allowed_domain", cfg.AllowedDomain,
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

	// 5. Initialize Cloudflare DNS provider client
	dnsClient := cloudflare.NewClient(cfg.CloudflareAPIToken, cfg.AllowedDomain)
	dnsClient.SetObserver(metrics)

	if cfg.CloudflareZoneID != "" {
		dnsClient.SetZoneID(cfg.AllowedDomain, cfg.CloudflareZoneID)
		slog.Info("pre-configured cloudflare zone id registered", "zone_id", cfg.CloudflareZoneID)
	}

	// 6. Build HTTP challenge server
	appServer := httpinternal.NewServer(cfg.AllowedDomain, cfg.Users, dnsClient, tr, metrics, cfg.RateLimitPerMinute)

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

	// 8. Graceful shutdown on SIGINT / SIGTERM
	shutdownSigCh := make(chan os.Signal, 1)
	signal.Notify(shutdownSigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-shutdownSigCh:
		slog.Info("received termination signal, initiating graceful shutdown", "signal", sig.String())
	case err := <-serverErrCh:
		slog.Error("server listener encountered fatal error", "error", err)
		os.Exit(1)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("graceful shutdown failed for main server", "error", err)
		_ = httpServer.Close()
	}

	if adminServer != nil {
		if err := adminServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("graceful shutdown failed for admin server", "error", err)
			_ = adminServer.Close()
		}
	}

	slog.Info("server shutdown completed cleanly")
}

func initLogger(levelStr string) {
	var level slog.Level
	switch strings.ToLower(levelStr) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	handler := slog.NewJSONHandler(os.Stdout, opts)
	logger := slog.New(handler)
	slog.SetDefault(logger)
}
