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
		"allowed_domain", cfg.AllowedDomain,
		"users_count", len(cfg.Users),
		"log_level", cfg.LogLevel,
	)

	// 3. Initialize record tracker and metrics
	tr := tracker.New()
	metrics := httpinternal.NewMetrics(nil, func() float64 {
		return float64(tr.Count())
	})

	// 4. Initialize Cloudflare DNS provider client
	dnsClient := cloudflare.NewClient(cfg.CloudflareAPIToken, cfg.AllowedDomain)
	dnsClient.SetObserver(metrics)

	if cfg.CloudflareZoneID != "" {
		dnsClient.SetZoneID(cfg.AllowedDomain, cfg.CloudflareZoneID)
		slog.Info("pre-configured cloudflare zone id registered", "zone_id", cfg.CloudflareZoneID)
	}

	// 5. Build HTTP server
	appServer := httpinternal.NewServer(cfg.AllowedDomain, cfg.Users, dnsClient, tr, metrics)

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr(),
		Handler:           appServer,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      35 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MiB
	}

	// 6. Start HTTP listener in background goroutine
	serverErrCh := make(chan error, 1)
	go func() {
		slog.Info("listening for incoming requests", "address", cfg.ListenAddr())
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrCh <- err
		}
	}()

	// 7. Graceful shutdown on SIGINT / SIGTERM
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
		slog.Error("graceful shutdown failed, forcing server closure", "error", err)
		_ = httpServer.Close()
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

	// Cloud-native JSON logging output
	handler := slog.NewJSONHandler(os.Stdout, opts)
	logger := slog.New(handler)
	slog.SetDefault(logger)
}
