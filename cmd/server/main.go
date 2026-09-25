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
	"github.com/FirPic/acme-dns-httpreq-proxy/internal/dns"
	"github.com/FirPic/acme-dns-httpreq-proxy/internal/lock"
	"github.com/FirPic/acme-dns-httpreq-proxy/internal/server"
)

var (
	// Version is populated during build via -ldflags
	Version = "1.0.0"
	Commit  = "dev"
	Date    = "unknown"
)

func main() {
	showVersion := flag.Bool("version", false, "Print version information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("acme-dns-httpreq-proxy version %s (commit: %s, built at: %s)\n", Version, Commit, Date)
		os.Exit(0)
	}

	// 1. Load configuration
	cfg, err := config.LoadFromEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	// 2. Setup structured logging
	initLogger(cfg.LogLevel)

	slog.Info("starting acme-dns-httpreq-proxy",
		"version", Version,
		"commit", Commit,
		"bind_addr", cfg.BindAddr,
		"port", cfg.Port,
		"allowed_domain", cfg.AllowedDomain,
		"users_count", len(cfg.Users),
		"log_level", cfg.LogLevel,
	)

	// 3. Initialize Cloudflare DNS client
	dnsClient := dns.NewCloudflareClient(cfg.CloudflareAPIToken)
	if cfg.CloudflareZoneID != "" {
		dnsClient.SetZoneIDCache(cfg.AllowedDomain, cfg.CloudflareZoneID)
		slog.Info("pre-configured cloudflare zone id set", "zone_id", cfg.CloudflareZoneID)
	}

	// 4. Initialize record tracker and HTTP server
	tracker := lock.NewRecordTracker()
	appServer := server.NewServer(cfg, dnsClient, tracker)

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr(),
		Handler:           appServer,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      35 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	// 5. Start HTTP server in a goroutine
	serverErrCh := make(chan error, 1)
	go func() {
		slog.Info("listening for incoming requests", "address", cfg.ListenAddr())
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrCh <- err
		}
	}()

	// 6. Graceful shutdown on SIGINT / SIGTERM
	shutdownSigCh := make(chan os.Signal, 1)
	signal.Notify(shutdownSigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-shutdownSigCh:
		slog.Info("received termination signal, initiating graceful shutdown", "signal", sig.String())
	case err := <-serverErrCh:
		slog.Error("server listener encountered fatal error", "error", err)
		os.Exit(1)
	}

	// Create shutdown context with 15 second grace period
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

	// JSON output for production cloud-native observability
	handler := slog.NewJSONHandler(os.Stdout, opts)
	logger := slog.New(handler)
	slog.SetDefault(logger)
}
