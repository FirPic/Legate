package config

import (
	"os"
	"path/filepath"
	"testing"
)

func clearEnv() {
	os.Unsetenv("PORT")
	os.Unsetenv("BIND_ADDR")
	os.Unsetenv("ADMIN_PORT")
	os.Unsetenv("ADMIN_BIND_ADDR")
	os.Unsetenv("RATE_LIMIT_PER_MINUTE")
	os.Unsetenv("CLOUDFLARE_API_TOKEN")
	os.Unsetenv("CLOUDFLARE_API_TOKEN_FILE")
	os.Unsetenv("CLOUDFLARE_ZONE_ID")
	os.Unsetenv("ALLOWED_DOMAIN")
	os.Unsetenv("USERS")
	os.Unsetenv("LOG_LEVEL")
	os.Unsetenv("USER_TEST_PASS")
	os.Unsetenv("USER_TRAEFIK_DMZ_PASS")
	os.Unsetenv("USER_TRAEFIK_DMZ_SUBDOMAINS")
}

func TestLoadFromEnv_Success(t *testing.T) {
	clearEnv()
	defer clearEnv()

	os.Setenv("CLOUDFLARE_API_TOKEN", "test-token")
	os.Setenv("ALLOWED_DOMAIN", "firpic.fr")
	os.Setenv("USERS", "admin:supersecret:*,traefik:anothersecret:*.dmz.firpic.fr;dmz.firpic.fr")
	os.Setenv("PORT", "9090")
	os.Setenv("BIND_ADDR", "127.0.0.1")
	os.Setenv("ADMIN_PORT", "9091")
	os.Setenv("RATE_LIMIT_PER_MINUTE", "120")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Port != "9090" {
		t.Errorf("expected port 9090, got %s", cfg.Port)
	}
	if cfg.AdminPort != "9091" {
		t.Errorf("expected admin port 9091, got %s", cfg.AdminPort)
	}
	if cfg.AdminListenAddr() != "127.0.0.1:9091" {
		t.Errorf("expected admin listen addr 127.0.0.1:9091, got %s", cfg.AdminListenAddr())
	}
	if cfg.RateLimitPerMinute != 120 {
		t.Errorf("expected rate limit 120, got %d", cfg.RateLimitPerMinute)
	}
	if len(cfg.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(cfg.Users))
	}
	if cfg.Users["admin"].Password != "supersecret" {
		t.Errorf("admin user pass mismatch")
	}
	if len(cfg.Users["traefik"].AllowedSubdomains) != 2 {
		t.Errorf("expected 2 allowed subdomains for traefik, got %d", len(cfg.Users["traefik"].AllowedSubdomains))
	}
}

func TestLoadFromEnv_StructuredJSONUsers(t *testing.T) {
	clearEnv()
	defer clearEnv()

	os.Setenv("CLOUDFLARE_API_TOKEN", "test-token")
	os.Setenv("ALLOWED_DOMAIN", "firpic.fr")
	os.Setenv("USERS", `{"traefik_dmz":{"password":"secret","allowed_subdomains":["*.dmz.firpic.fr","dmz.firpic.fr"]}}`)

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	u, ok := cfg.Users["traefik_dmz"]
	if !ok {
		t.Fatalf("expected traefik_dmz in users")
	}
	if u.Password != "secret" {
		t.Errorf("expected password 'secret', got %s", u.Password)
	}
	if len(u.AllowedSubdomains) != 2 || u.AllowedSubdomains[0] != "*.dmz.firpic.fr" {
		t.Errorf("unexpected allowed subdomains: %v", u.AllowedSubdomains)
	}
}

func TestLoadFromEnv_TokenFileFallback(t *testing.T) {
	clearEnv()
	defer clearEnv()

	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "cf_token")
	if err := os.WriteFile(tokenFile, []byte("token-from-file\n"), 0600); err != nil {
		t.Fatalf("failed to write token file: %v", err)
	}

	os.Setenv("CLOUDFLARE_API_TOKEN_FILE", tokenFile)
	os.Setenv("ALLOWED_DOMAIN", "firpic.fr")
	os.Setenv("USER_TRAEFIK_DMZ_PASS", "pass123")
	os.Setenv("USER_TRAEFIK_DMZ_SUBDOMAINS", "*.dmz.firpic.fr,dmz.firpic.fr")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.CloudflareAPIToken != "token-from-file" {
		t.Errorf("expected token from file 'token-from-file', got %s", cfg.CloudflareAPIToken)
	}
	u := cfg.Users["traefik_dmz"]
	if u.Password != "pass123" {
		t.Errorf("expected password pass123")
	}
	if len(u.AllowedSubdomains) != 2 {
		t.Errorf("expected 2 subdomains from USER_TRAEFIK_DMZ_SUBDOMAINS, got %v", u.AllowedSubdomains)
	}
}
