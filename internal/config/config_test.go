package config

import (
	"os"
	"testing"
)

func clearEnv() {
	os.Unsetenv("PORT")
	os.Unsetenv("BIND_ADDR")
	os.Unsetenv("CLOUDFLARE_API_TOKEN")
	os.Unsetenv("CLOUDFLARE_ZONE_ID")
	os.Unsetenv("ALLOWED_DOMAIN")
	os.Unsetenv("USERS")
	os.Unsetenv("LOG_LEVEL")
	os.Unsetenv("USER_TEST_PASS")
	os.Unsetenv("USER_TRAEFIK_DMZ_PASS")
}

func TestLoadFromEnv_Success(t *testing.T) {
	clearEnv()
	defer clearEnv()

	os.Setenv("CLOUDFLARE_API_TOKEN", "test-token")
	os.Setenv("ALLOWED_DOMAIN", "firpic.fr")
	os.Setenv("USERS", "admin:supersecret,traefik:anothersecret")
	os.Setenv("PORT", "9090")
	os.Setenv("BIND_ADDR", "127.0.0.1")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Port != "9090" {
		t.Errorf("expected port 9090, got %s", cfg.Port)
	}
	if cfg.ListenAddr() != "127.0.0.1:9090" {
		t.Errorf("expected listen addr 127.0.0.1:9090, got %s", cfg.ListenAddr())
	}
	if cfg.AllowedDomain != "firpic.fr" {
		t.Errorf("expected domain firpic.fr, got %s", cfg.AllowedDomain)
	}
	if len(cfg.Users) != 2 {
		t.Errorf("expected 2 users, got %d", len(cfg.Users))
	}
	if cfg.Users["admin"] != "supersecret" {
		t.Errorf("admin user pass mismatch")
	}
}

func TestLoadFromEnv_UserPrefixScan(t *testing.T) {
	clearEnv()
	defer clearEnv()

	os.Setenv("CLOUDFLARE_API_TOKEN", "test-token")
	os.Setenv("ALLOWED_DOMAIN", "firpic.fr.")
	os.Setenv("USER_TRAEFIK_DMZ_PASS", "pass123")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.AllowedDomain != "firpic.fr" {
		t.Errorf("expected trailing dot stripped, got %s", cfg.AllowedDomain)
	}
	if cfg.Users["traefik_dmz"] != "pass123" {
		t.Errorf("expected traefik_dmz user configured")
	}
}

func TestLoadFromEnv_JSONUsers(t *testing.T) {
	clearEnv()
	defer clearEnv()

	os.Setenv("CLOUDFLARE_API_TOKEN", "test-token")
	os.Setenv("ALLOWED_DOMAIN", "firpic.fr")
	os.Setenv("USERS", `{"bot":"secretbot"}`)

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Users["bot"] != "secretbot" {
		t.Errorf("expected bot user configured")
	}
}

func TestLoadFromEnv_ValidationErrors(t *testing.T) {
	clearEnv()
	defer clearEnv()

	// Missing token
	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("expected error on missing token")
	}

	// Missing domain
	os.Setenv("CLOUDFLARE_API_TOKEN", "token")
	_, err = LoadFromEnv()
	if err == nil {
		t.Fatal("expected error on missing domain")
	}

	// Missing users
	os.Setenv("ALLOWED_DOMAIN", "firpic.fr")
	_, err = LoadFromEnv()
	if err == nil {
		t.Fatal("expected error on missing users")
	}

	// Invalid Port
	os.Setenv("USERS", "u:p")
	os.Setenv("PORT", "invalid")
	_, err = LoadFromEnv()
	if err == nil {
		t.Fatal("expected error on invalid port")
	}
}
