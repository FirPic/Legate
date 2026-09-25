package config

import (
	"fmt"
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
	os.Unsetenv("TEST_CF_TOKEN")
	os.Unsetenv("TEST_IONOS_KEY")
	os.Unsetenv("TEST_INFOMANIAK_TOKEN")
}

const (
	testArgonHash1 = "$argon2id$v=19$m=65536,t=3,p=2$dGVzdHNhbHQxMjM0NTY3OA$B2WvM8iL+9wKqF2l6X2pY1z8v0s3j4h5g6f7e8d9c0b"
	testArgonHash2 = "$argon2id$v=19$m=65536,t=3,p=2$ZHZ1bmtsZXZhbGlkc2FsdA$YnlF0zPsh8H3R3m5x/l5g8B4o2gC7f6Q9r8u1v2w3x4"
)

func TestLoadFromEnv_Success(t *testing.T) {
	clearEnv()
	defer clearEnv()

	os.Setenv("CLOUDFLARE_API_TOKEN", "test-token")
	os.Setenv("ALLOWED_DOMAIN", "firpic.fr")
	os.Setenv("USERS", "admin:"+testArgonHash1+":*,traefik:"+testArgonHash2+":*.dmz.firpic.fr;dmz.firpic.fr")
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
	if cfg.Users["admin"].Password != testArgonHash1 {
		t.Errorf("admin user pass mismatch")
	}
	if len(cfg.Users["traefik"].AllowedSubdomains) != 2 {
		t.Errorf("expected 2 allowed subdomains for traefik, got %d", len(cfg.Users["traefik"].AllowedSubdomains))
	}

	// Verify BuildRegistry works on env-loaded config
	reg, err := cfg.BuildRegistry(nil)
	if err != nil {
		t.Fatalf("unexpected error building registry from env config: %v", err)
	}
	if reg.Count() != 1 {
		t.Errorf("expected 1 registered domain, got %d", reg.Count())
	}
}

func TestLoadFromEnv_StructuredJSONUsers(t *testing.T) {
	clearEnv()
	defer clearEnv()

	os.Setenv("CLOUDFLARE_API_TOKEN", "test-token")
	os.Setenv("ALLOWED_DOMAIN", "firpic.fr")
	os.Setenv("USERS", fmt.Sprintf(`{"traefik_dmz":{"password_hash":%q,"allowed_subdomains":["*.dmz.firpic.fr","dmz.firpic.fr"]}}`, testArgonHash1))

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	u, ok := cfg.Users["traefik_dmz"]
	if !ok {
		t.Fatalf("expected traefik_dmz in users")
	}
	if u.Password != testArgonHash1 {
		t.Errorf("expected password %q, got %s", testArgonHash1, u.Password)
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
	os.Setenv("USER_TRAEFIK_DMZ_PASS", testArgonHash1)
	os.Setenv("USER_TRAEFIK_DMZ_SUBDOMAINS", "*.dmz.firpic.fr,dmz.firpic.fr")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.CloudflareAPIToken != "token-from-file" {
		t.Errorf("expected token from file 'token-from-file', got %s", cfg.CloudflareAPIToken)
	}
	u := cfg.Users["traefik_dmz"]
	if u.Password != testArgonHash1 {
		t.Errorf("expected password %q, got %q", testArgonHash1, u.Password)
	}
	if len(u.AllowedSubdomains) != 2 {
		t.Errorf("expected 2 subdomains from USER_TRAEFIK_DMZ_SUBDOMAINS, got %v", u.AllowedSubdomains)
	}
}

func TestLoadFromFile_YAMLWithEnvExpansion(t *testing.T) {
	clearEnv()
	defer clearEnv()

	os.Setenv("TEST_CF_TOKEN", "expanded-cf-token")
	os.Setenv("TEST_IONOS_KEY", "prefix.expanded-ionos-key")
	os.Setenv("TEST_INFOMANIAK_TOKEN", "expanded-infomaniak-token")

	yamlContent := `
server:
  port: "8085"
  bind_addr: "127.0.0.1"
  admin_port: "9095"
  admin_bind_addr: "127.0.0.1"
  rate_limit_per_minute: 100
  log_level: "debug"

providers:
  my-cloudflare:
    type: cloudflare
    api_token: "${TEST_CF_TOKEN}"
    zone_id: "cf-zone-id"

  my-ionos:
    type: ionos
    api_key: "${TEST_IONOS_KEY}"

  my-infomaniak:
    type: infomaniak
    api_token: "${TEST_INFOMANIAK_TOKEN}"

domains:
  example.com:
    provider: my-cloudflare
  mondomaine.fr:
    provider: my-ionos
  entreprise.ch:
    provider: my-infomaniak

users:
  traefik:
    password_hash: "$argon2id$v=19$m=65536,t=3,p=2$ZHZ1bmtsZXZhbGlkc2FsdA$YnlF0zPsh8H3R3m5x/l5g8B4o2gC7f6Q9r8u1v2w3x4"
    allowed_subdomains: ["*.example.com", "*.mondomaine.fr"]
  caddy_argon:
    password_hash: "$argon2id$v=19$m=65536,t=3,p=2$dGVzdHNhbHQxMjM0NTY3OA$B2WvM8iL+9wKqF2l6X2pY1z8v0s3j4h5g6f7e8d9c0b"
    allowed_subdomains: ["*.entreprise.ch"]
`
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configFile, []byte(yamlContent), 0600); err != nil {
		t.Fatalf("failed to write test yaml: %v", err)
	}

	cfg, err := Load(configFile)
	if err != nil {
		t.Fatalf("unexpected LoadFromFile error: %v", err)
	}

	if cfg.Server.Port != "8085" || cfg.Port != "8085" {
		t.Errorf("expected port 8085, got %s / %s", cfg.Server.Port, cfg.Port)
	}
	if cfg.Server.RateLimitPerMinute != 100 {
		t.Errorf("expected rate limit 100, got %d", cfg.Server.RateLimitPerMinute)
	}

	// Verify secret expansion
	if cfg.Providers["my-cloudflare"].APIToken != "expanded-cf-token" {
		t.Errorf("expected CF token 'expanded-cf-token', got %q", cfg.Providers["my-cloudflare"].APIToken)
	}
	if cfg.Providers["my-ionos"].APIKey != "prefix.expanded-ionos-key" {
		t.Errorf("expected IONOS key 'prefix.expanded-ionos-key', got %q", cfg.Providers["my-ionos"].APIKey)
	}
	if cfg.Providers["my-infomaniak"].APIToken != "expanded-infomaniak-token" {
		t.Errorf("expected Infomaniak token 'expanded-infomaniak-token', got %q", cfg.Providers["my-infomaniak"].APIToken)
	}

	// Verify literal $ in Argon2id hash was strictly preserved and NOT mangled by env expansion
	expectedArgon := "$argon2id$v=19$m=65536,t=3,p=2$dGVzdHNhbHQxMjM0NTY3OA$B2WvM8iL+9wKqF2l6X2pY1z8v0s3j4h5g6f7e8d9c0b"
	if cfg.Users["caddy_argon"].Password != expectedArgon {
		t.Errorf("Argon2id hash was mangled by env expansion: expected %q, got %q", expectedArgon, cfg.Users["caddy_argon"].Password)
	}

	// Verify Registry building
	reg, err := cfg.BuildRegistry(nil)
	if err != nil {
		t.Fatalf("unexpected error building registry: %v", err)
	}

	if reg.Count() != 3 {
		t.Fatalf("expected 3 registered domains in registry, got %d", reg.Count())
	}

	// Check domain resolution for all 3
	_, base, err := reg.Resolve("_acme-challenge.sub.example.com")
	if err != nil || base != "example.com" {
		t.Errorf("expected example.com, got %q, err: %v", base, err)
	}

	_, base, err = reg.Resolve("_acme-challenge.app.mondomaine.fr")
	if err != nil || base != "mondomaine.fr" {
		t.Errorf("expected mondomaine.fr, got %q, err: %v", base, err)
	}

	_, base, err = reg.Resolve("_acme-challenge.vpn.entreprise.ch")
	if err != nil || base != "entreprise.ch" {
		t.Errorf("expected entreprise.ch, got %q, err: %v", base, err)
	}
}

func TestLoadFromFile_ValidationErrors(t *testing.T) {
	clearEnv()
	defer clearEnv()

	tmpDir := t.TempDir()

	// Missing provider
	yamlMissingProvider := `
server:
  port: "8080"
providers: {}
domains: {}
`
	f1 := filepath.Join(tmpDir, "c1.yaml")
	_ = os.WriteFile(f1, []byte(yamlMissingProvider), 0600)
	if _, err := LoadFromFile(f1); err == nil {
		t.Errorf("expected error for empty providers")
	}

	// Domain referencing non-existent provider
	yamlBadRef := `
server:
  port: "8080"
providers:
  cf:
    type: cloudflare
    api_token: "tok"
domains:
  example.com:
    provider: non-existent-provider
users:
  u:
    password: "p"
    allowed_subdomains: ["*"]
`
	f2 := filepath.Join(tmpDir, "c2.yaml")
	_ = os.WriteFile(f2, []byte(yamlBadRef), 0600)
	if _, err := LoadFromFile(f2); err == nil {
		t.Errorf("expected error for non-existent provider reference")
	}

	// Missing allowed_subdomains rejected (Fail-Closed)
	yamlMissingSubdomains := `
server:
  port: "8080"
providers:
  cf:
    type: cloudflare
    api_token: "tok"
domains:
  example.com:
    provider: cf
users:
  u:
    password: "p"
`
	fMissingSub := filepath.Join(tmpDir, "c_missing_sub.yaml")
	_ = os.WriteFile(fMissingSub, []byte(yamlMissingSubdomains), 0600)
	if _, err := LoadFromFile(fMissingSub); err == nil {
		t.Errorf("expected error for user with missing allowed_subdomains")
	}

	// Unknown provider type
	yamlBadType := `
server:
  port: "8080"
providers:
  bad:
    type: unknown-provider-xyz
    api_token: "tok"
domains:
  example.com:
    provider: bad
users:
  u:
    password: "p"
    allowed_subdomains: ["*"]
`
	f3 := filepath.Join(tmpDir, "c3.yaml")
	_ = os.WriteFile(f3, []byte(yamlBadType), 0600)
	if _, err := LoadFromFile(f3); err == nil {
		t.Errorf("expected error for unknown provider type")
	}

	// Insecure remote HTTP base_url rejected
	yamlInsecureURL := `
server:
  port: "8080"
providers:
  cf:
    type: cloudflare
    api_token: "tok"
    base_url: "http://api.cloudflare.com/client/v4"
domains:
  example.com:
    provider: cf
users:
  u:
    password: "p"
    allowed_subdomains: ["*"]
`
	f4 := filepath.Join(tmpDir, "c4.yaml")
	_ = os.WriteFile(f4, []byte(yamlInsecureURL), 0600)
	if _, err := LoadFromFile(f4); err == nil {
		t.Errorf("expected error for insecure remote http base_url")
	}

	// Incomplete TLS config rejected
	yamlPartialTLS := `
server:
  port: "8080"
  tls_cert_file: "/path/to/cert.pem"
providers:
  cf:
    type: cloudflare
    api_token: "tok"
domains:
  example.com:
    provider: cf
users:
  u:
    password: "p"
    allowed_subdomains: ["*"]
`
	f5 := filepath.Join(tmpDir, "c5.yaml")
	_ = os.WriteFile(f5, []byte(yamlPartialTLS), 0600)
	if _, err := LoadFromFile(f5); err == nil {
		t.Errorf("expected error for partial TLS configuration")
	}

	// Valid TLS files populated
	dummyCert := filepath.Join(tmpDir, "cert.pem")
	dummyKey := filepath.Join(tmpDir, "key.pem")
	_ = os.WriteFile(dummyCert, []byte("dummy cert"), 0600)
	_ = os.WriteFile(dummyKey, []byte("dummy key"), 0600)

	yamlValidTLS := fmt.Sprintf(`
server:
  port: "8443"
  tls_cert_file: %q
  tls_key_file: %q
providers:
  cf:
    type: cloudflare
    api_token: "tok"
domains:
  example.com:
    provider: cf
users:
  u:
    password_hash: %q
    allowed_subdomains: ["*"]
`, dummyCert, dummyKey, testArgonHash1)
	f6 := filepath.Join(tmpDir, "c6.yaml")
	_ = os.WriteFile(f6, []byte(yamlValidTLS), 0600)
	cfgValidTLS, err := LoadFromFile(f6)
	if err != nil {
		t.Fatalf("unexpected error for valid TLS configuration: %v", err)
	}
	if cfgValidTLS.TLSCertFile != dummyCert || cfgValidTLS.TLSKeyFile != dummyKey {
		t.Errorf("expected TLS files populated on cfg, got cert=%q, key=%q", cfgValidTLS.TLSCertFile, cfgValidTLS.TLSKeyFile)
	}
}

func TestLoadFromFile_FileSecrets_Success(t *testing.T) {
	clearEnv()
	defer clearEnv()

	tmpDir := t.TempDir()
	cfTokenFile := filepath.Join(tmpDir, "cf_token")
	ionosKeyFile := filepath.Join(tmpDir, "ionos_key")
	userPassFile := filepath.Join(tmpDir, "traefik_pass")

	_ = os.WriteFile(cfTokenFile, []byte("  secret-cf-token-from-file  \n"), 0600)
	_ = os.WriteFile(ionosKeyFile, []byte("  secret-ionos-key-from-file \n"), 0600)
	_ = os.WriteFile(userPassFile, []byte(testArgonHash1+"\n"), 0600)

	yamlContent := fmt.Sprintf(`
server:
  port: "8080"
providers:
  my-cf:
    type: cloudflare
    api_token_file: %q
  my-ionos:
    type: ionos
    api_key_file: %q
domains:
  example.com:
    provider: my-cf
  example.org:
    provider: my-ionos
users:
  traefik:
    password_hash_file: %q
    allowed_subdomains: ["*"]
`, cfTokenFile, ionosKeyFile, userPassFile)

	f := filepath.Join(tmpDir, "config_files.yaml")
	_ = os.WriteFile(f, []byte(yamlContent), 0600)

	cfg, err := LoadFromFile(f)
	if err != nil {
		t.Fatalf("unexpected error loading config with file secrets: %v", err)
	}

	if cfg.Providers["my-cf"].APIToken != "secret-cf-token-from-file" {
		t.Errorf("expected cf token 'secret-cf-token-from-file', got %q", cfg.Providers["my-cf"].APIToken)
	}
	if cfg.Providers["my-ionos"].APIKey != "secret-ionos-key-from-file" {
		t.Errorf("expected ionos key 'secret-ionos-key-from-file', got %q", cfg.Providers["my-ionos"].APIKey)
	}
	if cfg.Users["traefik"].Password != testArgonHash1 {
		t.Errorf("expected user pass %q, got %q", testArgonHash1, cfg.Users["traefik"].Password)
	}
}

func TestLoadFromFile_MutualExclusion(t *testing.T) {
	clearEnv()
	defer clearEnv()

	tmpDir := t.TempDir()
	dummyFile := filepath.Join(tmpDir, "dummy")
	_ = os.WriteFile(dummyFile, []byte("val"), 0600)

	// Both api_token and api_token_file
	yamlDualToken := fmt.Sprintf(`
server:
  port: "8080"
providers:
  cf:
    type: cloudflare
    api_token: "direct-token"
    api_token_file: %q
domains:
  example.com:
    provider: cf
users:
  u:
    password_hash: %q
    allowed_subdomains: ["*"]
`, dummyFile, testArgonHash1)

	f1 := filepath.Join(tmpDir, "c_dual.yaml")
	_ = os.WriteFile(f1, []byte(yamlDualToken), 0600)
	if _, err := LoadFromFile(f1); err == nil {
		t.Errorf("expected error when both api_token and api_token_file are specified")
	}

	// Plaintext password rejected
	yamlPlainPass := `
server:
  port: "8080"
providers:
  cf:
    type: cloudflare
    api_token: "direct-token"
domains:
  example.com:
    provider: cf
users:
  u:
    password_hash: "PlaintextInPasswordHash"
    allowed_subdomains: ["*"]
`
	f2 := filepath.Join(tmpDir, "c_plain.yaml")
	_ = os.WriteFile(f2, []byte(yamlPlainPass), 0600)
	if _, err := LoadFromFile(f2); err == nil {
		t.Errorf("expected error when plaintext password is used")
	}
}
