package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// Config holds the application configuration.
type Config struct {
	Port               string
	BindAddr           string
	CloudflareAPIToken string
	CloudflareZoneID   string
	AllowedDomain      string
	Users              map[string]string
	LogLevel           string
}

// LoadFromEnv loads and validates configuration from environment variables.
func LoadFromEnv() (*Config, error) {
	cfg := &Config{
		Port:               getEnv("PORT", "8080"),
		BindAddr:           getEnv("BIND_ADDR", "0.0.0.0"),
		CloudflareAPIToken: strings.TrimSpace(os.Getenv("CLOUDFLARE_API_TOKEN")),
		CloudflareZoneID:   strings.TrimSpace(os.Getenv("CLOUDFLARE_ZONE_ID")),
		AllowedDomain:      strings.TrimSpace(os.Getenv("ALLOWED_DOMAIN")),
		LogLevel:           strings.ToLower(getEnv("LOG_LEVEL", "info")),
		Users:              make(map[string]string),
	}

	// Validate Port
	portNum, err := strconv.Atoi(cfg.Port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return nil, fmt.Errorf("invalid PORT %q: must be between 1 and 65535", cfg.Port)
	}

	// Validate Cloudflare Token
	if cfg.CloudflareAPIToken == "" {
		return nil, errors.New("CLOUDFLARE_API_TOKEN is required")
	}

	// Validate Allowed Domain
	if cfg.AllowedDomain == "" {
		return nil, errors.New("ALLOWED_DOMAIN is required (e.g. 'firpic.fr')")
	}
	cfg.AllowedDomain = strings.ToLower(strings.TrimSuffix(cfg.AllowedDomain, "."))
	if strings.ContainsAny(cfg.AllowedDomain, " /\\:*?\"<>|") {
		return nil, fmt.Errorf("invalid ALLOWED_DOMAIN format %q", cfg.AllowedDomain)
	}

	// Load Users
	loadUsers(cfg.Users)
	if len(cfg.Users) == 0 {
		return nil, errors.New("no authorized users configured: set USERS (e.g. 'user:pass') or USER_<NAME>_PASS env variables")
	}

	return cfg, nil
}

// ListenAddr returns the formatted host:port string.
func (c *Config) ListenAddr() string {
	return net.JoinHostPort(c.BindAddr, c.Port)
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok && strings.TrimSpace(val) != "" {
		return strings.TrimSpace(val)
	}
	return fallback
}

func loadUsers(users map[string]string) {
	// 1. Check USERS environment variable
	if usersEnv := strings.TrimSpace(os.Getenv("USERS")); usersEnv != "" {
		if strings.HasPrefix(usersEnv, "{") {
			// Try JSON map
			var jsonMap map[string]string
			if err := json.Unmarshal([]byte(usersEnv), &jsonMap); err == nil {
				for u, p := range jsonMap {
					u = strings.TrimSpace(u)
					if u != "" && p != "" {
						users[u] = p
					}
				}
			}
		} else {
			// Comma separated list of user:pass
			pairs := strings.Split(usersEnv, ",")
			for _, pair := range pairs {
				pair = strings.TrimSpace(pair)
				if pair == "" {
					continue
				}
				parts := strings.SplitN(pair, ":", 2)
				if len(parts) == 2 {
					u := strings.TrimSpace(parts[0])
					p := parts[1]
					if u != "" && p != "" {
						users[u] = p
					}
				}
			}
		}
	}

	// 2. Check USER_<NAME>_PASS or USER_<NAME>_PASSWORD environment variables
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := parts[0], parts[1]
		if val == "" {
			continue
		}

		if strings.HasPrefix(key, "USER_") {
			var username string
			if strings.HasSuffix(key, "_PASS") {
				username = strings.TrimSuffix(strings.TrimPrefix(key, "USER_"), "_PASS")
			} else if strings.HasSuffix(key, "_PASSWORD") {
				username = strings.TrimSuffix(strings.TrimPrefix(key, "USER_"), "_PASSWORD")
			}

			if username != "" {
				// Convert USER_TRAEFIK_DMZ_PASS -> traefik_dmz
				u := strings.ToLower(username)
				users[u] = val
			}
		}
	}
}
