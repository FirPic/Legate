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

// UserConfig defines credentials and authorized subdomain patterns for an ACME client.
type UserConfig struct {
	Password          string   `json:"password"`
	AllowedSubdomains []string `json:"allowed_subdomains"`
}

// Config holds the application configuration.
type Config struct {
	Port                string
	BindAddr            string
	AdminPort           string
	AdminBindAddr       string
	RateLimitPerMinute  int
	CloudflareAPIToken  string
	CloudflareZoneID    string
	AllowedDomain       string
	Users               map[string]UserConfig
	LogLevel            string
}

// LoadFromEnv loads and validates configuration from environment variables and secret files.
func LoadFromEnv() (*Config, error) {
	rateLimitStr := getEnv("RATE_LIMIT_PER_MINUTE", "60")
	rateLimit, err := strconv.Atoi(rateLimitStr)
	if err != nil || rateLimit < 1 {
		return nil, fmt.Errorf("invalid RATE_LIMIT_PER_MINUTE %q: must be a positive integer", rateLimitStr)
	}

	cfg := &Config{
		Port:               getEnv("PORT", "8080"),
		BindAddr:           getEnv("BIND_ADDR", "0.0.0.0"),
		AdminPort:          getEnv("ADMIN_PORT", "9090"),
		AdminBindAddr:      getEnv("ADMIN_BIND_ADDR", "127.0.0.1"),
		RateLimitPerMinute: rateLimit,
		CloudflareZoneID:   strings.TrimSpace(os.Getenv("CLOUDFLARE_ZONE_ID")),
		AllowedDomain:      strings.TrimSpace(os.Getenv("ALLOWED_DOMAIN")),
		LogLevel:           strings.ToLower(getEnv("LOG_LEVEL", "info")),
		Users:              make(map[string]UserConfig),
	}

	// 1. Validate Challenge Service Port
	portNum, err := strconv.Atoi(cfg.Port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return nil, fmt.Errorf("invalid PORT %q: must be between 1 and 65535", cfg.Port)
	}

	// 2. Validate Admin Port
	if cfg.AdminPort != "" {
		adminPortNum, err := strconv.Atoi(cfg.AdminPort)
		if err != nil || adminPortNum < 1 || adminPortNum > 65535 {
			return nil, fmt.Errorf("invalid ADMIN_PORT %q: must be between 1 and 65535", cfg.AdminPort)
		}
	}

	// 3. Load Cloudflare Token (support file-based secret fallback)
	cfg.CloudflareAPIToken = loadCloudflareToken()
	if cfg.CloudflareAPIToken == "" {
		return nil, errors.New("CLOUDFLARE_API_TOKEN or CLOUDFLARE_API_TOKEN_FILE is required")
	}

	// 4. Validate Allowed Domain
	if cfg.AllowedDomain == "" {
		return nil, errors.New("ALLOWED_DOMAIN is required (e.g. 'firpic.fr')")
	}
	cfg.AllowedDomain = strings.ToLower(strings.TrimSuffix(cfg.AllowedDomain, "."))
	if strings.ContainsAny(cfg.AllowedDomain, " /\\:*?\"<>|") {
		return nil, fmt.Errorf("invalid ALLOWED_DOMAIN format %q", cfg.AllowedDomain)
	}

	// 5. Load Users and RBAC
	loadUsers(cfg.Users)
	if len(cfg.Users) == 0 {
		return nil, errors.New("no authorized users configured: set USERS or USER_<NAME>_PASS env variables")
	}

	return cfg, nil
}

// ListenAddr returns the formatted host:port string for the public challenge API.
func (c *Config) ListenAddr() string {
	return net.JoinHostPort(c.BindAddr, c.Port)
}

// AdminListenAddr returns the formatted host:port string for the internal admin API.
func (c *Config) AdminListenAddr() string {
	return net.JoinHostPort(c.AdminBindAddr, c.AdminPort)
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok && strings.TrimSpace(val) != "" {
		return strings.TrimSpace(val)
	}
	return fallback
}

func loadCloudflareToken() string {
	// 1. Check file-based secret (ANSSI BP-028 best practice to prevent /proc/$PID/environ leaks)
	if tokenFile := strings.TrimSpace(os.Getenv("CLOUDFLARE_API_TOKEN_FILE")); tokenFile != "" {
		content, err := os.ReadFile(tokenFile)
		if err == nil && len(strings.TrimSpace(string(content))) > 0 {
			return strings.TrimSpace(string(content))
		}
	}
	// 2. Direct environment variable
	return strings.TrimSpace(os.Getenv("CLOUDFLARE_API_TOKEN"))
}

func loadUsers(users map[string]UserConfig) {
	// 1. Check USERS environment variable
	if usersEnv := strings.TrimSpace(os.Getenv("USERS")); usersEnv != "" {
		if strings.HasPrefix(usersEnv, "{") {
			// Try parsing as JSON UserConfig map: {"traefik":{"password":"...","allowed_subdomains":[...]}}
			var structuredMap map[string]UserConfig
			if err := json.Unmarshal([]byte(usersEnv), &structuredMap); err == nil && len(structuredMap) > 0 {
				for u, cfg := range structuredMap {
					u = strings.ToLower(strings.TrimSpace(u))
					if u != "" && cfg.Password != "" {
						if len(cfg.AllowedSubdomains) == 0 {
							cfg.AllowedSubdomains = []string{"*"}
						}
						users[u] = cfg
					}
				}
			} else {
				// Fallback: simple flat JSON map: {"traefik":"password"}
				var flatMap map[string]string
				if err := json.Unmarshal([]byte(usersEnv), &flatMap); err == nil {
					for u, p := range flatMap {
						u = strings.ToLower(strings.TrimSpace(u))
						if u != "" && p != "" {
							users[u] = UserConfig{
								Password:          p,
								AllowedSubdomains: []string{"*"},
							}
						}
					}
				}
			}
		} else {
			// Comma separated list of user:pass or user:pass:subdomain1;subdomain2
			pairs := strings.Split(usersEnv, ",")
			for _, pair := range pairs {
				pair = strings.TrimSpace(pair)
				if pair == "" {
					continue
				}
				parts := strings.Split(pair, ":")
				if len(parts) >= 2 {
					u := strings.ToLower(strings.TrimSpace(parts[0]))
					p := parts[1]
					subdomains := []string{"*"}
					if len(parts) >= 3 && strings.TrimSpace(parts[2]) != "" {
						rawSubs := strings.Split(parts[2], ";")
						subdomains = make([]string, 0, len(rawSubs))
						for _, s := range rawSubs {
							s = strings.TrimSpace(s)
							if s != "" {
								subdomains = append(subdomains, s)
							}
						}
					}
					if u != "" && p != "" {
						users[u] = UserConfig{
							Password:          p,
							AllowedSubdomains: subdomains,
						}
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
				u := strings.ToLower(username)
				// Check if USER_<NAME>_SUBDOMAINS is defined
				subdomains := []string{"*"}
				if subEnv := os.Getenv("USER_" + username + "_SUBDOMAINS"); strings.TrimSpace(subEnv) != "" {
					rawSubs := strings.Split(subEnv, ",")
					subdomains = make([]string, 0, len(rawSubs))
					for _, s := range rawSubs {
						s = strings.TrimSpace(s)
						if s != "" {
							subdomains = append(subdomains, s)
						}
					}
				}

				users[u] = UserConfig{
					Password:          val,
					AllowedSubdomains: subdomains,
				}
			}
		}
	}
}
