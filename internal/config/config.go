package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/FirPic/legate/internal/provider"
	"github.com/FirPic/legate/internal/provider/cloudflare"
	"github.com/FirPic/legate/internal/provider/infomaniak"
	"github.com/FirPic/legate/internal/provider/ionos"
	"gopkg.in/yaml.v3"
)

// UserConfig defines credentials and authorized subdomain patterns for an ACME client.
type UserConfig struct {
	Password          string   `yaml:"password,omitempty" json:"password,omitempty"`
	PasswordHash      string   `yaml:"password_hash,omitempty" json:"password_hash,omitempty"`
	PasswordHashFile  string   `yaml:"password_hash_file,omitempty" json:"password_hash_file,omitempty"`
	AllowedSubdomains []string `yaml:"allowed_subdomains" json:"allowed_subdomains"`
}

// ServerConfig defines HTTP and operational server parameters.
type ServerConfig struct {
	Port               string `yaml:"port" json:"port"`
	BindAddr           string `yaml:"bind_addr" json:"bind_addr"`
	AdminPort          string `yaml:"admin_port" json:"admin_port"`
	AdminBindAddr      string `yaml:"admin_bind_addr" json:"admin_bind_addr"`
	RateLimitPerMinute int    `yaml:"rate_limit_per_minute" json:"rate_limit_per_minute"`
	LogLevel           string `yaml:"log_level" json:"log_level"`
	TLSCertFile        string `yaml:"tls_cert_file" json:"tls_cert_file"`
	TLSKeyFile         string `yaml:"tls_key_file" json:"tls_key_file"`
}

// ProviderConfig defines parameters for a single DNS provider instance.
type ProviderConfig struct {
	Type         string `yaml:"type" json:"type"` // "cloudflare", "ionos", "infomaniak"
	APIToken     string `yaml:"api_token,omitempty" json:"api_token,omitempty"`
	APITokenFile string `yaml:"api_token_file,omitempty" json:"api_token_file,omitempty"`
	APIKey       string `yaml:"api_key,omitempty" json:"api_key,omitempty"`
	APIKeyFile   string `yaml:"api_key_file,omitempty" json:"api_key_file,omitempty"`
	ZoneID       string `yaml:"zone_id,omitempty" json:"zone_id,omitempty"`
	BaseURL      string `yaml:"base_url,omitempty" json:"base_url,omitempty"`
}

// DomainConfig binds a domain zone to a configured provider.
type DomainConfig struct {
	Provider string `yaml:"provider" json:"provider"`
}

// Config holds the full application configuration.
type Config struct {
	Server    ServerConfig              `yaml:"server" json:"server"`
	Providers map[string]ProviderConfig `yaml:"providers" json:"providers"`
	Domains   map[string]DomainConfig   `yaml:"domains" json:"domains"`
	Users     map[string]UserConfig     `yaml:"users" json:"users"`

	// Flat backward-compatibility fields (kept for env-only single provider mode)
	Port               string
	BindAddr           string
	AdminPort          string
	AdminBindAddr      string
	RateLimitPerMinute int
	CloudflareAPIToken string
	CloudflareZoneID   string
	AllowedDomain      string
	LogLevel           string
	TLSCertFile        string
	TLSKeyFile         string
}

// Load loads configuration from either a YAML file or environment variables.
// If configPath is specified (or CONFIG_FILE env var is set), it loads and parses the YAML file.
// Otherwise, it falls back to 100% backward-compatible environment variable loading.
func Load(configPath string) (*Config, error) {
	targetPath := strings.TrimSpace(configPath)
	if targetPath == "" {
		targetPath = strings.TrimSpace(os.Getenv("CONFIG_FILE"))
	}

	if targetPath != "" {
		return LoadFromFile(targetPath)
	}

	return LoadFromEnv()
}

// LoadFromFile reads and validates a YAML configuration file with environment variable expansion.
func LoadFromFile(filePath string) (*Config, error) {
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read config file %q: %w", filePath, err)
	}

	// Expand strictly ${VAR} placeholders using environment variables, preserving literal $ tokens (such as in Argon2id hashes)
	expanded := expandEnvStrict(string(raw))

	var fileCfg struct {
		Server    ServerConfig              `yaml:"server"`
		Providers map[string]ProviderConfig `yaml:"providers"`
		Domains   map[string]DomainConfig   `yaml:"domains"`
		Users     map[string]UserConfig     `yaml:"users"`
	}

	if err := yaml.Unmarshal([]byte(expanded), &fileCfg); err != nil {
		return nil, fmt.Errorf("parse config file %q: %w", filePath, err)
	}

	cfg := &Config{
		Server:    fileCfg.Server,
		Providers: fileCfg.Providers,
		Domains:   fileCfg.Domains,
		Users:     fileCfg.Users,
	}

	// Apply defaults for ServerConfig
	if cfg.Server.Port == "" {
		cfg.Server.Port = getEnv("PORT", "8080")
	}
	if cfg.Server.BindAddr == "" {
		cfg.Server.BindAddr = getEnv("BIND_ADDR", "0.0.0.0")
	}
	if cfg.Server.AdminPort == "" {
		cfg.Server.AdminPort = getEnv("ADMIN_PORT", "9090")
	}
	if cfg.Server.AdminBindAddr == "" {
		cfg.Server.AdminBindAddr = getEnv("ADMIN_BIND_ADDR", "127.0.0.1")
	}
	if cfg.Server.RateLimitPerMinute <= 0 {
		rateLimitStr := getEnv("RATE_LIMIT_PER_MINUTE", "60")
		if rl, err := strconv.Atoi(rateLimitStr); err == nil && rl > 0 {
			cfg.Server.RateLimitPerMinute = rl
		} else {
			cfg.Server.RateLimitPerMinute = 60
		}
	}
	if cfg.Server.LogLevel == "" {
		cfg.Server.LogLevel = strings.ToLower(getEnv("LOG_LEVEL", "info"))
	}

	// Validate ports
	portNum, err := strconv.Atoi(cfg.Server.Port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return nil, fmt.Errorf("invalid server port %q: must be between 1 and 65535", cfg.Server.Port)
	}

	if cfg.Server.AdminPort != "" {
		adminPortNum, err := strconv.Atoi(cfg.Server.AdminPort)
		if err != nil || adminPortNum < 1 || adminPortNum > 65535 {
			return nil, fmt.Errorf("invalid admin port %q: must be between 1 and 65535", cfg.Server.AdminPort)
		}
	}

	// Validate providers
	if len(cfg.Providers) == 0 {
		return nil, errors.New("no providers configured in config file")
	}

	for pName, pCfg := range cfg.Providers {
		pType := strings.ToLower(strings.TrimSpace(pCfg.Type))
		switch pType {
		case "cloudflare", "infomaniak":
			if pCfg.APIKey != "" || pCfg.APIKeyFile != "" {
				return nil, fmt.Errorf("provider %q (%s): unexpected api_key/api_key_file (uses api_token or api_token_file)", pName, pType)
			}
			if pCfg.APIToken != "" && pCfg.APITokenFile != "" {
				return nil, fmt.Errorf("provider %q (%s): cannot specify both api_token and api_token_file", pName, pType)
			}
			if pCfg.APITokenFile != "" {
				rawToken, err := os.ReadFile(pCfg.APITokenFile)
				if err != nil {
					return nil, fmt.Errorf("provider %q (%s): read api_token_file %q: %w", pName, pType, pCfg.APITokenFile, err)
				}
				trimmed := strings.TrimSpace(string(rawToken))
				if trimmed == "" {
					return nil, fmt.Errorf("provider %q (%s): api_token_file %q is empty", pName, pType, pCfg.APITokenFile)
				}
				pCfg.APIToken = trimmed
			}
			if pCfg.APIToken == "" {
				return nil, fmt.Errorf("provider %q (%s): missing api_token or api_token_file", pName, pType)
			}

		case "ionos":
			if pCfg.APIToken != "" || pCfg.APITokenFile != "" {
				return nil, fmt.Errorf("provider %q (ionos): unexpected api_token/api_token_file (uses api_key or api_key_file)", pName)
			}
			if pCfg.APIKey != "" && pCfg.APIKeyFile != "" {
				return nil, fmt.Errorf("provider %q (ionos): cannot specify both api_key and api_key_file", pName)
			}
			if pCfg.APIKeyFile != "" {
				rawKey, err := os.ReadFile(pCfg.APIKeyFile)
				if err != nil {
					return nil, fmt.Errorf("provider %q (ionos): read api_key_file %q: %w", pName, pCfg.APIKeyFile, err)
				}
				trimmed := strings.TrimSpace(string(rawKey))
				if trimmed == "" {
					return nil, fmt.Errorf("provider %q (ionos): api_key_file %q is empty", pName, pCfg.APIKeyFile)
				}
				pCfg.APIKey = trimmed
			}
			if pCfg.APIKey == "" {
				return nil, fmt.Errorf("provider %q (ionos): missing api_key or api_key_file", pName)
			}

		default:
			return nil, fmt.Errorf("provider %q has unsupported type %q (supported: cloudflare, ionos, infomaniak)", pName, pCfg.Type)
		}

		if pCfg.BaseURL != "" {
			u, err := url.Parse(pCfg.BaseURL)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
				return nil, fmt.Errorf("provider %q: invalid base_url %q", pName, pCfg.BaseURL)
			}
			if u.Scheme == "http" && u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" {
				return nil, fmt.Errorf("provider %q: base_url must use https scheme to protect API credentials (got %q)", pName, pCfg.BaseURL)
			}
		}

		cfg.Providers[pName] = pCfg
	}

	// Validate domains
	if len(cfg.Domains) == 0 {
		return nil, errors.New("no domains configured in config file")
	}

	for dName, dCfg := range cfg.Domains {
		normD := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(dName), "."))
		if normD == "" || strings.ContainsAny(normD, " /\\:*?\"<>|") {
			return nil, fmt.Errorf("invalid domain format %q in domains configuration", dName)
		}
		if dCfg.Provider == "" {
			return nil, fmt.Errorf("domain %q has no provider specified", dName)
		}
		if _, exists := cfg.Providers[dCfg.Provider]; !exists {
			return nil, fmt.Errorf("domain %q references undefined provider %q", dName, dCfg.Provider)
		}
	}

	// Validate users
	if len(cfg.Users) == 0 {
		// Allow loading users from environment fallback if not in file
		cfg.Users = make(map[string]UserConfig)
		if err := loadUsers(cfg.Users); err != nil {
			return nil, err
		}
	} else {
		for u, uCfg := range cfg.Users {
			hasHash := strings.TrimSpace(uCfg.PasswordHash) != ""
			hasPass := strings.TrimSpace(uCfg.Password) != ""
			hasFile := strings.TrimSpace(uCfg.PasswordHashFile) != ""

			if hasFile && (hasHash || hasPass) {
				return nil, fmt.Errorf("user %q: cannot specify both password_hash (or password) and password_hash_file", u)
			}
			if hasHash && hasPass && strings.TrimSpace(uCfg.PasswordHash) != strings.TrimSpace(uCfg.Password) {
				return nil, fmt.Errorf("user %q: cannot specify conflicting password and password_hash", u)
			}

			var hash string
			if hasFile {
				raw, err := os.ReadFile(uCfg.PasswordHashFile)
				if err != nil {
					return nil, fmt.Errorf("user %q: read password_hash_file %q: %w", u, uCfg.PasswordHashFile, err)
				}
				hash = strings.TrimSpace(string(raw))
				if hash == "" {
					return nil, fmt.Errorf("user %q: password_hash_file %q is empty", u, uCfg.PasswordHashFile)
				}
			} else if hasHash {
				hash = strings.TrimSpace(uCfg.PasswordHash)
			} else if hasPass {
				hash = strings.TrimSpace(uCfg.Password)
			}

			if hash == "" {
				return nil, fmt.Errorf("user %q: missing password_hash or password_hash_file", u)
			}

			if !strings.HasPrefix(hash, "$argon2id$") {
				return nil, fmt.Errorf("user %q: plaintext passwords are strictly forbidden. Must be a valid Argon2id hash ($argon2id$...) configured via 'password_hash' or 'password_hash_file'", u)
			}

			uCfg.PasswordHash = hash
			uCfg.Password = hash

			if len(uCfg.AllowedSubdomains) == 0 {
				return nil, fmt.Errorf("user %q: allowed_subdomains cannot be empty (must specify explicit domain patterns, e.g. '*.example.com')", u)
			}
			cfg.Users[u] = uCfg
		}
	}

	if len(cfg.Users) == 0 {
		return nil, errors.New("no authorized users configured in config file or environment")
	}

	// Validate TLS files if configured
	if cfg.Server.TLSCertFile != "" || cfg.Server.TLSKeyFile != "" {
		if cfg.Server.TLSCertFile == "" || cfg.Server.TLSKeyFile == "" {
			return nil, errors.New("both tls_cert_file and tls_key_file must be specified to enable TLS")
		}
		if _, err := os.Stat(cfg.Server.TLSCertFile); err != nil {
			return nil, fmt.Errorf("tls_cert_file %q not accessible: %w", cfg.Server.TLSCertFile, err)
		}
		if _, err := os.Stat(cfg.Server.TLSKeyFile); err != nil {
			return nil, fmt.Errorf("tls_key_file %q not accessible: %w", cfg.Server.TLSKeyFile, err)
		}
	}

	// Sync flat fields for backward compatibility
	cfg.syncFlatFields()

	return cfg, nil
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
		Providers:          make(map[string]ProviderConfig),
		Domains:            make(map[string]DomainConfig),
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

	// 3. Load Cloudflare Token
	var cfErr error
	cfg.CloudflareAPIToken, cfErr = loadCloudflareToken()
	if cfErr != nil {
		return nil, cfErr
	}
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
	if err := loadUsers(cfg.Users); err != nil {
		return nil, err
	}
	if len(cfg.Users) == 0 {
		return nil, errors.New("no authorized users configured: set USERS or USER_<NAME>_PASS env variables")
	}

	// 6. Optional TLS Configuration
	cfg.TLSCertFile = getEnv("TLS_CERT_FILE", "")
	cfg.TLSKeyFile = getEnv("TLS_KEY_FILE", "")
	if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			return nil, errors.New("both TLS_CERT_FILE and TLS_KEY_FILE must be specified to enable TLS")
		}
		if _, err := os.Stat(cfg.TLSCertFile); err != nil {
			return nil, fmt.Errorf("TLS_CERT_FILE %q not accessible: %w", cfg.TLSCertFile, err)
		}
		if _, err := os.Stat(cfg.TLSKeyFile); err != nil {
			return nil, fmt.Errorf("TLS_KEY_FILE %q not accessible: %w", cfg.TLSKeyFile, err)
		}
	}

	// Populate Server, Providers and Domains maps for uniform Registry building
	cfg.Server = ServerConfig{
		Port:               cfg.Port,
		BindAddr:           cfg.BindAddr,
		AdminPort:          cfg.AdminPort,
		AdminBindAddr:      cfg.AdminBindAddr,
		RateLimitPerMinute: cfg.RateLimitPerMinute,
		LogLevel:           cfg.LogLevel,
		TLSCertFile:        cfg.TLSCertFile,
		TLSKeyFile:         cfg.TLSKeyFile,
	}

	cfg.Providers["cloudflare-env"] = ProviderConfig{
		Type:     "cloudflare",
		APIToken: cfg.CloudflareAPIToken,
		ZoneID:   cfg.CloudflareZoneID,
	}

	cfg.Domains[cfg.AllowedDomain] = DomainConfig{
		Provider: "cloudflare-env",
	}

	return cfg, nil
}

func (c *Config) syncFlatFields() {
	c.Port = c.Server.Port
	c.BindAddr = c.Server.BindAddr
	c.AdminPort = c.Server.AdminPort
	c.AdminBindAddr = c.Server.AdminBindAddr
	c.RateLimitPerMinute = c.Server.RateLimitPerMinute
	c.LogLevel = c.Server.LogLevel
	c.TLSCertFile = c.Server.TLSCertFile
	c.TLSKeyFile = c.Server.TLSKeyFile

	// If there is only one domain, populate AllowedDomain for backward compatibility
	if len(c.Domains) == 1 {
		for d := range c.Domains {
			c.AllowedDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		}
	}
}

// BuildRegistry constructs and returns an initialized provider.Registry according to the configured domains and providers.
func (c *Config) BuildRegistry(obs any) (*provider.Registry, error) {
	reg := provider.NewRegistry()

	for domain, dCfg := range c.Domains {
		normDomain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
		pCfg, exists := c.Providers[dCfg.Provider]
		if !exists {
			return nil, fmt.Errorf("domain %q references undefined provider %q", normDomain, dCfg.Provider)
		}

		pType := strings.ToLower(strings.TrimSpace(pCfg.Type))
		var p provider.DNSProvider

		switch pType {
		case "cloudflare":
			var customBase []string
			if pCfg.BaseURL != "" {
				customBase = append(customBase, pCfg.BaseURL)
			}
			cfClient := cloudflare.NewClient(pCfg.APIToken, normDomain, customBase...)
			if pCfg.ZoneID != "" {
				cfClient.SetZoneID(normDomain, pCfg.ZoneID)
			}
			if observer, ok := obs.(cloudflare.Observer); ok {
				cfClient.SetObserver(observer)
			}
			p = cfClient

		case "ionos":
			var customBase []string
			if pCfg.BaseURL != "" {
				customBase = append(customBase, pCfg.BaseURL)
			}
			ioClient := ionos.NewClient(pCfg.APIKey, normDomain, customBase...)
			if pCfg.ZoneID != "" {
				ioClient.SetZoneID(normDomain, pCfg.ZoneID)
			}
			if observer, ok := obs.(ionos.Observer); ok {
				ioClient.SetObserver(observer)
			}
			p = ioClient

		case "infomaniak":
			var customBase []string
			if pCfg.BaseURL != "" {
				customBase = append(customBase, pCfg.BaseURL)
			}
			infoClient := infomaniak.NewClient(pCfg.APIToken, normDomain, customBase...)
			if observer, ok := obs.(infomaniak.Observer); ok {
				infoClient.SetObserver(observer)
			}
			p = infoClient

		default:
			return nil, fmt.Errorf("unsupported provider type %q for domain %q", pCfg.Type, normDomain)
		}

		if err := reg.Register(normDomain, p); err != nil {
			return nil, fmt.Errorf("register domain %q: %w", normDomain, err)
		}
	}

	return reg, nil
}

// ListenAddr returns the formatted host:port string for the public challenge API.
func (c *Config) ListenAddr() string {
	if c.Server.Port != "" {
		return net.JoinHostPort(c.Server.BindAddr, c.Server.Port)
	}
	return net.JoinHostPort(c.BindAddr, c.Port)
}

// AdminListenAddr returns the formatted host:port string for the internal admin API.
func (c *Config) AdminListenAddr() string {
	if c.Server.AdminPort != "" {
		return net.JoinHostPort(c.Server.AdminBindAddr, c.Server.AdminPort)
	}
	return net.JoinHostPort(c.AdminBindAddr, c.AdminPort)
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok && strings.TrimSpace(val) != "" {
		return strings.TrimSpace(val)
	}
	return fallback
}

func loadCloudflareToken() (string, error) {
	hasToken := strings.TrimSpace(os.Getenv("CLOUDFLARE_API_TOKEN")) != ""
	tokenFile := strings.TrimSpace(os.Getenv("CLOUDFLARE_API_TOKEN_FILE"))
	if hasToken && tokenFile != "" {
		return "", errors.New("cannot specify both CLOUDFLARE_API_TOKEN and CLOUDFLARE_API_TOKEN_FILE")
	}
	if tokenFile != "" {
		content, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", fmt.Errorf("read CLOUDFLARE_API_TOKEN_FILE %q: %w", tokenFile, err)
		}
		trimmed := strings.TrimSpace(string(content))
		if trimmed == "" {
			return "", fmt.Errorf("CLOUDFLARE_API_TOKEN_FILE %q is empty", tokenFile)
		}
		return trimmed, nil
	}
	return strings.TrimSpace(os.Getenv("CLOUDFLARE_API_TOKEN")), nil
}

func loadUsers(users map[string]UserConfig) error {
	if usersEnv := strings.TrimSpace(os.Getenv("USERS")); usersEnv != "" {
		if strings.HasPrefix(usersEnv, "{") {
			var structuredMap map[string]UserConfig
			if err := json.Unmarshal([]byte(usersEnv), &structuredMap); err == nil && len(structuredMap) > 0 {
				for u, cfg := range structuredMap {
					u = strings.ToLower(strings.TrimSpace(u))
					if u != "" {
						pass := strings.TrimSpace(cfg.PasswordHash)
						if pass == "" {
							pass = strings.TrimSpace(cfg.Password)
						}
						if pass == "" && cfg.PasswordHashFile != "" {
							raw, err := os.ReadFile(cfg.PasswordHashFile)
							if err != nil {
								return fmt.Errorf("user %q: read password_hash_file %q: %w", u, cfg.PasswordHashFile, err)
							}
							pass = strings.TrimSpace(string(raw))
						}
						if pass == "" {
							return fmt.Errorf("user %q: missing password_hash", u)
						}
						if !strings.HasPrefix(pass, "$argon2id$") {
							return fmt.Errorf("user %q: plaintext password in USERS is strictly forbidden; must be an Argon2id hash ($argon2id$...)", u)
						}
						cfg.PasswordHash = pass
						cfg.Password = pass
						if len(cfg.AllowedSubdomains) == 0 {
							cfg.AllowedSubdomains = []string{"*"}
						}
						users[u] = cfg
					}
				}
			} else {
				var flatMap map[string]string
				if err := json.Unmarshal([]byte(usersEnv), &flatMap); err == nil {
					for u, p := range flatMap {
						u = strings.ToLower(strings.TrimSpace(u))
						p = strings.TrimSpace(p)
						if u != "" && p != "" {
							if !strings.HasPrefix(p, "$argon2id$") {
								return fmt.Errorf("user %q: plaintext password in USERS is strictly forbidden; must be an Argon2id hash ($argon2id$...)", u)
							}
							users[u] = UserConfig{
								Password:          p,
								PasswordHash:      p,
								AllowedSubdomains: []string{"*"},
							}
						}
					}
				} else {
					return fmt.Errorf("invalid USERS JSON format: %w", err)
				}
			}
		} else {
			pairs := splitUserEntries(usersEnv)
			for _, pair := range pairs {
				pair = strings.TrimSpace(pair)
				if pair == "" {
					continue
				}
				parts := strings.Split(pair, ":")
				if len(parts) >= 2 {
					u := strings.ToLower(strings.TrimSpace(parts[0]))
					p := strings.TrimSpace(parts[1])
					if !strings.HasPrefix(p, "$argon2id$") {
						return fmt.Errorf("user %q: plaintext password in USERS is strictly forbidden; must be an Argon2id hash ($argon2id$...)", u)
					}
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
							PasswordHash:      p,
							AllowedSubdomains: subdomains,
						}
					}
				}
			}
		}
	}

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
			var isFile bool
			if strings.HasSuffix(key, "_PASS_FILE") {
				username = strings.TrimSuffix(strings.TrimPrefix(key, "USER_"), "_PASS_FILE")
				isFile = true
			} else if strings.HasSuffix(key, "_PASSWORD_FILE") {
				username = strings.TrimSuffix(strings.TrimPrefix(key, "USER_"), "_PASSWORD_FILE")
				isFile = true
			} else if strings.HasSuffix(key, "_PASS") {
				username = strings.TrimSuffix(strings.TrimPrefix(key, "USER_"), "_PASS")
			} else if strings.HasSuffix(key, "_PASSWORD") {
				username = strings.TrimSuffix(strings.TrimPrefix(key, "USER_"), "_PASSWORD")
			}

			if username != "" {
				u := strings.ToLower(username)
				var pass string
				if isFile {
					raw, err := os.ReadFile(val)
					if err != nil {
						return fmt.Errorf("user %q: read %s %q: %w", u, key, val, err)
					}
					pass = strings.TrimSpace(string(raw))
				} else {
					pass = strings.TrimSpace(val)
				}

				if !strings.HasPrefix(pass, "$argon2id$") {
					return fmt.Errorf("user %q: plaintext password in %s is strictly forbidden; must be an Argon2id hash ($argon2id$...)", u, key)
				}

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
					Password:          pass,
					PasswordHash:      pass,
					AllowedSubdomains: subdomains,
				}
			}
		}
	}

	return nil
}

var envPlaceholderRegex = regexp.MustCompile(`\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}`)

// expandEnvStrict replaces only ${VAR} placeholders with environment variables.
// Unescaped $ characters (such as $argon2id$v=19$...) are strictly preserved.
func expandEnvStrict(s string) string {
	return envPlaceholderRegex.ReplaceAllStringFunc(s, func(match string) string {
		varName := match[2 : len(match)-1]
		return os.Getenv(varName)
	})
}

// splitUserEntries splits a USERS string by comma or newline, safely ignoring commas
// that occur within Argon2id parameter segments (e.g. $m=65536,t=3,p=2$).
func splitUserEntries(s string) []string {
	var entries []string
	var current strings.Builder
	dollarCount := 0

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '$' {
			dollarCount++
			if dollarCount == 6 {
				dollarCount = 0
			}
		}

		// A comma is only a separator if we are not inside the argon2id parameters (between 3rd and 4th $)
		if (ch == ',' || ch == '\n') && dollarCount != 3 {
			if dollarCount >= 5 {
				dollarCount = 0
			}
			trimmed := strings.TrimSpace(current.String())
			if trimmed != "" {
				entries = append(entries, trimmed)
			}
			current.Reset()
			continue
		}

		current.WriteByte(ch)
	}

	trimmed := strings.TrimSpace(current.String())
	if trimmed != "" {
		entries = append(entries, trimmed)
	}
	return entries
}
