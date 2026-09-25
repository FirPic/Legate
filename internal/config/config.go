package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
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
	Password          string   `yaml:"password" json:"password"`
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
	Type     string `yaml:"type" json:"type"` // "cloudflare", "ionos", "infomaniak"
	APIToken string `yaml:"api_token" json:"api_token"`
	APIKey   string `yaml:"api_key" json:"api_key"`
	ZoneID   string `yaml:"zone_id" json:"zone_id"`
	BaseURL  string `yaml:"base_url" json:"base_url"`
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

	// Expand ${VAR} and $VAR placeholders using environment variables
	expanded := os.ExpandEnv(string(raw))

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
		case "cloudflare":
			if pCfg.APIToken == "" {
				return nil, fmt.Errorf("provider %q (cloudflare): missing api_token", pName)
			}
		case "ionos":
			if pCfg.APIKey == "" {
				return nil, fmt.Errorf("provider %q (ionos): missing api_key", pName)
			}
		case "infomaniak":
			if pCfg.APIToken == "" {
				return nil, fmt.Errorf("provider %q (infomaniak): missing api_token", pName)
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
		loadUsers(cfg.Users)
	}

	if len(cfg.Users) == 0 {
		return nil, errors.New("no authorized users configured in config file or environment")
	}

	for u, uCfg := range cfg.Users {
		if strings.TrimSpace(uCfg.Password) == "" {
			return nil, fmt.Errorf("user %q has empty password", u)
		}
		if len(uCfg.AllowedSubdomains) == 0 {
			return nil, fmt.Errorf("user %q: allowed_subdomains cannot be empty (must specify explicit domain patterns, e.g. '*.example.com')", u)
		}
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

func loadCloudflareToken() string {
	if tokenFile := strings.TrimSpace(os.Getenv("CLOUDFLARE_API_TOKEN_FILE")); tokenFile != "" {
		content, err := os.ReadFile(tokenFile)
		if err == nil && len(strings.TrimSpace(string(content))) > 0 {
			return strings.TrimSpace(string(content))
		}
	}
	return strings.TrimSpace(os.Getenv("CLOUDFLARE_API_TOKEN"))
}

func loadUsers(users map[string]UserConfig) {
	if usersEnv := strings.TrimSpace(os.Getenv("USERS")); usersEnv != "" {
		if strings.HasPrefix(usersEnv, "{") {
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
