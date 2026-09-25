package ionos

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/FirPic/legate/internal/provider"
)

// Ensure Client satisfies provider.DNSProvider.
var _ provider.DNSProvider = (*Client)(nil)

// Observer allows external packages to record provider metrics.
type Observer interface {
	ObserveDNSRequest(providerName, endpoint, status string)
}

// Client implements provider.DNSProvider using the IONOS Developer DNS API v1.
type Client struct {
	baseURL       string
	apiKey        string
	allowedDomain string
	httpClient    *http.Client
	observer      Observer

	cacheMu sync.RWMutex
	zoneMap map[string]string
}

// NewClient creates an initialized IONOS DNS provider client.
func NewClient(apiKey, allowedDomain string, customBaseURL ...string) *Client {
	baseURL := "https://api.hosting.ionos.com/dns/v1"
	if len(customBaseURL) > 0 && customBaseURL[0] != "" {
		baseURL = strings.TrimRight(customBaseURL[0], "/")
	}

	normDomain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(allowedDomain), "."))

	return &Client{
		baseURL:       baseURL,
		apiKey:        strings.TrimSpace(apiKey),
		allowedDomain: normDomain,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		zoneMap: make(map[string]string),
	}
}

// SetObserver sets an observer to record request metrics.
func (c *Client) SetObserver(obs Observer) {
	c.observer = obs
}

// SetZoneID allows pre-seeding the zone ID cache for a domain.
func (c *Client) SetZoneID(domain, zoneID string) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	norm := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	c.zoneMap[norm] = strings.TrimSpace(zoneID)
}

// Present creates an ACME TXT record in IONOS DNS.
func (c *Client) Present(ctx context.Context, fqdn, value string) (string, error) {
	zoneID, err := c.GetZoneID(ctx, c.allowedDomain)
	if err != nil {
		return "", fmt.Errorf("resolve ionos zone id: %w", err)
	}

	return c.CreateTXTRecord(ctx, zoneID, fqdn, value)
}

// Cleanup removes an ACME TXT record from IONOS DNS.
func (c *Client) Cleanup(ctx context.Context, fqdn, recordID, value string) error {
	zoneID, err := c.GetZoneID(ctx, c.allowedDomain)
	if err != nil {
		return fmt.Errorf("resolve ionos zone id: %w", err)
	}

	targetRecordID := strings.TrimSpace(recordID)
	if targetRecordID == "" {
		foundID, errFind := c.FindTXTRecord(ctx, zoneID, fqdn, value)
		if errFind != nil {
			return fmt.Errorf("locate ionos txt record: %w", errFind)
		}
		targetRecordID = foundID
	}

	if targetRecordID == "" {
		// Record does not exist or was already removed
		return nil
	}

	return c.DeleteTXTRecord(ctx, zoneID, targetRecordID)
}

type ionosZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

type ionosRecordItem struct {
	ID       string `json:"id,omitempty"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
	Prio     int    `json:"prio"`
	Disabled bool   `json:"disabled"`
}

type ionosZoneDetails struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Records []ionosRecordItem `json:"records"`
}

// GetZoneID retrieves the IONOS zone ID for a domain name.
func (c *Client) GetZoneID(ctx context.Context, zoneName string) (string, error) {
	normZone := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zoneName), "."))

	c.cacheMu.RLock()
	cachedID, found := c.zoneMap[normZone]
	c.cacheMu.RUnlock()
	if found && cachedID != "" {
		return cachedID, nil
	}

	endpoint := fmt.Sprintf("%s/zones", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("create ionos zones request: %w", err)
	}

	var zones []ionosZone
	if err := c.doRequest(req, "zones", &zones); err != nil {
		return "", fmt.Errorf("get ionos zones: %w", err)
	}

	for _, z := range zones {
		normZ := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(z.Name), "."))
		if normZ == normZone {
			c.cacheMu.Lock()
			c.zoneMap[normZone] = z.ID
			c.cacheMu.Unlock()
			return z.ID, nil
		}
	}

	return "", fmt.Errorf("zone %q not found in IONOS account", normZone)
}

// CreateTXTRecord creates a TXT record in the given zone.
func (c *Client) CreateTXTRecord(ctx context.Context, zoneID, fqdn, value string) (string, error) {
	normFQDN := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))

	records := []ionosRecordItem{
		{
			Name:     normFQDN,
			Type:     "TXT",
			Content:  value,
			TTL:      120,
			Prio:     0,
			Disabled: false,
		},
	}

	payload, err := json.Marshal(records)
	if err != nil {
		return "", fmt.Errorf("marshal ionos record: %w", err)
	}

	endpoint := fmt.Sprintf("%s/zones/%s/records", c.baseURL, url.PathEscape(zoneID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("create ionos record request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	var createdRecords []ionosRecordItem
	if err := c.doRequest(req, "records_create", &createdRecords); err != nil {
		return "", fmt.Errorf("create ionos txt record for %q: %w", normFQDN, err)
	}

	if len(createdRecords) == 0 || createdRecords[0].ID == "" {
		return "", errors.New("ionos returned empty record ID upon creation")
	}

	return createdRecords[0].ID, nil
}

// DeleteTXTRecord removes a record by ID.
func (c *Client) DeleteTXTRecord(ctx context.Context, zoneID, recordID string) error {
	endpoint := fmt.Sprintf("%s/zones/%s/records/%s", c.baseURL, url.PathEscape(zoneID), url.PathEscape(recordID))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return fmt.Errorf("create ionos delete request: %w", err)
	}

	if err := c.doRequest(req, "records_delete", nil); err != nil {
		return fmt.Errorf("delete ionos record %q: %w", recordID, err)
	}

	return nil
}

// FindTXTRecord searches for an existing TXT record matching fqdn and value.
func (c *Client) FindTXTRecord(ctx context.Context, zoneID, fqdn, value string) (string, error) {
	normFQDN := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))

	endpoint := fmt.Sprintf("%s/zones/%s?recordName=%s&recordType=TXT",
		c.baseURL,
		url.PathEscape(zoneID),
		url.QueryEscape(normFQDN),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("create ionos find record request: %w", err)
	}

	var details ionosZoneDetails
	if err := c.doRequest(req, "records_find", &details); err != nil {
		return "", fmt.Errorf("find ionos records for %q: %w", normFQDN, err)
	}

	for _, rec := range details.Records {
		normName := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rec.Name), "."))
		// Content may or may not be quoted depending on IONOS API formatting
		cleanContent := strings.Trim(rec.Content, "\"")
		if rec.Type == "TXT" && normName == normFQDN && cleanContent == value {
			return rec.ID, nil
		}
	}

	return "", nil
}

func (c *Client) doRequest(req *http.Request, endpoint string, target interface{}) error {
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("User-Agent", "acme-dns-proxy/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if c.observer != nil {
			c.observer.ObserveDNSRequest("ionos", endpoint, "network_error")
		}
		return fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	statusStr := fmt.Sprintf("%d", resp.StatusCode)
	if c.observer != nil {
		c.observer.ObserveDNSRequest("ionos", endpoint, statusStr)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound && req.Method == http.MethodDelete {
		// Idempotent delete: already gone
		return nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ionos api error (status %d): %s", resp.StatusCode, string(body))
	}

	if target != nil && len(body) > 0 {
		if err := json.Unmarshal(body, target); err != nil {
			return fmt.Errorf("unmarshal ionos response: %w", err)
		}
	}

	return nil
}
