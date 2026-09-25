package cloudflare

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

// Observer allows external packages (e.g., Prometheus metrics) to observe API requests.
type Observer interface {
	ObserveCloudflareRequest(endpoint, status string)
}

// Client implements provider.DNSProvider using Cloudflare REST API v4.
type Client struct {
	baseURL       string
	apiToken      string
	allowedDomain string
	httpClient    *http.Client
	observer      Observer

	cacheMu sync.RWMutex
	zoneMap map[string]string
}

// NewClient creates an initialized Cloudflare DNS provider client.
func NewClient(apiToken, allowedDomain string, customBaseURL ...string) *Client {
	baseURL := "https://api.cloudflare.com/client/v4"
	if len(customBaseURL) > 0 && customBaseURL[0] != "" {
		baseURL = strings.TrimRight(customBaseURL[0], "/")
	}

	normDomain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(allowedDomain), "."))

	return &Client{
		baseURL:       baseURL,
		apiToken:      apiToken,
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

// Present implements provider.DNSProvider. It ensures the TXT challenge record is published.
func (c *Client) Present(ctx context.Context, fqdn, value string) (string, error) {
	zoneID, err := c.GetZoneID(ctx, c.allowedDomain)
	if err != nil {
		return "", fmt.Errorf("resolve zone id: %w", err)
	}

	return c.CreateTXTRecord(ctx, zoneID, fqdn, value)
}

// Cleanup implements provider.DNSProvider. It deletes the TXT challenge record.
func (c *Client) Cleanup(ctx context.Context, fqdn, recordID, value string) error {
	zoneID, err := c.GetZoneID(ctx, c.allowedDomain)
	if err != nil {
		return fmt.Errorf("resolve zone id: %w", err)
	}

	targetRecordID := strings.TrimSpace(recordID)
	if targetRecordID == "" {
		// Fallback: search for existing record directly on Cloudflare
		foundID, errFind := c.FindTXTRecord(ctx, zoneID, fqdn, value)
		if errFind != nil {
			return fmt.Errorf("locate txt record: %w", errFind)
		}
		targetRecordID = foundID
	}

	if targetRecordID == "" {
		// Record does not exist or is already removed
		return nil
	}

	return c.DeleteTXTRecord(ctx, zoneID, targetRecordID)
}

// GetZoneID retrieves the Cloudflare Zone ID for a domain, using in-memory cache when possible.
func (c *Client) GetZoneID(ctx context.Context, zoneName string) (string, error) {
	normZone := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zoneName), "."))

	c.cacheMu.RLock()
	cachedID, found := c.zoneMap[normZone]
	c.cacheMu.RUnlock()
	if found && cachedID != "" {
		return cachedID, nil
	}

	endpoint := fmt.Sprintf("%s/zones?name=%s&status=active", c.baseURL, url.QueryEscape(normZone))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("create zone request: %w", err)
	}

	var respData cfZoneResponse
	if err := c.doRequest(req, "zones", &respData); err != nil {
		return "", fmt.Errorf("get zone %q: %w", normZone, err)
	}

	if !respData.Success || len(respData.Result) == 0 {
		return "", fmt.Errorf("zone %q not found or inactive in Cloudflare account", normZone)
	}

	zoneID := respData.Result[0].ID
	c.cacheMu.Lock()
	c.zoneMap[normZone] = zoneID
	c.cacheMu.Unlock()

	return zoneID, nil
}

// CreateTXTRecord creates an ACME TXT record on Cloudflare with a short TTL (120s).
func (c *Client) CreateTXTRecord(ctx context.Context, zoneID, name, content string) (string, error) {
	normName := strings.TrimSuffix(strings.TrimSpace(name), ".")
	normContent := strings.TrimSpace(content)

	payload := cfRecordRequest{
		Type:    "TXT",
		Name:    normName,
		Content: normContent,
		TTL:     120, // 2 minutes for rapid ACME propagation
		Comment: "managed by acme-dns-httpreq-proxy",
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal txt payload: %w", err)
	}

	endpoint := fmt.Sprintf("%s/zones/%s/dns_records", c.baseURL, url.PathEscape(zoneID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("create txt request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	var respData cfRecordResponse
	if err := c.doRequest(req, "dns_records_create", &respData); err != nil {
		return "", fmt.Errorf("cloudflare create txt record: %w", err)
	}

	if !respData.Success || respData.Result.ID == "" {
		return "", fmt.Errorf("cloudflare create txt record failed: %s", formatErrors(respData.Errors))
	}

	return respData.Result.ID, nil
}

// DeleteTXTRecord removes a DNS record by ID. 404 Not Found is treated as successful (idempotent).
func (c *Client) DeleteTXTRecord(ctx context.Context, zoneID, recordID string) error {
	endpoint := fmt.Sprintf("%s/zones/%s/dns_records/%s", c.baseURL, url.PathEscape(zoneID), url.PathEscape(recordID))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return fmt.Errorf("create delete record request: %w", err)
	}

	var respData cfRecordResponse
	err = c.doRequest(req, "dns_records_delete", &respData)
	if err != nil {
		var httpErr *httpStatusError
		if errors.As(err, &httpErr) && httpErr.statusCode == http.StatusNotFound {
			// Record already deleted
			return nil
		}
		return fmt.Errorf("cloudflare delete txt record: %w", err)
	}

	if !respData.Success {
		return fmt.Errorf("cloudflare delete txt record failed: %s", formatErrors(respData.Errors))
	}

	return nil
}

// FindTXTRecord searches Cloudflare for an existing TXT record matching name and content.
func (c *Client) FindTXTRecord(ctx context.Context, zoneID, name, content string) (string, error) {
	normName := strings.TrimSuffix(strings.TrimSpace(name), ".")
	normContent := strings.TrimSpace(content)

	query := url.Values{}
	query.Set("type", "TXT")
	query.Set("name", normName)
	query.Set("content", normContent)

	endpoint := fmt.Sprintf("%s/zones/%s/dns_records?%s", c.baseURL, url.PathEscape(zoneID), query.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("create find record request: %w", err)
	}

	var respData cfRecordListResponse
	if err := c.doRequest(req, "dns_records_list", &respData); err != nil {
		return "", fmt.Errorf("cloudflare find txt record: %w", err)
	}

	if !respData.Success || len(respData.Result) == 0 {
		return "", nil // Not found
	}

	return respData.Result[0].ID, nil
}

func (c *Client) doRequest(req *http.Request, metricEndpoint string, target any) error {
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("User-Agent", "acme-dns-httpreq-proxy/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if c.observer != nil {
			c.observer.ObserveCloudflareRequest(metricEndpoint, "error")
		}
		return fmt.Errorf("http execute: %w", err)
	}
	defer resp.Body.Close()

	statusStr := "success"
	if resp.StatusCode >= 400 {
		statusStr = fmt.Sprintf("%d", resp.StatusCode)
	}
	if c.observer != nil {
		c.observer.ObserveCloudflareRequest(metricEndpoint, statusStr)
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errResp cfErrorWrapper
		_ = json.Unmarshal(bodyBytes, &errResp)
		msg := formatErrors(errResp.Errors)
		if msg == "" {
			msg = string(bodyBytes)
		}
		return &httpStatusError{
			statusCode: resp.StatusCode,
			message:    fmt.Sprintf("status %d: %s", resp.StatusCode, msg),
		}
	}

	if target != nil {
		if err := json.Unmarshal(bodyBytes, target); err != nil {
			return fmt.Errorf("unmarshal response: %w", err)
		}
	}

	return nil
}

type httpStatusError struct {
	statusCode int
	message    string
}

func (e *httpStatusError) Error() string {
	return e.message
}

type cfZoneResponse struct {
	Success  bool              `json:"success"`
	Errors   []cfErrorResponse `json:"errors"`
	Messages []string          `json:"messages"`
	Result   []cfZone          `json:"result"`
}

type cfZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfRecordRequest struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Comment string `json:"comment"`
}

type cfRecordResponse struct {
	Success  bool              `json:"success"`
	Errors   []cfErrorResponse `json:"errors"`
	Messages []string          `json:"messages"`
	Result   cfRecord          `json:"result"`
}

type cfRecordListResponse struct {
	Success  bool              `json:"success"`
	Errors   []cfErrorResponse `json:"errors"`
	Messages []string          `json:"messages"`
	Result   []cfRecord        `json:"result"`
}

type cfRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
}

type cfErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfErrorWrapper struct {
	Success bool              `json:"success"`
	Errors  []cfErrorResponse `json:"errors"`
}

func formatErrors(errs []cfErrorResponse) string {
	if len(errs) == 0 {
		return ""
	}
	var sb strings.Builder
	for i, e := range errs {
		if i > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(fmt.Sprintf("[%d] %s", e.Code, e.Message))
	}
	return sb.String()
}
