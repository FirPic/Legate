package dns

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
)

// DNSClient defines the interface for interacting with DNS records for ACME challenges.
type DNSClient interface {
	GetZoneID(ctx context.Context, zoneName string) (string, error)
	CreateTXTRecord(ctx context.Context, zoneID, name, content string) (string, error)
	DeleteTXTRecord(ctx context.Context, zoneID, recordID string) error
	FindTXTRecord(ctx context.Context, zoneID, name, content string) (string, error)
}

// CloudflareClient implements DNSClient using Cloudflare REST API v4.
type CloudflareClient struct {
	baseURL    string
	apiToken   string
	httpClient *http.Client

	cacheMu sync.RWMutex
	zoneMap map[string]string
}

// NewCloudflareClient creates an initialized CloudflareClient.
func NewCloudflareClient(apiToken string, customBaseURL ...string) *CloudflareClient {
	baseURL := "https://api.cloudflare.com/client/v4"
	if len(customBaseURL) > 0 && customBaseURL[0] != "" {
		baseURL = strings.TrimRight(customBaseURL[0], "/")
	}

	return &CloudflareClient{
		baseURL:  baseURL,
		apiToken: apiToken,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		zoneMap: make(map[string]string),
	}
}

// SetZoneIDCache allows pre-seeding the zone ID cache (e.g. from CLOUDFLARE_ZONE_ID config).
func (c *CloudflareClient) SetZoneIDCache(zoneName, zoneID string) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	c.zoneMap[strings.ToLower(strings.TrimSuffix(zoneName, "."))] = zoneID
}

// GetZoneID retrieves the Cloudflare Zone ID for a domain name.
func (c *CloudflareClient) GetZoneID(ctx context.Context, zoneName string) (string, error) {
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
	if err := c.doRequest(req, &respData); err != nil {
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

// CreateTXTRecord creates an ACME TXT record on Cloudflare.
func (c *CloudflareClient) CreateTXTRecord(ctx context.Context, zoneID, name, content string) (string, error) {
	normName := strings.TrimSuffix(strings.TrimSpace(name), ".")
	normContent := strings.TrimSpace(content)

	payload := cfRecordRequest{
		Type:    "TXT",
		Name:    normName,
		Content: normContent,
		TTL:     120, // 2 minutes TTL for rapid propagation
		Comment: "managed by acme-dns-httpreq-proxy",
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal txt record payload: %w", err)
	}

	endpoint := fmt.Sprintf("%s/zones/%s/dns_records", c.baseURL, url.PathEscape(zoneID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("create txt record request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	var respData cfRecordResponse
	if err := c.doRequest(req, &respData); err != nil {
		return "", fmt.Errorf("cloudflare create txt record: %w", err)
	}

	if !respData.Success || respData.Result.ID == "" {
		return "", fmt.Errorf("cloudflare create txt record failed: %s", formatErrors(respData.Errors))
	}

	return respData.Result.ID, nil
}

// DeleteTXTRecord removes a DNS record by ID.
func (c *CloudflareClient) DeleteTXTRecord(ctx context.Context, zoneID, recordID string) error {
	endpoint := fmt.Sprintf("%s/zones/%s/dns_records/%s", c.baseURL, url.PathEscape(zoneID), url.PathEscape(recordID))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return fmt.Errorf("create delete record request: %w", err)
	}

	var respData cfRecordResponse
	err = c.doRequest(req, &respData)
	if err != nil {
		// If 404, record is already gone, consider cleanup successful (idempotent)
		var httpErr *httpStatusError
		if errors.As(err, &httpErr) && httpErr.statusCode == http.StatusNotFound {
			return nil
		}
		return fmt.Errorf("cloudflare delete txt record: %w", err)
	}

	if !respData.Success {
		return fmt.Errorf("cloudflare delete txt record failed: %s", formatErrors(respData.Errors))
	}

	return nil
}

// FindTXTRecord searches for an existing TXT record by name and content.
func (c *CloudflareClient) FindTXTRecord(ctx context.Context, zoneID, name, content string) (string, error) {
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
	if err := c.doRequest(req, &respData); err != nil {
		return "", fmt.Errorf("cloudflare find txt record: %w", err)
	}

	if !respData.Success || len(respData.Result) == 0 {
		return "", nil // Not found
	}

	return respData.Result[0].ID, nil
}

func (c *CloudflareClient) doRequest(req *http.Request, target any) error {
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("User-Agent", "acme-dns-httpreq-proxy/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http execute: %w", err)
	}
	defer resp.Body.Close()

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
