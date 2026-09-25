package infomaniak

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/FirPic/legate/internal/provider"
)

// Ensure Client satisfies provider.DNSProvider.
var _ provider.DNSProvider = (*Client)(nil)

// Observer allows external packages to record provider metrics.
type Observer interface {
	ObserveDNSRequest(providerName, endpoint, status string)
}

// Client implements provider.DNSProvider using the Infomaniak DNS API.
type Client struct {
	baseURL       string
	apiToken      string
	allowedDomain string
	httpClient    *http.Client
	observer      Observer
}

// NewClient creates an initialized Infomaniak DNS provider client.
func NewClient(apiToken, allowedDomain string, customBaseURL ...string) *Client {
	baseURL := "https://api.infomaniak.com"
	if len(customBaseURL) > 0 && customBaseURL[0] != "" {
		baseURL = strings.TrimRight(customBaseURL[0], "/")
	}

	normDomain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(allowedDomain), "."))

	return &Client{
		baseURL:       baseURL,
		apiToken:      strings.TrimSpace(apiToken),
		allowedDomain: normDomain,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SetObserver sets an observer to record request metrics.
func (c *Client) SetObserver(obs Observer) {
	c.observer = obs
}

// Present creates an ACME TXT record in Infomaniak DNS.
func (c *Client) Present(ctx context.Context, fqdn, value string) (string, error) {
	source := c.computeRelativeSource(fqdn)

	payload := map[string]interface{}{
		"source": source,
		"type":   "TXT",
		"target": value,
		"ttl":    300,
	}

	dataBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal infomaniak record: %w", err)
	}

	endpoint := fmt.Sprintf("%s/2/zones/%s/records", c.baseURL, url.PathEscape(c.allowedDomain))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(dataBytes))
	if err != nil {
		return "", fmt.Errorf("create infomaniak request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	var respBody struct {
		Result string          `json:"result"`
		Data   json.RawMessage `json:"data"`
		Error  *struct {
			Code        string `json:"code"`
			Description string `json:"description"`
		} `json:"error,omitempty"`
	}

	if err := c.doRequest(req, "records_create", &respBody); err != nil {
		return "", fmt.Errorf("create infomaniak txt record for %q: %w", fqdn, err)
	}

	if respBody.Result != "success" {
		errMsg := "unknown infomaniak error"
		if respBody.Error != nil {
			errMsg = fmt.Sprintf("%s: %s", respBody.Error.Code, respBody.Error.Description)
		}
		return "", fmt.Errorf("infomaniak api returned failure: %s", errMsg)
	}

	// Parse record ID which can be numeric ID or object {"id": 123}
	var numericID int64
	if err := json.Unmarshal(respBody.Data, &numericID); err == nil && numericID != 0 {
		return strconv.FormatInt(numericID, 10), nil
	}

	var objectID struct {
		ID interface{} `json:"id"`
	}
	if err := json.Unmarshal(respBody.Data, &objectID); err == nil && objectID.ID != nil {
		return fmt.Sprintf("%v", objectID.ID), nil
	}

	// If data was a string ID
	var stringID string
	if err := json.Unmarshal(respBody.Data, &stringID); err == nil && stringID != "" {
		return stringID, nil
	}

	return "", errors.New("unable to parse created record ID from Infomaniak response")
}

// Cleanup removes an ACME TXT record from Infomaniak DNS.
func (c *Client) Cleanup(ctx context.Context, fqdn, recordID, value string) error {
	targetRecordID := strings.TrimSpace(recordID)
	if targetRecordID == "" {
		foundID, errFind := c.FindTXTRecord(ctx, fqdn, value)
		if errFind != nil {
			return fmt.Errorf("locate infomaniak txt record: %w", errFind)
		}
		targetRecordID = foundID
	}

	if targetRecordID == "" {
		// Record does not exist or was already removed
		return nil
	}

	endpoint := fmt.Sprintf("%s/2/zones/%s/records/%s", c.baseURL, url.PathEscape(c.allowedDomain), url.PathEscape(targetRecordID))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return fmt.Errorf("create infomaniak delete request: %w", err)
	}

	if err := c.doRequest(req, "records_delete", nil); err != nil {
		return fmt.Errorf("delete infomaniak record %q: %w", targetRecordID, err)
	}

	return nil
}

type infomaniakRecordItem struct {
	ID     interface{} `json:"id"`
	Source string      `json:"source"`
	Type   string      `json:"type"`
	Target string      `json:"target"`
}

// FindTXTRecord searches for an existing TXT record matching relative source and value.
func (c *Client) FindTXTRecord(ctx context.Context, fqdn, value string) (string, error) {
	expectedSource := c.computeRelativeSource(fqdn)

	endpoint := fmt.Sprintf("%s/2/zones/%s/records?type=TXT", c.baseURL, url.PathEscape(c.allowedDomain))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("create infomaniak search request: %w", err)
	}

	var respBody struct {
		Result string                 `json:"result"`
		Data   []infomaniakRecordItem `json:"data"`
	}

	if err := c.doRequest(req, "records_find", &respBody); err != nil {
		return "", fmt.Errorf("list infomaniak txt records: %w", err)
	}

	cleanTarget := strings.Trim(value, "\"")
	for _, rec := range respBody.Data {
		recSource := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rec.Source), "."))
		recTarget := strings.Trim(rec.Target, "\"")

		if rec.Type == "TXT" && recSource == expectedSource && recTarget == cleanTarget {
			return fmt.Sprintf("%v", rec.ID), nil
		}
	}

	return "", nil
}

func (c *Client) computeRelativeSource(fqdn string) string {
	norm := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))
	if norm == c.allowedDomain {
		return "@"
	}
	suffix := "." + c.allowedDomain
	if strings.HasSuffix(norm, suffix) {
		return strings.TrimSuffix(norm, suffix)
	}
	return norm
}

func (c *Client) doRequest(req *http.Request, endpoint string, target interface{}) error {
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("User-Agent", "legate/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if c.observer != nil {
			c.observer.ObserveDNSRequest("infomaniak", endpoint, "network_error")
		}
		return fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	statusStr := fmt.Sprintf("%d", resp.StatusCode)
	if c.observer != nil {
		c.observer.ObserveDNSRequest("infomaniak", endpoint, statusStr)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound && req.Method == http.MethodDelete {
		return nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("infomaniak api error (status %d): %s", resp.StatusCode, string(body))
	}

	if target != nil && len(body) > 0 {
		if err := json.Unmarshal(body, target); err != nil {
			return fmt.Errorf("unmarshal infomaniak response: %w", err)
		}
	}

	return nil
}
