package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/FirPic/acme-dns-httpreq-proxy/internal/challenge"
	"github.com/FirPic/acme-dns-httpreq-proxy/internal/config"
	"github.com/FirPic/acme-dns-httpreq-proxy/internal/provider"
	"github.com/FirPic/acme-dns-httpreq-proxy/internal/tracker"
	"github.com/prometheus/client_golang/prometheus"
)

type mockDNSProvider struct {
	mu          sync.Mutex
	records     map[string]string // fqdn+value -> recordID
	createCalls int
	deleteCalls int
	shouldFail  bool
}

var _ provider.DNSProvider = (*mockDNSProvider)(nil)

func newMockDNSProvider() *mockDNSProvider {
	return &mockDNSProvider{
		records: make(map[string]string),
	}
}

func (m *mockDNSProvider) Present(ctx context.Context, fqdn, value string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shouldFail {
		return "", fmt.Errorf("sensitive internal cloudflare api failure: api.cloudflare.com/client/v4/zones/123/dns_records: unauthorized token secret")
	}
	m.createCalls++
	recID := fmt.Sprintf("cf-rec-%d", m.createCalls)
	m.records[fqdn+"|"+value] = recID
	return recID, nil
}

func (m *mockDNSProvider) Cleanup(ctx context.Context, fqdn, recordID, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shouldFail {
		return fmt.Errorf("sensitive upstream timeout error connecting to cloudflare")
	}
	m.deleteCalls++
	for k, v := range m.records {
		if v == recordID || k == (fqdn+"|"+value) {
			delete(m.records, k)
			break
		}
	}
	return nil
}

func setupTestServer() (*Server, *mockDNSProvider, *tracker.Tracker, *Metrics) {
	allowedDomain := "firpic.fr"
	users := map[string]config.UserConfig{
		"traefik_dmz": {
			Password:          "secret123",
			AllowedSubdomains: []string{"*.dmz.firpic.fr", "dmz.firpic.fr"},
		},
		"admin": {
			Password:          "adminsecret",
			AllowedSubdomains: []string{"*"},
		},
	}
	mockDNS := newMockDNSProvider()
	tr := tracker.New()
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg, func() float64 { return float64(tr.Count()) })

	srv := NewServer(allowedDomain, users, mockDNS, tr, m, 600)
	return srv, mockDNS, tr, m
}

func TestHealthzEndpointOnAdmin(t *testing.T) {
	srv, _, _, _ := setupTestServer()
	adminHandler := srv.AdminHandler()

	// 1. Check admin handler serves /healthz
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	adminHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 on admin /healthz, got %d", rr.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("expected status ok, got %v", resp["status"])
	}

	// 2. Check main server rejects /healthz (VULN-02 separation)
	mainReq := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	mainRR := httptest.NewRecorder()
	srv.ServeHTTP(mainRR, mainReq)
	if mainRR.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on main server for /healthz, got %d", mainRR.Code)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	srv, _, _, m := setupTestServer()
	adminHandler := srv.AdminHandler()

	// Record an observation
	m.ChallengesTotal.WithLabelValues("success").Inc()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	adminHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 on /metrics, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "acme_dns_challenges_total") {
		t.Errorf("expected metric acme_dns_challenges_total in body")
	}
	// Verify VULN-02: client label must NOT exist in metrics
	if strings.Contains(body, `client="`) {
		t.Errorf("information leak: client label found in metrics: %s", body)
	}
}

func TestPresent_Success(t *testing.T) {
	srv, mockDNS, tr, _ := setupTestServer()

	payload := challenge.PresentRequest{
		FQDN:  "_acme-challenge.sub.dmz.firpic.fr.",
		Value: "challenge-test-value-123",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/present", bytes.NewReader(body))
	req.SetBasicAuth("traefik_dmz", "secret123")
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp Response
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status != "success" || resp.Action != "present" || resp.RecordID == "" {
		t.Fatalf("unexpected response content: %+v", resp)
	}

	// Verify tracker holds record
	recID, found := tr.Get("_acme-challenge.sub.dmz.firpic.fr", "challenge-test-value-123")
	if !found || recID != resp.RecordID {
		t.Fatalf("record not properly saved in tracker (found: %v, id: %s)", found, recID)
	}

	if mockDNS.createCalls != 1 {
		t.Errorf("expected 1 create call, got %d", mockDNS.createCalls)
	}
}

func TestPresent_RBAC_Violation_Forbidden(t *testing.T) {
	srv, _, _, _ := setupTestServer()

	// DMZ user attempting to issue certificate for the apex root firpic.fr (VULN-01)
	payload := challenge.PresentRequest{
		FQDN:  "_acme-challenge.firpic.fr",
		Value: "val123",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/present", bytes.NewReader(body))
	req.SetBasicAuth("traefik_dmz", "secret123")
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for DMZ user requesting apex, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestPresent_BodyTooLarge_413(t *testing.T) {
	srv, _, _, _ := setupTestServer()

	// Payload larger than 16 KiB (VULN-06)
	oversizedBody := strings.Repeat("A", 17*1024)

	req := httptest.NewRequest(http.MethodPost, "/present", strings.NewReader(oversizedBody))
	req.SetBasicAuth("traefik_dmz", "secret123")
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 Request Entity Too Large, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestPresent_ProviderFailure_Masking(t *testing.T) {
	srv, mockDNS, _, _ := setupTestServer()
	mockDNS.shouldFail = true

	payload := challenge.PresentRequest{
		FQDN:  "_acme-challenge.sub.dmz.firpic.fr",
		Value: "val123",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/present", bytes.NewReader(body))
	req.SetBasicAuth("traefik_dmz", "secret123")
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 Bad Gateway, got %d", rr.Code)
	}

	var resp Response
	_ = json.NewDecoder(rr.Body).Decode(&resp)

	// Verify internal details/tokens were NOT leaked (VULN-07)
	if strings.Contains(resp.Error, "cloudflare.com") || strings.Contains(resp.Error, "secret") {
		t.Fatalf("information leak detected in 502 response: %s", resp.Error)
	}
	if resp.Error != "upstream DNS provider error" {
		t.Errorf("expected generic error message, got: %s", resp.Error)
	}
}

func TestRateLimiter(t *testing.T) {
	allowedDomain := "firpic.fr"
	users := map[string]config.UserConfig{
		"traefik_dmz": {
			Password:          "secret123",
			AllowedSubdomains: []string{"*"},
		},
	}
	mockDNS := newMockDNSProvider()
	tr := tracker.New()
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg, nil)

	// Rate limit: 2 requests per minute
	srv := NewServer(allowedDomain, users, mockDNS, tr, m, 2)

	payload := challenge.PresentRequest{
		FQDN:  "_acme-challenge.sub.firpic.fr",
		Value: "val123",
	}
	body, _ := json.Marshal(payload)

	// 1st request -> allowed
	req1 := httptest.NewRequest(http.MethodPost, "/present", bytes.NewReader(body))
	req1.SetBasicAuth("traefik_dmz", "secret123")
	rr1 := httptest.NewRecorder()
	srv.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("request 1 expected 200, got %d", rr1.Code)
	}

	// 2nd request -> allowed
	req2 := httptest.NewRequest(http.MethodPost, "/present", bytes.NewReader(body))
	req2.SetBasicAuth("traefik_dmz", "secret123")
	rr2 := httptest.NewRecorder()
	srv.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("request 2 expected 200, got %d", rr2.Code)
	}

	// 3rd request -> rate limited (429) (VULN-04)
	req3 := httptest.NewRequest(http.MethodPost, "/present", bytes.NewReader(body))
	req3.SetBasicAuth("traefik_dmz", "secret123")
	rr3 := httptest.NewRecorder()
	srv.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusTooManyRequests {
		t.Fatalf("request 3 expected 429 Too Many Requests, got %d", rr3.Code)
	}
	if rr3.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header in 429 response")
	}
}

func TestCleanup_Success(t *testing.T) {
	srv, mockDNS, tr, _ := setupTestServer()

	fqdn := "_acme-challenge.sub.dmz.firpic.fr"
	val := "challenge-123"

	mockDNS.records[fqdn+"|"+val] = "rec-to-delete"
	tr.Store(fqdn, val, "rec-to-delete")

	payload := challenge.CleanupRequest{
		FQDN:  fqdn,
		Value: val,
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/cleanup", bytes.NewReader(body))
	req.SetBasicAuth("traefik_dmz", "secret123")
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	if mockDNS.deleteCalls != 1 {
		t.Errorf("expected 1 delete call, got %d", mockDNS.deleteCalls)
	}

	if _, found := tr.Get(fqdn, val); found {
		t.Errorf("record should be deleted from tracker")
	}
}
