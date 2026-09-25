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
		return "", fmt.Errorf("mock error presenting challenge")
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
		return fmt.Errorf("mock error cleaning up challenge")
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
	users := map[string]string{
		"traefik_dmz": "secret123",
	}
	mockDNS := newMockDNSProvider()
	tr := tracker.New()
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg, func() float64 { return float64(tr.Count()) })

	srv := NewServer(allowedDomain, users, mockDNS, tr, m)
	return srv, mockDNS, tr, m
}

func TestHealthzEndpoint(t *testing.T) {
	srv, _, _, _ := setupTestServer()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("expected status ok, got %v", resp["status"])
	}
	if resp["allowed_domain"] != "firpic.fr" {
		t.Errorf("expected allowed_domain firpic.fr, got %v", resp["allowed_domain"])
	}
}

func TestMetricsEndpoint(t *testing.T) {
	srv, _, _, m := setupTestServer()

	// Simulate a metric observation so the counter series exists
	m.ChallengesTotal.WithLabelValues("success", "traefik_dmz").Inc()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 on /metrics, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "acme_dns_challenges_total") {
		t.Errorf("expected metric acme_dns_challenges_total in body")
	}
	if !strings.Contains(body, "acme_dns_active_records") {
		t.Errorf("expected metric acme_dns_active_records in body")
	}
}

func TestPresent_Success(t *testing.T) {
	srv, mockDNS, tr, _ := setupTestServer()

	payload := challenge.PresentRequest{
		FQDN:  "_acme-challenge.sub.firpic.fr.",
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
	recID, found := tr.Get("_acme-challenge.sub.firpic.fr", "challenge-test-value-123")
	if !found || recID != resp.RecordID {
		t.Fatalf("record not properly saved in tracker (found: %v, id: %s)", found, recID)
	}

	if mockDNS.createCalls != 1 {
		t.Errorf("expected 1 create call, got %d", mockDNS.createCalls)
	}
}

func TestPresent_Unauthorized(t *testing.T) {
	srv, _, _, _ := setupTestServer()

	payload := challenge.PresentRequest{
		FQDN:  "_acme-challenge.sub.firpic.fr",
		Value: "val123",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/present", bytes.NewReader(body))
	req.SetBasicAuth("traefik_dmz", "wrongpassword")
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestPresent_ForbiddenDomain(t *testing.T) {
	srv, _, _, _ := setupTestServer()

	payload := challenge.PresentRequest{
		FQDN:  "_acme-challenge.attacker.com",
		Value: "val123",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/present", bytes.NewReader(body))
	req.SetBasicAuth("traefik_dmz", "secret123")
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestPresent_RawMode(t *testing.T) {
	srv, mockDNS, tr, _ := setupTestServer()

	payload := challenge.PresentRequest{
		Domain:  "sub.firpic.fr",
		Token:   "tok123",
		KeyAuth: "key-auth-token-xyz",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/present", bytes.NewReader(body))
	req.SetBasicAuth("traefik_dmz", "secret123")
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 in raw mode, got %d: %s", rr.Code, rr.Body.String())
	}

	if mockDNS.createCalls != 1 {
		t.Errorf("expected 1 create call, got %d", mockDNS.createCalls)
	}

	if tr.Count() != 1 {
		t.Errorf("expected 1 tracked record, got %d", tr.Count())
	}
}

func TestPresent_ProviderFailure(t *testing.T) {
	srv, mockDNS, _, _ := setupTestServer()
	mockDNS.shouldFail = true

	payload := challenge.PresentRequest{
		FQDN:  "_acme-challenge.sub.firpic.fr",
		Value: "val123",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/present", bytes.NewReader(body))
	req.SetBasicAuth("traefik_dmz", "secret123")
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 Bad Gateway on provider failure, got %d", rr.Code)
	}
}

func TestCleanup_Success(t *testing.T) {
	srv, mockDNS, tr, _ := setupTestServer()

	fqdn := "_acme-challenge.sub.firpic.fr"
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

func TestCleanup_FallbackDirectSearch(t *testing.T) {
	srv, mockDNS, tr, _ := setupTestServer()

	fqdn := "_acme-challenge.sub.firpic.fr"
	val := "challenge-fallback"

	// Exists in provider, but NOT in local tracker
	mockDNS.records[fqdn+"|"+val] = "rec-found-in-cf"

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
		t.Fatalf("expected 200 on fallback cleanup, got %d", rr.Code)
	}

	if mockDNS.deleteCalls != 1 {
		t.Errorf("expected 1 delete call on fallback, got %d", mockDNS.deleteCalls)
	}
	if tr.Count() != 0 {
		t.Errorf("expected tracker empty, got %d", tr.Count())
	}
}
