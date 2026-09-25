package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/FirPic/acme-dns-httpreq-proxy/internal/config"
	"github.com/FirPic/acme-dns-httpreq-proxy/internal/lock"
)

type mockDNSClient struct {
	mu           sync.Mutex
	zoneID       string
	records      map[string]string // fqdn+content -> recordID
	createCalls  int
	deleteCalls  int
	findCalls    int
	shouldFail   bool
}

func newMockDNSClient(zoneID string) *mockDNSClient {
	return &mockDNSClient{
		zoneID:  zoneID,
		records: make(map[string]string),
	}
}

func (m *mockDNSClient) GetZoneID(ctx context.Context, zoneName string) (string, error) {
	if m.shouldFail {
		return "", fmt.Errorf("mock error get zone")
	}
	return m.zoneID, nil
}

func (m *mockDNSClient) CreateTXTRecord(ctx context.Context, zoneID, name, content string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shouldFail {
		return "", fmt.Errorf("mock error create record")
	}
	m.createCalls++
	recID := fmt.Sprintf("cf-rec-%d", m.createCalls)
	m.records[name+"|"+content] = recID
	return recID, nil
}

func (m *mockDNSClient) DeleteTXTRecord(ctx context.Context, zoneID, recordID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shouldFail {
		return fmt.Errorf("mock error delete record")
	}
	m.deleteCalls++
	for k, v := range m.records {
		if v == recordID {
			delete(m.records, k)
			break
		}
	}
	return nil
}

func (m *mockDNSClient) FindTXTRecord(ctx context.Context, zoneID, name, content string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.findCalls++
	recID, ok := m.records[name+"|"+content]
	if !ok {
		return "", nil
	}
	return recID, nil
}

func setupTestServer() (*Server, *mockDNSClient, *lock.RecordTracker) {
	cfg := &config.Config{
		Port:          "8080",
		BindAddr:      "0.0.0.0",
		AllowedDomain: "firpic.fr",
		Users: map[string]string{
			"traefik_dmz": "secret123",
		},
	}
	mockDNS := newMockDNSClient("zone-abc-123")
	tracker := lock.NewRecordTracker()
	srv := NewServer(cfg, mockDNS, tracker)
	return srv, mockDNS, tracker
}

func TestHealthzEndpoint(t *testing.T) {
	srv, _, _ := setupTestServer()

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
}

func TestPresent_Success(t *testing.T) {
	srv, mockDNS, tracker := setupTestServer()

	payload := ChallengeRequest{
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
	recID, found := tracker.Get("_acme-challenge.sub.firpic.fr", "challenge-test-value-123")
	if !found || recID != resp.RecordID {
		t.Fatalf("record not properly saved in tracker (found: %v, id: %s)", found, recID)
	}

	// Verify mock calls
	if mockDNS.createCalls != 1 {
		t.Errorf("expected 1 create call, got %d", mockDNS.createCalls)
	}
}

func TestPresent_Unauthorized(t *testing.T) {
	srv, _, _ := setupTestServer()

	payload := ChallengeRequest{
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
	srv, _, _ := setupTestServer()

	payload := ChallengeRequest{
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
	srv, mockDNS, tracker := setupTestServer()

	payload := ChallengeRequest{
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

	if tracker.Count() != 1 {
		t.Errorf("expected 1 tracked record, got %d", tracker.Count())
	}
}

func TestCleanup_Success(t *testing.T) {
	srv, mockDNS, tracker := setupTestServer()

	fqdn := "_acme-challenge.sub.firpic.fr"
	val := "challenge-123"

	// Pre-seed tracker and mock DNS
	mockDNS.records[fqdn+"|"+val] = "rec-to-delete"
	tracker.Store(fqdn, val, "rec-to-delete")

	payload := ChallengeRequest{
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

	// Verify tracker no longer has record
	if _, found := tracker.Get(fqdn, val); found {
		t.Errorf("record should be deleted from tracker")
	}
}

func TestCleanup_FallbackDirectCloudflareSearch(t *testing.T) {
	srv, mockDNS, tracker := setupTestServer()

	fqdn := "_acme-challenge.sub.firpic.fr"
	val := "challenge-fallback"

	// DNS record exists in DNS provider, but NOT in local tracker (e.g. restart)
	mockDNS.records[fqdn+"|"+val] = "rec-found-in-cf"

	payload := ChallengeRequest{
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

	if mockDNS.findCalls != 1 {
		t.Errorf("expected 1 find call on fallback, got %d", mockDNS.findCalls)
	}
	if mockDNS.deleteCalls != 1 {
		t.Errorf("expected 1 delete call on fallback, got %d", mockDNS.deleteCalls)
	}
	if tracker.Count() != 0 {
		t.Errorf("expected tracker empty, got %d", tracker.Count())
	}
}
