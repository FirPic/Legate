package cloudflare

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/FirPic/legate/internal/provider"
)

type mockObserver struct {
	mu       sync.Mutex
	requests map[string]int
}

func (m *mockObserver) ObserveCloudflareRequest(endpoint, status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := endpoint + ":" + status
	m.requests[key]++
}

func TestCloudflareClient(t *testing.T) {
	mockZoneID := "mock-zone-12345"
	mockRecordID := "mock-rec-67890"
	mockZoneName := "firpic.fr"
	mockFQDN := "_acme-challenge.traefik.firpic.fr"
	mockValue := "challenge-value-test-abc"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Bearer token
		if r.Header.Get("Authorization") != "Bearer test-cf-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		// 1. Get Zone ID
		if r.Method == http.MethodGet && r.URL.Path == "/zones" {
			if r.URL.Query().Get("name") == mockZoneName {
				_ = json.NewEncoder(w).Encode(cfZoneResponse{
					Success: true,
					Result: []cfZone{
						{ID: mockZoneID, Name: mockZoneName},
					},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(cfZoneResponse{Success: true, Result: []cfZone{}})
			return
		}

		// 2. Create DNS Record
		if r.Method == http.MethodPost && r.URL.Path == "/zones/"+mockZoneID+"/dns_records" {
			var req cfRecordRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.Type == "TXT" && req.Name == mockFQDN && req.Content == mockValue {
				_ = json.NewEncoder(w).Encode(cfRecordResponse{
					Success: true,
					Result: cfRecord{
						ID:      mockRecordID,
						Name:    req.Name,
						Type:    req.Type,
						Content: req.Content,
					},
				})
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// 3. Delete DNS Record
		if r.Method == http.MethodDelete && r.URL.Path == "/zones/"+mockZoneID+"/dns_records/"+mockRecordID {
			_ = json.NewEncoder(w).Encode(cfRecordResponse{
				Success: true,
				Result: cfRecord{
					ID: mockRecordID,
				},
			})
			return
		}

		// 4. Find DNS Record
		if r.Method == http.MethodGet && r.URL.Path == "/zones/"+mockZoneID+"/dns_records" {
			if r.URL.Query().Get("name") == mockFQDN && r.URL.Query().Get("content") == mockValue {
				_ = json.NewEncoder(w).Encode(cfRecordListResponse{
					Success: true,
					Result: []cfRecord{
						{ID: mockRecordID, Name: mockFQDN, Type: "TXT", Content: mockValue},
					},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(cfRecordListResponse{Success: true, Result: []cfRecord{}})
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient("test-cf-token", mockZoneName, server.URL)
	obs := &mockObserver{requests: make(map[string]int)}
	client.SetObserver(obs)

	// Verify client satisfies DNSProvider interface
	var p provider.DNSProvider = client
	ctx := context.Background()

	// Test Present
	recID, err := p.Present(ctx, mockFQDN, mockValue)
	if err != nil {
		t.Fatalf("unexpected error presenting challenge: %v", err)
	}
	if recID != mockRecordID {
		t.Fatalf("expected record ID %s, got %s", mockRecordID, recID)
	}

	// Verify observer tracked requests (zones + dns_records_create)
	obs.mu.Lock()
	if obs.requests["zones:success"] != 1 {
		t.Errorf("expected 1 zone lookup metric, got %d", obs.requests["zones:success"])
	}
	if obs.requests["dns_records_create:success"] != 1 {
		t.Errorf("expected 1 record create metric, got %d", obs.requests["dns_records_create:success"])
	}
	obs.mu.Unlock()

	// Test Cleanup with known record ID
	err = p.Cleanup(ctx, mockFQDN, mockRecordID, mockValue)
	if err != nil {
		t.Fatalf("unexpected error cleaning up record: %v", err)
	}

	// Test Cleanup with empty record ID (should find via API then delete)
	err = p.Cleanup(ctx, mockFQDN, "", mockValue)
	if err != nil {
		t.Fatalf("unexpected error on fallback cleanup: %v", err)
	}

	// Test Cleanup of nonexistent record (idempotent)
	err = client.DeleteTXTRecord(ctx, mockZoneID, "nonexistent-rec-id")
	if err != nil {
		t.Fatalf("expected 404 to be treated idempotently as success, got error: %v", err)
	}
}
