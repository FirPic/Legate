package dns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCloudflareClient(t *testing.T) {
	mockZoneID := "mock-zone-12345"
	mockRecordID := "mock-rec-67890"
	mockZoneName := "firpic.fr"
	mockFQDN := "_acme-challenge.traefik.firpic.fr"
	mockValue := "challenge-value-test-abc"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check auth bearer
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

	client := NewCloudflareClient("test-cf-token", server.URL)
	ctx := context.Background()

	// Test GetZoneID
	zoneID, err := client.GetZoneID(ctx, mockZoneName)
	if err != nil {
		t.Fatalf("unexpected error getting zone ID: %v", err)
	}
	if zoneID != mockZoneID {
		t.Fatalf("expected zone ID %s, got %s", mockZoneID, zoneID)
	}

	// Verify caching works (server will still return it if requested, but check consistency)
	zoneID2, err := client.GetZoneID(ctx, mockZoneName)
	if err != nil || zoneID2 != mockZoneID {
		t.Fatalf("zone caching failed")
	}

	// Test CreateTXTRecord
	recID, err := client.CreateTXTRecord(ctx, mockZoneID, mockFQDN, mockValue)
	if err != nil {
		t.Fatalf("unexpected error creating TXT record: %v", err)
	}
	if recID != mockRecordID {
		t.Fatalf("expected record ID %s, got %s", mockRecordID, recID)
	}

	// Test FindTXTRecord
	foundID, err := client.FindTXTRecord(ctx, mockZoneID, mockFQDN, mockValue)
	if err != nil {
		t.Fatalf("unexpected error finding record: %v", err)
	}
	if foundID != mockRecordID {
		t.Fatalf("expected found record ID %s, got %s", mockRecordID, foundID)
	}

	// Test DeleteTXTRecord
	err = client.DeleteTXTRecord(ctx, mockZoneID, mockRecordID)
	if err != nil {
		t.Fatalf("unexpected error deleting TXT record: %v", err)
	}
}
