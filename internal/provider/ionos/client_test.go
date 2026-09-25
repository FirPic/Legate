package ionos_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/FirPic/legate/internal/provider/ionos"
)

type mockObserver struct {
	requests []string
}

func (m *mockObserver) ObserveDNSRequest(provider, endpoint, status string) {
	m.requests = append(m.requests, provider+":"+endpoint+":"+status)
}

func TestIONOSClient_PresentAndCleanup(t *testing.T) {
	recordCreated := false
	recordDeleted := false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey != "test-api-key" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`[{"code":"401","message":"Unauthorized"}]`))
			return
		}

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": "zone-uuid-1234", "name": "example.com", "type": "NATIVE"},
			})

		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone-uuid-1234/records":
			var records []map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&records); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if len(records) == 0 || records[0]["name"] != "_acme-challenge.sub.example.com" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			recordCreated = true
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id":      "rec-uuid-5678",
					"name":    records[0]["name"],
					"content": records[0]["content"],
					"type":    "TXT",
				},
			})

		case r.Method == http.MethodDelete && r.URL.Path == "/zones/zone-uuid-1234/records/rec-uuid-5678":
			recordDeleted = true
			w.WriteHeader(http.StatusOK)

		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/zones/zone-uuid-1234"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":   "zone-uuid-1234",
				"name": "example.com",
				"records": []map[string]interface{}{
					{
						"id":      "rec-uuid-found-9999",
						"name":    "_acme-challenge.sub.example.com",
						"type":    "TXT",
						"content": `"test-challenge-val"`,
					},
				},
			})

		case r.Method == http.MethodDelete && r.URL.Path == "/zones/zone-uuid-1234/records/rec-uuid-found-9999":
			recordDeleted = true
			w.WriteHeader(http.StatusOK)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	obs := &mockObserver{}
	client := ionos.NewClient("test-api-key", "example.com", ts.URL)
	client.SetObserver(obs)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Present
	recID, err := client.Present(ctx, "_acme-challenge.sub.example.com", "test-challenge-val")
	if err != nil {
		t.Fatalf("unexpected Present error: %v", err)
	}
	if recID != "rec-uuid-5678" {
		t.Errorf("got recID %q, want %q", recID, "rec-uuid-5678")
	}
	if !recordCreated {
		t.Errorf("expected recordCreated to be true")
	}

	// 2. Cleanup with known recordID
	err = client.Cleanup(ctx, "_acme-challenge.sub.example.com", "rec-uuid-5678", "test-challenge-val")
	if err != nil {
		t.Fatalf("unexpected Cleanup error: %v", err)
	}
	if !recordDeleted {
		t.Errorf("expected recordDeleted to be true")
	}

	// 3. Cleanup without recordID (fallback search)
	recordDeleted = false
	err = client.Cleanup(ctx, "_acme-challenge.sub.example.com", "", "test-challenge-val")
	if err != nil {
		t.Fatalf("unexpected Cleanup fallback error: %v", err)
	}
	if !recordDeleted {
		t.Errorf("expected recordDeleted via fallback to be true")
	}
}

func TestIONOSClient_Errors(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`Unauthorized`))
	}))
	defer ts.Close()

	client := ionos.NewClient("bad-key", "example.com", ts.URL)
	ctx := context.Background()

	_, err := client.Present(ctx, "_acme-challenge.example.com", "val")
	if err == nil {
		t.Fatal("expected error on 401, got nil")
	}
}
