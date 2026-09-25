package infomaniak_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/FirPic/legate/internal/provider/infomaniak"
)

type mockObserver struct {
	events []string
}

func (m *mockObserver) ObserveDNSRequest(provider, endpoint, status string) {
	m.events = append(m.events, provider+":"+endpoint+":"+status)
}

func TestInfomaniakClient_PresentAndCleanup(t *testing.T) {
	recordCreated := false
	recordDeleted := false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer secret-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"result":"error","error":{"code":"unauthorized","description":"invalid token"}}`))
			return
		}

		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/2/zones/example.ch/records":
			var payload map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if payload["source"] != "_acme-challenge.sub" || payload["target"] != "challenge-val" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			recordCreated = true
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"result": "success",
				"data":   987654,
			})

		case r.Method == http.MethodDelete && r.URL.Path == "/2/zones/example.ch/records/987654":
			recordDeleted = true
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"result": "success",
			})

		case r.Method == http.MethodGet && r.URL.Path == "/2/zones/example.ch/records":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"result": "success",
				"data": []map[string]interface{}{
					{
						"id":     554433,
						"source": "_acme-challenge.sub",
						"type":   "TXT",
						"target": "challenge-val",
					},
				},
			})

		case r.Method == http.MethodDelete && r.URL.Path == "/2/zones/example.ch/records/554433":
			recordDeleted = true
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"result": "success",
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	obs := &mockObserver{}
	client := infomaniak.NewClient("secret-token", "example.ch", ts.URL)
	client.SetObserver(obs)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Present
	recID, err := client.Present(ctx, "_acme-challenge.sub.example.ch", "challenge-val")
	if err != nil {
		t.Fatalf("unexpected Present error: %v", err)
	}
	if recID != "987654" {
		t.Errorf("got recID %q, want %q", recID, "987654")
	}
	if !recordCreated {
		t.Errorf("expected recordCreated to be true")
	}

	// 2. Cleanup with known recordID
	err = client.Cleanup(ctx, "_acme-challenge.sub.example.ch", "987654", "challenge-val")
	if err != nil {
		t.Fatalf("unexpected Cleanup error: %v", err)
	}
	if !recordDeleted {
		t.Errorf("expected recordDeleted to be true")
	}

	// 3. Cleanup without recordID (fallback search)
	recordDeleted = false
	err = client.Cleanup(ctx, "_acme-challenge.sub.example.ch", "", "challenge-val")
	if err != nil {
		t.Fatalf("unexpected Cleanup fallback error: %v", err)
	}
	if !recordDeleted {
		t.Errorf("expected recordDeleted via fallback to be true")
	}
}

func TestInfomaniakClient_Errors(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"result":"error","error":{"code":"forbidden","description":"no permission"}}`))
	}))
	defer ts.Close()

	client := infomaniak.NewClient("bad-token", "example.ch", ts.URL)
	ctx := context.Background()

	_, err := client.Present(ctx, "_acme-challenge.example.ch", "val")
	if err == nil {
		t.Fatal("expected error on 403, got nil")
	}
	if !strings.Contains(err.Error(), "forbidden") {
		t.Errorf("expected forbidden in error, got %v", err)
	}
}
