package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheckHealth_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	if err := checkHealth(ts.URL+"/healthz", 2*time.Second); err != nil {
		t.Fatalf("expected healthcheck success, got: %v", err)
	}
}

func TestCheckHealth_FailureStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	if err := checkHealth(ts.URL+"/healthz", 2*time.Second); err == nil {
		t.Fatal("expected healthcheck to fail on 503 Service Unavailable")
	}
}

func TestCheckHealth_ConnectionRefused(t *testing.T) {
	if err := checkHealth("http://127.0.0.1:54321/healthz", 500*time.Millisecond); err == nil {
		t.Fatal("expected healthcheck to fail on closed port")
	}
}
