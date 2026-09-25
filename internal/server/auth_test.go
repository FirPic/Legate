package server

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthenticator_Verify(t *testing.T) {
	users := map[string]string{
		"traefik_dmz":   "strongpassword1",
		"traefik_infra": "strongpassword2",
	}
	auth := NewAuthenticator(users)

	// Valid credentials
	if !auth.Verify("traefik_dmz", "strongpassword1") {
		t.Error("expected valid verification for traefik_dmz")
	}
	if !auth.Verify("TRAEFIK_DMZ", "strongpassword1") {
		t.Error("expected case-insensitive username match")
	}

	// Invalid password
	if auth.Verify("traefik_dmz", "wrongpassword") {
		t.Error("expected failure on wrong password")
	}

	// Non-existent user
	if auth.Verify("unknown_user", "strongpassword1") {
		t.Error("expected failure on non-existent user")
	}

	// Empty credentials
	if auth.Verify("", "") {
		t.Error("expected failure on empty credentials")
	}
}

func TestAuthenticator_Middleware(t *testing.T) {
	users := map[string]string{
		"traefik": "secret123",
	}
	auth := NewAuthenticator(users)

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetAuthUser(r)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("welcome:" + user))
	})

	handler := auth.Middleware(dummyHandler)

	// 1. Missing Authorization header
	req := httptest.NewRequest(http.MethodPost, "/present", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Error("expected WWW-Authenticate header")
	}

	// 2. Invalid credentials
	req = httptest.NewRequest(http.MethodPost, "/present", nil)
	req.SetBasicAuth("traefik", "badpass")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 for bad pass, got %d", rr.Code)
	}

	// 3. Malformed Auth header
	req = httptest.NewRequest(http.MethodPost, "/present", nil)
	req.Header.Set("Authorization", "Bearer invalid")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 for malformed header, got %d", rr.Code)
	}

	// 4. Valid credentials
	req = httptest.NewRequest(http.MethodPost, "/present", nil)
	req.SetBasicAuth("traefik", "secret123")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	if rr.Body.String() != "welcome:traefik" {
		t.Fatalf("expected body 'welcome:traefik', got %q", rr.Body.String())
	}

	// 5. Basic auth with colon in password
	users["user2"] = "pass:with:colons"
	auth2 := NewAuthenticator(users)
	handler2 := auth2.Middleware(dummyHandler)
	req = httptest.NewRequest(http.MethodPost, "/present", nil)
	authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte("user2:pass:with:colons"))
	req.Header.Set("Authorization", authHeader)
	rr = httptest.NewRecorder()
	handler2.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 for colon in password, got %d", rr.Code)
	}
}
