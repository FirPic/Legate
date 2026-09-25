package http

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/FirPic/legate/internal/config"
)

func TestAuthenticator_Verify(t *testing.T) {
	users := map[string]config.UserConfig{
		"traefik_dmz": {
			Password:          "strongpassword1",
			AllowedSubdomains: []string{"*.dmz.firpic.fr", "dmz.firpic.fr"},
		},
		"traefik_infra": {
			Password:          "strongpassword2",
			AllowedSubdomains: []string{"*"},
		},
		"traefik_argon": {
			Password:          "$argon2id$v=19$m=65536,t=3,p=2$dGVzdHNhbHQxMjM0NTY3OA$B2WvM8iL+9wKqF2l6X2pY1z8v0s3j4h5g6f7e8d9c0b",
			AllowedSubdomains: []string{"*.secure.fr"},
		},
	}
	auth := NewAuthenticator(users)

	// Valid credentials
	cfg, valid := auth.Verify("traefik_dmz", "strongpassword1")
	if !valid || cfg == nil {
		t.Error("expected valid verification for traefik_dmz")
	}
	if len(cfg.AllowedSubdomains) != 2 {
		t.Errorf("expected 2 subdomains, got %d", len(cfg.AllowedSubdomains))
	}

	// Case-insensitive username match
	_, validCase := auth.Verify("TRAEFIK_DMZ", "strongpassword1")
	if !validCase {
		t.Error("expected case-insensitive username match")
	}

	// Invalid password of equal length
	_, validBadPass := auth.Verify("traefik_dmz", "wrongpassword1")
	if validBadPass {
		t.Error("expected failure on wrong password")
	}

	// Invalid password of vastly different length (timing attack check)
	_, validLongPass := auth.Verify("traefik_dmz", strings.Repeat("x", 256))
	if validLongPass {
		t.Error("expected failure on long password")
	}

	// Non-existent user
	_, validUnknown := auth.Verify("unknown_user", "strongpassword1")
	if validUnknown {
		t.Error("expected failure on non-existent user")
	}

	// Empty credentials
	_, validEmpty := auth.Verify("", "")
	if validEmpty {
		t.Error("expected failure on empty credentials")
	}

	// Argon2id user verification
	argonPass := "argonSecret#2026"
	argonHash, err := HashPassword(argonPass)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	users["argon_user"] = config.UserConfig{
		Password:          argonHash,
		AllowedSubdomains: []string{"*.secure.fr"},
	}
	authWithArgon := NewAuthenticator(users)

	_, validArgon := authWithArgon.Verify("argon_user", argonPass)
	if !validArgon {
		t.Error("expected valid verification for Argon2id hashed password")
	}

	_, invalidArgon := authWithArgon.Verify("argon_user", "wrongArgonPass")
	if invalidArgon {
		t.Error("expected failure on wrong password for Argon2id user")
	}
}

func TestAuthenticator_Middleware(t *testing.T) {
	users := map[string]config.UserConfig{
		"traefik": {
			Password:          "secret123",
			AllowedSubdomains: []string{"*.dmz.firpic.fr"},
		},
	}
	auth := NewAuthenticator(users)

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authCtx := GetAuthContext(r)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("welcome:" + authCtx.Username + ":" + authCtx.AllowedSubdomains[0]))
	})

	handler := auth.Middleware(dummyHandler)

	// 1. Missing Authorization header
	req := httptest.NewRequest(http.MethodPost, "/present", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") != `Basic realm="legate", charset="UTF-8"` {
		t.Errorf("expected realm legate, got %q", rr.Header().Get("WWW-Authenticate"))
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
	if rr.Body.String() != "welcome:traefik:*.dmz.firpic.fr" {
		t.Fatalf("expected body 'welcome:traefik:*.dmz.firpic.fr', got %q", rr.Body.String())
	}

	// 5. Basic auth with colon in password
	users["user2"] = config.UserConfig{
		Password:          "pass:with:colons",
		AllowedSubdomains: []string{"*"},
	}
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
