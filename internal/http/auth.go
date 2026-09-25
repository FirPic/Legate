package http

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/FirPic/legate/internal/config"
)

type contextKey string

const (
	authContextKey contextKey = "auth_context"
	dummySecret               = "invalid-dummy-password-for-constant-time-comparison-protection"
)

// AuthContext holds the verified identity and RBAC boundaries of an authenticated request.
type AuthContext struct {
	Username          string
	AllowedSubdomains []string
}

// Authenticator handles HTTP Basic Authentication using constant-time hashed comparisons.
type Authenticator struct {
	users map[string]config.UserConfig
}

// NewAuthenticator creates an Authenticator with a normalized map of user configurations.
func NewAuthenticator(users map[string]config.UserConfig) *Authenticator {
	copyUsers := make(map[string]config.UserConfig, len(users))
	for u, cfg := range users {
		copyUsers[strings.ToLower(strings.TrimSpace(u))] = cfg
	}
	return &Authenticator{users: copyUsers}
}

// Verify checks the provided username and password.
// If the stored password is an Argon2id hash ($argon2id$), it performs constant-time Argon2id verification.
// Otherwise, it falls back to SHA-256 constant-time comparison for legacy plaintext passwords.
// To prevent timing-based user enumeration, non-existent users trigger an equivalent evaluation.
func (a *Authenticator) Verify(username, password string) (*config.UserConfig, bool) {
	u := strings.ToLower(strings.TrimSpace(username))
	expectedCfg, userFound := a.users[u]

	if userFound {
		if IsArgon2idHash(expectedCfg.Password) {
			valid, err := VerifyPassword(password, expectedCfg.Password)
			if err == nil && valid {
				return &expectedCfg, true
			}
			return nil, false
		}

		// Legacy fallback: SHA-256 constant-time comparison
		hProvided := sha256.Sum256([]byte(password))
		hExpected := sha256.Sum256([]byte(expectedCfg.Password))
		if subtle.ConstantTimeCompare(hProvided[:], hExpected[:]) == 1 {
			return &expectedCfg, true
		}
		return nil, false
	}

	// Prevent user enumeration by evaluating against a dummy password hash
	hProvided := sha256.Sum256([]byte(password))
	hExpected := sha256.Sum256([]byte(dummySecret))
	_ = subtle.ConstantTimeCompare(hProvided[:], hExpected[:])
	return nil, false
}

// Middleware returns an HTTP middleware enforcing Basic Auth and injecting AuthContext.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			a.writeUnauthorized(w, r, "missing authorization header")
			return
		}

		userCfg, valid := a.Verify(username, password)
		if !valid {
			a.writeUnauthorized(w, r, "invalid credentials")
			return
		}

		normUser := strings.ToLower(strings.TrimSpace(username))
		authCtx := &AuthContext{
			Username:          normUser,
			AllowedSubdomains: userCfg.AllowedSubdomains,
		}

		ctx := context.WithValue(r.Context(), authContextKey, authCtx)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *Authenticator) writeUnauthorized(w http.ResponseWriter, r *http.Request, reason string) {
	username, _, _ := r.BasicAuth()
	slog.Warn("unauthorized request attempt",
		"remote_addr", r.RemoteAddr,
		"path", r.URL.Path,
		"user_provided", username,
		"reason", reason,
	)

	w.Header().Set("WWW-Authenticate", `Basic realm="legate", charset="UTF-8"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "error",
		"error":  "unauthorized: valid basic authentication credentials required",
	})
}

// GetAuthContext retrieves the AuthContext from the request context, if present.
func GetAuthContext(r *http.Request) *AuthContext {
	if val := r.Context().Value(authContextKey); val != nil {
		if authCtx, ok := val.(*AuthContext); ok {
			return authCtx
		}
	}
	return &AuthContext{
		Username:          "anonymous",
		AllowedSubdomains: nil,
	}
}

// GetAuthUser retrieves the authenticated username from the request context.
func GetAuthUser(r *http.Request) string {
	return GetAuthContext(r).Username
}

// GetAuthSubdomains retrieves the allowed subdomains from the request context.
func GetAuthSubdomains(r *http.Request) []string {
	return GetAuthContext(r).AllowedSubdomains
}
