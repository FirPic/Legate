package http

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

type contextKey string

const (
	authUserKey contextKey = "auth_user"
	dummySecret            = "invalid-dummy-password-for-constant-time-comparison-protection"
)

// Authenticator handles HTTP Basic Authentication using constant-time comparisons.
type Authenticator struct {
	users map[string]string
}

// NewAuthenticator creates an Authenticator with a normalized map of username to password.
func NewAuthenticator(users map[string]string) *Authenticator {
	copyUsers := make(map[string]string, len(users))
	for u, p := range users {
		copyUsers[strings.ToLower(strings.TrimSpace(u))] = p
	}
	return &Authenticator{users: copyUsers}
}

// Verify checks the provided username and password using constant-time comparison.
// It executes a dummy comparison if the user is missing to mitigate timing attack user enumeration.
func (a *Authenticator) Verify(username, password string) bool {
	u := strings.ToLower(strings.TrimSpace(username))
	expectedPassword, userFound := a.users[u]

	var passMatch int
	if userFound {
		passMatch = subtle.ConstantTimeCompare([]byte(password), []byte(expectedPassword))
	} else {
		_ = subtle.ConstantTimeCompare([]byte(password), []byte(dummySecret))
		passMatch = 0
	}

	return userFound && passMatch == 1
}

// Middleware returns an HTTP middleware enforcing Basic Auth.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || !a.Verify(username, password) {
			slog.Warn("unauthorized request attempt",
				"remote_addr", r.RemoteAddr,
				"path", r.URL.Path,
				"user_provided", username,
			)

			w.Header().Set("WWW-Authenticate", `Basic realm="acme-dns-httpreq-proxy", charset="UTF-8"`)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status": "error",
				"error":  "unauthorized: valid basic authentication credentials required",
			})
			return
		}

		ctx := context.WithValue(r.Context(), authUserKey, strings.ToLower(strings.TrimSpace(username)))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetAuthUser retrieves the authenticated username from the request context, if present.
func GetAuthUser(r *http.Request) string {
	if val := r.Context().Value(authUserKey); val != nil {
		if user, ok := val.(string); ok {
			return user
		}
	}
	return "anonymous"
}
