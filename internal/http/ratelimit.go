package http

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type tokenBucket struct {
	tokens     float64
	lastRefill time.Time
}

// RateLimiter implements a concurrency-safe in-memory token bucket rate limiter.
type RateLimiter struct {
	mu           sync.Mutex
	ratePerSec   float64
	capacity     float64
	buckets      map[string]*tokenBucket
	cleanupTimer *time.Ticker
	stopCh       chan struct{}
}

// NewRateLimiter creates a RateLimiter allowing requestsPerMinute with burst up to requestsPerMinute.
func NewRateLimiter(requestsPerMinute int) *RateLimiter {
	if requestsPerMinute < 1 {
		requestsPerMinute = 60
	}

	capacity := float64(requestsPerMinute)
	ratePerSec := capacity / 60.0

	rl := &RateLimiter{
		ratePerSec:   ratePerSec,
		capacity:     capacity,
		buckets:      make(map[string]*tokenBucket),
		cleanupTimer: time.NewTicker(5 * time.Minute),
		stopCh:       make(chan struct{}),
	}

	go rl.cleanupLoop()

	return rl
}

// Stop terminates the background cleanup goroutine.
func (rl *RateLimiter) Stop() {
	rl.cleanupTimer.Stop()
	close(rl.stopCh)
}

func (rl *RateLimiter) cleanupLoop() {
	for {
		select {
		case <-rl.cleanupTimer.C:
			rl.mu.Lock()
			now := time.Now()
			for k, b := range rl.buckets {
				// Evict buckets idle for more than 10 minutes
				if now.Sub(b.lastRefill) > 10*time.Minute {
					delete(rl.buckets, k)
				}
			}
			rl.mu.Unlock()
		case <-rl.stopCh:
			return
		}
	}
}

// Allow reports whether a request from the given key is permitted.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, exists := rl.buckets[key]
	if !exists {
		rl.buckets[key] = &tokenBucket{
			tokens:     rl.capacity - 1.0,
			lastRefill: now,
		}
		return true
	}

	// Refill tokens based on elapsed duration
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * rl.ratePerSec
	if b.tokens > rl.capacity {
		b.tokens = rl.capacity
	}
	b.lastRefill = now

	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true
	}

	return false
}

// IPMiddleware enforces rate limiting strictly based on the client's remote IP address.
// This is used pre-authentication to prevent brute-force attacks and volumetric DoS.
func (rl *RateLimiter) IPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = strings.TrimSpace(r.RemoteAddr)
		}

		if !rl.Allow(host) {
			w.Header().Set("Retry-After", "1")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status": "error",
				"error":  "rate limit exceeded: too many requests from this IP",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// UserMiddleware enforces rate limiting based on the authenticated user identity.
func (rl *RateLimiter) UserMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetAuthUser(r)
		if user == "" || user == "anonymous" {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = strings.TrimSpace(r.RemoteAddr)
			}
			user = host
		}

		if !rl.Allow(user) {
			w.Header().Set("Retry-After", "1")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status": "error",
				"error":  "rate limit exceeded: too many requests",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Middleware wraps an http.Handler with rate limiting (defaults to UserMiddleware).
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return rl.UserMiddleware(next)
}
