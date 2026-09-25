package http

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/FirPic/legate/internal/challenge"
)

// MaxRequestBodyBytes defines the strict upper limit for challenge payloads (16 KiB).
const MaxRequestBodyBytes int64 = 16384

// Response represents the standard JSON API response structure.
type Response struct {
	Status   string `json:"status"`
	Action   string `json:"action,omitempty"`
	FQDN     string `json:"fqdn,omitempty"`
	RecordID string `json:"record_id,omitempty"`
	Error    string `json:"error,omitempty"`
}

func (s *Server) handlePresent(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	user := GetAuthUser(r)

	rawReq, statusErr := s.parsePresentPayload(w, r)
	if statusErr != nil {
		s.recordMetric("present", "error", start)
		s.writeJSONError(w, statusErr.code, statusErr.message)
		return
	}

	targetFQDN := strings.TrimSpace(rawReq.FQDN)
	if targetFQDN == "" && strings.TrimSpace(rawReq.Domain) != "" {
		targetFQDN = challenge.ACMEPrefix + strings.TrimSpace(rawReq.Domain)
	}
	if targetFQDN == "" {
		s.recordMetric("present", "error", start)
		s.writeJSONError(w, http.StatusBadRequest, "missing fqdn or domain in challenge payload")
		return
	}

	// 1. Dynamic multi-provider resolution from Registry
	dnsProv, baseDomain, err := s.registry.Resolve(targetFQDN)
	if err != nil {
		s.recordMetric("present", "error", start)
		slog.Warn("domain not authorized or not registered", "user", user, "fqdn", targetFQDN, "error", err)
		s.writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("domain %q is not authorized", targetFQDN))
		return
	}

	// 2. Validate and enforce RBAC against the resolved base domain
	authCtx := GetAuthContext(r)
	res, err := challenge.ResolveAndValidateForUser(
		rawReq.FQDN, rawReq.Value, rawReq.Domain, rawReq.Token, rawReq.KeyAuth,
		baseDomain, authCtx.Username, authCtx.AllowedSubdomains,
	)
	if err != nil {
		s.recordMetric("present", "error", start)
		code := http.StatusBadRequest
		if strings.Contains(err.Error(), "not authorized") || strings.Contains(err.Error(), "rbac authorization failed") {
			code = http.StatusForbidden
		}
		s.writeJSONError(w, code, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()

	recordID, err := dnsProv.Present(ctx, res.FQDN, res.Value)
	if err != nil {
		s.recordMetric("present", "error", start)
		slog.Error("dns provider failed to present challenge",
			"user", user,
			"fqdn", res.FQDN,
			"domain", baseDomain,
			"error", err,
		)
		s.writeJSONError(w, http.StatusBadGateway, "upstream DNS provider error")
		return
	}

	s.tracker.Store(res.FQDN, res.Value, recordID)
	s.recordMetric("present", "success", start)

	slog.Info("successfully presented ACME DNS challenge",
		"user", user,
		"fqdn", res.FQDN,
		"domain", baseDomain,
		"record_id", recordID,
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(Response{
		Status:   "success",
		Action:   "present",
		FQDN:     res.FQDN,
		RecordID: recordID,
	})
}

func (s *Server) handleCleanup(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	user := GetAuthUser(r)

	rawReq, statusErr := s.parseCleanupPayload(w, r)
	if statusErr != nil {
		s.recordMetric("cleanup", "error", start)
		s.writeJSONError(w, statusErr.code, statusErr.message)
		return
	}

	targetFQDN := strings.TrimSpace(rawReq.FQDN)
	if targetFQDN == "" && strings.TrimSpace(rawReq.Domain) != "" {
		targetFQDN = challenge.ACMEPrefix + strings.TrimSpace(rawReq.Domain)
	}
	if targetFQDN == "" {
		s.recordMetric("cleanup", "error", start)
		s.writeJSONError(w, http.StatusBadRequest, "missing fqdn or domain in challenge payload")
		return
	}

	// 1. Dynamic multi-provider resolution from Registry
	dnsProv, baseDomain, err := s.registry.Resolve(targetFQDN)
	if err != nil {
		s.recordMetric("cleanup", "error", start)
		slog.Warn("domain not authorized or not registered", "user", user, "fqdn", targetFQDN, "error", err)
		s.writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("domain %q is not authorized", targetFQDN))
		return
	}

	// 2. Validate and enforce RBAC against the resolved base domain
	authCtx := GetAuthContext(r)
	res, err := challenge.ResolveAndValidateForUser(
		rawReq.FQDN, rawReq.Value, rawReq.Domain, rawReq.Token, rawReq.KeyAuth,
		baseDomain, authCtx.Username, authCtx.AllowedSubdomains,
	)
	if err != nil {
		s.recordMetric("cleanup", "error", start)
		code := http.StatusBadRequest
		if strings.Contains(err.Error(), "not authorized") || strings.Contains(err.Error(), "rbac authorization failed") {
			code = http.StatusForbidden
		}
		s.writeJSONError(w, code, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()

	recordID, _ := s.tracker.Delete(res.FQDN, res.Value)

	err = dnsProv.Cleanup(ctx, res.FQDN, recordID, res.Value)
	if err != nil {
		s.recordMetric("cleanup", "error", start)
		slog.Error("dns provider failed to clean up challenge",
			"user", user,
			"fqdn", res.FQDN,
			"domain", baseDomain,
			"record_id", recordID,
			"error", err,
		)
		s.writeJSONError(w, http.StatusBadGateway, "upstream DNS provider error")
		return
	}

	s.recordMetric("cleanup", "success", start)

	slog.Info("successfully cleaned up ACME DNS challenge",
		"user", user,
		"fqdn", res.FQDN,
		"domain", baseDomain,
		"record_id", recordID,
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(Response{
		Status:   "success",
		Action:   "cleanup",
		FQDN:     res.FQDN,
		RecordID: recordID,
	})
}

type httpError struct {
	code    int
	message string
}

func (s *Server) parsePresentPayload(w http.ResponseWriter, r *http.Request) (*challenge.PresentRequest, *httpError) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return nil, &httpError{
				code:    http.StatusRequestEntityTooLarge,
				message: fmt.Sprintf("request body too large (maximum %d bytes)", MaxRequestBodyBytes),
			}
		}
		return nil, &httpError{code: http.StatusBadRequest, message: "failed to read request body"}
	}

	var req challenge.PresentRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, &httpError{code: http.StatusBadRequest, message: fmt.Sprintf("malformed json: %v", err)}
	}

	return &req, nil
}

func (s *Server) parseCleanupPayload(w http.ResponseWriter, r *http.Request) (*challenge.CleanupRequest, *httpError) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return nil, &httpError{
				code:    http.StatusRequestEntityTooLarge,
				message: fmt.Sprintf("request body too large (maximum %d bytes)", MaxRequestBodyBytes),
			}
		}
		return nil, &httpError{code: http.StatusBadRequest, message: "failed to read request body"}
	}

	var req challenge.CleanupRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, &httpError{code: http.StatusBadRequest, message: fmt.Sprintf("malformed json: %v", err)}
	}

	return &req, nil
}

func (s *Server) recordMetric(handler, status string, start time.Time) {
	if s.metrics != nil {
		s.metrics.ChallengesTotal.WithLabelValues(status).Inc()
		s.metrics.RequestDuration.WithLabelValues(handler, status).Observe(time.Since(start).Seconds())
	}
}

func (s *Server) writeJSONError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(Response{
		Status: "error",
		Error:  message,
	})
}
