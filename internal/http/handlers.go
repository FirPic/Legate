package http

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/FirPic/acme-dns-httpreq-proxy/internal/challenge"
)

// Response represents the standard JSON API response structure.
type Response struct {
	Status   string `json:"status"`
	Action   string `json:"action,omitempty"`
	FQDN     string `json:"fqdn,omitempty"`
	RecordID string `json:"record_id,omitempty"`
	Error    string `json:"error,omitempty"`
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":          "ok",
		"tracked_records": s.tracker.Count(),
		"allowed_domain":  s.allowedDomain,
	})
}

func (s *Server) handlePresent(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	user := GetAuthUser(r)

	res, statusErr := s.parsePresentRequest(r)
	if statusErr != nil {
		s.recordMetric("present", "error", user, start)
		s.writeJSONError(w, statusErr.code, statusErr.message)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()

	recordID, err := s.dnsProvider.Present(ctx, res.FQDN, res.Value)
	if err != nil {
		s.recordMetric("present", "error", user, start)
		slog.Error("dns provider failed to present challenge",
			"user", user,
			"fqdn", res.FQDN,
			"error", err,
		)
		s.writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("failed to present challenge: %v", err))
		return
	}

	s.tracker.Store(res.FQDN, res.Value, recordID)
	s.recordMetric("present", "success", user, start)

	slog.Info("successfully presented ACME DNS challenge",
		"user", user,
		"fqdn", res.FQDN,
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

	res, statusErr := s.parseCleanupRequest(r)
	if statusErr != nil {
		s.recordMetric("cleanup", "error", user, start)
		s.writeJSONError(w, statusErr.code, statusErr.message)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()

	recordID, _ := s.tracker.Delete(res.FQDN, res.Value)

	err := s.dnsProvider.Cleanup(ctx, res.FQDN, recordID, res.Value)
	if err != nil {
		s.recordMetric("cleanup", "error", user, start)
		slog.Error("dns provider failed to clean up challenge",
			"user", user,
			"fqdn", res.FQDN,
			"record_id", recordID,
			"error", err,
		)
		s.writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("failed to cleanup challenge: %v", err))
		return
	}

	s.recordMetric("cleanup", "success", user, start)

	slog.Info("successfully cleaned up ACME DNS challenge",
		"user", user,
		"fqdn", res.FQDN,
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

func (s *Server) parsePresentRequest(r *http.Request) (*challenge.ValidationResult, *httpError) {
	body, err := io.ReadAll(challenge.LimitReader(r.Body))
	if err != nil {
		return nil, &httpError{code: http.StatusBadRequest, message: "failed to read request body"}
	}

	var req challenge.PresentRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, &httpError{code: http.StatusBadRequest, message: fmt.Sprintf("malformed json: %v", err)}
	}

	res, err := challenge.ResolveAndValidate(req.FQDN, req.Value, req.Domain, req.Token, req.KeyAuth, s.allowedDomain)
	if err != nil {
		code := http.StatusBadRequest
		if strings.Contains(err.Error(), "not authorized") {
			code = http.StatusForbidden
		}
		return nil, &httpError{code: code, message: err.Error()}
	}

	return res, nil
}

func (s *Server) parseCleanupRequest(r *http.Request) (*challenge.ValidationResult, *httpError) {
	body, err := io.ReadAll(challenge.LimitReader(r.Body))
	if err != nil {
		return nil, &httpError{code: http.StatusBadRequest, message: "failed to read request body"}
	}

	var req challenge.CleanupRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, &httpError{code: http.StatusBadRequest, message: fmt.Sprintf("malformed json: %v", err)}
	}

	res, err := challenge.ResolveAndValidate(req.FQDN, req.Value, req.Domain, req.Token, req.KeyAuth, s.allowedDomain)
	if err != nil {
		code := http.StatusBadRequest
		if strings.Contains(err.Error(), "not authorized") {
			code = http.StatusForbidden
		}
		return nil, &httpError{code: code, message: err.Error()}
	}

	return res, nil
}

func (s *Server) recordMetric(handler, status, client string, start time.Time) {
	if s.metrics != nil {
		s.metrics.ChallengesTotal.WithLabelValues(status, client).Inc()
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
