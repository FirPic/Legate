package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/FirPic/acme-dns-httpreq-proxy/internal/config"
	"github.com/FirPic/acme-dns-httpreq-proxy/internal/dns"
	"github.com/FirPic/acme-dns-httpreq-proxy/internal/lock"
)

// ChallengeRequest represents the JSON payload sent by Lego httpreq provider.
// It supports both default mode (fqdn + value) and raw mode (domain + keyAuth).
type ChallengeRequest struct {
	FQDN    string `json:"fqdn"`
	Value   string `json:"value"`
	Domain  string `json:"domain"`
	Token   string `json:"token"`
	KeyAuth string `json:"keyAuth"`
}

// Response is the standard JSON response format.
type Response struct {
	Status   string `json:"status"`
	Action   string `json:"action,omitempty"`
	FQDN     string `json:"fqdn,omitempty"`
	RecordID string `json:"record_id,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Server handles HTTP requests for ACME DNS-01 challenges.
type Server struct {
	cfg           *config.Config
	dnsClient     dns.DNSClient
	tracker       *lock.RecordTracker
	authenticator *Authenticator
	mux           *http.ServeMux
}

// NewServer creates a new HTTP server instance with route bindings.
func NewServer(cfg *config.Config, dnsClient dns.DNSClient, tracker *lock.RecordTracker) *Server {
	auth := NewAuthenticator(cfg.Users)
	s := &Server{
		cfg:           cfg,
		dnsClient:     dnsClient,
		tracker:       tracker,
		authenticator: auth,
		mux:           http.NewServeMux(),
	}

	s.routes()
	return s
}

func (s *Server) routes() {
	// Public health check
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)

	// Protected Lego httpreq endpoints
	s.mux.Handle("POST /present", s.authenticator.Middleware(http.HandlerFunc(s.handlePresent)))
	s.mux.Handle("POST /cleanup", s.authenticator.Middleware(http.HandlerFunc(s.handleCleanup)))
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":          "ok",
		"tracked_records": s.tracker.Count(),
		"allowed_domain":  s.cfg.AllowedDomain,
	})
}

func (s *Server) handlePresent(w http.ResponseWriter, r *http.Request) {
	user := GetAuthUser(r)
	fqdn, value, err := s.parseAndValidate(r)
	if err != nil {
		s.writeJSONError(w, r, err.statusCode, err.message)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()

	zoneID, errZone := s.getZoneID(ctx)
	if errZone != nil {
		slog.Error("failed to resolve zone ID", "error", errZone, "domain", s.cfg.AllowedDomain)
		s.writeJSONError(w, r, http.StatusBadGateway, fmt.Sprintf("failed to resolve zone ID: %v", errZone))
		return
	}

	recordID, errCreate := s.dnsClient.CreateTXTRecord(ctx, zoneID, fqdn, value)
	if errCreate != nil {
		slog.Error("failed to create TXT record in Cloudflare",
			"user", user,
			"fqdn", fqdn,
			"error", errCreate,
		)
		s.writeJSONError(w, r, http.StatusBadGateway, fmt.Sprintf("failed to create DNS TXT record: %v", errCreate))
		return
	}

	// Track created record
	s.tracker.Store(fqdn, value, recordID)

	slog.Info("successfully created ACME challenge TXT record",
		"user", user,
		"fqdn", fqdn,
		"record_id", recordID,
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(Response{
		Status:   "success",
		Action:   "present",
		FQDN:     fqdn,
		RecordID: recordID,
	})
}

func (s *Server) handleCleanup(w http.ResponseWriter, r *http.Request) {
	user := GetAuthUser(r)
	fqdn, value, err := s.parseAndValidate(r)
	if err != nil {
		s.writeJSONError(w, r, err.statusCode, err.message)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()

	zoneID, errZone := s.getZoneID(ctx)
	if errZone != nil {
		slog.Error("failed to resolve zone ID during cleanup", "error", errZone, "domain", s.cfg.AllowedDomain)
		s.writeJSONError(w, r, http.StatusBadGateway, fmt.Sprintf("failed to resolve zone ID: %v", errZone))
		return
	}

	recordID, foundInTracker := s.tracker.Delete(fqdn, value)
	if !foundInTracker {
		slog.Warn("record not found in local tracker, searching Cloudflare directly",
			"user", user,
			"fqdn", fqdn,
		)
		foundID, errFind := s.dnsClient.FindTXTRecord(ctx, zoneID, fqdn, value)
		if errFind != nil {
			slog.Error("failed to query Cloudflare for existing record", "error", errFind, "fqdn", fqdn)
			s.writeJSONError(w, r, http.StatusBadGateway, fmt.Sprintf("failed to find DNS record: %v", errFind))
			return
		}
		recordID = foundID
	}

	if recordID != "" {
		if errDel := s.dnsClient.DeleteTXTRecord(ctx, zoneID, recordID); errDel != nil {
			slog.Error("failed to delete TXT record from Cloudflare",
				"user", user,
				"fqdn", fqdn,
				"record_id", recordID,
				"error", errDel,
			)
			s.writeJSONError(w, r, http.StatusBadGateway, fmt.Sprintf("failed to delete DNS TXT record: %v", errDel))
			return
		}
	} else {
		slog.Info("no matching record found to delete (already removed)",
			"user", user,
			"fqdn", fqdn,
		)
	}

	slog.Info("successfully cleaned up ACME challenge TXT record",
		"user", user,
		"fqdn", fqdn,
		"record_id", recordID,
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(Response{
		Status:   "success",
		Action:   "cleanup",
		FQDN:     fqdn,
		RecordID: recordID,
	})
}

func (s *Server) getZoneID(ctx context.Context) (string, error) {
	if s.cfg.CloudflareZoneID != "" {
		return s.cfg.CloudflareZoneID, nil
	}
	return s.dnsClient.GetZoneID(ctx, s.cfg.AllowedDomain)
}

type validationError struct {
	statusCode int
	message    string
}

func (e *validationError) Error() string {
	return e.message
}

func (s *Server) parseAndValidate(r *http.Request) (string, string, *validationError) {
	// Limit request size to prevent DoS (max 64KB)
	r.Body = http.MaxBytesReader(nil, r.Body, 64*1024)

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return "", "", &validationError{
			statusCode: http.StatusBadRequest,
			message:    "cannot read request body or body too large",
		}
	}

	var req ChallengeRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		return "", "", &validationError{
			statusCode: http.StatusBadRequest,
			message:    fmt.Sprintf("malformed json body: %v", err),
		}
	}

	// Extract or construct FQDN
	fqdn := strings.TrimSpace(req.FQDN)
	if fqdn == "" && req.Domain != "" {
		// RAW mode fallback
		domain := strings.TrimSpace(req.Domain)
		fqdn = acmePrefix + domain
	}

	// Extract or construct Value
	value := strings.TrimSpace(req.Value)
	if value == "" && req.KeyAuth != "" {
		// RAW mode computes SHA256 of keyAuth
		h := sha256.Sum256([]byte(strings.TrimSpace(req.KeyAuth)))
		value = base64.RawURLEncoding.EncodeToString(h[:])
	}

	// Validate FQDN against allowed domain
	normalizedFQDN, errVal := ValidateFQDN(fqdn, s.cfg.AllowedDomain)
	if errVal != nil {
		slog.Warn("forbidden challenge request: fqdn rejected",
			"fqdn_provided", fqdn,
			"allowed_domain", s.cfg.AllowedDomain,
			"reason", errVal.Error(),
			"remote_addr", r.RemoteAddr,
		)
		return "", "", &validationError{
			statusCode: http.StatusForbidden,
			message:    fmt.Sprintf("forbidden: %v", errVal),
		}
	}

	// Validate Challenge value
	if errValVal := ValidateChallengeValue(value); errValVal != nil {
		return "", "", &validationError{
			statusCode: http.StatusBadRequest,
			message:    fmt.Sprintf("invalid challenge value: %v", errValVal),
		}
	}

	return normalizedFQDN, value, nil
}

func (s *Server) writeJSONError(w http.ResponseWriter, r *http.Request, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(Response{
		Status: "error",
		Error:  message,
	})
}
