package challenge

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// PresentRequest represents the payload sent by ACME Lego httpreq provider on /present.
// Supports both standard mode (fqdn + value) and raw mode (domain + keyAuth/token).
type PresentRequest struct {
	FQDN    string `json:"fqdn"`
	Value   string `json:"value"`
	Domain  string `json:"domain"`
	Token   string `json:"token"`
	KeyAuth string `json:"keyAuth"`
}

// CleanupRequest represents the payload sent by ACME Lego httpreq provider on /cleanup.
type CleanupRequest struct {
	FQDN    string `json:"fqdn"`
	Value   string `json:"value"`
	Domain  string `json:"domain"`
	Token   string `json:"token"`
	KeyAuth string `json:"keyAuth"`
}

// ValidationResult contains the sanitized, normalized, and validated challenge parameters.
type ValidationResult struct {
	FQDN  string
	Value string
}

// ResolveAndValidate parses raw input fields, derives challenge TXT parameters if raw mode is used,
// and enforces strict RFC 1123, FQDN allowlist, and value safety rules.
func ResolveAndValidate(rawFQDN, rawValue, rawDomain, rawToken, rawKeyAuth, allowedDomain string) (*ValidationResult, error) {
	return ResolveAndValidateForUser(rawFQDN, rawValue, rawDomain, rawToken, rawKeyAuth, allowedDomain, "anonymous", []string{"*"})
}

// ResolveAndValidateForUser enforces both zone-level validation and user-level subdomain RBAC.
func ResolveAndValidateForUser(
	rawFQDN, rawValue, rawDomain, rawToken, rawKeyAuth, allowedDomain, user string,
	allowedSubdomains []string,
) (*ValidationResult, error) {
	fqdn := strings.TrimSpace(rawFQDN)
	if fqdn == "" && strings.TrimSpace(rawDomain) != "" {
		// Lego raw mode fallback: compute FQDN from domain
		fqdn = ACMEPrefix + strings.TrimSpace(rawDomain)
	}

	value := strings.TrimSpace(rawValue)
	if value == "" && strings.TrimSpace(rawKeyAuth) != "" {
		// Lego raw mode fallback: SHA256 digest of keyAuth encoded in base64 URL raw format
		h := sha256.Sum256([]byte(strings.TrimSpace(rawKeyAuth)))
		value = base64.RawURLEncoding.EncodeToString(h[:])
	}

	if fqdn == "" {
		return nil, errors.New("missing fqdn or domain in challenge payload")
	}
	if value == "" {
		return nil, errors.New("missing value or keyAuth in challenge payload")
	}

	normFQDN, err := ValidateFQDN(fqdn, allowedDomain)
	if err != nil {
		return nil, fmt.Errorf("invalid fqdn: %w", err)
	}

	if err := ValidateForUser(user, normFQDN, allowedSubdomains); err != nil {
		return nil, fmt.Errorf("rbac authorization failed: %w", err)
	}

	if err := ValidateChallengeValue(value); err != nil {
		return nil, fmt.Errorf("invalid challenge value: %w", err)
	}

	return &ValidationResult{
		FQDN:  normFQDN,
		Value: value,
	}, nil
}
