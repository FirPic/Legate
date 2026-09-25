package server

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	// labelRegex matches standard DNS labels (RFC 1123): lowercase alphanumeric, hyphens allowed in middle.
	labelRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

const (
	acmePrefix = "_acme-challenge."
)

// ValidateFQDN checks whether a given FQDN is valid, safe, and belongs to the allowed domain.
// It strictly requires the format:
//   _acme-challenge.<allowedDomain>
// or
//   _acme-challenge.<subdomain>.<allowedDomain>
// (with or without a trailing dot).
func ValidateFQDN(fqdn, allowedDomain string) (string, error) {
	if fqdn == "" {
		return "", errors.New("fqdn cannot be empty")
	}

	// Normalize FQDN and allowedDomain
	normalizedFQDN := strings.ToLower(strings.TrimSpace(fqdn))
	normalizedFQDN = strings.TrimSuffix(normalizedFQDN, ".")

	normalizedAllowed := strings.ToLower(strings.TrimSpace(allowedDomain))
	normalizedAllowed = strings.TrimSuffix(normalizedAllowed, ".")

	if normalizedAllowed == "" {
		return "", errors.New("allowed domain is not configured")
	}

	// Total length check (RFC 1035 / RFC 1123)
	if len(normalizedFQDN) > 253 {
		return "", fmt.Errorf("fqdn exceeds maximum DNS length of 253 characters (got %d)", len(normalizedFQDN))
	}

	// Must start strictly with `_acme-challenge.`
	if !strings.HasPrefix(normalizedFQDN, acmePrefix) {
		return "", fmt.Errorf("fqdn %q must start with prefix %q", fqdn, acmePrefix)
	}

	domainPart := strings.TrimPrefix(normalizedFQDN, acmePrefix)
	if domainPart == "" {
		return "", errors.New("fqdn missing domain after challenge prefix")
	}

	// Verify that domainPart matches allowedDomain or is a subdomain of allowedDomain
	isExact := domainPart == normalizedAllowed
	isSubdomain := strings.HasSuffix(domainPart, "."+normalizedAllowed)

	if !isExact && !isSubdomain {
		return "", fmt.Errorf("domain %q is not authorized (must match or be subdomain of %q)", domainPart, normalizedAllowed)
	}

	// Validate each DNS label in domainPart
	labels := strings.Split(domainPart, ".")
	for _, label := range labels {
		if label == "" {
			return "", fmt.Errorf("invalid empty label in domain %q", domainPart)
		}
		if len(label) > 63 {
			return "", fmt.Errorf("label %q exceeds 63 characters", label)
		}
		if !labelRegex.MatchString(label) {
			return "", fmt.Errorf("invalid label format %q: must adhere to RFC 1123", label)
		}
	}

	return normalizedFQDN, nil
}

// ValidateChallengeValue validates that the ACME TXT value is non-empty and contains safe characters.
func ValidateChallengeValue(value string) error {
	v := strings.TrimSpace(value)
	if v == "" {
		return errors.New("challenge value cannot be empty")
	}
	if len(v) > 512 {
		return errors.New("challenge value is too long")
	}
	// Check for dangerous control characters (CRLF, null byte)
	for _, r := range v {
		if r < 32 || r == 127 {
			return errors.New("challenge value contains invalid control characters")
		}
	}
	return nil
}
