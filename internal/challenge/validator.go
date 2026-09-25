package challenge

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	// ACMEPrefix is the standardized ACME DNS-01 challenge prefix.
	ACMEPrefix = "_acme-challenge."
	// MaxFQDNLength is the maximum length of a DNS domain according to RFC 1035 / RFC 1123.
	MaxFQDNLength = 253
	// MaxLabelLength is the maximum length of a single DNS label according to RFC 1035.
	MaxLabelLength = 63
	// MaxValueLength is the upper bound on ACME challenge TXT token length.
	MaxValueLength = 512
)

var (
	// labelRegex matches standard DNS labels (RFC 1123): lowercase alphanumeric, hyphens allowed internally.
	labelRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// ValidateFQDN checks whether a given FQDN is valid, safe, and belongs to the allowed domain.
// It strictly requires the format:
//
//	_acme-challenge.<allowedDomain>
//
// or
//
//	_acme-challenge.<subdomain>.<allowedDomain>
//
// (with or without a trailing dot). Returns normalized lowercase FQDN without trailing dot.
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
	if len(normalizedFQDN) > MaxFQDNLength {
		return "", fmt.Errorf("fqdn exceeds maximum DNS length of %d characters (got %d)", MaxFQDNLength, len(normalizedFQDN))
	}

	// Check for path traversal or invalid characters in FQDN
	if strings.ContainsAny(normalizedFQDN, "/\\:*?\"<>| \t\r\n\x00") {
		return "", errors.New("fqdn contains forbidden control or path traversal characters")
	}

	// Must start strictly with `_acme-challenge.`
	if !strings.HasPrefix(normalizedFQDN, ACMEPrefix) {
		return "", fmt.Errorf("fqdn %q must start with prefix %q", fqdn, ACMEPrefix)
	}

	domainPart := strings.TrimPrefix(normalizedFQDN, ACMEPrefix)
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
		if len(label) > MaxLabelLength {
			return "", fmt.Errorf("label %q exceeds %d characters", label, MaxLabelLength)
		}
		if !labelRegex.MatchString(label) {
			return "", fmt.Errorf("invalid label format %q: must adhere to RFC 1123", label)
		}
	}

	return normalizedFQDN, nil
}

// ValidateForUser verifies that the requested FQDN falls strictly within the subdomain patterns assigned to the user.
// Supported pattern formats:
//   - "*" : permits any domain under the zone
//   - "dmz.firpic.fr" : exact match for dmz.firpic.fr
//   - "*.dmz.firpic.fr" : wildcard match for any direct or nested child (e.g. app.dmz.firpic.fr)
func ValidateForUser(user string, reqFQDN string, allowedSubdomains []string) error {
	if len(allowedSubdomains) == 0 {
		return fmt.Errorf("user %q has no authorized subdomains configured", user)
	}

	normFQDN := strings.ToLower(strings.TrimSpace(reqFQDN))
	normFQDN = strings.TrimSuffix(normFQDN, ".")

	if !strings.HasPrefix(normFQDN, ACMEPrefix) {
		return fmt.Errorf("fqdn %q must start with prefix %q", reqFQDN, ACMEPrefix)
	}

	domainPart := strings.TrimPrefix(normFQDN, ACMEPrefix)

	for _, pattern := range allowedSubdomains {
		p := strings.ToLower(strings.TrimSpace(pattern))
		p = strings.TrimSuffix(p, ".")

		if p == "*" {
			return nil
		}

		if strings.HasPrefix(p, "*.") {
			base := strings.TrimPrefix(p, "*.")
			if strings.HasSuffix(domainPart, "."+base) {
				return nil
			}
		} else if domainPart == p {
			return nil
		}
	}

	return fmt.Errorf("user %q is not authorized for domain %q (allowed patterns: %v)", user, domainPart, allowedSubdomains)
}

// ValidateChallengeValue validates that the ACME TXT value is non-empty and contains safe characters.
func ValidateChallengeValue(value string) error {
	v := strings.TrimSpace(value)
	if v == "" {
		return errors.New("challenge value cannot be empty")
	}
	if len(v) > MaxValueLength {
		return fmt.Errorf("challenge value exceeds maximum length of %d characters", MaxValueLength)
	}

	// Check for dangerous control characters (CRLF, null byte) to prevent header or command injection
	for _, r := range v {
		if r < 32 || r == 127 {
			return errors.New("challenge value contains invalid control characters")
		}
	}
	return nil
}
