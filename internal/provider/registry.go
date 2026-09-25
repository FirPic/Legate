package provider

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// ACMEChallengePrefix is the standard ACME DNS-01 prefix.
const ACMEChallengePrefix = "_acme-challenge."

// ErrDomainNotFound is returned when no registered provider matches the target FQDN.
var ErrDomainNotFound = errors.New("no registered DNS provider found for domain")

// Registry maps root DNS domains to their respective DNSProvider implementations.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]DNSProvider
}

// NewRegistry initializes an empty DNS provider Registry.
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]DNSProvider),
	}
}

// Register registers a DNSProvider for a specific domain zone (e.g. "example.com").
// Domain normalization ensures lowercasing and removal of trailing dots.
func (r *Registry) Register(domain string, p DNSProvider) error {
	if p == nil {
		return errors.New("provider cannot be nil")
	}

	norm := normalizeDomain(domain)
	if norm == "" {
		return errors.New("domain cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.providers[norm]; exists {
		return fmt.Errorf("domain %q is already registered", norm)
	}

	r.providers[norm] = p
	return nil
}

// Resolve looks up the most specific DNSProvider matching the provided FQDN.
// It handles FQDNs with or without the "_acme-challenge." prefix and trailing dots.
// Returns the matched DNSProvider, the registered base domain, and any error.
func (r *Registry) Resolve(fqdn string) (DNSProvider, string, error) {
	norm := normalizeDomain(fqdn)
	if norm == "" {
		return nil, "", errors.New("fqdn cannot be empty")
	}

	// Strip ACME prefix if present to match against domain tree
	targetDomain := norm
	if strings.HasPrefix(norm, ACMEChallengePrefix) {
		targetDomain = strings.TrimPrefix(norm, ACMEChallengePrefix)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	var bestMatchDomain string
	var bestProvider DNSProvider

	for registeredDomain, prov := range r.providers {
		// Exact match or subdomain match
		if targetDomain == registeredDomain || strings.HasSuffix(targetDomain, "."+registeredDomain) {
			if len(registeredDomain) > len(bestMatchDomain) {
				bestMatchDomain = registeredDomain
				bestProvider = prov
			}
		}
	}

	if bestProvider == nil {
		return nil, "", fmt.Errorf("%w: %q", ErrDomainNotFound, targetDomain)
	}

	return bestProvider, bestMatchDomain, nil
}

// RegisteredDomains returns a sorted slice of all domains configured in the registry.
func (r *Registry) RegisteredDomains() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	domains := make([]string, 0, len(r.providers))
	for d := range r.providers {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	return domains
}

// Count returns the number of registered domains.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.providers)
}

func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	return strings.TrimSuffix(d, ".")
}
