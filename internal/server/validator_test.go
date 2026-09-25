package server

import (
	"strings"
	"testing"
)

func TestValidateFQDN(t *testing.T) {
	allowedDomain := "firpic.fr"

	testCases := []struct {
		name      string
		fqdn      string
		allowed   string
		expectErr bool
		expected  string
	}{
		{
			name:      "Valid apex challenge without trailing dot",
			fqdn:      "_acme-challenge.firpic.fr",
			allowed:   allowedDomain,
			expectErr: false,
			expected:  "_acme-challenge.firpic.fr",
		},
		{
			name:      "Valid apex challenge with trailing dot",
			fqdn:      "_acme-challenge.firpic.fr.",
			allowed:   allowedDomain,
			expectErr: false,
			expected:  "_acme-challenge.firpic.fr",
		},
		{
			name:      "Valid single-level subdomain",
			fqdn:      "_acme-challenge.traefik.firpic.fr",
			allowed:   allowedDomain,
			expectErr: false,
			expected:  "_acme-challenge.traefik.firpic.fr",
		},
		{
			name:      "Valid multi-level subdomain with trailing dot and uppercase",
			fqdn:      "_ACME-CHALLENGE.Sub.Internal.FirPic.FR.",
			allowed:   allowedDomain,
			expectErr: false,
			expected:  "_acme-challenge.sub.internal.firpic.fr",
		},
		{
			name:      "Attack: Suffix mismatch / external domain",
			fqdn:      "_acme-challenge.firpic.fr.attacker.com",
			allowed:   allowedDomain,
			expectErr: true,
		},
		{
			name:      "Attack: Similar domain / typosquatting",
			fqdn:      "_acme-challenge.notfirpic.fr",
			allowed:   allowedDomain,
			expectErr: true,
		},
		{
			name:      "Attack: Prefix evasion (missing underscore)",
			fqdn:      "acme-challenge.firpic.fr",
			allowed:   allowedDomain,
			expectErr: true,
		},
		{
			name:      "Attack: Double prefix injection",
			fqdn:      "_acme-challenge._acme-challenge.firpic.fr",
			allowed:   allowedDomain,
			expectErr: true, // label cannot start with underscore
		},
		{
			name:      "Attack: Missing challenge prefix entirely",
			fqdn:      "firpic.fr",
			allowed:   allowedDomain,
			expectErr: true,
		},
		{
			name:      "Attack: Empty FQDN",
			fqdn:      "",
			allowed:   allowedDomain,
			expectErr: true,
		},
		{
			name:      "Attack: Directory traversal attempt",
			fqdn:      "_acme-challenge.foo/../firpic.fr",
			allowed:   allowedDomain,
			expectErr: true,
		},
		{
			name:      "Attack: CRLF injection in FQDN",
			fqdn:      "_acme-challenge.sub\r\n.firpic.fr",
			allowed:   allowedDomain,
			expectErr: true,
		},
		{
			name:      "Attack: Empty label (double dot)",
			fqdn:      "_acme-challenge..firpic.fr",
			allowed:   allowedDomain,
			expectErr: true,
		},
		{
			name:      "Attack: Label starting with hyphen",
			fqdn:      "_acme-challenge.-sub.firpic.fr",
			allowed:   allowedDomain,
			expectErr: true,
		},
		{
			name:      "Attack: Label ending with hyphen",
			fqdn:      "_acme-challenge.sub-.firpic.fr",
			allowed:   allowedDomain,
			expectErr: true,
		},
		{
			name:      "Attack: Oversized FQDN (>253 chars)",
			fqdn:      "_acme-challenge." + strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." + strings.Repeat("d", 60) + ".firpic.fr",
			allowed:   allowedDomain,
			expectErr: true,
		},
		{
			name:      "Attack: Oversized single label (>63 chars)",
			fqdn:      "_acme-challenge." + strings.Repeat("a", 64) + ".firpic.fr",
			allowed:   allowedDomain,
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateFQDN(tc.fqdn, tc.allowed)
			if tc.expectErr {
				if err == nil {
					t.Errorf("expected error for FQDN %q, got nil (result: %q)", tc.fqdn, got)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for FQDN %q: %v", tc.fqdn, err)
				}
				if got != tc.expected {
					t.Errorf("expected %q, got %q", tc.expected, got)
				}
			}
		})
	}
}

func TestValidateChallengeValue(t *testing.T) {
	testCases := []struct {
		name      string
		val       string
		expectErr bool
	}{
		{"Valid standard token", "LHDhK3oGRvkiefQnx7OOczTY5Tic_xZ6HcMOc_gmtoM", false},
		{"Valid base64url characters", "a-zA-Z0-9_-", false},
		{"Empty value", "", true},
		{"Whitespace only", "   ", true},
		{"Null byte injection", "token\x00extra", true},
		{"CRLF injection", "token\r\nextra", true},
		{"Too long token", strings.Repeat("a", 513), true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateChallengeValue(tc.val)
			if tc.expectErr && err == nil {
				t.Errorf("expected error for value %q, got nil", tc.val)
			}
			if !tc.expectErr && err != nil {
				t.Errorf("unexpected error for value %q: %v", tc.val, err)
			}
		})
	}
}
