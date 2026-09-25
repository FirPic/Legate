package challenge

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
			fqdn:      " _ACME-CHALLENGE.Sub.Internal.FirPic.FR. ",
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
			expectErr: true,
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
			name:      "Attack: Unconfigured allowed domain",
			fqdn:      "_acme-challenge.firpic.fr",
			allowed:   "",
			expectErr: true,
		},
		{
			name:      "Attack: Directory traversal attempt slash",
			fqdn:      "_acme-challenge.foo/../firpic.fr",
			allowed:   allowedDomain,
			expectErr: true,
		},
		{
			name:      "Attack: Backslash directory traversal",
			fqdn:      "_acme-challenge.foo\\..\\firpic.fr",
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
			name:      "Attack: Null byte injection in FQDN",
			fqdn:      "_acme-challenge.sub\x00.firpic.fr",
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

func TestValidateForUser(t *testing.T) {
	dmzUser := "traefik_dmz"
	dmzPatterns := []string{"*.dmz.firpic.fr", "dmz.firpic.fr"}

	testCases := []struct {
		name        string
		user        string
		patterns    []string
		fqdn        string
		expectError bool
	}{
		{
			name:        "Authorized direct child subdomain",
			user:        dmzUser,
			patterns:    dmzPatterns,
			fqdn:        "_acme-challenge.traefik.dmz.firpic.fr",
			expectError: false,
		},
		{
			name:        "Authorized nested child subdomain",
			user:        dmzUser,
			patterns:    dmzPatterns,
			fqdn:        "_acme-challenge.api.nested.dmz.firpic.fr.",
			expectError: false,
		},
		{
			name:        "Authorized exact subdomain",
			user:        dmzUser,
			patterns:    dmzPatterns,
			fqdn:        "_acme-challenge.dmz.firpic.fr",
			expectError: false,
		},
		{
			name:        "Attack: DMZ user attempting root apex",
			user:        dmzUser,
			patterns:    dmzPatterns,
			fqdn:        "_acme-challenge.firpic.fr",
			expectError: true,
		},
		{
			name:        "Attack: DMZ user attempting security zone",
			user:        dmzUser,
			patterns:    dmzPatterns,
			fqdn:        "_acme-challenge.vault.sec.firpic.fr",
			expectError: true,
		},
		{
			name:        "Attack: DMZ user attempting internal infra zone",
			user:        dmzUser,
			patterns:    dmzPatterns,
			fqdn:        "_acme-challenge.proxmox.infra.firpic.fr",
			expectError: true,
		},
		{
			name:        "Admin user with wildcard",
			user:        "admin",
			patterns:    []string{"*"},
			fqdn:        "_acme-challenge.firpic.fr",
			expectError: false,
		},
		{
			name:        "User with empty allowed subdomains",
			user:        "nobody",
			patterns:    []string{},
			fqdn:        "_acme-challenge.test.firpic.fr",
			expectError: true,
		},
		{
			name:        "Wildcard *.domain also authorizes apex domain",
			user:        "app_user",
			patterns:    []string{"*.firpic.fr"},
			fqdn:        "_acme-challenge.firpic.fr",
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateForUser(tc.user, tc.fqdn, tc.patterns)
			if tc.expectError && err == nil {
				t.Errorf("expected authorization error for user %s on %s, got nil", tc.user, tc.fqdn)
			}
			if !tc.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
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
		{"DEL control char", "token\x7fextra", true},
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

func TestResolveAndValidate(t *testing.T) {
	allowed := "firpic.fr"

	t.Run("Standard mode success", func(t *testing.T) {
		res, err := ResolveAndValidate(
			"_acme-challenge.traefik.firpic.fr.",
			"challenge-value-test-123",
			"", "", "", allowed,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.FQDN != "_acme-challenge.traefik.firpic.fr" {
			t.Errorf("expected normalized FQDN, got %s", res.FQDN)
		}
		if res.Value != "challenge-value-test-123" {
			t.Errorf("expected value, got %s", res.Value)
		}
	})

	t.Run("RBAC user violation", func(t *testing.T) {
		_, err := ResolveAndValidateForUser(
			"_acme-challenge.firpic.fr",
			"val123",
			"", "", "", allowed,
			"traefik_dmz",
			[]string{"*.dmz.firpic.fr"},
		)
		if err == nil {
			t.Fatal("expected RBAC failure for DMZ user requesting apex")
		}
		if !strings.Contains(err.Error(), "rbac authorization failed") {
			t.Errorf("expected 'rbac authorization failed' error, got %v", err)
		}
	})

	t.Run("Raw mode keyAuth SHA256 derivation", func(t *testing.T) {
		res, err := ResolveAndValidate(
			"", "",
			"traefik.firpic.fr",
			"token123",
			"key-auth-xyz",
			allowed,
		)
		if err != nil {
			t.Fatalf("unexpected error in raw mode: %v", err)
		}
		if res.FQDN != "_acme-challenge.traefik.firpic.fr" {
			t.Errorf("expected derived FQDN, got %s", res.FQDN)
		}
		if res.Value == "" {
			t.Errorf("expected non-empty derived value")
		}
	})

	t.Run("Missing FQDN and domain", func(t *testing.T) {
		_, err := ResolveAndValidate("", "val", "", "", "", allowed)
		if err == nil {
			t.Error("expected error for missing fqdn and domain")
		}
	})

	t.Run("Missing value and keyAuth", func(t *testing.T) {
		_, err := ResolveAndValidate("_acme-challenge.firpic.fr", "", "", "", "", allowed)
		if err == nil {
			t.Error("expected error for missing value and keyAuth")
		}
	})

	t.Run("Invalid FQDN rejected", func(t *testing.T) {
		_, err := ResolveAndValidate("_acme-challenge.evil.com", "val", "", "", "", allowed)
		if err == nil {
			t.Error("expected error for unauthorized domain")
		}
	})
}
