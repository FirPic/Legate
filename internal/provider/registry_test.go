package provider_test

import (
	"context"
	"errors"
	"testing"

	"github.com/FirPic/legate/internal/provider"
)

type mockProvider struct {
	id string
}

func (m *mockProvider) Present(ctx context.Context, fqdn, value string) (string, error) {
	return m.id, nil
}

func (m *mockProvider) Cleanup(ctx context.Context, fqdn, recordID, value string) error {
	return nil
}

func TestRegistry_RegisterAndResolve(t *testing.T) {
	reg := provider.NewRegistry()

	cfProvider := &mockProvider{id: "cf"}
	ionosProvider := &mockProvider{id: "ionos"}
	subProvider := &mockProvider{id: "sub-corp"}

	if err := reg.Register("example.com", cfProvider); err != nil {
		t.Fatalf("unexpected error registering example.com: %v", err)
	}
	if err := reg.Register("ionos-domain.fr.", ionosProvider); err != nil {
		t.Fatalf("unexpected error registering ionos-domain.fr: %v", err)
	}
	if err := reg.Register("corp.example.com", subProvider); err != nil {
		t.Fatalf("unexpected error registering corp.example.com: %v", err)
	}

	// Duplicate registration error
	if err := reg.Register("EXAMPLE.COM", cfProvider); err == nil {
		t.Fatal("expected error on duplicate domain registration, got nil")
	}

	// Invalid inputs
	if err := reg.Register("", cfProvider); err == nil {
		t.Fatal("expected error registering empty domain, got nil")
	}
	if err := reg.Register("valid.com", nil); err == nil {
		t.Fatal("expected error registering nil provider, got nil")
	}

	tests := []struct {
		name         string
		fqdn         string
		wantID       string
		wantDomain   string
		expectErr    bool
		errSubstring string
	}{
		{
			name:       "exact root domain with acme prefix",
			fqdn:       "_acme-challenge.example.com.",
			wantID:     "cf",
			wantDomain: "example.com",
		},
		{
			name:       "subdomain with acme prefix",
			fqdn:       "_acme-challenge.app.example.com",
			wantID:     "cf",
			wantDomain: "example.com",
		},
		{
			name:       "more specific nested subdomain match",
			fqdn:       "_acme-challenge.api.corp.example.com.",
			wantID:     "sub-corp",
			wantDomain: "corp.example.com",
		},
		{
			name:       "second provider ionos match",
			fqdn:       "_acme-challenge.www.ionos-domain.fr",
			wantID:     "ionos",
			wantDomain: "ionos-domain.fr",
		},
		{
			name:       "plain fqdn without acme prefix",
			fqdn:       "vpn.example.com",
			wantID:     "cf",
			wantDomain: "example.com",
		},
		{
			name:         "unregistered domain",
			fqdn:         "_acme-challenge.unknown.org",
			expectErr:    true,
			errSubstring: "no registered DNS provider found",
		},
		{
			name:         "empty fqdn",
			fqdn:         "",
			expectErr:    true,
			errSubstring: "fqdn cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, baseDomain, err := reg.Resolve(tt.fqdn)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !errors.Is(err, provider.ErrDomainNotFound) && tt.errSubstring != "" {
					// Check error message
					if err.Error() == "" {
						t.Errorf("expected non-empty error")
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			mockP, ok := p.(*mockProvider)
			if !ok {
				t.Fatalf("resolved provider is not *mockProvider")
			}
			if mockP.id != tt.wantID {
				t.Errorf("got provider id %q, want %q", mockP.id, tt.wantID)
			}
			if baseDomain != tt.wantDomain {
				t.Errorf("got base domain %q, want %q", baseDomain, tt.wantDomain)
			}
		})
	}

	domains := reg.RegisteredDomains()
	if len(domains) != 3 {
		t.Fatalf("expected 3 domains, got %d", len(domains))
	}
	expectedDomains := []string{"corp.example.com", "example.com", "ionos-domain.fr"}
	for i, d := range domains {
		if d != expectedDomains[i] {
			t.Errorf("index %d: got %q, want %q", i, d, expectedDomains[i])
		}
	}

	if reg.Count() != 3 {
		t.Errorf("expected Count() == 3, got %d", reg.Count())
	}
}
