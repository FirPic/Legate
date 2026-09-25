package provider

import "context"

// DNSProvider defines the domain contract for presenting and cleaning up ACME DNS-01 challenge TXT records.
type DNSProvider interface {
	// Present creates an ACME TXT record for the given FQDN and value, returning the provider's record identifier.
	Present(ctx context.Context, fqdn, value string) (recordID string, err error)
	// Cleanup removes the ACME TXT record. If recordID is empty, the provider queries its API to locate and remove it.
	Cleanup(ctx context.Context, fqdn, recordID, value string) error
}
