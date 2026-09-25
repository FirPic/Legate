package lock

import (
	"strings"
	"sync"
)

// RecordTracker manages mappings between ACME TXT challenges and their Cloudflare DNS record IDs.
// It is fully thread-safe for concurrent access.
type RecordTracker struct {
	mu      sync.RWMutex
	records map[string]string // key: normalized(fqdn) + "|" + value -> recordID
}

// NewRecordTracker creates an initialized RecordTracker instance.
func NewRecordTracker() *RecordTracker {
	return &RecordTracker{
		records: make(map[string]string),
	}
}

func makeKey(fqdn, value string) string {
	normalizedFQDN := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))
	return normalizedFQDN + "|" + strings.TrimSpace(value)
}

// Store associates a specific (fqdn, value) challenge with its Cloudflare record ID.
func (rt *RecordTracker) Store(fqdn, value, recordID string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.records[makeKey(fqdn, value)] = strings.TrimSpace(recordID)
}

// Get retrieves the Cloudflare record ID for a given (fqdn, value) if it exists.
func (rt *RecordTracker) Get(fqdn, value string) (string, bool) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	id, exists := rt.records[makeKey(fqdn, value)]
	return id, exists
}

// Delete removes and returns the Cloudflare record ID for a given (fqdn, value).
func (rt *RecordTracker) Delete(fqdn, value string) (string, bool) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	key := makeKey(fqdn, value)
	id, exists := rt.records[key]
	if exists {
		delete(rt.records, key)
	}
	return id, exists
}

// Count returns the number of active tracked records.
func (rt *RecordTracker) Count() int {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return len(rt.records)
}
