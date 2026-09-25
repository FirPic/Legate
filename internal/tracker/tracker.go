package tracker

import (
	"strings"
	"sync"
)

// Tracker provides a thread-safe in-memory store mapping ACME challenge tuples (fqdn, value)
// to provider record IDs. This allows concurrent certificate requests across multiple clients
// to manage records without race conditions or unintended deletions.
type Tracker struct {
	mu      sync.RWMutex
	records map[string]string // key: normalized(fqdn) + "|" + value -> recordID
}

// New creates an initialized Tracker instance.
func New() *Tracker {
	return &Tracker{
		records: make(map[string]string),
	}
}

func makeKey(fqdn, value string) string {
	normalizedFQDN := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))
	return normalizedFQDN + "|" + strings.TrimSpace(value)
}

// Store associates a specific (fqdn, value) challenge with its provider record ID.
func (t *Tracker) Store(fqdn, value, recordID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.records[makeKey(fqdn, value)] = strings.TrimSpace(recordID)
}

// Get retrieves the provider record ID for a given (fqdn, value) challenge if present.
func (t *Tracker) Get(fqdn, value string) (string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	id, exists := t.records[makeKey(fqdn, value)]
	return id, exists
}

// Delete removes and returns the provider record ID for a given (fqdn, value) challenge.
func (t *Tracker) Delete(fqdn, value string) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := makeKey(fqdn, value)
	id, exists := t.records[key]
	if exists {
		delete(t.records, key)
	}
	return id, exists
}

// Count returns the current number of active tracked challenge records.
func (t *Tracker) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.records)
}
