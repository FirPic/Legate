package tracker

import (
	"strings"
	"sync"
	"time"
)

type recordEntry struct {
	fqdn      string
	value     string
	recordID  string
	createdAt time.Time
}

// ExpiredRecord represents challenge metadata of a record being purged from the tracker.
type ExpiredRecord struct {
	FQDN     string
	Value    string
	RecordID string
}

// EvictionCallback is invoked when an expired challenge record is evicted by the GC.
type EvictionCallback func(record ExpiredRecord)

// Tracker provides a thread-safe in-memory store mapping ACME challenge tuples (fqdn, value)
// to provider record IDs with TTL tracking to prevent memory exhaustion and abandoned records.
type Tracker struct {
	mu      sync.RWMutex
	records map[string]recordEntry // key: normalized(fqdn) + "|" + value -> recordEntry
}

// New creates an initialized Tracker instance.
func New() *Tracker {
	return &Tracker{
		records: make(map[string]recordEntry),
	}
}

func makeKey(fqdn, value string) string {
	normalizedFQDN := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))
	return normalizedFQDN + "|" + strings.TrimSpace(value)
}

// Store associates a specific (fqdn, value) challenge with its provider record ID and current timestamp.
func (t *Tracker) Store(fqdn, value, recordID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	normFQDN := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))
	val := strings.TrimSpace(value)
	t.records[makeKey(fqdn, value)] = recordEntry{
		fqdn:      normFQDN,
		value:     val,
		recordID:  strings.TrimSpace(recordID),
		createdAt: time.Now(),
	}
}

// Get retrieves the provider record ID for a given (fqdn, value) challenge if present.
func (t *Tracker) Get(fqdn, value string) (string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	entry, exists := t.records[makeKey(fqdn, value)]
	return entry.recordID, exists
}

// Delete removes and returns the provider record ID for a given (fqdn, value) challenge.
func (t *Tracker) Delete(fqdn, value string) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := makeKey(fqdn, value)
	entry, exists := t.records[key]
	if exists {
		delete(t.records, key)
	}
	return entry.recordID, exists
}

// Count returns the current number of active tracked challenge records.
func (t *Tracker) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.records)
}

// PurgeExpired evicts records that have been in the tracker longer than maxAge,
// invoking optional EvictionCallback callbacks for each evicted record.
// Returns the number of evicted records.
func (t *Tracker) PurgeExpired(maxAge time.Duration, callbacks ...EvictionCallback) int {
	t.mu.Lock()
	now := time.Now()
	var expired []ExpiredRecord

	for k, entry := range t.records {
		if now.Sub(entry.createdAt) > maxAge {
			delete(t.records, k)
			expired = append(expired, ExpiredRecord{
				FQDN:     entry.fqdn,
				Value:    entry.value,
				RecordID: entry.recordID,
			})
		}
	}
	t.mu.Unlock()

	for _, rec := range expired {
		for _, cb := range callbacks {
			if cb != nil {
				cb(rec)
			}
		}
	}

	return len(expired)
}

// StartGC starts a background ticker that periodically purges records older than maxAge,
// executing optional EvictionCallback callbacks on eviction (e.g. upstream DNS cleanup).
func (t *Tracker) StartGC(interval, maxAge time.Duration, stopCh <-chan struct{}, callbacks ...EvictionCallback) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				t.PurgeExpired(maxAge, callbacks...)
			case <-stopCh:
				return
			}
		}
	}()
}
