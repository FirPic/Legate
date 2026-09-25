package tracker

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestTracker_BasicOperations(t *testing.T) {
	tr := New()

	fqdn := "_acme-challenge.example.com."
	value := "challenge-token-123"
	recordID := "cf-rec-999"

	// Initial check
	if _, found := tr.Get(fqdn, value); found {
		t.Fatal("expected record not to be found initially")
	}

	// Store
	tr.Store(fqdn, value, recordID)

	if tr.Count() != 1 {
		t.Fatalf("expected count 1, got %d", tr.Count())
	}

	// Retrieve with trailing dot
	got, found := tr.Get(fqdn, value)
	if !found || got != recordID {
		t.Fatalf("expected to find %s, got %s (found: %v)", recordID, got, found)
	}

	// Retrieve without trailing dot
	gotNoDot, foundNoDot := tr.Get("_acme-challenge.example.com", value)
	if !foundNoDot || gotNoDot != recordID {
		t.Fatalf("expected to find %s without trailing dot, got %s (found: %v)", recordID, gotNoDot, foundNoDot)
	}

	// Delete
	deletedID, deleted := tr.Delete(fqdn, value)
	if !deleted || deletedID != recordID {
		t.Fatalf("expected deleted %s, got %s (deleted: %v)", recordID, deletedID, deleted)
	}

	// Verify absence
	if _, found := tr.Get(fqdn, value); found {
		t.Fatal("expected record to be deleted")
	}

	if tr.Count() != 0 {
		t.Fatalf("expected count 0, got %d", tr.Count())
	}
}

func TestTracker_TTLExpiration(t *testing.T) {
	tr := New()

	fqdn := "_acme-challenge.expired.com"
	val := "val-123"
	tr.Store(fqdn, val, "rec-1")

	// Artificially age the entry
	tr.mu.Lock()
	entry := tr.records[makeKey(fqdn, val)]
	entry.createdAt = time.Now().Add(-20 * time.Minute)
	tr.records[makeKey(fqdn, val)] = entry
	tr.mu.Unlock()

	// Store fresh entry
	freshFQDN := "_acme-challenge.fresh.com"
	freshVal := "val-456"
	tr.Store(freshFQDN, freshVal, "rec-2")

	if tr.Count() != 2 {
		t.Fatalf("expected 2 records before purge, got %d", tr.Count())
	}

	// Purge with 15m TTL
	evicted := tr.PurgeExpired(15 * time.Minute)
	if evicted != 1 {
		t.Errorf("expected 1 record evicted, got %d", evicted)
	}

	if _, found := tr.Get(fqdn, val); found {
		t.Errorf("expected aged record to be evicted")
	}
	if _, found := tr.Get(freshFQDN, freshVal); !found {
		t.Errorf("expected fresh record to still be present")
	}
}

func TestTracker_EvictionCallback(t *testing.T) {
	tr := New()

	fqdn := "_acme-challenge.callback.com"
	val := "token-val"
	recID := "rec-to-clean"
	tr.Store(fqdn, val, recID)

	// Artificially age the entry
	tr.mu.Lock()
	entry := tr.records[makeKey(fqdn, val)]
	entry.createdAt = time.Now().Add(-30 * time.Minute)
	tr.records[makeKey(fqdn, val)] = entry
	tr.mu.Unlock()

	var calledWith ExpiredRecord
	callbackCount := 0

	evicted := tr.PurgeExpired(15*time.Minute, func(rec ExpiredRecord) {
		callbackCount++
		calledWith = rec
	})

	if evicted != 1 || callbackCount != 1 {
		t.Fatalf("expected 1 eviction and 1 callback, got evicted=%d, callbacks=%d", evicted, callbackCount)
	}

	if calledWith.FQDN != fqdn || calledWith.Value != val || calledWith.RecordID != recID {
		t.Errorf("unexpected callback record: %+v", calledWith)
	}
}

func TestTracker_ConcurrentAccess(t *testing.T) {
	tr := New()
	const workers = 50
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(workers * 3)

	// Concurrently store
	for i := 0; i < workers; i++ {
		go func(w int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				fqdn := fmt.Sprintf("_acme-challenge.sub%d-%d.example.com.", w, j)
				val := fmt.Sprintf("val-%d-%d", w, j)
				rec := fmt.Sprintf("rec-%d-%d", w, j)
				tr.Store(fqdn, val, rec)
			}
		}(i)

		// Concurrently get
		go func(w int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				fqdn := fmt.Sprintf("_acme-challenge.sub%d-%d.example.com.", w, j)
				val := fmt.Sprintf("val-%d-%d", w, j)
				tr.Get(fqdn, val)
			}
		}(i)

		// Concurrently count & purge
		go func(w int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = tr.Count()
				if j%10 == 0 {
					_ = tr.PurgeExpired(1 * time.Hour)
				}
			}
		}(i)
	}

	wg.Wait()
}
