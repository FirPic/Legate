package lock

import (
	"fmt"
	"sync"
	"testing"
)

func TestRecordTracker_BasicOperations(t *testing.T) {
	tracker := NewRecordTracker()

	fqdn := "_acme-challenge.example.com."
	value := "challenge-token-123"
	recordID := "cf-rec-999"

	// Initial check
	if _, found := tracker.Get(fqdn, value); found {
		t.Fatal("expected record not to be found initially")
	}

	// Store
	tracker.Store(fqdn, value, recordID)

	// Retrieve with trailing dot
	got, found := tracker.Get(fqdn, value)
	if !found || got != recordID {
		t.Fatalf("expected to find %s, got %s (found: %v)", recordID, got, found)
	}

	// Retrieve without trailing dot
	gotNoDot, foundNoDot := tracker.Get("_acme-challenge.example.com", value)
	if !foundNoDot || gotNoDot != recordID {
		t.Fatalf("expected to find %s without trailing dot, got %s (found: %v)", recordID, gotNoDot, foundNoDot)
	}

	// Delete
	deletedID, deleted := tracker.Delete(fqdn, value)
	if !deleted || deletedID != recordID {
		t.Fatalf("expected deleted %s, got %s (deleted: %v)", recordID, deletedID, deleted)
	}

	// Verify absence
	if _, found := tracker.Get(fqdn, value); found {
		t.Fatal("expected record to be deleted")
	}
}

func TestRecordTracker_ConcurrentAccess(t *testing.T) {
	tracker := NewRecordTracker()
	const workers = 50
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(workers * 2)

	// Concurrently store and retrieve
	for i := 0; i < workers; i++ {
		go func(w int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				fqdn := fmt.Sprintf("_acme-challenge.sub%d-%d.example.com.", w, j)
				val := fmt.Sprintf("val-%d-%d", w, j)
				rec := fmt.Sprintf("rec-%d-%d", w, j)
				tracker.Store(fqdn, val, rec)
			}
		}(i)

		go func(w int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				fqdn := fmt.Sprintf("_acme-challenge.sub%d-%d.example.com.", w, j)
				val := fmt.Sprintf("val-%d-%d", w, j)
				tracker.Get(fqdn, val)
			}
		}(i)
	}

	wg.Wait()
}
