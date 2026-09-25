package tracker

import (
	"fmt"
	"sync"
	"testing"
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

		// Concurrently count
		go func(w int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = tr.Count()
			}
		}(i)
	}

	wg.Wait()
}
