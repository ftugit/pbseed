package main

import (
	"sync"
	"testing"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// TestGeoConcurrentLookupDuringClose verifies that finish() holds Lock
// through Close(munmap), so no goroutine can be inside Lookup+DecodePath
// on the old reader when it is closed. The old code released Lock before
// Close — any goroutine that entered RLock before the swap was still
// reading from the old (now closed) mmap.
func TestGeoConcurrentLookupDuringClose(t *testing.T) {
	const fixture = "tests/fixtures/country-test.mmdb"
	r0, err := maxminddb.Open(fixture)
	if err != nil {
		t.Skipf("no fixture: %v", err)
	}
	geoMgr.mu.Lock()
	prev := geoMgr.reader
	geoMgr.reader = r0
	geoMgr.state = "ready"
	geoMgr.mu.Unlock()
	defer func() {
		geoMgr.mu.Lock()
		if geoMgr.reader != nil {
			geoMgr.reader.Close()
		}
		geoMgr.reader = prev
		geoMgr.mu.Unlock()
	}()

	const goroutines = 50
	const iterations = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	panicked := make(chan interface{}, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panicked <- r
				}
			}()
			for j := 0; j < iterations; j++ {
				_ = geoCountry("192.0.2.1") // TEST-NET, hits DB
			}
		}()
	}

	// Concurrently swap the reader (simulates finish from a geo update).
	for i := 0; i < 10; i++ {
		fresh, err := maxminddb.Open(fixture)
		if err != nil {
			t.Fatalf("open fresh: %v", err)
		}
		geoMgr.finish("", &geoMeta{}, fresh)
		time.Sleep(time.Millisecond)
	}

	wg.Wait()
	close(panicked)

	for p := range panicked {
		t.Fatalf("panic during concurrent lookup+close: %v", p)
	}
}
