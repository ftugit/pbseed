package main

// N1 regression: concurrent geoCountry lookups while the updater swaps and
// closes readers must be race-free. Run with: go test -race -run TestGeo .
// The old copy-the-pointer-then-unlock pattern died here (DATA RACE +
// SIGSEGV in the MaxMind mmap); holding RLock across Lookup is clean.

import (
	"sync"
	"testing"

	"github.com/oschwald/maxminddb-golang/v2"
)

func TestGeoConcurrentLookupDuringSwap(t *testing.T) {
	const fixture = "tests/fixtures/country-test.mmdb"
	r0, err := maxminddb.Open(fixture)
	if err != nil {
		t.Skipf("no fixture: %v", err)
	}
	geoMgr.mu.Lock()
	prev := geoMgr.reader
	geoMgr.reader = r0
	geoMgr.mu.Unlock()
	defer func() {
		geoMgr.mu.Lock()
		if geoMgr.reader != nil {
			geoMgr.reader.Close()
		}
		geoMgr.reader = prev
		geoMgr.mu.Unlock()
	}()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = geoCountry("192.0.2.1")
				}
			}
		}()
	}

	for i := 0; i < 50; i++ {
		r, err := maxminddb.Open(fixture)
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		geoMgr.finish("", &geoMeta{}, r) // swaps under Lock, closes old after
	}
	close(stop)
	wg.Wait()
}
