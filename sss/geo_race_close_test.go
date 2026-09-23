package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
	"github.com/oschwald/mmdbwriter"
	"github.com/oschwald/mmdbwriter/inserter"
	"github.com/oschwald/maxminddb-golang/v2/pkg/mmdbtype"
)

// TestGeoConcurrentLookupDuringClose verifies that the readers WaitGroup
// prevents Close (munmap) from racing an active Lookup. The old code
// closed the reader immediately after Unlock — any goroutine that acquired
// RLock before the swap was still reading from the old (now closed) mmap.
//
// This test:
//  1. Loads a tiny DB, starts a long Lookup in goroutines.
//  2. Swaps the DB (simulates a geo update via finish).
//  3. Verifies no SIGSEGV / panic — the old reader is only closed after
//     every pre-swap RLock holder finishes.
func TestGeoConcurrentLookupDuringClose(t *testing.T) {
	dir := t.TempDir()
	writeTinyDB(t, filepath.Join(dir, "country.mmdb"))

	r, err := maxminddb.Open(filepath.Join(dir, "country.mmdb"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	geoMgr.mu.Lock()
	geoMgr.reader = r
	geoMgr.state = "ready"
	geoMgr.mu.Unlock()

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
				_ = geoCountry("1.2.3.4")
			}
		}()
	}

	// Concurrently swap the reader (simulates finish).
	for i := 0; i < 10; i++ {
		writeTinyDB(t, filepath.Join(dir, "country.mmdb"))
		fresh, err := maxminddb.Open(filepath.Join(dir, "country.mmdb"))
		if err != nil {
			t.Fatalf("open fresh: %v", err)
		}
		geoMgr.finish("", nil, fresh)
		time.Sleep(time.Millisecond)
	}

	wg.Wait()
	close(panicked)

	for p := range panicked {
		t.Fatalf("panic during concurrent lookup+close: %v", p)
	}
}

// writeTinyDB creates a minimal mmdb with one entry for the test.
func writeTinyDB(t *testing.T, path string) {
	t.Helper()
	writer, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            "Test",
		RecordSize:              24,
		IncludeReservedNetworks: false,
		Languages:               []string{"en"},
	})
	if err != nil {
		t.Fatalf("writer: %v", err)
	}

	_, network, _ := netip.MustParsePrefix("0.0.0.0/0").MarshalText()
	_ = network

	ipNet := parseCIDR(t, "0.0.0.0/0")
	data := mmdbtype.Map{
		"country": mmdbtype.Map{
			"iso_code": mmdbtype.String("US"),
		},
	}
	if err := writer.InsertFunc(ipNet, inserter.TopLevelMergeWith(data)); err != nil {
		t.Fatalf("insert: %v", err)
	}

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()
	if _, err := writer.WriteTo(f); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func parseCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("parseCIDR %s: %v", s, err)
	}
	return ipNet
}
