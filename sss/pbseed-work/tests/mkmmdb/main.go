// Command mkmmdb builds tests/fixtures/country-test.mmdb(.gz): a tiny
// MaxMind-DB with RFC 5737 TEST-NET records. Those ranges are guaranteed
// absent from real DBs, so fixture assertions can't false-pass against
// production data.
//
// Usage: go run ./tests/mkmmdb [out.mmdb]
package main

import (
	"compress/gzip"
	"fmt"
	"net"
	"os"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	out := "tests/fixtures/country-test.mmdb"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	w, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            "pbseed-test",
		Description:             map[string]string{"en": "pbseed geo test fixture"},
		IncludeReservedNetworks: true, // TEST-NETs are reserved ranges
	})
	must(err)
	rec := func(cc string) mmdbtype.DataType {
		return mmdbtype.Map{
			mmdbtype.String("country"): mmdbtype.Map{
				mmdbtype.String("iso_code"): mmdbtype.String(cc),
			},
		}
	}
	for _, pair := range [][2]string{
		{"192.0.2.0/24", "JP"},    // TEST-NET-1
		{"198.51.100.0/24", "DE"}, // TEST-NET-2
		{"203.0.113.0/24", "US"},  // TEST-NET-3
	} {
		_, n, err := net.ParseCIDR(pair[0])
		must(err)
		must(w.Insert(n, rec(pair[1])))
	}
	f, err := os.Create(out)
	must(err)
	_, err = w.WriteTo(f)
	must(err)
	must(f.Close())

	raw, err := os.ReadFile(out)
	must(err)
	gz, err := os.Create(out + ".gz")
	must(err)
	zw := gzip.NewWriter(gz)
	_, err = zw.Write(raw)
	must(err)
	must(zw.Close())
	must(gz.Close())
	fmt.Println("wrote", out, len(raw), "bytes")
}
