package main

// N2 regression: the SSRF dial gate. Pure table test, no network.

import (
	"net/netip"
	"testing"
)

func TestGeoIPAllowed(t *testing.T) {
	t.Setenv("SEED_GEO_ALLOW_PRIVATE", "")
	cases := []struct {
		ip    string
		allow bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"140.82.121.4", true},
		{"2606:4700:4700::1111", true},
		{"127.0.0.1", false},
		{"10.1.2.3", false},
		{"172.16.0.1", false},
		{"192.168.1.1", false},
		{"169.254.169.254", false}, // cloud metadata
		{"100.64.0.1", false},      // CGN shared space
		{"100.127.255.255", false},
		{"0.0.0.0", false},
		{"224.0.0.1", false},
		{"::1", false},
		{"fd00::1", false},
		{"fe80::1", false},
	}
	for _, c := range cases {
		a := netip.MustParseAddr(c.ip)
		if got := geoIPAllowed(a); got != c.allow {
			t.Errorf("geoIPAllowed(%s) = %v, want %v", c.ip, got, c.allow)
		}
	}
}

func TestGeoAllowPrivateFlag(t *testing.T) {
	t.Setenv("SEED_GEO_ALLOW_PRIVATE", "1")
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "::1"} {
		if !geoIPAllowed(netip.MustParseAddr(ip)) {
			t.Errorf("allow-private flag must permit %s", ip)
		}
	}
}
