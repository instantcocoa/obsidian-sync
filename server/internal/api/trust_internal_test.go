package api

import (
	"errors"
	"net"
	"net/http"
	"testing"
)

// --trust-proxy accepts a host name: its addresses are trusted, refreshed
// later, kept when a lookup fails, and nothing else is (review 14, F7).
func TestTrustProxyByName(t *testing.T) {
	addrs := map[string][]net.IP{"caddy": {net.ParseIP("10.0.5.5")}}
	lookup := func(h string) ([]net.IP, error) {
		if ips, ok := addrs[h]; ok {
			return ips, nil
		}
		return nil, errors.New("no such host")
	}
	ts, err := parseTrustWith([]string{"caddy,127.0.0.1"}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	names := ts.names
	peer := func(ip string) *http.Request {
		return &http.Request{RemoteAddr: net.JoinHostPort(ip, "443"), Header: http.Header{"X-Forwarded-For": {"203.0.113.9"}}}
	}
	for ip, want := range map[string]bool{"10.0.5.5": true, "127.0.0.1": true, "10.0.5.1": false, "10.0.5.6": false} {
		if got := fromTrustedProxy(peer(ip), ts.nets()); got != want {
			t.Errorf("%s trusted=%v, want %v", ip, got, want)
		}
	}
	// The proxy is recreated with a new address.
	addrs["caddy"] = []net.IP{net.ParseIP("10.0.5.9")}
	names = ts.refresh(names)
	if fromTrustedProxy(peer("10.0.5.5"), ts.nets()) || !fromTrustedProxy(peer("10.0.5.9"), ts.nets()) {
		t.Error("refresh did not follow the new address")
	}
	// A failed lookup keeps the last good addresses instead of dropping or widening trust.
	delete(addrs, "caddy")
	ts.refresh(names)
	if !fromTrustedProxy(peer("10.0.5.9"), ts.nets()) {
		t.Error("a failed lookup dropped the proxy")
	}
	// A name that never resolves refuses to start rather than trust nothing.
	if _, err := parseTrustWith([]string{"no-such-host"}, lookup); err == nil {
		t.Error("an unresolvable proxy name was accepted")
	}
	// Answers naming "any" or broadcast are ignored, never trusted.
	wide := &trustSet{hosts: []string{"x"}, lookup: func(string) ([]net.IP, error) {
		return []net.IP{net.IPv4zero, net.IPv6unspecified, net.IPv4bcast, net.ParseIP("10.0.5.5")}, nil
	}}
	wide.refresh(nil)
	if got := len(wide.nets()); got != 1 || !fromTrustedProxy(peer("10.0.5.5"), wide.nets()) || fromTrustedProxy(peer("10.0.5.6"), wide.nets()) {
		t.Errorf("unspecified or broadcast answers widened trust: %v", wide.nets())
	}
	for _, bad := range []string{"cad dy", "10.0.5.0/33", "evil_host"} {
		if _, err := parseTrust([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
