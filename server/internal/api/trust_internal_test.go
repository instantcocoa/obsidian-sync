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
	ts, err := parseTrust([]string{"caddy,127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	ts.lookup = func(h string) ([]net.IP, error) {
		if ips, ok := addrs[h]; ok {
			return ips, nil
		}
		return nil, errors.New("no such host")
	}
	names := ts.refresh(nil)
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
	for _, bad := range []string{"cad dy", "10.0.5.0/33", "evil_host"} {
		if _, err := parseTrust([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
