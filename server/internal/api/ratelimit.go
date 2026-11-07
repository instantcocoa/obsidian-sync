package api

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// limiter is a per-key token bucket used to slow brute force on the
// unauthenticated routes (invite redemption, recovery lookup and join) and
// on failed device authentication. Keys are client IPs; behind a proxy set
// --trust-proxy to the proxy's address range so X-Forwarded-For is used for
// requests that arrive from it.
type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   float64
	lastGC  time.Time
	trusted []*net.IPNet
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(perMinute, burst int, trusted []*net.IPNet) *limiter {
	return &limiter{buckets: map[string]*bucket{}, rate: float64(perMinute) / 60, burst: float64(burst), lastGC: time.Now(), trusted: trusted}
}

// parseCIDRs parses the --trust-proxy value: comma-separated CIDRs, a bare
// address meaning that host only. An unparsable entry is an error, never a
// silently wider trust.
func parseCIDRs(list []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, raw := range list {
		for _, item := range strings.Split(raw, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if !strings.Contains(item, "/") {
				ip := net.ParseIP(item)
				if ip == nil {
					return nil, fmt.Errorf("trust-proxy: %q is not an address or CIDR", item)
				}
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				item = ip.String() + "/" + strconv.Itoa(bits)
			}
			_, n, err := net.ParseCIDR(item)
			if err != nil {
				return nil, fmt.Errorf("trust-proxy: %w", err)
			}
			out = append(out, n)
		}
	}
	return out, nil
}

// fromTrustedProxy reports whether the TCP peer is one of the configured
// proxies. Only then is X-Forwarded-For worth reading: any other peer wrote
// it itself. (A boolean "trust the header" let anyone who could reach the
// listener directly, past the proxy, choose its own limiter bucket.)
func fromTrustedProxy(r *http.Request, trusted []*net.IPNet) bool {
	if len(trusted) == 0 {
		return false
	}
	ip := net.ParseIP(peerIP(r))
	if ip == nil {
		return false
	}
	for _, n := range trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (l *limiter) key(r *http.Request) string {
	if fromTrustedProxy(r, l.trusted) {
		if ip := proxiedClient(r); ip != "" {
			return bucketKey(ip)
		}
	}
	return bucketKey(peerIP(r))
}

// peerIP is the TCP peer's address, without port, zone or brackets.
func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return normalizeIP(r.RemoteAddr)
	}
	return normalizeIP(host)
}

// proxiedClient is the client address the trusted proxy recorded, or "" when
// the request carries none the server can trust. A proxy appends the address
// it saw to X-Forwarded-For; every earlier entry is whatever the client
// wrote. The header may arrive as several lines (HAProxy adds its own line
// rather than appending to the client's), and RFC 9110 says the lines are
// one list, so they are joined before the last entry is taken; reading only
// the first line would hand the client the choice of bucket. An entry that is
// not an address is treated as absent rather than minted into a bucket.
func proxiedClient(r *http.Request) string {
	all := strings.Join(r.Header.Values("X-Forwarded-For"), ",")
	parts := strings.Split(all, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		p := strings.TrimSpace(parts[i])
		if p == "" {
			continue
		}
		if ip := normalizeIP(p); net.ParseIP(ip) != nil {
			return ip
		}
		return ""
	}
	return ""
}

// bucketKey is the address an IPv4 client is limited by, and the /64 for
// IPv6: a host owns at least a /64 and could otherwise present 2^64 fresh
// addresses, one bucket each, never throttled.
func bucketKey(a string) string {
	ip := net.ParseIP(a)
	if ip == nil || ip.To4() != nil {
		return a
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// maxBuckets bounds the limiter's memory: past it, addresses the map has
// never seen are refused until the next sweep frees room (fail closed).
const maxBuckets = 100_000

// take consumes one token for the key; false means "rate limited".
func (l *limiter) take(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.lastGC) > 10*time.Minute || len(l.buckets) >= maxBuckets {
		for k, b := range l.buckets {
			if now.Sub(b.last) > 10*time.Minute || (len(l.buckets) >= maxBuckets && now.Sub(b.last) > time.Minute) {
				delete(l.buckets, k)
			}
		}
		l.lastGC = now
	}
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxBuckets {
			return false
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// allow is a middleware that charges one token per request.
func (l *limiter) allow(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !l.take(l.key(r)) {
			w.Header().Set("Retry-After", "60")
			writeErr(w, http.StatusTooManyRequests, "rate limited")
			return
		}
		next(w, r)
	}
}

// normalizeIP makes "[::1]:1234", "[::1]", "::1" and "::1%en0" one key, so an
// address written with brackets, a port or a zone cannot buy a fresh bucket.
func normalizeIP(a string) string {
	if h, _, err := net.SplitHostPort(a); err == nil {
		a = h
	}
	a = strings.TrimPrefix(strings.TrimSuffix(a, "]"), "[")
	if i := strings.IndexByte(a, '%'); i >= 0 {
		a = a[:i]
	}
	if ip := net.ParseIP(a); ip != nil {
		return ip.String()
	}
	return a
}
