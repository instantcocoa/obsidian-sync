package api

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// limiter is a per-key token bucket used to slow brute force on the
// unauthenticated routes (invite redemption, recovery lookup and join) and
// on failed device authentication. Keys are client IPs; behind a proxy set
// --trust-proxy so X-Forwarded-For is used.
type limiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64 // tokens per second
	burst    float64
	lastGC   time.Time
	trustXFF bool
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(perMinute, burst int, trustXFF bool) *limiter {
	return &limiter{buckets: map[string]*bucket{}, rate: float64(perMinute) / 60, burst: float64(burst), lastGC: time.Now(), trustXFF: trustXFF}
}

func (l *limiter) key(r *http.Request) string {
	if l.trustXFF {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// take consumes one token for the key; false means "rate limited".
func (l *limiter) take(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.lastGC) > 10*time.Minute {
		for k, b := range l.buckets {
			if now.Sub(b.last) > 10*time.Minute {
				delete(l.buckets, k)
			}
		}
		l.lastGC = now
	}
	b, ok := l.buckets[key]
	if !ok {
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
