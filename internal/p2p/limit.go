package p2p

import (
	"sync"
	"time"
)

// Limiter is one peer's token buckets and strike counter.
type Limiter struct {
	mu      sync.Mutex
	buckets map[byte]*bucket
	strikes int
	until   time.Time
}

type bucket struct {
	rate    int
	burst   int
	tokens  int
	updated time.Time
}

// NewLimiter returns a limiter with full bursts.
func NewLimiter() *Limiter {
	return &Limiter{buckets: map[byte]*bucket{}}
}

// Allow reports whether one frame of kind may be accepted at now.
// A banned peer is refused without consuming a strike.
func (l *Limiter) Allow(now time.Time, kind byte) bool {
	rate, burst, ok := bucketFor(kind)
	if !ok {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Before(l.until) {
		return false
	}
	b := l.buckets[kind]
	if b == nil {
		b = &bucket{rate: rate, burst: burst, tokens: burst, updated: now}
		l.buckets[kind] = b
	}
	refill(b, now)
	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

func refill(b *bucket, now time.Time) {
	if now.Before(b.updated) {
		return
	}
	elapsed := now.Sub(b.updated).Milliseconds()
	if elapsed <= 0 {
		return
	}
	add := int(elapsed) * b.rate / 1000
	if add <= 0 {
		return
	}
	b.tokens += add
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.updated = now
}

// Strike records one rejected frame. The second result is true when the
// peer has just been banned.
func (l *Limiter) Strike(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.strikes++
	if l.strikes < MaxStrikes {
		return false
	}
	l.strikes = 0
	l.until = now.Add(BanFor)
	return true
}

// Credit forgets one strike after a frame that was accepted. A peer
// that mostly behaves does not accumulate a ban from a single bad frame.
func (l *Limiter) Credit() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.strikes > 0 {
		l.strikes--
	}
}

// Banned reports whether now is inside a ban window.
func (l *Limiter) Banned(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return now.Before(l.until)
}

// BanDeadline is the end of the current ban, or the zero time.
func (l *Limiter) BanDeadline() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.until
}
