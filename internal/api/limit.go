package api

import (
	"net"
	"time"
)

// maxRateKeys is how many remote hosts the limiter remembers. A full
// table drops the oldest host. The key is the host, not the ephemeral
// port: a client that reconnects must not fill the table or escape the cap.
const maxRateKeys = 256

type gate struct {
	peers map[string]*rates
	order []string
}

type rates struct {
	submit bucket
	read   bucket
}

type bucket struct {
	rate    int
	burst   int
	tokens  int
	updated time.Time
}

func newGate() *gate {
	return &gate{peers: map[string]*rates{}}
}

func (g *gate) allow(now time.Time, remote string, submit bool) bool {
	remote = remoteHost(remote)
	if remote == "" {
		return false
	}
	r := g.peers[remote]
	if r == nil {
		if len(g.peers) >= maxRateKeys {
			oldest := g.order[0]
			g.order = g.order[1:]
			delete(g.peers, oldest)
		}
		r = &rates{
			submit: bucket{rate: SubmitRate, burst: SubmitBurst, tokens: SubmitBurst, updated: now},
			read:   bucket{rate: ReadRate, burst: ReadBurst, tokens: ReadBurst, updated: now},
		}
		g.peers[remote] = r
		g.order = append(g.order, remote)
	}
	b := &r.read
	if submit {
		b = &r.submit
	}
	elapsed := now.Sub(b.updated).Milliseconds()
	if elapsed > 0 {
		add := int(elapsed) * b.rate / 1000
		if add > 0 {
			b.tokens += add
			if b.tokens > b.burst {
				b.tokens = b.burst
			}
			b.updated = now
		}
	}
	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

func remoteHost(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil || host == "" {
		return remote
	}
	return host
}
