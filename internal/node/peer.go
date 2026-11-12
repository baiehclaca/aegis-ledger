package node

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/silvergreyhound/silver-grey-ledger/internal/p2p"
)

var errPeerDown = errors.New("node: peer is down")

const (
	maxConsensusQueue = 32
	maxGossipQueue    = 256
	// A peer that has stopped ACKing must not pin the replica loop.
	// One second is far above the parent-fetch reply and far below a
	// view spent blocked on a black hole.
	writeDeadline = time.Second
)

// peerConn is one other validator. The replica loop and the read loop
// share the mutex. Consensus frames are never dropped to make room for
// gossip; a full consensus queue closes the connection instead.
type peerConn struct {
	index int
	addr  string
	lim   *p2p.Limiter
	tls   *tls.Config
	mu    sync.Mutex
	conn  net.Conn
	consQ [][]byte
	gossQ [][]byte
}

func (p *peerConn) send(raw []byte) {
	if len(raw) < 5 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn != nil {
		if err := writeRaw(p.conn, raw); err == nil {
			return
		}
		_ = p.conn.Close()
		p.conn = nil
	}
	if isGossip(raw[4]) {
		if len(p.gossQ) == maxGossipQueue {
			p.gossQ = append([][]byte(nil), p.gossQ[1:]...)
		}
		p.gossQ = append(p.gossQ, raw)
		return
	}
	if len(p.consQ) == maxConsensusQueue {
		p.consQ = nil
		p.gossQ = nil
		return
	}
	p.consQ = append(p.consQ, raw)
}

func (p *peerConn) attach(conn net.Conn) [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn != nil {
		_ = p.conn.Close()
	}
	p.conn = conn
	queued := append(append([][]byte(nil), p.consQ...), p.gossQ...)
	p.consQ = nil
	p.gossQ = nil
	return queued
}

func (p *peerConn) detach(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn == conn {
		p.conn = nil
	}
}

func (p *peerConn) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn != nil {
		_ = p.conn.Close()
		p.conn = nil
	}
}

// writeFrame is the only writer besides send. Both hold mu, so two
// goroutines do not write the TLS connection at once.
func (p *peerConn) writeFrame(kind byte, payload []byte) error {
	raw, err := frameKind(kind, payload)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn == nil {
		return errPeerDown
	}
	if err := writeRaw(p.conn, raw); err != nil {
		_ = p.conn.Close()
		p.conn = nil
		return err
	}
	return nil
}

func writeRaw(conn net.Conn, raw []byte) error {
	if err := conn.SetWriteDeadline(time.Now().Add(writeDeadline)); err != nil {
		return err
	}
	_, err := conn.Write(raw)
	return err
}

func isGossip(kind byte) bool {
	class, ok := p2p.ClassOf(kind)
	return ok && class == p2p.ClassGossip
}
