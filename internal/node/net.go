package node

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/mempool"
	"github.com/silvergreyhound/silver-grey-ledger/internal/p2p"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

const handshakeTimeout = 5 * time.Second

func (n *Node) serveConsensus(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		n.wg.Add(1)
		go func(conn net.Conn) {
			defer n.wg.Done()
			n.inbound(conn)
		}(conn)
	}
}

func (n *Node) inbound(conn net.Conn) {
	conn = p2p.Count(conn, n.cfg.Meter)
	keepAlive(conn)
	tlsConn := tls.Server(conn, n.serverTLS)
	ctx, cancel := context.WithTimeout(n.ctx, handshakeTimeout)
	err := tlsConn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		_ = tlsConn.Close()
		return
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		_ = tlsConn.Close()
		return
	}
	key, err := p2p.PublicFromCert(state.PeerCertificates[0])
	if err != nil {
		_ = tlsConn.Close()
		return
	}
	idx, ok := p2p.Index(n.validatorKeys(), key)
	if !ok || idx == n.cfg.Index || n.peers[idx] == nil {
		_ = tlsConn.Close()
		return
	}
	p := n.peers[idx]
	if p.lim.Banned(time.Now()) || !n.holdInbound(idx, tlsConn) {
		_ = tlsConn.Close()
		return
	}
	defer n.releaseInbound(idx, tlsConn)
	defer func() { _ = tlsConn.Close() }()
	n.readPeer(tlsConn, p)
}

func (n *Node) dial(ctx context.Context, p *peerConn) {
	backoff := 50 * time.Millisecond
	for {
		if ctx.Err() != nil {
			return
		}
		if until := p.lim.BanDeadline(); time.Now().Before(until) {
			timer := time.NewTimer(time.Until(until))
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return
			case <-timer.C:
			}
		}
		dialer := net.Dialer{Timeout: 2 * time.Second}
		raw, err := dialer.DialContext(ctx, "tcp", p.addr)
		if err != nil {
			if !sleep(ctx, backoff) {
				return
			}
			if backoff < 500*time.Millisecond {
				backoff *= 2
			}
			continue
		}
		backoff = 50 * time.Millisecond
		raw = p2p.Count(raw, n.cfg.Meter)
		keepAlive(raw)
		tlsConn := tls.Client(raw, p.tls)
		hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
		err = tlsConn.HandshakeContext(hctx)
		cancel()
		if err != nil {
			_ = tlsConn.Close()
			if !sleep(ctx, backoff) {
				return
			}
			continue
		}
		queued := p.attach(tlsConn)
		for _, rawFrame := range queued {
			p.send(rawFrame)
		}
		n.poke()
		n.readPeer(tlsConn, p)
		p.detach(tlsConn)
		_ = tlsConn.Close()
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func keepAlive(conn net.Conn) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tcp.SetKeepAlive(true)
	_ = tcp.SetKeepAlivePeriod(30 * time.Second)
}

func (n *Node) readPeer(conn net.Conn, p *peerConn) {
	for {
		if n.ctx.Err() != nil {
			return
		}
		kind, payload, err := p2p.ReadFrame(conn)
		if err != nil {
			if errors.Is(err, p2p.ErrFrame) || errors.Is(err, p2p.ErrUnknown) {
				if p.lim.Strike(time.Now()) {
					return
				}
			}
			return
		}
		now := time.Now()
		if !p.lim.Allow(now, kind) {
			if p.lim.Strike(now) {
				return
			}
			continue
		}
		switch kind {
		case p2p.KindBlockRequest:
			n.replySync(p, payload)
			p.lim.Credit()
		case p2p.KindBlockResponse:
			if len(payload) == 0 {
				n.poke()
				p.lim.Credit()
				continue
			}
			if !n.storeSynced(payload) {
				if p.lim.Strike(time.Now()) {
					return
				}
				continue
			}
			p.lim.Credit()
		case p2p.KindPing:
			n.replyPing(p, payload)
			p.lim.Credit()
		case p2p.KindTxAnnounce, p2p.KindTxRequest, p2p.KindTxBody, p2p.KindGov:
			if !n.pushGossip(p.index, kind, payload) {
				if p.lim.Strike(time.Now()) {
					return
				}
				continue
			}
			p.lim.Credit()
		case p2p.KindProposal, p2p.KindVote, p2p.KindTimeout, p2p.KindTC, p2p.KindEvidence:
			in, err := decodeConsensus(kind, payload)
			if err != nil {
				if p.lim.Strike(time.Now()) {
					return
				}
				continue
			}
			select {
			case n.incoming <- inbound{input: in}:
				p.lim.Credit()
			case <-n.ctx.Done():
				return
			default:
				return
			}
		default:
			if p.lim.Strike(time.Now()) {
				return
			}
		}
	}
}

func (n *Node) replySync(p *peerConn, payload []byte) {
	if len(payload) != 8 {
		return
	}
	height := binary.BigEndian.Uint64(payload)
	blocks, err := n.disk.Suffix(height)
	if err != nil {
		_ = p.writeFrame(p2p.KindBlockResponse, nil)
		return
	}
	for _, block := range blocks {
		raw, err := block.MarshalBinary()
		if err != nil {
			continue
		}
		if err := p.writeFrame(p2p.KindBlockResponse, raw); err != nil {
			return
		}
	}
	_ = p.writeFrame(p2p.KindBlockResponse, nil)
}

func (n *Node) replyPing(p *peerConn, payload []byte) {
	if len(payload) != 8 || payload[0] != 0 {
		return
	}
	echo := append([]byte(nil), payload...)
	echo[0] = 1
	_ = p.writeFrame(p2p.KindPing, echo)
}

func (n *Node) storeSynced(payload []byte) bool {
	block, err := types.UnmarshalBlock(payload)
	if err != nil || block.Header.ChainID != n.chain || block.Header.Height == 0 {
		return false
	}
	if err := block.Validate(); err != nil {
		return false
	}
	pub, ok := n.proposer(block.Header.ProposerID)
	if !ok {
		return false
	}
	if err := block.VerifyProposer(pub); err != nil {
		return false
	}
	if err := block.Header.Justify.Verify(n.chain, n.validatorKeys()); err != nil {
		return false
	}
	if err := n.disk.PutBlock(block); err != nil {
		return false
	}
	n.poke()
	return true
}

func (n *Node) validatorKeys() []crypto.PublicKey {
	if n.trust == nil {
		return n.pubs
	}
	return n.trust.snapshot()
}

func (n *Node) proposer(id [32]byte) (crypto.PublicKey, bool) {
	for _, pub := range n.validatorKeys() {
		got, err := pub.ID()
		if err == nil && got == id {
			return pub, true
		}
	}
	return crypto.PublicKey{}, false
}

func (n *Node) poke() {
	select {
	case n.kick <- struct{}{}:
	default:
	}
}

func (n *Node) holdInbound(idx int, conn net.Conn) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.inBy[idx] != nil {
		return false
	}
	n.inBy[idx] = conn
	n.inboundC = append(n.inboundC, conn)
	return true
}

func (n *Node) releaseInbound(idx int, conn net.Conn) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.inBy[idx] == conn {
		delete(n.inBy, idx)
	}
	for i, c := range n.inboundC {
		if c == conn {
			n.inboundC = append(n.inboundC[:i], n.inboundC[i+1:]...)
			return
		}
	}
}

func (n *Node) dropInbound() {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, c := range n.inboundC {
		_ = c.Close()
	}
	n.inboundC = nil
	n.inBy = map[int]net.Conn{}
}

func (n *Node) pushGossip(from int, kind byte, payload []byte) bool {
	switch kind {
	case p2p.KindTxAnnounce, p2p.KindTxRequest:
		if _, err := mempool.UnmarshalIDs(payload); err != nil {
			return false
		}
	case p2p.KindTxBody:
		if _, _, err := mempool.UnmarshalBody(payload); err != nil {
			return false
		}
	default:
		return false
	}
	n.gmu.Lock()
	if len(n.gossipQ) == gossipCap {
		n.gossipQ = n.gossipQ[1:]
	}
	n.gossipQ = append(n.gossipQ, gossipMsg{from: from, kind: kind, body: append([]byte(nil), payload...)})
	n.gmu.Unlock()
	n.poke()
	return true
}
