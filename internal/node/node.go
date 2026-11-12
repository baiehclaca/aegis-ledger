package node

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/silvergreyhound/silver-grey-ledger/internal/api"
	"github.com/silvergreyhound/silver-grey-ledger/internal/consensus"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/keyfile"
	"github.com/silvergreyhound/silver-grey-ledger/internal/mempool"
	"github.com/silvergreyhound/silver-grey-ledger/internal/p2p"
	"github.com/silvergreyhound/silver-grey-ledger/internal/state"
	"github.com/silvergreyhound/silver-grey-ledger/internal/store"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

const (
	defaultBase uint64 = 500
	defaultMax  uint64 = 4_000
	defaultSkew int64  = 120_000
	maxHold            = 256
	chainWalk          = 64
	gossipCap          = 256
	gossipEvery        = 200 * time.Millisecond
	maxSubs            = 32
)

// errSignature is a gossip body whose writer signature failed.
// Other rejections are not strikes: a stale nonce is not an attack.
var errSignature = errors.New("node: signature")

// Run serves the consensus listener and the API until ctx is cancelled.
// ready receives one line, "listening consensus=<addr> client=<addr>",
// after the replica has entered its first view.
func Run(ctx context.Context, cfg Config, ready io.Writer) error {
	if err := cfg.check(); err != nil {
		return err
	}
	n, err := prepare(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = n.disk.Close() }()
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	apiLn, err := net.Listen("tcp", cfg.Client)
	if err != nil {
		_ = ln.Close()
		return err
	}
	n.ln = ln
	n.apiLn = apiLn
	n.ctx = ctx
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		n.serveConsensus(ln)
	}()
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		_ = api.Serve(ctx, apiLn, n.apiTLS, n)
	}()
	for _, p := range n.peers {
		if p == nil {
			continue
		}
		n.wg.Add(1)
		go func(p *peerConn) {
			defer n.wg.Done()
			n.dial(ctx, p)
		}(p)
	}
	err = n.loop(ctx, ready)
	_ = ln.Close()
	_ = apiLn.Close()
	for _, p := range n.peers {
		if p != nil {
			p.close()
		}
	}
	n.dropInbound()
	n.wg.Wait()
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

type inbound struct {
	input consensus.Input
}

type gossipMsg struct {
	from int
	kind byte
	body []byte
}

// Node is one process. The loop method is the only caller of the replica.
type Node struct {
	cfg       Config
	disk      *store.Disk
	replica   *consensus.Replica
	pubs      []crypto.PublicKey
	chain     [32]byte
	fresh     bool
	pool      *mempool.Pool
	led       *state.Ledger
	trust     *keyRing
	serverTLS *tls.Config
	apiTLS    *tls.Config
	office    map[[crypto.DigestSize]byte]types.GovTx
	seenGov   map[[crypto.DigestSize]byte]struct{}

	ctx   context.Context
	ln    net.Listener
	apiLn net.Listener
	peers []*peerConn

	incoming chan inbound
	apiCh    chan apiCall
	kick     chan struct{}

	hold   []inbound
	timer  *time.Timer
	armed  consensus.Timer
	syncAt time.Time

	mu       sync.Mutex
	inboundC []net.Conn
	inBy     map[int]net.Conn

	gmu     sync.Mutex
	gossipQ []gossipMsg

	subMu sync.Mutex
	subs  []chan api.Notice

	// wg tracks the listener, dials, and each accepted connection.
	// Run waits for it before the deferred disk close, so a sync write
	// cannot land on a closed log.
	wg sync.WaitGroup
}

func prepare(cfg Config) (*Node, error) {
	key := cfg.Key
	if key.Algorithm() == 0 {
		opened, err := keyfile.Open(cfg.KeyPath, cfg.Passphrase)
		if err != nil {
			return nil, err
		}
		key = opened
	}
	cert, err := p2p.Certificate(key)
	if err != nil {
		return nil, err
	}
	g, block, qc, err := ReadGenesis(cfg.GenesisPath)
	if err != nil {
		return nil, err
	}
	if len(cfg.Peers) != len(g.Validators().Keys) {
		return nil, fmt.Errorf("node: peer list does not match the validator set")
	}
	chain, err := g.ChainID()
	if err != nil {
		return nil, err
	}
	d, err := store.Open(cfg.Dir)
	if err != nil {
		return nil, err
	}
	if err := d.SetValidators(g.Validators()); err != nil {
		_ = d.Close()
		return nil, err
	}
	base, capTimeout, skew := cfg.BaseTimeout, cfg.MaxTimeout, cfg.Skew
	if base == 0 {
		base = defaultBase
	}
	if capTimeout == 0 {
		capTimeout = defaultMax
	}
	if skew == 0 {
		skew = defaultSkew
	}
	ccfg := consensus.Config{BaseTimeout: base, MaxTimeout: capTimeout, Skew: skew}
	snap, have, err := d.GetSnapshot()
	if err != nil {
		_ = d.Close()
		return nil, err
	}
	var replica *consensus.Replica
	fresh := !have
	if fresh {
		replica, err = consensus.Init(cfg.Index, key, g, block, qc, ccfg, d)
	} else {
		if snap.Chain != chain {
			err = fmt.Errorf("node: safety file is for a different chain")
		} else {
			replica, err = consensus.Load(cfg.Index, key, g, ccfg, d)
		}
	}
	if err != nil {
		_ = d.Close()
		return nil, err
	}
	ring := newKeyRing(g.Validators().Keys)
	peers := make([]*peerConn, len(cfg.Peers))
	for i, addr := range cfg.Peers {
		if i == cfg.Index {
			continue
		}
		peers[i] = &peerConn{
			index: i,
			addr:  addr,
			lim:   p2p.NewLimiter(),
			tls:   p2p.PeerClientConfigSource(cert, ring.snapshot, cfg.Index, i),
		}
	}
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	n := &Node{
		cfg:       cfg,
		disk:      d,
		replica:   replica,
		pubs:      g.Validators().Keys,
		chain:     chain,
		fresh:     fresh,
		pool:      mempool.New(),
		trust:     ring,
		serverTLS: p2p.PeerServerConfigSource(cert, ring.snapshot, cfg.Index),
		apiTLS:    p2p.APIServerConfig(cert),
		peers:     peers,
		office:    map[[crypto.DigestSize]byte]types.GovTx{},
		seenGov:   map[[crypto.DigestSize]byte]struct{}{},
		incoming:  make(chan inbound, 256),
		apiCh:     make(chan apiCall, 16),
		kick:      make(chan struct{}, 1),
		timer:     timer,
		inBy:      map[int]net.Conn{},
	}
	if err := n.syncLedger(); err != nil {
		_ = d.Close()
		return nil, err
	}
	return n, nil
}

func (n *Node) loop(ctx context.Context, ready io.Writer) error {
	now := time.Now().UnixMilli()
	if n.fresh {
		out, err := n.replica.Start(now)
		if err != nil {
			return err
		}
		if err := n.disk.CatchUp(); err != nil {
			return err
		}
		if err := n.dispatch(out); err != nil {
			return err
		}
	} else {
		n.rearm(n.replica.Arm())
	}
	n.requestSync()
	if ready != nil {
		if _, err := fmt.Fprintf(ready, "listening consensus=%s client=%s\n", n.ln.Addr(), n.apiLn.Addr()); err != nil {
			return err
		}
	}
	tick := time.NewTicker(gossipEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case item := <-n.incoming:
			if err := n.drainGossip(); err != nil {
				return err
			}
			if err := n.arrive(item); err != nil {
				return err
			}
		case call := <-n.apiCh:
			if err := n.drainGossip(); err != nil {
				return err
			}
			call.resp <- call.fn()
		case <-n.kick:
			if err := n.drainGossip(); err != nil {
				return err
			}
			n.requestSync()
			if err := n.flush(); err != nil {
				return err
			}
		case <-tick.C:
			if err := n.drainGossip(); err != nil {
				return err
			}
			n.announce()
			if err := n.refill(); err != nil {
				return err
			}
			if err := n.flush(); err != nil {
				return err
			}
		case <-n.timer.C:
			if n.replica.View() == n.armed.View {
				if err := n.step(consensus.Input{Timeout: true}); err != nil {
					return err
				}
			}
			if err := n.flush(); err != nil {
				return err
			}
		}
	}
}

func (n *Node) arrive(item inbound) error {
	n.hold = append(n.hold, item)
	if len(n.hold) > maxHold {
		n.hold = n.hold[len(n.hold)-maxHold:]
	}
	return n.flush()
}

func (n *Node) flush() error {
	var keep []inbound
	for _, item := range n.hold {
		plain := item.input.Proposal == nil && item.input.TimeoutMsg == nil && item.input.TC == nil
		if plain || n.ready(item.input) {
			if err := n.step(item.input); err != nil {
				return err
			}
			continue
		}
		keep = append(keep, item)
	}
	n.hold = keep
	if len(n.hold) > 0 {
		n.requestSync()
	}
	return nil
}

func (n *Node) ready(in consensus.Input) bool {
	switch {
	case in.Proposal != nil:
		return n.linked(in.Proposal.Block)
	case in.TimeoutMsg != nil:
		return n.haveQC(in.TimeoutMsg.HighQC)
	case in.TC != nil:
		for _, to := range in.TC.Timeouts {
			if !n.haveQC(to.HighQC) {
				return false
			}
		}
		return true
	default:
		return true
	}
}

func (n *Node) linked(b types.Block) bool {
	if b.Header.Height == 0 {
		return true
	}
	h := b.Header.ParentHash
	for range chainWalk {
		parent, ok, err := n.disk.GetBlock(h)
		if err != nil || !ok {
			return false
		}
		if parent.Header.Height == 0 {
			return true
		}
		h = parent.Header.ParentHash
	}
	// The bound is a cycle guard. A long stored chain is linked; waiting
	// for genesis inside this walk would stall every later proposal.
	return true
}

func (n *Node) haveQC(qc types.QC) bool {
	if qc.IsEmpty() {
		return true
	}
	_, ok, err := n.disk.GetBlock(qc.BlockHash)
	return err == nil && ok
}

func (n *Node) step(in consensus.Input) error {
	in.Now = time.Now().UnixMilli()
	out, err := n.replica.Step(in)
	if err != nil {
		return err
	}
	if err := n.disk.CatchUp(); err != nil {
		return err
	}
	return n.dispatch(out)
}

func (n *Node) dispatch(out consensus.Output) error {
	for _, m := range out.Messages {
		raw, err := encodeOutbound(m)
		if err != nil || m.To < 0 || m.To >= len(n.peers) || n.peers[m.To] == nil {
			continue
		}
		n.peers[m.To].send(raw)
	}
	if out.Timer.After > 0 {
		n.rearm(out.Timer)
	}
	for _, c := range out.Commits {
		block, ok, err := n.disk.GetBlock(c.Hash)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		ids := make([][crypto.DigestSize]byte, 0, len(block.Events))
		for _, ev := range block.Events {
			id, err := ev.ID()
			if err != nil {
				return err
			}
			ids = append(ids, id)
			n.notify(api.Notice{ID: id, Height: c.Height})
		}
		n.pool.Forget(ids)
	}
	if err := n.syncLedger(); err != nil {
		return err
	}
	return n.refill()
}

func (n *Node) rearm(tm consensus.Timer) {
	if !n.timer.Stop() {
		select {
		case <-n.timer.C:
		default:
		}
	}
	n.armed = tm
	n.timer.Reset(time.Duration(tm.After) * time.Millisecond)
}

func (n *Node) requestSync() {
	if time.Since(n.syncAt) < 100*time.Millisecond {
		return
	}
	n.syncAt = time.Now()
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], n.replica.CommitHeight())
	raw, err := frameKind(p2p.KindBlockRequest, buf[:])
	if err != nil {
		return
	}
	for _, p := range n.peers {
		if p != nil {
			p.send(raw)
		}
	}
}

func (n *Node) announce() {
	ids := n.pool.IDs(32)
	if len(ids) == 0 {
		return
	}
	raw, err := mempool.MarshalIDs(ids)
	if err != nil {
		return
	}
	frame, err := frameKind(p2p.KindTxAnnounce, raw)
	if err != nil {
		return
	}
	for _, p := range n.peers {
		if p != nil {
			p.send(frame)
		}
	}
}

func (n *Node) refill() error {
	for _, writer := range n.pool.Writers() {
		last, err := n.disk.LastNonce(writer)
		if err != nil {
			return err
		}
		for _, ev := range n.pool.Ready(writer, last) {
			if err := n.replica.Submit([]types.Event{ev}); err != nil {
				if errors.Is(err, consensus.ErrQueueFull) {
					return nil
				}
				return err
			}
		}
	}
	return nil
}

func (n *Node) acceptEvent(pub crypto.PublicKey, ev types.Event) error {
	if err := ev.Verify(pub); err != nil {
		return errSignature
	}
	if ev.ChainID != n.chain {
		return api.ErrRejected
	}
	id, err := ev.ID()
	if err != nil {
		return err
	}
	committed, err := n.disk.Committed(id)
	if err != nil {
		return err
	}
	if committed {
		return nil
	}
	if n.led == nil {
		return api.ErrRejected
	}
	wid, err := pub.ID()
	if err != nil || ev.WriterID != wid {
		return api.ErrRejected
	}
	if err := n.led.AuthorizeEvent(ev, n.replica.CommitHeight()+1); err != nil {
		return api.ErrRejected
	}
	last, err := n.disk.LastNonce(ev.WriterID)
	if err != nil {
		return err
	}
	if ev.Nonce == 0 || ev.Nonce <= last {
		return api.ErrRejected
	}
	if err := n.pool.Add(pub, ev); err != nil {
		if errors.Is(err, mempool.ErrFull) || errors.Is(err, mempool.ErrConflict) {
			return api.ErrRejected
		}
		return err
	}
	return n.refill()
}

func (n *Node) drainGossip() error {
	n.gmu.Lock()
	batch := n.gossipQ
	n.gossipQ = nil
	n.gmu.Unlock()
	for _, msg := range batch {
		if err := n.onGossip(msg); err != nil {
			return err
		}
	}
	return nil
}

func (n *Node) onGossip(msg gossipMsg) error {
	var peer *peerConn
	if msg.from >= 0 && msg.from < len(n.peers) {
		peer = n.peers[msg.from]
	}
	switch msg.kind {
	case p2p.KindTxAnnounce:
		ids, err := mempool.UnmarshalIDs(msg.body)
		if err != nil || peer == nil {
			return nil
		}
		var want [][crypto.DigestSize]byte
		for _, id := range ids {
			if n.pool.Has(id) {
				continue
			}
			ok, err := n.disk.Committed(id)
			if err != nil {
				return err
			}
			if ok {
				continue
			}
			want = append(want, id)
			if len(want) == mempool.MaxIDs {
				break
			}
		}
		if len(want) == 0 {
			return nil
		}
		raw, err := mempool.MarshalIDs(want)
		if err != nil {
			return nil
		}
		frame, err := frameKind(p2p.KindTxRequest, raw)
		if err != nil {
			return nil
		}
		peer.send(frame)
	case p2p.KindTxRequest:
		ids, err := mempool.UnmarshalIDs(msg.body)
		if err != nil || peer == nil {
			return nil
		}
		for _, id := range ids {
			pub, ev, ok := n.pool.Get(id)
			if !ok {
				continue
			}
			body, err := mempool.MarshalBody(pub, ev)
			if err != nil {
				continue
			}
			frame, err := frameKind(p2p.KindTxBody, body)
			if err != nil {
				continue
			}
			peer.send(frame)
		}
	case p2p.KindTxBody:
		pub, ev, err := mempool.UnmarshalBody(msg.body)
		if err != nil {
			return nil
		}
		err = n.acceptEvent(pub, ev)
		if errors.Is(err, errSignature) {
			if peer != nil && peer.lim.Strike(time.Now()) {
				peer.close()
			}
			return nil
		}
		if errors.Is(err, api.ErrRejected) {
			return nil
		}
		return err
	case p2p.KindGov:
		tx, err := types.UnmarshalGovTx(msg.body)
		if err != nil {
			if peer != nil && peer.lim.Strike(time.Now()) {
				peer.close()
			}
			return nil
		}
		n.acceptGov(tx, msg.from)
		return nil
	default:
		return nil
	}
	return nil
}

func (n *Node) notify(note api.Notice) {
	n.subMu.Lock()
	subs := append([]chan api.Notice(nil), n.subs...)
	n.subMu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- note:
		default:
		}
	}
}

// Subscribe registers a committed-event listener. The cancel function
// removes it. The channel is not closed.
func (n *Node) Subscribe() (<-chan api.Notice, func(), error) {
	ch := make(chan api.Notice, 16)
	n.subMu.Lock()
	defer n.subMu.Unlock()
	if len(n.subs) >= maxSubs {
		return nil, nil, api.ErrRejected
	}
	n.subs = append(n.subs, ch)
	cancel := func() {
		n.subMu.Lock()
		defer n.subMu.Unlock()
		for i, sub := range n.subs {
			if sub == ch {
				n.subs = append(n.subs[:i], n.subs[i+1:]...)
				return
			}
		}
	}
	return ch, cancel, nil
}
