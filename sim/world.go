package sim

import (
	"fmt"
	"math/rand/v2"
	"sync"

	"github.com/silvergreyhound/silver-grey-ledger/internal/consensus"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

// One genesis per validator count. Signing two SLH-DSA-SHAKE-128s
// founding keys is the slow part, and the seed selects faults and the
// delivery schedule, not the founding keys. Genesis signing itself is
// covered by the types and consensus tests.
var (
	genesisMu sync.Mutex
	genesisBy = map[int]genesisBundle{}
)

type genesisBundle struct {
	keys  []crypto.PrivateKey
	g     types.Genesis
	block types.Block
	qc    types.QC
	chain [crypto.DigestSize]byte
}

func sharedGenesis(n int) (genesisBundle, error) {
	genesisMu.Lock()
	defer genesisMu.Unlock()
	if got, ok := genesisBy[n]; ok {
		return got, nil
	}
	keys := make([]crypto.PrivateKey, n)
	for i := range keys {
		k, err := crypto.GenerateMLDSA65()
		if err != nil {
			return genesisBundle{}, err
		}
		keys[i] = k
	}
	g, block, qc, err := consensus.BuildGenesis(0, keys)
	if err != nil {
		return genesisBundle{}, err
	}
	chain, err := g.ChainID()
	if err != nil {
		return genesisBundle{}, err
	}
	got := genesisBundle{keys: keys, g: g, block: block, qc: qc, chain: chain}
	genesisBy[n] = got
	return got, nil
}

type fault uint8

const (
	faultHonest fault = iota
	faultEquivocate
	faultWithhold
	faultBadSig
	faultStale
)

type packet struct {
	to  int
	msg consensus.Outbound
	at  int64
}

type held struct {
	msg consensus.Outbound
}

type voteKey struct {
	signer uint8
	view   uint64
}

type world struct {
	opt     Options
	rng     *rand.Rand
	keys    []crypto.PrivateKey
	nodes   []*consensus.Replica
	fault   []fault
	honest  []int
	timers  []consensus.Timer
	armed   []int64
	queue   []packet
	held    []held
	saved   [][]consensus.Outbound
	part0   int64
	partEnd int64
	tick    int64
	commits [][]Commit
	voted   map[voteKey][crypto.DigestSize]byte
	double  string
	atGST   []uint64
	chain   [crypto.DigestSize]byte
}

func newWorld(opt Options) (*world, error) {
	bundle, err := sharedGenesis(opt.N)
	if err != nil {
		return nil, err
	}
	keys, g, block, qc, chain := bundle.keys, bundle.g, bundle.block, bundle.qc, bundle.chain
	cfg := consensus.Config{
		BaseTimeout: opt.BaseTimeout,
		MaxTimeout:  opt.MaxTimeout,
		Skew:        1 << 30,
	}
	w := &world{
		opt:     opt,
		rng:     rand.New(rand.NewPCG(uint64(opt.Seed), 0x6d1)),
		keys:    keys,
		nodes:   make([]*consensus.Replica, opt.N),
		fault:   make([]fault, opt.N),
		timers:  make([]consensus.Timer, opt.N),
		armed:   make([]int64, opt.N),
		saved:   make([][]consensus.Outbound, opt.N),
		commits: make([][]Commit, opt.N),
		voted:   map[voteKey][crypto.DigestSize]byte{},
		atGST:   make([]uint64, opt.N),
		chain:   chain,
	}
	w.placeFaults()
	w.placePartition()
	for i := range keys {
		node, err := consensus.Init(i, keys[i], g, block, qc, cfg, consensus.NewMemoryStore())
		if err != nil {
			return nil, err
		}
		w.nodes[i] = node
	}
	return w, nil
}

func (w *world) placeFaults() {
	f := (w.opt.N - 1) / 3
	start := int(uint64(w.opt.Seed) % uint64(w.opt.N))
	modes := []fault{faultEquivocate, faultWithhold, faultBadSig, faultStale}
	for i := range w.opt.N {
		w.fault[i] = faultHonest
	}
	for i := range f {
		idx := (start + i) % w.opt.N
		w.fault[idx] = modes[(int(uint64(w.opt.Seed))+i)%len(modes)]
	}
	for i := range w.opt.N {
		if w.fault[i] == faultHonest {
			w.honest = append(w.honest, i)
		}
	}
}

func (w *world) placePartition() {
	// One run in three has no partition, so the campaign also covers a
	// merely delayed network. The window is inside the seed's stream.
	if w.rng.IntN(3) == 0 {
		w.partEnd = -1
		return
	}
	w.part0 = w.rng.Int64N(w.opt.GST)
	if w.opt.Drop {
		span := w.rng.Int64N(w.opt.Ticks-w.part0) + 1
		w.partEnd = w.part0 + span
		return
	}
	// Liveness partitions end at GST. Cross traffic is buffered, not lost.
	w.partEnd = w.opt.GST
}

func (w *world) start() error {
	for i, node := range w.nodes {
		out, err := node.Start(0)
		if err != nil {
			return err
		}
		w.apply(i, out)
	}
	return nil
}

func (w *world) deliver() error {
	pending := make([]packet, 0, len(w.queue))
	rest := make([]packet, 0, len(w.queue))
	for _, p := range w.queue {
		if p.at <= w.tick {
			pending = append(pending, p)
		} else {
			rest = append(rest, p)
		}
	}
	w.queue = rest
	for _, p := range pending {
		out, err := w.nodes[p.to].Step(inputOf(p.msg, w.tick))
		if err != nil {
			return fmt.Errorf("sim: deliver to %d at %d: %w", p.to, w.tick, err)
		}
		w.apply(p.to, out)
	}
	return nil
}

func (w *world) timeouts() error {
	for i, node := range w.nodes {
		tm := w.timers[i]
		if tm.After == 0 || node.View() != tm.View {
			continue
		}
		if w.tick < w.armed[i]+int64(tm.After) {
			continue
		}
		w.timers[i] = consensus.Timer{}
		out, err := node.Step(consensus.Input{Now: w.tick, Timeout: true})
		if err != nil {
			return fmt.Errorf("sim: timeout %d at %d: %w", i, w.tick, err)
		}
		w.apply(i, out)
	}
	return nil
}

func (w *world) apply(from int, out consensus.Output) {
	w.observe(from, out)
	var proposal *types.Proposal
	var vote *types.Vote
	for _, m := range out.Messages {
		if m.Proposal != nil && proposal == nil {
			cp := *m.Proposal
			proposal = &cp
		}
		if m.Vote != nil && vote == nil {
			cp := *m.Vote
			vote = &cp
		}
		w.dispatch(from, m)
	}
	if w.fault[from] == faultEquivocate {
		w.inject(from, proposal, vote)
	}
	if out.Timer.After != 0 {
		w.timers[from] = out.Timer
		w.armed[from] = w.tick
	}
	for _, c := range out.Commits {
		w.commits[from] = append(w.commits[from], Commit{Height: c.Height, Hash: c.Hash})
	}
}

func (w *world) dispatch(from int, m consensus.Outbound) {
	switch w.fault[from] {
	case faultHonest, faultEquivocate:
		w.enqueue(from, m)
	case faultWithhold:
	case faultBadSig:
		w.enqueue(from, corrupt(cloneOutbound(m)))
	case faultStale:
		c := cloneOutbound(m)
		w.remember(from, c)
		w.enqueue(from, c)
		w.replay(from)
	default:
		w.enqueue(from, m)
	}
}

func (w *world) inject(from int, proposal *types.Proposal, vote *types.Vote) {
	if proposal != nil {
		second, err := equivocateProposal(*proposal, w.keys[from])
		if err == nil {
			for to := range w.nodes {
				if to == from {
					continue
				}
				w.enqueue(from, consensus.Outbound{To: to, Proposal: &second})
			}
		}
	}
	view := uint64(0)
	switch {
	case vote != nil:
		view = vote.View
	case proposal != nil:
		view = proposal.Block.Header.View
	default:
		return
	}
	var dummy [crypto.DigestSize]byte
	dummy[0] = 0xff
	extra := types.Vote{
		ChainID:   w.chain,
		View:      view,
		BlockHash: dummy,
		Signer:    uint8(from),
	}
	if err := extra.Sign(w.keys[from]); err != nil {
		return
	}
	next := int((view + 1) % uint64(len(w.nodes)))
	w.enqueue(from, consensus.Outbound{To: next, Vote: &extra})
}

func (w *world) enqueue(from int, m consensus.Outbound) {
	m = cloneOutbound(m)
	if w.partitioned(from, m.To) {
		w.held = append(w.held, held{msg: m})
		return
	}
	delay := int64(1)
	if w.tick < w.opt.GST {
		delay = 1 + w.rng.Int64N(w.opt.MaxDelay)
		if w.opt.Drop && w.rng.IntN(20) == 0 {
			return
		}
	}
	w.queue = append(w.queue, packet{to: m.To, msg: m, at: w.tick + delay})
}

func (w *world) partitioned(from, to int) bool {
	if w.partEnd < 0 || w.tick < w.part0 || w.tick >= w.partEnd {
		return false
	}
	cut := len(w.nodes) / 2
	return (from < cut) != (to < cut)
}

func (w *world) flush() {
	for _, h := range w.held {
		w.queue = append(w.queue, packet{to: h.msg.To, msg: h.msg, at: w.tick})
	}
	w.held = nil
	w.partEnd = -1
}

func (w *world) remember(from int, m consensus.Outbound) {
	w.saved[from] = append(w.saved[from], m)
	if len(w.saved[from]) > 8 {
		w.saved[from] = w.saved[from][1:]
	}
}

func (w *world) replay(from int) {
	saved := w.saved[from]
	if len(saved) == 0 {
		return
	}
	w.enqueue(from, saved[0])
}

func (w *world) observe(from int, out consensus.Output) {
	if w.fault[from] != faultHonest {
		return
	}
	for _, m := range out.Messages {
		if m.Vote == nil {
			continue
		}
		key := voteKey{signer: m.Vote.Signer, view: m.Vote.View}
		if prev, ok := w.voted[key]; ok {
			w.double = fmt.Sprintf("honest node %d voted twice in view %d (hashes equal: %v)", from, m.Vote.View, prev == m.Vote.BlockHash)
			return
		}
		w.voted[key] = m.Vote.BlockHash
	}
}

func (w *world) markGST() {
	for i, node := range w.nodes {
		w.atGST[i] = node.CommitHeight()
	}
}

func (w *world) result() Result {
	final := make([]uint64, len(w.nodes))
	for i, node := range w.nodes {
		final[i] = node.CommitHeight()
	}
	return Result{
		Seed:    w.opt.Seed,
		N:       w.opt.N,
		Honest:  append([]int(nil), w.honest...),
		Final:   final,
		AtGST:   append([]uint64(nil), w.atGST...),
		Commits: w.commits,
		Double:  w.double,
	}
}

func inputOf(m consensus.Outbound, now int64) consensus.Input {
	in := consensus.Input{Now: now}
	switch {
	case m.Proposal != nil:
		in.Proposal = m.Proposal
	case m.Vote != nil:
		in.Vote = m.Vote
	case m.Timeout != nil:
		in.TimeoutMsg = m.Timeout
	case m.TC != nil:
		in.TC = m.TC
	case m.Evidence != nil:
		in.Evidence = m.Evidence
	}
	return in
}
