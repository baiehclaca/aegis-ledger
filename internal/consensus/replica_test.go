package consensus

import (
	"math"
	"testing"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

func TestLeader(t *testing.T) {
	got, err := Leader(5, 4)
	if err != nil || got != 1 {
		t.Fatalf("leader: %d %v", got, err)
	}
	if _, err := Leader(0, 5); err == nil {
		t.Fatal("accepted n that is not 3f+1")
	}
	if _, err := Leader(0, 3); err == nil {
		t.Fatal("accepted n below 4")
	}
}

func TestWithinSkew(t *testing.T) {
	cases := []struct {
		now, claimed, skew int64
		want               bool
	}{
		{0, 0, 0, true},
		{10, 12, 2, true},
		{10, 13, 2, false},
		{math.MaxInt64, math.MaxInt64, math.MaxInt64, true},
		{0, math.MinInt64, math.MaxInt64, false},
		{math.MinInt64, math.MaxInt64, math.MaxInt64, false},
		{5, 5, 0, true},
	}
	for _, tc := range cases {
		if got := withinSkew(tc.now, tc.claimed, tc.skew); got != tc.want {
			t.Fatalf("withinSkew(%d,%d,%d)=%v", tc.now, tc.claimed, tc.skew, got)
		}
	}
}

func TestHappyPathCommits(t *testing.T) {
	n := newNet(t, 4, 1_000, 40)
	n.drive(t, 80, nil)
	n.requireCommit(t, 1)
	n.requireAgreement(t)
}

func TestTimeoutPathCommits(t *testing.T) {
	n := newNet(t, 4, 1_000, 15)
	n.skipView = 1
	n.drive(t, 200, nil)
	n.requireCommit(t, 1)
	n.requireAgreement(t)
	for _, node := range n.nodes {
		if node.View() < 2 {
			t.Fatalf("view %d never left the discarded proposal", node.View())
		}
	}
}

func TestEventCommitsOnce(t *testing.T) {
	keys := testKeys(t, 4)
	g, block, qc, err := BuildGenesis(1_000, keys)
	if err != nil {
		t.Fatal(err)
	}
	sim := &net{
		nodes:   make([]*Replica, 4),
		timers:  make([]Timer, 4),
		armed:   make([]int64, 4),
		now:     1_000,
		base:    40,
		commits: make([]map[uint64][crypto.DigestSize]byte, 4),
		voted:   map[voteKey][crypto.DigestSize]byte{},
	}
	for i := range sim.nodes {
		sim.commits[i] = map[uint64][crypto.DigestSize]byte{}
		sim.nodes[i] = newReplica(t, i, keys, g, block, qc)
		out, err := sim.nodes[i].Start(sim.now)
		if err != nil {
			t.Fatal(err)
		}
		sim.take(i, out)
	}
	ev, _ := signedEvent(t, g, keys[0])
	id, err := ev.ID()
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range sim.nodes {
		if err := node.Submit([]types.Event{ev}); err != nil {
			t.Fatal(err)
		}
	}
	sim.driveUntil(t, 800, nil, func() bool {
		for _, node := range sim.nodes {
			if countEvent(node, id) != 1 {
				return false
			}
		}
		return true
	})
	for i, node := range sim.nodes {
		if got := countEvent(node, id); got != 1 {
			t.Fatalf("node %d committed the event %d times", i, got)
		}
	}
	parent, ok, err := sim.nodes[0].store.GetBlock(sim.nodes[0].commitHash)
	if err != nil || !ok {
		t.Fatalf("commit block: %v %v", ok, err)
	}
	fresh, err := sim.nodes[0].eventsFresh(parent, []types.Event{ev}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fresh {
		t.Fatal("a committed event was treated as fresh")
	}
}

func countEvent(r *Replica, id [crypto.DigestSize]byte) int {
	hash := r.commitHash
	n := 0
	for range 1 << 12 {
		block, ok, err := r.store.GetBlock(hash)
		if err != nil || !ok {
			return -1
		}
		for _, ev := range block.Events {
			got, err := ev.ID()
			if err != nil {
				return -1
			}
			if got == id {
				n++
			}
		}
		if block.Header.Height == 0 {
			return n
		}
		hash = block.Header.ParentHash
	}
	return -1
}

func TestSubmitCarriesEvent(t *testing.T) {
	keys := testKeys(t, 4)
	g, block, qc, err := BuildGenesis(1_000, keys)
	if err != nil {
		t.Fatal(err)
	}
	leader := 1
	r := newReplica(t, leader, keys, g, block, qc)
	ev, writer := signedEvent(t, g, keys[0])
	if err := r.Submit([]types.Event{ev}); err != nil {
		t.Fatal(err)
	}
	out, err := r.Start(1_000)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, m := range out.Messages {
		if m.Proposal == nil {
			continue
		}
		if len(m.Proposal.Block.Events) != 1 {
			t.Fatalf("events: %d", len(m.Proposal.Block.Events))
		}
		if err := m.Proposal.Block.Events[0].Verify(writer); err != nil {
			t.Fatal(err)
		}
		found = true
	}
	if !found {
		t.Fatal("leader did not propose the queued event")
	}
}

func TestSkewDropsProposal(t *testing.T) {
	keys := testKeys(t, 4)
	g, block, qc, err := BuildGenesis(50, keys)
	if err != nil {
		t.Fatal(err)
	}
	leader := newReplica(t, 1, keys, g, block, qc)
	out, err := leader.Start(50)
	if err != nil {
		t.Fatal(err)
	}
	var prop *types.Proposal
	for _, m := range out.Messages {
		if m.Proposal != nil {
			prop = m.Proposal
		}
	}
	if prop == nil {
		t.Fatal("no proposal")
	}
	bad := *prop
	bad.Block.Header.ProposerTime = 50 + 1_000
	if err := bad.Block.Sign(keys[1]); err != nil {
		t.Fatal(err)
	}
	cfg := testCfg(40)
	cfg.Skew = 10
	follower, err := Init(0, keys[0], g, block, qc, cfg, NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := follower.Start(50); err != nil {
		t.Fatal(err)
	}
	got, err := follower.Step(Input{Now: 50, Proposal: &bad})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Dropped {
		t.Fatal("skewed proposal was accepted")
	}
	for _, m := range got.Messages {
		if m.Vote != nil {
			t.Fatal("voted for a skewed proposal")
		}
	}
}

func TestStateRootMustLink(t *testing.T) {
	keys := testKeys(t, 4)
	g, block, qc, err := BuildGenesis(50, keys)
	if err != nil {
		t.Fatal(err)
	}
	leader := newReplica(t, 1, keys, g, block, qc)
	out, err := leader.Start(50)
	if err != nil {
		t.Fatal(err)
	}
	var prop *types.Proposal
	for _, m := range out.Messages {
		if m.Proposal != nil {
			prop = m.Proposal
		}
	}
	if prop == nil {
		t.Fatal("no proposal")
	}
	bad := *prop
	bad.Block.Header.StateRoot[0] ^= 1
	if err := bad.Block.Sign(keys[1]); err != nil {
		t.Fatal(err)
	}
	follower := newReplica(t, 0, keys, g, block, qc)
	if _, err := follower.Start(50); err != nil {
		t.Fatal(err)
	}
	got, err := follower.Step(Input{Now: 50, Proposal: &bad})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Dropped || votesOf(got) != 0 {
		t.Fatal("a broken state root was voted for")
	}
}

func TestVoteEquivocation(t *testing.T) {
	keys := testKeys(t, 4)
	g, block, qc, err := BuildGenesis(50, keys)
	if err != nil {
		t.Fatal(err)
	}
	r := newReplica(t, 2, keys, g, block, qc)
	if _, err := r.Start(50); err != nil {
		t.Fatal(err)
	}
	chain, err := g.ChainID()
	if err != nil {
		t.Fatal(err)
	}
	var a, b [crypto.DigestSize]byte
	a[0] = 1
	b[0] = 2
	first := types.Vote{ChainID: chain, View: 1, BlockHash: a, Signer: 0}
	second := types.Vote{ChainID: chain, View: 1, BlockHash: b, Signer: 0}
	if err := first.Sign(keys[0]); err != nil {
		t.Fatal(err)
	}
	if err := second.Sign(keys[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Step(Input{Now: 50, Vote: &first}); err != nil {
		t.Fatal(err)
	}
	got, err := r.Step(Input{Now: 50, Vote: &second})
	if err != nil {
		t.Fatal(err)
	}
	var proof *types.Equivocation
	for _, m := range got.Messages {
		if m.Evidence != nil {
			proof = m.Evidence
		}
	}
	if proof == nil {
		t.Fatal("no equivocation proof")
	}
	if err := proof.Verify(g.Validators().Keys); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRefusesSecondVote(t *testing.T) {
	keys := testKeys(t, 4)
	g, block, qc, err := BuildGenesis(1_000, keys)
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryStore()
	r, err := Init(0, keys[0], g, block, qc, testCfg(20), store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Start(1_000); err != nil {
		t.Fatal(err)
	}
	// A proposal replica 0 would vote for, built as if it extended genesis.
	prop := proposalFrom(t, keys, g, block, qc, 1, 1_000)
	first, err := r.Step(Input{Now: 1_000, Proposal: &prop})
	if err != nil {
		t.Fatal(err)
	}
	if votesOf(first) != 1 {
		t.Fatalf("votes: %d", votesOf(first))
	}
	again, err := Load(0, keys[0], g, testCfg(20), store)
	if err != nil {
		t.Fatal(err)
	}
	second, err := again.Step(Input{Now: 1_000, Proposal: &prop})
	if err != nil {
		t.Fatal(err)
	}
	if votesOf(second) != 0 {
		t.Fatal("restarted replica voted twice")
	}
}

type net struct {
	nodes    []*Replica
	timers   []Timer
	armed    []int64
	queue    []packet
	now      int64
	base     uint64
	skipView uint64
	commits  []map[uint64][crypto.DigestSize]byte
	voted    map[voteKey][crypto.DigestSize]byte
}

type packet struct {
	to  int
	msg Outbound
	at  int64
}

type voteKey struct {
	signer uint8
	view   uint64
}

func newNet(t *testing.T, n int, now int64, base uint64) *net {
	t.Helper()
	keys := testKeys(t, n)
	g, block, qc, err := BuildGenesis(now, keys)
	if err != nil {
		t.Fatal(err)
	}
	net := &net{
		nodes:   make([]*Replica, n),
		timers:  make([]Timer, n),
		armed:   make([]int64, n),
		now:     now,
		base:    base,
		commits: make([]map[uint64][crypto.DigestSize]byte, n),
		voted:   map[voteKey][crypto.DigestSize]byte{},
	}
	for i := range n {
		net.commits[i] = map[uint64][crypto.DigestSize]byte{}
		net.nodes[i] = newReplica(t, i, keys, g, block, qc)
		out, err := net.nodes[i].Start(now)
		if err != nil {
			t.Fatal(err)
		}
		net.take(i, out)
	}
	return net
}

func (n *net) drive(t *testing.T, limit int, hook func(int, Output)) {
	t.Helper()
	n.driveUntil(t, limit, hook, func() bool { return n.allCommitted(1) })
}

func (n *net) driveUntil(t *testing.T, limit int, hook func(int, Output), stop func() bool) {
	t.Helper()
	for step := 0; step < limit; step++ {
		if stop() {
			return
		}
		n.now++
		due, rest := n.split()
		n.queue = rest
		for _, p := range due {
			if n.skip(p.msg) {
				continue
			}
			out, err := n.nodes[p.to].Step(inputOf(p.msg, n.now))
			if err != nil {
				t.Fatalf("deliver to %d: %v", p.to, err)
			}
			n.observe(t, p.to, out)
			n.take(p.to, out)
			if hook != nil {
				hook(p.to, out)
			}
		}
		for i, node := range n.nodes {
			tm := n.timers[i]
			if tm.After == 0 || node.View() != tm.View || n.now < n.armed[i]+int64(tm.After) {
				continue
			}
			n.timers[i] = Timer{}
			out, err := node.Step(Input{Now: n.now, Timeout: true})
			if err != nil {
				t.Fatalf("timeout %d: %v", i, err)
			}
			n.observe(t, i, out)
			n.take(i, out)
		}
	}
}

func (n *net) take(i int, out Output) {
	for _, m := range out.Messages {
		n.queue = append(n.queue, packet{to: m.To, msg: m, at: n.now + 1})
	}
	if out.Timer.After != 0 {
		n.timers[i] = out.Timer
		n.armed[i] = n.now
	}
	for _, c := range out.Commits {
		n.commits[i][c.Height] = c.Hash
	}
}

func (n *net) split() (due, rest []packet) {
	for _, p := range n.queue {
		if p.at <= n.now {
			due = append(due, p)
		} else {
			rest = append(rest, p)
		}
	}
	return due, rest
}

func (n *net) skip(m Outbound) bool {
	return n.skipView != 0 && m.Proposal != nil && m.Proposal.Block.Header.View == n.skipView
}

func (n *net) observe(t *testing.T, node int, out Output) {
	t.Helper()
	for _, m := range out.Messages {
		if m.Vote == nil {
			continue
		}
		key := voteKey{signer: m.Vote.Signer, view: m.Vote.View}
		if prev, ok := n.voted[key]; ok && prev != m.Vote.BlockHash {
			t.Fatalf("node %d double vote view %d", node, m.Vote.View)
		}
		if _, ok := n.voted[key]; ok {
			t.Fatalf("node %d repeated a vote in view %d", node, m.Vote.View)
		}
		n.voted[key] = m.Vote.BlockHash
	}
	for _, c := range out.Commits {
		if prev, ok := n.commits[node][c.Height]; ok && prev != c.Hash {
			t.Fatalf("node %d recommitted height %d", node, c.Height)
		}
	}
}

func (n *net) allCommitted(height uint64) bool {
	for _, node := range n.nodes {
		if node.CommitHeight() < height {
			return false
		}
	}
	return true
}

func (n *net) requireCommit(t *testing.T, height uint64) {
	t.Helper()
	if !n.allCommitted(height) {
		for i, node := range n.nodes {
			t.Logf("node %d view %d commit %d", i, node.View(), node.CommitHeight())
		}
		t.Fatalf("commit height %d not reached at tick %d, queue %d", height, n.now, len(n.queue))
	}
}

func (n *net) requireAgreement(t *testing.T) {
	t.Helper()
	for height := uint64(1); height <= n.nodes[0].CommitHeight(); height++ {
		want, ok := n.commits[0][height]
		if !ok {
			want = n.nodes[0].CommitHash()
			if height != n.nodes[0].CommitHeight() {
				t.Fatalf("missing commit record at height %d", height)
			}
		}
		for i, node := range n.nodes {
			got, ok := n.commits[i][height]
			if !ok {
				t.Fatalf("node %d has no commit at height %d", i, height)
			}
			if got != want || node.CommitHash() == ([crypto.DigestSize]byte{}) {
				t.Fatalf("node %d disagrees at height %d", i, height)
			}
		}
	}
	first := n.nodes[0].CommitHash()
	for i, node := range n.nodes {
		if node.CommitHash() != first {
			t.Fatalf("node %d commit hash differs", i)
		}
	}
}

func inputOf(m Outbound, now int64) Input {
	in := Input{Now: now}
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

func votesOf(out Output) int {
	n := 0
	for _, m := range out.Messages {
		if m.Vote != nil {
			n++
		}
	}
	return n
}

func testCfg(base uint64) Config {
	return Config{BaseTimeout: base, MaxTimeout: base * 8, Skew: 1_000_000}
}

func testKeys(t *testing.T, n int) []crypto.PrivateKey {
	t.Helper()
	keys := make([]crypto.PrivateKey, n)
	for i := range keys {
		k, err := crypto.GenerateMLDSA65()
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = k
	}
	return keys
}

func newReplica(t *testing.T, index int, keys []crypto.PrivateKey, g types.Genesis, block types.Block, qc types.QC) *Replica {
	t.Helper()
	r, err := Init(index, keys[index], g, block, qc, testCfg(40), NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func signedEvent(t *testing.T, g types.Genesis, writer crypto.PrivateKey) (types.Event, crypto.PublicKey) {
	t.Helper()
	pub, err := writer.Public()
	if err != nil {
		t.Fatal(err)
	}
	id, err := pub.ID()
	if err != nil {
		t.Fatal(err)
	}
	chain, err := g.ChainID()
	if err != nil {
		t.Fatal(err)
	}
	var doc [crypto.DigestSize]byte
	doc[0] = 9
	ev := types.Event{
		ChainID:     chain,
		EventType:   types.EventShipmentDispatched,
		Subject:     []byte("crate-7"),
		Status:      1,
		DocHashes:   []types.DocHash{types.SHA3Doc(doc)},
		ClaimedTime: 1_000,
		WriterID:    id,
		Nonce:       1,
		ReadPolicy:  types.ReadAllMembers,
	}
	if err := ev.Sign(writer); err != nil {
		t.Fatal(err)
	}
	return ev, pub
}

func proposalFrom(t *testing.T, keys []crypto.PrivateKey, g types.Genesis, parent types.Block, justify types.QC, view uint64, now int64) types.Proposal {
	t.Helper()
	leader := int(view % uint64(len(keys)))
	r := newReplica(t, leader, keys, g, parent, justify)
	// Force the replica into the view by starting only when view is 1.
	if view != 1 {
		t.Fatal("test helper only builds view 1")
	}
	out, err := r.Start(now)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range out.Messages {
		if m.Proposal != nil {
			return *m.Proposal
		}
	}
	t.Fatal("no proposal")
	return types.Proposal{}
}
