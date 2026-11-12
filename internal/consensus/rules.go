package consensus

import (
	"fmt"
	"slices"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/merkle"
	"github.com/silvergreyhound/silver-grey-ledger/internal/state"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

func (r *Replica) onTimer(now int64) (Output, error) {
	if !r.canSign() {
		return Output{}, nil
	}
	// One signature per view. A later firing sends those same bytes again.
	// The first round is not a delivery: a userspace bridge that sheds
	// frames, or a connection that dies after the write is accepted, drops
	// it. Without another send the view stays put, because nothing rearms
	// the timer, and a committed event never reaches the next leader.
	retry := Timer{View: r.view, After: r.pace.Duration(r.pCfg)}
	if !r.pace.MarkSent(r.view) {
		signed, ok := r.pace.Signed(r.view, uint8(r.index))
		if !ok {
			return Output{}, nil
		}
		return Output{
			Timer: retry,
			Messages: r.fanout(func(i int) Outbound {
				return Outbound{To: i, Timeout: &signed}
			}),
		}, nil
	}
	to := types.Timeout{
		ChainID: r.chain,
		View:    r.view,
		Signer:  uint8(r.index),
		HighQC:  r.lockQC,
	}
	if err := to.Sign(r.key); err != nil {
		return Output{}, err
	}
	out, err := r.addTimeout(to, now)
	if err != nil {
		return Output{}, err
	}
	out.Messages = append(r.fanout(func(i int) Outbound {
		return Outbound{To: i, Timeout: &to}
	}), out.Messages...)
	if out.Timer.After == 0 {
		out.Timer = retry
	}
	return out, nil
}

func (r *Replica) onTimeout(t types.Timeout, now int64) (Output, error) {
	if t.ChainID != r.chain || int(t.Signer) >= len(r.pubs) {
		return Output{Dropped: true}, nil
	}
	if err := t.Verify(r.pubs); err != nil {
		return Output{Dropped: true}, nil
	}
	return r.addTimeout(t, now)
}

func (r *Replica) addTimeout(t types.Timeout, now int64) (Output, error) {
	tc, conflict, err := r.pace.Add(t, len(r.pubs))
	if err != nil {
		return Output{}, err
	}
	var out Output
	if conflict != nil {
		ev, err := evidencePair(types.EquivocationTimeout, *conflict, t)
		if err != nil {
			return Output{}, err
		}
		msgs, err := r.takeEvidence(ev)
		if err != nil {
			return Output{}, err
		}
		out.Messages = append(out.Messages, msgs...)
	}
	if tc == nil {
		return out, nil
	}
	accepted, err := r.acceptTC(*tc, now)
	if err != nil {
		return Output{}, err
	}
	merge(&out, accepted)
	return out, nil
}

func (r *Replica) onTC(tc types.TC, now int64) (Output, error) {
	if err := tc.Verify(r.pubs); err != nil {
		return Output{Dropped: true}, nil
	}
	return r.acceptTC(tc, now)
}

func (r *Replica) acceptTC(tc types.TC, now int64) (Output, error) {
	var out Output
	for _, to := range tc.Timeouts {
		if to.HighQC.IsEmpty() {
			continue
		}
		part, err := r.adoptQC(to.HighQC)
		if err != nil {
			return Output{}, err
		}
		merge(&out, part)
	}
	if tc.View+1 > r.view {
		entered, err := r.enter(tc.View+1, false, &tc, now)
		if err != nil {
			return Output{}, err
		}
		merge(&out, entered)
	}
	if _, ok := r.relayed[tc.View]; !ok {
		r.relayed[tc.View] = struct{}{}
		out.Messages = append(out.Messages, r.fanout(func(i int) Outbound {
			return Outbound{To: i, TC: &tc}
		})...)
	}
	return out, nil
}

func (r *Replica) onVote(v types.Vote, now int64) (Output, error) {
	if v.ChainID != r.chain || v.Signer >= uint8(types.MaxValidators) {
		return Output{Dropped: true}, nil
	}
	if int(v.Signer) >= len(r.pubs) || v.Verify(r.pubs) != nil {
		r.holdVote(v)
		return Output{Dropped: true}, nil
	}
	live, err := r.signerLive(int(v.Signer))
	if err != nil {
		return Output{}, err
	}
	if !live {
		return Output{Dropped: true}, nil
	}
	extra, err := r.noteVote(v)
	if err != nil {
		return Output{}, err
	}
	var out Output
	out.Messages = extra
	if r.leader(v.View+1) != r.index || r.view > v.View+1 {
		return out, nil
	}
	assembled, err := r.tryAssemble(v.View, v.BlockHash, now)
	if err != nil {
		return Output{}, err
	}
	merge(&out, assembled)
	return out, nil
}

func (r *Replica) onProposal(p types.Proposal, now int64) (Output, error) {
	var out Output
	if !r.proposalShape(p) {
		out.Dropped = true
		return out, nil
	}
	ev, err := r.noteProposal(p)
	if err != nil {
		return Output{}, err
	}
	out.Messages = append(out.Messages, ev...)
	if !withinSkew(now, p.Block.Header.ProposerTime, r.cfg.Skew) {
		out.Dropped = true
		return out, nil
	}
	parent, ok, err := r.linkedParent(p.Block)
	if err != nil {
		return Output{}, err
	}
	if !ok {
		out.Dropped = true
		return out, nil
	}
	led, err := r.ledgerAt(p.Block.Header.ParentHash)
	if err != nil {
		out.Dropped = true
		return out, nil
	}
	if _, err := led.Apply(p.Block); err != nil {
		out.Dropped = true
		return out, nil
	}
	child, err := led.VotersForChild(p.Block.Header.Height)
	if err != nil {
		out.Dropped = true
		return out, nil
	}
	r.adoptKeys(child)
	fresh, err := r.eventsFresh(parent, p.Block.Events, p.Block.Gov)
	if err != nil {
		return Output{}, err
	}
	if !fresh {
		out.Dropped = true
		return out, nil
	}
	if err := r.putBlock(p.Block); err != nil {
		return Output{}, err
	}
	adopted, err := r.adoptQC(p.Block.Header.Justify)
	if err != nil {
		return Output{}, err
	}
	merge(&out, adopted)
	if p.Block.Header.View > r.view {
		viaQC := p.Block.Header.View == p.Block.Header.Justify.View+1
		var tc *types.TC
		if !viaQC {
			tc = &p.TC
		}
		entered, err := r.enter(p.Block.Header.View, viaQC, tc, now)
		if err != nil {
			return Output{}, err
		}
		merge(&out, entered)
	}
	if p.Block.Header.View == r.view {
		voted, err := r.castVote(p.Block, now)
		if err != nil {
			return Output{}, err
		}
		merge(&out, voted)
	}
	// Votes for this block may already be waiting with the next leader.
	if r.leader(p.Block.Header.View+1) == r.index {
		hash, err := p.Block.Header.Hash()
		if err != nil {
			return Output{}, err
		}
		assembled, err := r.tryAssemble(p.Block.Header.View, hash, now)
		if err != nil {
			return Output{}, err
		}
		merge(&out, assembled)
	}
	return out, nil
}

func (r *Replica) onEvidence(e types.Equivocation) (Output, error) {
	if err := e.Verify(r.pubs); err != nil {
		return Output{Dropped: true}, nil
	}
	return r.relayEvidence(e)
}

func (r *Replica) enter(view uint64, viaQC bool, tc *types.TC, now int64) (Output, error) {
	if view < r.view {
		return Output{}, nil
	}
	var out Output
	if view > r.view {
		r.view = view
		r.pace.NoteEnter(viaQC)
		r.pace.ForgetBefore(view)
		r.prune(view)
		out.Timer = Timer{View: r.view, After: r.pace.Duration(r.pCfg)}
	}
	if err := r.adoptLock(); err != nil {
		return Output{}, err
	}
	drained, err := r.drainPending(now)
	if err != nil {
		return Output{}, err
	}
	merge(&out, drained)
	if r.leader(r.view) != r.index || !r.canSign() {
		return out, nil
	}
	proposed, err := r.propose(now, tc)
	if err != nil {
		return Output{}, err
	}
	merge(&out, proposed)
	return out, nil
}

func (r *Replica) propose(now int64, tc *types.TC) (Output, error) {
	if _, ok := r.proposed[r.view]; ok {
		return Output{}, nil
	}
	justify := r.lockQC
	if tc != nil && !tc.IsEmpty() {
		hi, err := tc.HighestQC()
		if err != nil {
			return Output{}, nil
		}
		if qcPreferred(hi, justify) {
			if _, ok, err := r.getBlock(hi.BlockHash); err != nil {
				return Output{}, err
			} else if ok {
				justify = hi
			}
		}
	}
	var attach types.TC
	if r.view != justify.View+1 {
		if tc == nil || tc.IsEmpty() {
			return Output{}, nil
		}
		attach = *tc
	}
	parent, ok, err := r.getBlock(justify.BlockHash)
	if err != nil || !ok {
		return Output{}, err
	}
	parentHash, err := parent.Header.Hash()
	if err != nil {
		return Output{}, err
	}
	parentLed, err := r.ledgerAt(parentHash)
	if err != nil {
		return Output{}, nil
	}
	child, err := parentLed.VotersForChild(parent.Header.Height + 1)
	if err != nil {
		return Output{}, nil
	}
	r.adoptKeys(child)
	if r.leader(r.view) != r.index || !r.canSign() {
		return Output{}, nil
	}
	evs, govs, err := r.selectBatch(parent)
	if err != nil {
		return Output{}, err
	}
	block, err := r.build(parent, justify, evs, govs, now)
	if err != nil {
		return Output{}, err
	}
	if err := r.putBlock(block); err != nil {
		return Output{}, err
	}
	hash, err := block.Header.Hash()
	if err != nil {
		return Output{}, err
	}
	r.proposed[r.view] = hash
	proposal := types.Proposal{Block: block, TC: attach}
	out := Output{Messages: r.fanout(func(i int) Outbound {
		return Outbound{To: i, Proposal: &proposal}
	})}
	voted, err := r.castVote(block, now)
	if err != nil {
		return Output{}, err
	}
	merge(&out, voted)
	return out, nil
}

func (r *Replica) build(parent types.Block, justify types.QC, evs []types.Event, govs []types.GovTx, now int64) (types.Block, error) {
	parentHash, err := parent.Header.Hash()
	if err != nil {
		return types.Block{}, err
	}
	ids := make([][crypto.DigestSize]byte, len(evs))
	for i, ev := range evs {
		id, err := ev.ID()
		if err != nil {
			return types.Block{}, err
		}
		ids[i] = id
	}
	root, err := merkle.Root(ids)
	if err != nil {
		return types.Block{}, err
	}
	led, err := r.ledgerAt(parentHash)
	if err != nil {
		return types.Block{}, err
	}
	next, err := led.Transition(parent.Header.Height+1, evs, govs)
	if err != nil {
		return types.Block{}, err
	}
	if !r.canSign() {
		return types.Block{}, fmt.Errorf("consensus: leader key: %w", ErrState)
	}
	block := types.Block{
		Header: types.BlockHeader{
			ChainID:      r.chain,
			Height:       parent.Header.Height + 1,
			View:         r.view,
			ParentHash:   parentHash,
			Justify:      justify,
			EventsRoot:   root,
			StateRoot:    next.Root(),
			ProposerID:   r.ids[r.index],
			ProposerTime: now,
		},
		Events: evs,
		Gov:    govs,
	}
	if err := block.Sign(r.key); err != nil {
		return types.Block{}, err
	}
	return block, nil
}

func (r *Replica) castVote(block types.Block, now int64) (Output, error) {
	hash, err := block.Header.Hash()
	if err != nil {
		return Output{}, err
	}
	if block.Header.View != r.view || !r.canSign() {
		return Output{}, nil
	}
	if _, ok := r.voted[r.view]; ok {
		return Output{}, nil
	}
	if !r.safe(block) {
		return Output{}, nil
	}
	vote := types.Vote{
		ChainID:   r.chain,
		View:      r.view,
		BlockHash: hash,
		Signer:    uint8(r.index),
	}
	if err := vote.Sign(r.key); err != nil {
		return Output{}, err
	}
	r.voted[r.view] = hash
	if r.leader(r.view+1) == r.index {
		return r.onVote(vote, now)
	}
	return Output{Messages: []Outbound{{To: r.leader(r.view + 1), Vote: &vote}}}, nil
}

func (r *Replica) tryAssemble(view uint64, hash [crypto.DigestSize]byte, now int64) (Output, error) {
	if _, ok, err := r.getBlock(hash); err != nil || !ok {
		return Output{}, err
	}
	qc, ok := r.collect(view, hash)
	if !ok {
		return Output{}, nil
	}
	out, err := r.adoptQC(qc)
	if err != nil {
		return Output{}, err
	}
	if r.view <= view {
		entered, err := r.enter(view+1, true, nil, now)
		if err != nil {
			return Output{}, err
		}
		merge(&out, entered)
	}
	return out, nil
}

func (r *Replica) collect(view uint64, hash [crypto.DigestSize]byte) (types.QC, bool) {
	votes := r.seenVote[view]
	block, ok, err := r.getBlock(hash)
	if err != nil || !ok {
		return types.QC{}, false
	}
	parentLed, err := r.ledgerAt(block.Header.ParentHash)
	if err != nil {
		return types.QC{}, false
	}
	keys, err := parentLed.VotersForChild(block.Header.Height)
	if err != nil {
		return types.QC{}, false
	}
	need, err := types.Quorum(len(keys))
	if err != nil {
		return types.QC{}, false
	}
	signers := make([]int, 0, len(votes))
	for s, v := range votes {
		if v.BlockHash == hash && int(v.Signer) == int(s) {
			signers = append(signers, int(s))
		}
	}
	if len(signers) < need {
		return types.QC{}, false
	}
	slices.Sort(signers)
	qc := types.QC{View: view, BlockHash: hash}
	for _, s := range signers {
		qc.SignerBitmap |= 1 << uint(s)
		qc.Signatures = append(qc.Signatures, append([]byte(nil), votes[uint8(s)].Signature...))
	}
	if err := qc.Verify(r.chain, keys); err != nil {
		return types.QC{}, false
	}
	return qc, true
}

func (r *Replica) adoptQC(qc types.QC) (Output, error) {
	if qc.IsEmpty() {
		return Output{}, nil
	}
	block, ok, err := r.getBlock(qc.BlockHash)
	if err != nil || !ok {
		return Output{}, err
	}
	hash, err := block.Header.Hash()
	if err != nil {
		return Output{}, err
	}
	if hash != qc.BlockHash || block.Header.View != qc.View {
		return Output{}, nil
	}
	if qc.View == r.lockQC.View && qc.BlockHash != r.lockQC.BlockHash && !r.lockQC.IsEmpty() {
		return Output{}, nil
	}
	if qcPreferred(qc, r.lockQC) {
		r.lockQC = qc
		r.lockHash = qc.BlockHash
	}
	commits, err := r.maybeCommit(block)
	if err != nil {
		return Output{}, err
	}
	return Output{Commits: commits}, nil
}

func (r *Replica) maybeCommit(certified types.Block) ([]Commit, error) {
	parent, ok, err := r.parentOf(certified)
	if err != nil || !ok {
		return nil, err
	}
	if certified.Header.View != parent.Header.View+1 {
		return nil, nil
	}
	return r.commitThrough(parent)
}

func (r *Replica) commitThrough(block types.Block) ([]Commit, error) {
	var chain []types.Block
	cur := block
	connected := false
	for {
		hash, err := cur.Header.Hash()
		if err != nil {
			return nil, err
		}
		if hash == r.commitHash {
			connected = true
			break
		}
		chain = append(chain, cur)
		if cur.Header.Height == 0 || len(chain) > len(r.blocks)+1 {
			break
		}
		parent, ok, err := r.parentOf(cur)
		if err != nil || !ok {
			return nil, err
		}
		cur = parent
	}
	if !connected {
		return nil, nil
	}
	commits := make([]Commit, 0, len(chain))
	for i := len(chain) - 1; i >= 0; i-- {
		hash, err := chain[i].Header.Hash()
		if err != nil {
			return nil, err
		}
		r.commitH = chain[i].Header.Height
		r.commitHash = hash
		commits = append(commits, Commit{Height: r.commitH, View: chain[i].Header.View, Hash: hash})
	}
	return commits, nil
}

func (r *Replica) safe(b types.Block) bool {
	if r.extends(b) {
		return true
	}
	return b.Header.Justify.View > r.lockQC.View
}

func (r *Replica) extends(b types.Block) bool {
	cur := b
	for range len(r.blocks) + 1 {
		hash, err := cur.Header.Hash()
		if err != nil {
			return false
		}
		if hash == r.lockHash {
			return true
		}
		if cur.Header.Height == 0 {
			return false
		}
		parent, ok, err := r.parentOf(cur)
		if err != nil || !ok {
			return false
		}
		cur = parent
	}
	return false
}

func (r *Replica) proposalShape(p types.Proposal) bool {
	h := p.Block.Header
	if h.ChainID != r.chain || h.Height == 0 || h.View == 0 {
		return false
	}
	led, err := r.ledgerAt(h.ParentHash)
	if err != nil {
		return false
	}
	parentKeys, err := led.ValidatorKeys()
	if err != nil || h.Justify.Verify(r.chain, parentKeys) != nil {
		return false
	}
	child, err := led.VotersForChild(h.Height)
	if err != nil || len(child) == 0 {
		return false
	}
	leader := int(h.View % uint64(len(child)))
	if leader < 0 || leader >= len(child) {
		return false
	}
	id, err := child[leader].ID()
	if err != nil || id != h.ProposerID {
		return false
	}
	if err := p.Block.VerifyProposer(child[leader]); err != nil {
		return false
	}
	consecutive := h.View == h.Justify.View+1
	if consecutive {
		return p.TC.IsEmpty()
	}
	if p.TC.IsEmpty() || p.TC.View+1 != h.View {
		return false
	}
	if err := p.TC.Verify(child); err != nil {
		if err := p.TC.Verify(parentKeys); err != nil {
			return false
		}
	}
	hi, err := p.TC.HighestQC()
	if err != nil {
		return false
	}
	return covers(h.Justify, hi)
}

func covers(justify, highest types.QC) bool {
	if highest.IsEmpty() {
		return true
	}
	if justify.IsEmpty() {
		return false
	}
	if justify.View > highest.View {
		return true
	}
	return justify.View == highest.View && justify.BlockHash == highest.BlockHash
}

func (r *Replica) linkedParent(b types.Block) (types.Block, bool, error) {
	parent, ok, err := r.getBlock(b.Header.ParentHash)
	if err != nil || !ok {
		return types.Block{}, false, err
	}
	ph, err := parent.Header.Hash()
	if err != nil {
		return types.Block{}, false, err
	}
	if ph != b.Header.Justify.BlockHash || parent.Header.View != b.Header.Justify.View {
		return types.Block{}, false, nil
	}
	if parent.Header.Height+1 != b.Header.Height {
		return types.Block{}, false, nil
	}
	return parent, true, nil
}

func (r *Replica) parentOf(b types.Block) (types.Block, bool, error) {
	if b.Header.Height == 0 {
		return types.Block{}, false, nil
	}
	parent, ok, err := r.getBlock(b.Header.ParentHash)
	if err != nil || !ok {
		return types.Block{}, false, err
	}
	if parent.Header.Height+1 != b.Header.Height {
		return types.Block{}, false, nil
	}
	return parent, true, nil
}

func (r *Replica) noteVote(v types.Vote) ([]Outbound, error) {
	m := r.seenVote[v.View]
	if m == nil {
		m = map[uint8]types.Vote{}
		r.seenVote[v.View] = m
	}
	prev, ok := m[v.Signer]
	if !ok {
		cp := v
		cp.Signature = append([]byte(nil), v.Signature...)
		m[v.Signer] = cp
		return nil, nil
	}
	if prev.BlockHash == v.BlockHash {
		return nil, nil
	}
	ev, err := evidencePair(types.EquivocationVote, prev, v)
	if err != nil {
		return nil, err
	}
	return r.takeEvidence(ev)
}

func (r *Replica) noteProposal(p types.Proposal) ([]Outbound, error) {
	raw, err := p.MarshalBinary()
	if err != nil {
		return nil, err
	}
	hash, err := p.Block.Header.Hash()
	if err != nil {
		return nil, err
	}
	m := r.seenProp[p.Block.Header.View]
	if m == nil {
		m = map[[crypto.DigestSize]byte]seenProposal{}
		r.seenProp[p.Block.Header.View] = m
	}
	id := p.Block.Header.ProposerID
	prev, ok := m[id]
	if !ok {
		m[id] = seenProposal{raw: raw, hash: hash}
		return nil, nil
	}
	if prev.hash == hash {
		return nil, nil
	}
	ev := types.Equivocation{Kind: types.EquivocationProposal, First: prev.raw, Second: raw}
	return r.takeEvidence(ev)
}

func (r *Replica) takeEvidence(e types.Equivocation) ([]Outbound, error) {
	if err := e.Verify(r.pubs); err != nil {
		return nil, fmt.Errorf("consensus: evidence: %w", err)
	}
	out, err := r.relayEvidence(e)
	if err != nil {
		return nil, err
	}
	return out.Messages, nil
}

func (r *Replica) relayEvidence(e types.Equivocation) (Output, error) {
	raw, err := e.MarshalBinary()
	if err != nil {
		return Output{}, err
	}
	sum := crypto.Sum256(raw)
	if _, ok := r.evidence[sum]; ok {
		return Output{}, nil
	}
	if len(r.evidence) >= maxEvidence {
		return Output{}, nil
	}
	r.evidence[sum] = struct{}{}
	ev := e
	return Output{Messages: r.fanout(func(i int) Outbound {
		return Outbound{To: i, Evidence: &ev}
	})}, nil
}

func (r *Replica) putBlock(b types.Block) error {
	hash, err := b.Header.Hash()
	if err != nil {
		return err
	}
	if err := r.store.PutBlock(b); err != nil {
		return wrapStore(err)
	}
	r.blocks[hash] = b
	return nil
}

func (r *Replica) getBlock(h [crypto.DigestSize]byte) (types.Block, bool, error) {
	if b, ok := r.blocks[h]; ok {
		return b, true, nil
	}
	b, ok, err := r.store.GetBlock(h)
	if err != nil {
		return types.Block{}, false, wrapStore(err)
	}
	if ok {
		r.blocks[h] = b
	}
	return b, ok, nil
}

// maxAncestorWalk stops a parent cycle from spinning. A chain that long
// is not a chain this process can certify, so the walk reports it incomplete.
const maxAncestorWalk = 1 << 20

// eventsFresh reports whether the body can extend parent. A repeated id,
// in the block or anywhere in its parent chain, is not fresh. An
// incomplete chain is not fresh either. An empty body is always fresh.
func (r *Replica) eventsFresh(parent types.Block, evs []types.Event, gov []types.GovTx) (bool, error) {
	if len(evs) == 0 && len(gov) == 0 {
		return true, nil
	}
	known, ok, err := r.ancestorIDs(parent)
	if err != nil || !ok {
		return false, err
	}
	seen := make(map[[crypto.DigestSize]byte]struct{}, len(evs)+len(gov))
	for _, ev := range evs {
		id, err := ev.ID()
		if err != nil {
			return false, nil
		}
		if _, dup := known[id]; dup {
			return false, nil
		}
		if _, dup := seen[id]; dup {
			return false, nil
		}
		seen[id] = struct{}{}
	}
	for _, tx := range gov {
		id, err := tx.ID()
		if err != nil {
			return false, nil
		}
		if _, dup := known[id]; dup {
			return false, nil
		}
		if _, dup := seen[id]; dup {
			return false, nil
		}
		seen[id] = struct{}{}
	}
	return true, nil
}

// selectBatch is the queue subset the parent ledger accepts at the next
// height. Items that fail permanently are dropped. Items that do not fit
// stay queued.
func (r *Replica) selectBatch(parent types.Block) ([]types.Event, []types.GovTx, error) {
	hash, err := parent.Header.Hash()
	if err != nil {
		return nil, nil, err
	}
	led, err := r.ledgerAt(hash)
	if err != nil {
		return nil, nil, err
	}
	height := parent.Header.Height + 1
	base, err := led.Prepare(height)
	if err != nil {
		return nil, nil, err
	}
	var evs []types.Event
	var rest []types.Event
	for _, ev := range r.queue {
		if len(evs) == types.MaxEventsPerBlock {
			rest = append(rest, ev)
			continue
		}
		trial := append(append([]types.Event(nil), evs...), ev)
		if _, err := base.Transition(height, trial, nil); err != nil {
			continue
		}
		evs = trial
	}
	var govs []types.GovTx
	var grest []types.GovTx
	for _, tx := range r.govQ {
		if len(govs) == types.MaxGovPerBlock {
			grest = append(grest, tx)
			continue
		}
		trial := append(append([]types.GovTx(nil), govs...), tx)
		if _, err := base.Transition(height, evs, trial); err != nil {
			continue
		}
		govs = trial
	}
	r.queue = rest
	r.govQ = grest
	return evs, govs, nil
}

func (r *Replica) ancestorIDs(tip types.Block) (map[[crypto.DigestSize]byte]struct{}, bool, error) {
	out := map[[crypto.DigestSize]byte]struct{}{}
	block := tip
	for range maxAncestorWalk {
		for _, ev := range block.Events {
			id, err := ev.ID()
			if err != nil {
				return nil, false, nil
			}
			out[id] = struct{}{}
		}
		for _, tx := range block.Gov {
			id, err := tx.ID()
			if err != nil {
				return nil, false, nil
			}
			out[id] = struct{}{}
		}
		if block.Header.Height == 0 {
			return out, true, nil
		}
		parent, ok, err := r.getBlock(block.Header.ParentHash)
		if err != nil {
			return nil, false, err
		}
		if !ok {
			return nil, false, nil
		}
		block = parent
	}
	return nil, false, nil
}

func (r *Replica) fanout(build func(i int) Outbound) []Outbound {
	out := make([]Outbound, 0, len(r.pubs)-1)
	for i := range r.pubs {
		if i == r.index {
			continue
		}
		out = append(out, build(i))
	}
	return out
}

func (r *Replica) ledgerAt(hash [crypto.DigestSize]byte) (*state.Ledger, error) {
	if s, ok := r.ledgers[hash]; ok {
		return s, nil
	}
	block, ok, err := r.getBlock(hash)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("consensus: missing block: %w", ErrState)
	}
	if block.Header.Height == 0 {
		if r.gen == nil || block.Header.StateRoot != r.gen.Root() {
			return nil, fmt.Errorf("consensus: genesis state: %w", ErrState)
		}
		r.ledgers[hash] = r.gen
		return r.gen, nil
	}
	parent, err := r.ledgerAt(block.Header.ParentHash)
	if err != nil {
		return nil, err
	}
	next, err := parent.Apply(block)
	if err != nil {
		return nil, err
	}
	r.ledgers[hash] = next
	return next, nil
}

func (r *Replica) remember(hash [crypto.DigestSize]byte) error {
	_, err := r.ledgerAt(hash)
	return err
}

func (r *Replica) adoptLock() error {
	block, ok, err := r.getBlock(r.lockHash)
	if err != nil || !ok {
		if err != nil {
			return err
		}
		return fmt.Errorf("consensus: missing lock: %w", ErrState)
	}
	led, err := r.ledgerAt(r.lockHash)
	if err != nil {
		return err
	}
	keys, err := led.VotersForChild(block.Header.Height + 1)
	if err != nil {
		return err
	}
	r.adoptKeys(keys)
	return nil
}

func (r *Replica) adoptKeys(keys []crypto.PublicKey) {
	r.pubs = append([]crypto.PublicKey(nil), keys...)
	r.ids = make([][crypto.DigestSize]byte, len(keys))
	for i, key := range keys {
		id, err := key.ID()
		if err != nil {
			r.ids[i] = [crypto.DigestSize]byte{}
			continue
		}
		r.ids[i] = id
	}
	r.index = -1
	pub, err := r.key.Public()
	if err != nil {
		return
	}
	for i, key := range keys {
		if key.Equal(pub) {
			r.index = i
			return
		}
	}
}

func (r *Replica) canSign() bool {
	if r.index < 0 || r.index >= len(r.pubs) {
		return false
	}
	pub, err := r.key.Public()
	if err != nil {
		return false
	}
	return r.pubs[r.index].Equal(pub)
}

func (r *Replica) signerLive(index int) (bool, error) {
	if index < 0 || index >= len(r.pubs) {
		return false, nil
	}
	block, ok, err := r.getBlock(r.lockHash)
	if err != nil || !ok {
		if err != nil {
			return false, err
		}
		return false, nil
	}
	led, err := r.ledgerAt(r.lockHash)
	if err != nil {
		return false, err
	}
	return led.SignerLive(block.Header.Height+1, index)
}

func (r *Replica) holdVote(v types.Vote) {
	if r.draining || len(r.pendingVotes) >= 64 {
		return
	}
	r.pendingVotes = append(r.pendingVotes, heldVote{vote: v})
}

func (r *Replica) drainPending(now int64) (Output, error) {
	if r.draining || len(r.pendingVotes) == 0 {
		return Output{}, nil
	}
	held := r.pendingVotes
	r.pendingVotes = nil
	r.draining = true
	defer func() { r.draining = false }()
	var out Output
	for _, item := range held {
		if int(item.vote.Signer) >= len(r.pubs) || item.vote.Verify(r.pubs) != nil {
			if item.tries < 8 && len(r.pendingVotes) < 64 {
				item.tries++
				r.pendingVotes = append(r.pendingVotes, item)
			}
			continue
		}
		got, err := r.onVote(item.vote, now)
		if err != nil {
			return Output{}, err
		}
		merge(&out, got)
	}
	return out, nil
}

func evidencePair(kind uint8, a, b any) (types.Equivocation, error) {
	first, err := marshalAny(a)
	if err != nil {
		return types.Equivocation{}, err
	}
	second, err := marshalAny(b)
	if err != nil {
		return types.Equivocation{}, err
	}
	return types.Equivocation{Kind: kind, First: first, Second: second}, nil
}

func marshalAny(v any) ([]byte, error) {
	switch m := v.(type) {
	case types.Vote:
		return m.MarshalBinary()
	case types.Timeout:
		return m.MarshalBinary()
	default:
		return nil, fmt.Errorf("consensus: evidence message: %w", ErrState)
	}
}
