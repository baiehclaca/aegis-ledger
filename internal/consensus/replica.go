package consensus

import (
	"fmt"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/pacemaker"
	"github.com/silvergreyhound/silver-grey-ledger/internal/state"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

// maxEvidence bounds stored proofs so a noisy network cannot grow the
// map without limit. Older proofs are still valid; we just stop keeping
// new ones after the cap.
const maxEvidence = 1024

// How many views of other replicas' votes and proposals are remembered.
// Our own votes are kept for the life of the snapshot: forgetting one
// would make a replayed proposal look new.
const retainViews = 64

// Config is the part of the protocol that is not the safety rule.
type Config struct {
	BaseTimeout uint64
	MaxTimeout  uint64
	// Skew is the largest absolute gap between a proposal's claimed
	// time and the time the caller passes in, before the proposal is
	// rejected. It is a sanity check. Safety does not depend on it.
	Skew int64
}

// Input is one event. Exactly one of the fields is set. Now is the
// caller's clock sample, in the same unit as proposal timestamps.
type Input struct {
	Now        int64
	Timeout    bool
	Proposal   *types.Proposal
	Vote       *types.Vote
	TimeoutMsg *types.Timeout
	TC         *types.TC
	Evidence   *types.Equivocation
}

// Outbound is one message for one validator. The replica expands a
// broadcast itself, so the caller does not guess who must hear it.
type Outbound struct {
	To       int
	Proposal *types.Proposal
	Vote     *types.Vote
	Timeout  *types.Timeout
	TC       *types.TC
	Evidence *types.Equivocation
}

// Commit is a block that became final in this step, oldest first.
type Commit struct {
	Height uint64
	View   uint64
	Hash   [crypto.DigestSize]byte
}

// Timer is the deadline the caller should enforce for View. After is
// in the caller's ticks. Zero means this step did not arm a timer.
type Timer struct {
	View  uint64
	After uint64
}

// Output is everything a step asks the caller to do.
type Output struct {
	Messages []Outbound
	Commits  []Commit
	Timer    Timer
	Dropped  bool
}

// Replica is one validator's consensus state.
type Replica struct {
	index int
	key   crypto.PrivateKey
	pubs  []crypto.PublicKey
	ids   [][crypto.DigestSize]byte
	chain [crypto.DigestSize]byte
	cfg   Config
	pace  *pacemaker.State
	pCfg  pacemaker.Config
	store Store

	view       uint64
	lockQC     types.QC
	lockHash   [crypto.DigestSize]byte
	commitH    uint64
	commitHash [crypto.DigestSize]byte
	voted      map[uint64][crypto.DigestSize]byte
	proposed   map[uint64][crypto.DigestSize]byte
	seenVote   map[uint64]map[uint8]types.Vote
	seenProp   map[uint64]map[[crypto.DigestSize]byte]seenProposal
	blocks     map[[crypto.DigestSize]byte]types.Block
	queue      []types.Event
	govQ       []types.GovTx
	evidence   map[[crypto.DigestSize]byte]struct{}
	relayed    map[uint64]struct{}
	ready      bool

	gen          *state.Ledger
	ledgers      map[[crypto.DigestSize]byte]*state.Ledger
	pendingVotes []heldVote
	draining     bool
}

type seenProposal struct {
	raw  []byte
	hash [crypto.DigestSize]byte
}

// Init checks genesis and starts a replica that has not yet entered the
// first view. Call Start with the local time.
func Init(index int, key crypto.PrivateKey, g types.Genesis, block types.Block, qc types.QC, cfg Config, store Store) (*Replica, error) {
	r, err := prepare(index, key, g.Validators().Keys, cfg, store, true)
	if err != nil {
		return nil, err
	}
	if err := g.Verify(); err != nil {
		return nil, err
	}
	chain, err := g.ChainID()
	if err != nil {
		return nil, err
	}
	hash, err := block.Header.Hash()
	if err != nil {
		return nil, err
	}
	if block.Header.ChainID != chain || block.Header.Height != 0 || block.Header.View != 0 {
		return nil, fmt.Errorf("consensus: genesis block: %w", ErrState)
	}
	if len(block.Events) != 0 || len(block.Gov) != 0 {
		return nil, fmt.Errorf("consensus: genesis block is not empty: %w", ErrState)
	}
	if err := block.VerifyProposer(g.Validators().Keys[0]); err != nil {
		return nil, err
	}
	led, err := state.FromGenesis(g)
	if err != nil {
		return nil, err
	}
	if block.Header.StateRoot != led.Root() {
		return nil, fmt.Errorf("consensus: genesis state root: %w", ErrState)
	}
	if qc.View != 0 || qc.BlockHash != hash {
		return nil, fmt.Errorf("consensus: genesis certificate: %w", ErrState)
	}
	if err := qc.Verify(chain, g.Validators().Keys); err != nil {
		return nil, err
	}
	if err := r.store.PutBlock(block); err != nil {
		return nil, wrapStore(err)
	}
	r.blocks[hash] = block
	r.gen = led
	r.ledgers[hash] = led
	r.chain = chain
	r.lockQC = qc
	r.lockHash = hash
	r.commitHash = hash
	// View 0 means "genesis is loaded, Start has not run". Start is what
	// enters view 1, so a timer exists before any message is handled.
	r.view = 0
	return r, nil
}

// Load resumes a replica from the store. key may be the genesis seat
// key or the key that seat holds after a rotation that has committed.
func Load(index int, key crypto.PrivateKey, g types.Genesis, cfg Config, store Store) (*Replica, error) {
	if err := g.Verify(); err != nil {
		return nil, err
	}
	r, err := prepare(index, key, g.Validators().Keys, cfg, store, false)
	if err != nil {
		return nil, err
	}
	snap, ok, err := store.GetSnapshot()
	if err != nil {
		return nil, wrapStore(err)
	}
	if !ok {
		return nil, fmt.Errorf("consensus: empty store: %w", ErrState)
	}
	chain, err := g.ChainID()
	if err != nil {
		return nil, err
	}
	if snap.Chain != chain {
		return nil, fmt.Errorf("consensus: snapshot chain: %w", ErrState)
	}
	led, err := state.FromGenesis(g)
	if err != nil {
		return nil, err
	}
	r.gen = led
	if _, ok, err := store.GetBlock(snap.CommitHash); err != nil || !ok {
		if err != nil {
			return nil, wrapStore(err)
		}
		return nil, fmt.Errorf("consensus: missing commit block: %w", ErrState)
	}
	if _, ok, err := store.GetBlock(snap.LockHash); err != nil || !ok {
		if err != nil {
			return nil, wrapStore(err)
		}
		return nil, fmt.Errorf("consensus: missing lock block: %w", ErrState)
	}
	r.chain = snap.Chain
	r.view = snap.View
	r.lockQC = snap.LockQC
	r.lockHash = snap.LockHash
	r.commitH = snap.CommitHeight
	r.commitHash = snap.CommitHash
	r.voted = snap.Voted
	r.proposed = snap.Proposed
	if r.voted == nil {
		r.voted = map[uint64][crypto.DigestSize]byte{}
	}
	if r.proposed == nil {
		r.proposed = map[uint64][crypto.DigestSize]byte{}
	}
	r.pace.Restore(snap.Failures, snap.TimeoutsSent)
	if err := r.remember(snap.CommitHash); err != nil {
		return nil, err
	}
	if err := r.remember(snap.LockHash); err != nil {
		return nil, err
	}
	if err := r.adoptLock(); err != nil {
		return nil, err
	}
	if !r.canSign() {
		pub, err := key.Public()
		if err != nil {
			return nil, err
		}
		if index >= len(g.Validators().Keys) || !pub.Equal(g.Validators().Keys[index]) {
			return nil, fmt.Errorf("consensus: key is not active: %w", ErrState)
		}
	}
	r.ready = true
	return r, nil
}

// heldVote is a vote that arrived before this replica had the key set
// that can check it. tries bounds how often a bad vote is retried.
type heldVote struct {
	vote  types.Vote
	tries int
}

// Start enters view 1 and, when this replica leads it, proposes.
func (r *Replica) Start(now int64) (Output, error) {
	if r.ready || r.view != 0 || len(r.proposed) != 0 || len(r.voted) != 0 {
		return Output{}, fmt.Errorf("consensus: start: %w", ErrState)
	}
	r.ready = true
	out, err := r.enter(1, true, nil, now)
	if err != nil {
		return Output{}, err
	}
	if err := r.persist(); err != nil {
		return Output{}, err
	}
	return out, nil
}

// Step applies one input.
func (r *Replica) Step(in Input) (Output, error) {
	if !r.ready {
		return Output{}, fmt.Errorf("consensus: replica is not started: %w", ErrState)
	}
	if err := oneInput(in); err != nil {
		return Output{}, err
	}
	var (
		out Output
		err error
	)
	switch {
	case in.Timeout:
		out, err = r.onTimer(in.Now)
	case in.Proposal != nil:
		out, err = r.onProposal(*in.Proposal, in.Now)
	case in.Vote != nil:
		out, err = r.onVote(*in.Vote, in.Now)
	case in.TimeoutMsg != nil:
		out, err = r.onTimeout(*in.TimeoutMsg, in.Now)
	case in.TC != nil:
		out, err = r.onTC(*in.TC, in.Now)
	case in.Evidence != nil:
		out, err = r.onEvidence(*in.Evidence)
	default:
		err = fmt.Errorf("consensus: empty input: %w", ErrState)
	}
	if err != nil {
		return Output{}, err
	}
	if err := r.persist(); err != nil {
		return Output{}, err
	}
	return out, nil
}

// Submit queues events for the next block this replica proposes.
// An event already queued is skipped. ErrQueueFull means the queue
// already holds a full block and this event was not added.
func (r *Replica) Submit(evs []types.Event) error {
	var zero [crypto.DigestSize]byte
	if r.chain == zero {
		return fmt.Errorf("consensus: replica is not started: %w", ErrState)
	}
	for _, ev := range evs {
		if ev.ChainID != r.chain {
			return fmt.Errorf("consensus: event chain: %w", ErrState)
		}
		if _, err := ev.MarshalBinary(); err != nil {
			return err
		}
		id, err := ev.ID()
		if err != nil {
			return err
		}
		if r.queueHas(id) {
			continue
		}
		if len(r.queue) >= types.MaxEventsPerBlock {
			return ErrQueueFull
		}
		r.queue = append(r.queue, ev)
	}
	return nil
}

// SubmitGov queues governance transactions for the next block this
// replica proposes. A transaction already queued is skipped.
func (r *Replica) SubmitGov(txs []types.GovTx) error {
	var zero [crypto.DigestSize]byte
	if r.chain == zero {
		return fmt.Errorf("consensus: replica is not started: %w", ErrState)
	}
	for _, tx := range txs {
		if tx.ChainID != r.chain {
			return fmt.Errorf("consensus: governance chain: %w", ErrState)
		}
		if _, err := tx.MarshalBinary(); err != nil {
			return err
		}
		id, err := tx.ID()
		if err != nil {
			return err
		}
		if r.govHas(id) {
			continue
		}
		if len(r.govQ) >= types.MaxGovPerBlock {
			return ErrQueueFull
		}
		r.govQ = append(r.govQ, tx)
	}
	return nil
}

func (r *Replica) govHas(id [crypto.DigestSize]byte) bool {
	for _, tx := range r.govQ {
		got, err := tx.ID()
		if err == nil && got == id {
			return true
		}
	}
	return false
}

// AdoptKey installs the private key this replica will vote with.
// Rotation does not change the process key until the caller does this
// or restarts from a key file that holds the new key.
func (r *Replica) AdoptKey(key crypto.PrivateKey) error {
	pub, err := key.Public()
	if err != nil {
		return err
	}
	led, err := r.CommittedLedger()
	if err != nil {
		return err
	}
	keys, err := led.ValidatorKeys()
	if err != nil {
		return err
	}
	for i, have := range keys {
		if have.Equal(pub) {
			r.key = key
			r.adoptKeys(keys)
			r.index = i
			return nil
		}
	}
	return fmt.Errorf("consensus: key is not in the active set: %w", ErrState)
}

// CommittedLedger is the state after the highest committed block.
func (r *Replica) CommittedLedger() (*state.Ledger, error) {
	return r.ledgerAt(r.commitHash)
}

// Witness is the state commitment of the block at hash.
func (r *Replica) Witness(hash [crypto.DigestSize]byte) ([]byte, error) {
	led, err := r.ledgerAt(hash)
	if err != nil {
		return nil, err
	}
	return led.Witness()
}

// BlockVoters is the validator set that was allowed to sign the block.
// The justify certificate of that block was signed by the parent's set.
func (r *Replica) BlockVoters(hash [crypto.DigestSize]byte) ([]crypto.PublicKey, error) {
	block, ok, err := r.getBlock(hash)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("consensus: missing block: %w", ErrState)
	}
	if block.Header.Height == 0 {
		led, err := r.ledgerAt(hash)
		if err != nil {
			return nil, err
		}
		return led.ValidatorKeys()
	}
	parent, err := r.ledgerAt(block.Header.ParentHash)
	if err != nil {
		return nil, err
	}
	return parent.VotersForChild(block.Header.Height)
}

func (r *Replica) queueHas(id [crypto.DigestSize]byte) bool {
	for _, ev := range r.queue {
		got, err := ev.ID()
		if err == nil && got == id {
			return true
		}
	}
	return false
}

// View is the view the replica is in.
func (r *Replica) View() uint64 { return r.view }

// CommitHeight is the highest final height, including genesis at 0.
func (r *Replica) CommitHeight() uint64 { return r.commitH }

// CommitHash is the hash of the highest final block.
func (r *Replica) CommitHash() [crypto.DigestSize]byte { return r.commitHash }

// Arm is the timer a restarted replica should enforce.
func (r *Replica) Arm() Timer {
	return Timer{View: r.view, After: r.pace.Duration(r.pCfg)}
}

func prepare(index int, key crypto.PrivateKey, pubs []crypto.PublicKey, cfg Config, store Store, bind bool) (*Replica, error) {
	if store == nil {
		return nil, fmt.Errorf("consensus: nil store: %w", ErrState)
	}
	if _, err := Leader(0, len(pubs)); err != nil {
		return nil, err
	}
	if index < 0 || index >= len(pubs) {
		return nil, fmt.Errorf("consensus: index: %w", ErrState)
	}
	pCfg := pacemaker.Config{Base: cfg.BaseTimeout, Cap: cfg.MaxTimeout}
	if err := pCfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.Skew < 0 {
		return nil, fmt.Errorf("consensus: skew: %w", ErrState)
	}
	pub, err := key.Public()
	if err != nil {
		return nil, err
	}
	if pub.Algorithm() != crypto.AlgMLDSA65 {
		return nil, fmt.Errorf("consensus: vote key: %w", ErrState)
	}
	if bind && !pub.Equal(pubs[index]) {
		return nil, fmt.Errorf("consensus: key is not the validator at %d: %w", index, ErrState)
	}
	ids := make([][crypto.DigestSize]byte, len(pubs))
	for i, p := range pubs {
		id, err := p.ID()
		if err != nil {
			return nil, err
		}
		ids[i] = id
	}
	return &Replica{
		index:    index,
		key:      key,
		pubs:     pubs,
		ids:      ids,
		cfg:      cfg,
		pace:     pacemaker.New(),
		pCfg:     pCfg,
		store:    store,
		voted:    map[uint64][crypto.DigestSize]byte{},
		proposed: map[uint64][crypto.DigestSize]byte{},
		seenVote: map[uint64]map[uint8]types.Vote{},
		seenProp: map[uint64]map[[crypto.DigestSize]byte]seenProposal{},
		blocks:   map[[crypto.DigestSize]byte]types.Block{},
		evidence: map[[crypto.DigestSize]byte]struct{}{},
		relayed:  map[uint64]struct{}{},
		ledgers:  map[[crypto.DigestSize]byte]*state.Ledger{},
	}, nil
}

func oneInput(in Input) error {
	n := 0
	if in.Timeout {
		n++
	}
	if in.Proposal != nil {
		n++
	}
	if in.Vote != nil {
		n++
	}
	if in.TimeoutMsg != nil {
		n++
	}
	if in.TC != nil {
		n++
	}
	if in.Evidence != nil {
		n++
	}
	if n != 1 {
		return fmt.Errorf("consensus: input must carry one event: %w", ErrState)
	}
	return nil
}

func (r *Replica) leader(view uint64) int {
	return int(view % uint64(len(r.pubs)))
}

func (r *Replica) persist() error {
	snap := Snapshot{
		Chain:        r.chain,
		View:         r.view,
		LockQC:       r.lockQC,
		LockHash:     r.lockHash,
		CommitHeight: r.commitH,
		CommitHash:   r.commitHash,
		Voted:        r.voted,
		Proposed:     r.proposed,
		TimeoutsSent: r.pace.SentViews(),
		Failures:     r.pace.Failures(),
	}
	if err := r.store.PutSnapshot(snap); err != nil {
		return wrapStore(err)
	}
	return nil
}

func (r *Replica) prune(view uint64) {
	if view < retainViews {
		return
	}
	oldest := view - retainViews
	for v := range r.seenVote {
		if v < oldest {
			delete(r.seenVote, v)
		}
	}
	for v := range r.seenProp {
		if v < oldest {
			delete(r.seenProp, v)
		}
	}
}

func merge(dst *Output, src Output) {
	dst.Messages = append(dst.Messages, src.Messages...)
	dst.Commits = append(dst.Commits, src.Commits...)
	if src.Timer.After != 0 {
		dst.Timer = src.Timer
	}
	if src.Dropped {
		dst.Dropped = true
	}
}

func qcPreferred(a, b types.QC) bool {
	if a.IsEmpty() {
		return false
	}
	if b.IsEmpty() {
		return true
	}
	return a.View > b.View
}
