package state

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"github.com/silvergreyhound/silver-grey-ledger/internal/codec"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/merkle"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

// ErrTransition means a block, event, or governance transaction is not
// valid in this state. Callers use errors.Is.
var ErrTransition = errors.New("state: transition rejected")

// Ledger is the state after one block. Values are not safe to share
// across goroutines. Clone before a second writer.
type Ledger struct {
	chain      [crypto.DigestSize]byte
	delay      uint64
	threshold  int
	founderOrg map[string]struct{}
	registry   map[uint16]string
	ids        map[[crypto.DigestSize]byte]*ident
	order      [][crypto.DigestSize]byte
	nonces     map[[crypto.DigestSize]byte]uint64
	pending    map[uint64][]types.GovAction
	applied    map[[crypto.DigestSize]byte]struct{}
	govRoot    [crypto.DigestSize]byte
}

type ident struct {
	key     crypto.PublicKey
	org     string
	address string
	roles   uint16
	types   []uint16
	revoked uint64
	suspect uint64
}

// FromGenesis builds the state a height-0 block commits to.
// The caller has already checked the founding signatures.
func FromGenesis(g types.Genesis) (*Ledger, error) {
	chain, err := g.ChainID()
	if err != nil {
		return nil, err
	}
	s := &Ledger{
		chain:      chain,
		delay:      g.EpochDelay,
		threshold:  int(g.Threshold),
		founderOrg: map[string]struct{}{},
		registry:   map[uint16]string{},
		ids:        map[[crypto.DigestSize]byte]*ident{},
		nonces:     map[[crypto.DigestSize]byte]uint64{},
		pending:    map[uint64][]types.GovAction{},
		applied:    map[[crypto.DigestSize]byte]struct{}{},
	}
	for _, f := range g.Founders {
		s.founderOrg[f.Org] = struct{}{}
	}
	for _, r := range g.Registry {
		s.registry[r.Type] = r.Name
	}
	for _, gr := range g.Grants {
		id, err := gr.Key.ID()
		if err != nil {
			return nil, err
		}
		s.ids[id] = &ident{
			key:   gr.Key,
			org:   gr.Org,
			roles: gr.Roles,
			types: append([]uint16(nil), gr.EventTypes...),
		}
	}
	s.order = make([][crypto.DigestSize]byte, len(g.Seats))
	for i, seat := range g.Seats {
		id, err := seat.Key.ID()
		if err != nil {
			return nil, err
		}
		s.order[i] = id
		if ent := s.ids[id]; ent != nil {
			ent.address = seat.Address
		}
	}
	empty, err := merkle.Root(nil)
	if err != nil {
		return nil, err
	}
	s.govRoot = empty
	return s, nil
}

// Chain is the chain id this state belongs to.
func (s *Ledger) Chain() [crypto.DigestSize]byte { return s.chain }

// Threshold is the number of distinct founding organisations a
// governance transaction must carry.
func (s *Ledger) Threshold() int { return s.threshold }

// EpochDelay is the height gap from inclusion to effect.
func (s *Ledger) EpochDelay() uint64 { return s.delay }

// Root is the Merkle commitment of this state.
func (s *Ledger) Root() [crypto.DigestSize]byte {
	return stateRoot(s.pairs())
}

// Nonce is the highest accepted nonce for a writer. Zero means none.
func (s *Ledger) Nonce(id [crypto.DigestSize]byte) uint64 {
	return s.nonces[id]
}

// ValidatorSet is the active validator list in bitmap order.
// A revoked validator is removed from this list at the effect height.
func (s *Ledger) ValidatorSet() (types.ValidatorSet, error) {
	keys, err := s.ValidatorKeys()
	if err != nil {
		return types.ValidatorSet{}, err
	}
	return types.ValidatorSet{Keys: keys}, nil
}

// ValidatorKeys is the active validator list in bitmap order.
func (s *Ledger) ValidatorKeys() ([]crypto.PublicKey, error) {
	out := make([]crypto.PublicKey, len(s.order))
	for i, id := range s.order {
		ent := s.ids[id]
		if ent == nil {
			return nil, fmt.Errorf("%w: missing validator", ErrTransition)
		}
		out[i] = ent.key
	}
	return out, nil
}

// VotersForChild is the validator list that signs a block at height.
// height is the child height. s is the state after the parent.
func (s *Ledger) VotersForChild(height uint64) ([]crypto.PublicKey, error) {
	n, err := s.Prepare(height)
	if err != nil {
		return nil, err
	}
	return n.ValidatorKeys()
}

// SignerLive reports whether the validator at index may sign a block at height.
func (s *Ledger) SignerLive(height uint64, index int) (bool, error) {
	n, err := s.Prepare(height)
	if err != nil {
		return false, err
	}
	if index < 0 || index >= len(n.order) {
		return false, nil
	}
	ent := n.ids[n.order[index]]
	if ent == nil {
		return false, nil
	}
	if ent.revoked != 0 && height >= ent.revoked {
		return false, nil
	}
	return true, nil
}

// IdentityByID is Identity addressed by key id.
func (s *Ledger) IdentityByID(id [crypto.DigestSize]byte, height uint64) (key crypto.PublicKey, org string, roles uint16, revoked bool, ok bool) {
	ent := s.ids[id]
	if ent == nil {
		return crypto.PublicKey{}, "", 0, false, false
	}
	return ent.key, ent.org, ent.roles, ent.revoked != 0 && height >= ent.revoked, true
}

// Identity is the grant stored for key. revoked is true when height is
// at or after the revocation epoch.
func (s *Ledger) Identity(key crypto.PublicKey, height uint64) (org string, roles uint16, revoked bool, ok bool) {
	id, err := key.ID()
	if err != nil {
		return "", 0, false, false
	}
	ent := s.ids[id]
	if ent == nil || !ent.key.Equal(key) {
		return "", 0, false, false
	}
	return ent.org, ent.roles, ent.revoked != 0 && height >= ent.revoked, true
}

// CanRead reports whether caller may be shown ev at height.
// Auditors read every event. Any other member reads ALL_MEMBERS.
// ORG_ONLY requires the same organisation. AUDITORS is auditors only.
func (s *Ledger) CanRead(caller crypto.PublicKey, ev types.Event, height uint64) bool {
	org, roles, revoked, ok := s.Identity(caller, height)
	if !ok || revoked || roles == 0 {
		return false
	}
	if roles&types.RoleAuditor != 0 {
		return true
	}
	switch ev.ReadPolicy {
	case types.ReadAllMembers:
		return true
	case types.ReadOrgOnly:
		writer := s.ids[ev.WriterID]
		return writer != nil && writer.org != "" && writer.org == org
	case types.ReadAuditors:
		return false
	default:
		return false
	}
}

// Suspect reports whether a committed event at eventHeight should be
// marked suspect. Events at or before the flagged height stay clean.
func (s *Ledger) Suspect(writer [crypto.DigestSize]byte, eventHeight uint64) bool {
	ent := s.ids[writer]
	if ent == nil || ent.suspect == 0 {
		return false
	}
	return eventHeight > ent.suspect
}

// AuthorizeEvent checks a writer, a role, a nonce, and the read policy
// against the state that will sign a block at height. It does not update
// the nonce. That happens when the block is applied.
func (s *Ledger) AuthorizeEvent(ev types.Event, height uint64) error {
	n, err := s.Prepare(height)
	if err != nil {
		return err
	}
	return n.checkEvent(ev, height)
}

// Prepare opens the epoch at height and returns the state events in
// that block are checked against. s is not modified.
func (s *Ledger) Prepare(height uint64) (*Ledger, error) {
	n := s.clone()
	if err := n.openEpoch(height); err != nil {
		return nil, err
	}
	return n, nil
}

// Transition applies events and governance on top of the parent state
// and returns the state the child block must commit to.
func (s *Ledger) Transition(height uint64, evs []types.Event, gov []types.GovTx) (*Ledger, error) {
	n, err := s.Prepare(height)
	if err != nil {
		return nil, err
	}
	for _, ev := range evs {
		if err := n.admitEvent(ev, height); err != nil {
			return nil, err
		}
	}
	for _, tx := range gov {
		if err := n.admitGov(tx, height); err != nil {
			return nil, err
		}
	}
	if err := n.seal(gov); err != nil {
		return nil, err
	}
	return n, nil
}

// Apply checks that block's state root is the transition from s and
// returns the resulting state. s is the state after the parent.
func (s *Ledger) Apply(block types.Block) (*Ledger, error) {
	if block.Header.Height == 0 {
		return nil, fmt.Errorf("%w: genesis is not applied", ErrTransition)
	}
	if block.Header.ChainID != s.chain {
		return nil, fmt.Errorf("%w: chain id", ErrTransition)
	}
	next, err := s.Transition(block.Header.Height, block.Events, block.Gov)
	if err != nil {
		return nil, err
	}
	if next.Root() != block.Header.StateRoot {
		return nil, fmt.Errorf("%w: state root", ErrTransition)
	}
	return next, nil
}

func (s *Ledger) clone() *Ledger {
	n := &Ledger{
		chain:      s.chain,
		delay:      s.delay,
		threshold:  s.threshold,
		founderOrg: make(map[string]struct{}, len(s.founderOrg)),
		registry:   make(map[uint16]string, len(s.registry)),
		ids:        make(map[[crypto.DigestSize]byte]*ident, len(s.ids)),
		order:      append([][crypto.DigestSize]byte(nil), s.order...),
		nonces:     make(map[[crypto.DigestSize]byte]uint64, len(s.nonces)),
		pending:    make(map[uint64][]types.GovAction, len(s.pending)),
		applied:    make(map[[crypto.DigestSize]byte]struct{}, len(s.applied)),
		govRoot:    s.govRoot,
	}
	for k := range s.founderOrg {
		n.founderOrg[k] = struct{}{}
	}
	for k, v := range s.registry {
		n.registry[k] = v
	}
	for k, v := range s.ids {
		cp := *v
		cp.types = append([]uint16(nil), v.types...)
		n.ids[k] = &cp
	}
	for k, v := range s.nonces {
		n.nonces[k] = v
	}
	for k, v := range s.pending {
		n.pending[k] = append([]types.GovAction(nil), v...)
	}
	for k := range s.applied {
		n.applied[k] = struct{}{}
	}
	return n
}

func (s *Ledger) pairs() []pair {
	var out []pair
	add := func(key, val []byte) {
		out = append(out, pair{key: append([]byte(nil), key...), val: append([]byte(nil), val...)})
	}
	add([]byte{0x00}, s.chain[:])
	var delay [10]byte
	binary.BigEndian.PutUint64(delay[:8], s.delay)
	binary.BigEndian.PutUint16(delay[8:], uint16(s.threshold))
	add([]byte{0x02}, delay[:])
	add([]byte{0x08}, s.govRoot[:])
	orgs := make([]string, 0, len(s.founderOrg))
	for org := range s.founderOrg {
		orgs = append(orgs, org)
	}
	slices.Sort(orgs)
	for _, org := range orgs {
		add(append([]byte{0x01}, org...), []byte{1})
	}
	typesIn := make([]uint16, 0, len(s.registry))
	for t := range s.registry {
		typesIn = append(typesIn, t)
	}
	slices.Sort(typesIn)
	for _, t := range typesIn {
		var k [3]byte
		k[0] = 0x03
		binary.BigEndian.PutUint16(k[1:], t)
		add(k[:], []byte(s.registry[t]))
	}
	ids := make([][crypto.DigestSize]byte, 0, len(s.ids))
	for id := range s.ids {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b [crypto.DigestSize]byte) int {
		return bytes.Compare(a[:], b[:])
	})
	for _, id := range ids {
		add(append([]byte{0x04}, id[:]...), s.ids[id].encode())
		if nonce := s.nonces[id]; nonce > 0 {
			var buf [8]byte
			binary.BigEndian.PutUint64(buf[:], nonce)
			add(append([]byte{0x05}, id[:]...), buf[:])
		}
	}
	for i, id := range s.order {
		var k [3]byte
		k[0] = 0x06
		binary.BigEndian.PutUint16(k[1:], uint16(i))
		add(k[:], id[:])
	}
	heights := make([]uint64, 0, len(s.pending))
	for h := range s.pending {
		heights = append(heights, h)
	}
	slices.Sort(heights)
	for _, h := range heights {
		var k [9]byte
		k[0] = 0x07
		binary.BigEndian.PutUint64(k[1:], h)
		raw, err := types.PendingBody(s.chain, s.pending[h])
		if err != nil {
			sum := crypto.DomainSum(crypto.DomainGovernance, []byte(err.Error()))
			raw = sum[:]
		}
		add(k[:], raw)
	}
	applied := make([][crypto.DigestSize]byte, 0, len(s.applied))
	for id := range s.applied {
		applied = append(applied, id)
	}
	slices.SortFunc(applied, func(a, b [crypto.DigestSize]byte) int {
		return bytes.Compare(a[:], b[:])
	})
	for _, id := range applied {
		add(append([]byte{0x09}, id[:]...), []byte{1})
	}
	return out
}

func (e *ident) encode() []byte {
	enc := codec.NewEncoder()
	raw, err := types.MarshalPublicKey(e.key)
	if err != nil {
		sum := crypto.DomainSum(crypto.DomainGovernance, []byte(err.Error()))
		return sum[:]
	}
	enc.Fixed(raw)
	enc.BytesField([]byte(e.org))
	enc.BytesField([]byte(e.address))
	enc.Uint16(e.roles)
	enc.Length(len(e.types))
	for _, t := range e.types {
		enc.Uint16(t)
	}
	enc.Uint64(e.revoked)
	enc.Uint64(e.suspect)
	return enc.Bytes()
}
