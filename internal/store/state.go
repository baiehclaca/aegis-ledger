package store

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/cockroachdb/pebble/v2"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/merkle"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

// Pebble keeps the derived index. The block log is the source of truth.
// A mismatch between the recorded commit and the safety snapshot wipes
// this directory and replays the committed chain. That replay is local
// crash recovery, not the state-sync snapshot protocol.
const stateDirName = "state"

const (
	keyMeta = "M"
	keySet  = "V"
)

type eventLoc struct {
	Height uint64
	Index  uint32
	Block  [crypto.DigestSize]byte
}

func openState(dir string) (db *pebble.DB, err error) {
	path := dir + string(os.PathSeparator) + stateDirName
	if err = os.MkdirAll(path, 0o700); err != nil {
		return nil, err
	}
	// Pebble's logger Fatalf panics, and Open turns that into a process
	// crash. A manifest rename that loses a race with the directory we
	// just replaced is an error the caller can retry, not a reason to
	// bring the node down.
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("store: pebble open: %v", r)
			}
		}()
		db, err = pebble.Open(path, &pebble.Options{Logger: quietLog{}})
	}()
	if err != nil {
		return nil, err
	}
	return db, nil
}

// quietLog drops Pebble's info line. Fatalf is an internal failure of
// the library, not a response to a network message.
type quietLog struct{}

func (quietLog) Infof(string, ...any)  {}
func (quietLog) Errorf(string, ...any) {}
func (quietLog) Fatalf(format string, args ...any) {
	panic(fmt.Sprintf("pebble: "+format, args...))
}

func (d *Disk) resetState() error {
	// Drop the pointer before Close returns. Pebble panics if Close runs
	// twice, and a later Disk.Close must not see this handle if rebuild fails.
	old := d.db
	d.db = nil
	if err := old.Close(); err != nil {
		return err
	}
	path := d.dir + string(os.PathSeparator) + stateDirName
	var last error
	for range 3 {
		if err := os.RemoveAll(path); err != nil {
			return err
		}
		db, err := openState(d.dir)
		if err == nil {
			d.db = db
			return nil
		}
		last = err
	}
	return last
}

func (d *Disk) readMeta() (uint64, [crypto.DigestSize]byte, bool, error) {
	raw, ok, err := d.get(keyMeta)
	if err != nil || !ok {
		return 0, [crypto.DigestSize]byte{}, ok, err
	}
	if len(raw) != 8+crypto.DigestSize {
		return 0, [crypto.DigestSize]byte{}, false, fmt.Errorf("%w: state meta", ErrCorrupt)
	}
	var hash [crypto.DigestSize]byte
	copy(hash[:], raw[8:])
	return binary.BigEndian.Uint64(raw[:8]), hash, true, nil
}

func (d *Disk) catchUpLocked(snap consensusSnapshot, have bool) error {
	if !have {
		_, _, ok, err := d.readMeta()
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		// The state batch is written before the safety file is published.
		// A crash in between leaves derived state and no record of a vote.
		// Drop the state. The block log is unchanged.
		return d.resetState()
	}
	height, hash, ok, err := d.readMeta()
	if err != nil {
		return err
	}
	if ok && height == snap.CommitHeight && hash == snap.CommitHash {
		return nil
	}
	chain, err := d.chain(snap.CommitHash, snap.CommitHeight)
	if err != nil {
		return err
	}
	if err := d.resetState(); err != nil {
		return err
	}
	if err := d.applyChain(chain, snap.CommitHeight, snap.CommitHash); err != nil {
		return err
	}
	return d.indexParents()
}

// indexParents records each stored block under its parent. A state
// rebuild deletes the index, and proofs need it again.
func (d *Disk) indexParents() error {
	batch := d.db.NewBatch()
	defer func() { _ = batch.Close() }()
	for hash := range d.log.index {
		block, ok, err := d.log.get(hash)
		if err != nil {
			return err
		}
		if !ok || block.Header.Height == 0 {
			continue
		}
		key := make([]byte, 1+crypto.DigestSize+crypto.DigestSize)
		key[0] = 'C'
		copy(key[1:], block.Header.ParentHash[:])
		copy(key[1+crypto.DigestSize:], hash[:])
		if err := batch.Set(key, []byte{1}, nil); err != nil {
			return err
		}
	}
	return batch.Commit(pebble.Sync)
}

// consensusSnapshot is the subset of the safety snapshot the state
// rebuild reads. It is duplicated as fields so state.go does not have
// to mention the lock certificate.
type consensusSnapshot struct {
	CommitHeight uint64
	CommitHash   [crypto.DigestSize]byte
}

func (d *Disk) chain(hash [crypto.DigestSize]byte, height uint64) ([]types.Block, error) {
	var rev []types.Block
	cur := hash
	for {
		block, ok, err := d.log.get(cur)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("%w: commit block is not in the log", ErrCorrupt)
		}
		rev = append(rev, block)
		if block.Header.Height == 0 {
			break
		}
		if uint64(len(rev)) > height+1 {
			return nil, fmt.Errorf("%w: commit chain exceeds its height", ErrCorrupt)
		}
		cur = block.Header.ParentHash
	}
	if rev[0].Header.Height != height {
		return nil, fmt.Errorf("%w: commit height does not match the block", ErrCorrupt)
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return rev, nil
}

func (d *Disk) applyChain(chain []types.Block, height uint64, hash [crypto.DigestSize]byte) error {
	batch := d.db.NewBatch()
	defer func() { _ = batch.Close() }()
	// A plain batch cannot be read. Nonces written earlier in this
	// chain are remembered here so a later event cannot lower one.
	nonces := map[[crypto.DigestSize]byte]uint64{}
	for _, block := range chain {
		if err := d.applyBlock(batch, block, nonces); err != nil {
			return err
		}
	}
	meta := make([]byte, 8+crypto.DigestSize)
	binary.BigEndian.PutUint64(meta[:8], height)
	copy(meta[8:], hash[:])
	if err := batch.Set([]byte(keyMeta), meta, nil); err != nil {
		return err
	}
	return batch.Commit(pebble.Sync)
}

func (d *Disk) applyBlock(batch *pebble.Batch, block types.Block, nonces map[[crypto.DigestSize]byte]uint64) error {
	hash, err := block.Header.Hash()
	if err != nil {
		return err
	}
	hk := make([]byte, 1+8)
	hk[0] = 'H'
	binary.BigEndian.PutUint64(hk[1:], block.Header.Height)
	if err := batch.Set(hk, hash[:], nil); err != nil {
		return err
	}
	for i, ev := range block.Events {
		if err := d.indexEvent(batch, ev, block.Header.Height, uint32(i), hash, nonces); err != nil {
			return err
		}
	}
	return nil
}

func (d *Disk) indexEvent(batch *pebble.Batch, ev types.Event, height uint64, index uint32, block [crypto.DigestSize]byte, nonces map[[crypto.DigestSize]byte]uint64) error {
	id, err := ev.ID()
	if err != nil {
		return err
	}
	loc := make([]byte, 8+4+crypto.DigestSize)
	binary.BigEndian.PutUint64(loc[:8], height)
	binary.BigEndian.PutUint32(loc[8:12], index)
	copy(loc[12:], block[:])
	ek := append([]byte{'E'}, id[:]...)
	if err := batch.Set(ek, loc, nil); err != nil {
		return err
	}
	sk := subjectKey(ev.Subject, id)
	if err := batch.Set(sk, []byte{1}, nil); err != nil {
		return err
	}
	yk := make([]byte, 1+2+crypto.DigestSize)
	yk[0] = 'Y'
	binary.BigEndian.PutUint16(yk[1:3], ev.EventType)
	copy(yk[3:], id[:])
	if err := batch.Set(yk, []byte{1}, nil); err != nil {
		return err
	}
	for _, doc := range ev.DocHashes {
		dk := make([]byte, 1+crypto.DigestSize+crypto.DigestSize)
		dk[0] = 'D'
		copy(dk[1:], doc.Sum[:])
		copy(dk[1+crypto.DigestSize:], id[:])
		if err := batch.Set(dk, []byte{1}, nil); err != nil {
			return err
		}
	}
	return d.noteNonce(batch, ev.WriterID, ev.Nonce, nonces)
}

func (d *Disk) noteNonce(batch *pebble.Batch, writer [crypto.DigestSize]byte, nonce uint64, nonces map[[crypto.DigestSize]byte]uint64) error {
	have, ok := nonces[writer]
	if !ok {
		key := append([]byte{'N'}, writer[:]...)
		raw, found, err := d.get(string(key))
		if err != nil {
			return err
		}
		if found && len(raw) == 8 {
			have = binary.BigEndian.Uint64(raw)
		}
	}
	if nonce < have {
		nonce = have
	}
	nonces[writer] = nonce
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], nonce)
	key := append([]byte{'N'}, writer[:]...)
	return batch.Set(key, buf[:], nil)
}

func subjectKey(subject []byte, id [crypto.DigestSize]byte) []byte {
	key := make([]byte, 1+2+len(subject)+crypto.DigestSize)
	key[0] = 'S'
	binary.BigEndian.PutUint16(key[1:3], uint16(len(subject)))
	copy(key[3:], subject)
	copy(key[3+len(subject):], id[:])
	return key
}

func (d *Disk) noteParent(block types.Block) error {
	if block.Header.Height == 0 {
		return nil
	}
	hash, err := block.Header.Hash()
	if err != nil {
		return err
	}
	key := make([]byte, 1+crypto.DigestSize+crypto.DigestSize)
	key[0] = 'C'
	copy(key[1:], block.Header.ParentHash[:])
	copy(key[1+crypto.DigestSize:], hash[:])
	return d.db.Set(key, []byte{1}, pebble.Sync)
}

func (d *Disk) get(key string) ([]byte, bool, error) {
	val, closer, err := d.db.Get([]byte(key))
	if errors.Is(err, pebble.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	out := append([]byte(nil), val...)
	if err := closer.Close(); err != nil {
		return nil, false, err
	}
	return out, true, nil
}

// LastNonce is the highest nonce committed for writer. A writer with
// no committed event has nonce 0. Role checks are a later milestone.
func (d *Disk) LastNonce(writer [crypto.DigestSize]byte) (uint64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := append([]byte{'N'}, writer[:]...)
	raw, ok, err := d.get(string(key))
	if err != nil || !ok || len(raw) != 8 {
		if err == nil && ok && len(raw) != 8 {
			return 0, fmt.Errorf("%w: nonce", ErrCorrupt)
		}
		return 0, err
	}
	return binary.BigEndian.Uint64(raw), nil
}

// SetValidators records the membership bytes. A different set on a
// later open is refused. Enforcement of roles is a later milestone.
func (d *Disk) SetValidators(set types.ValidatorSet) error {
	raw, err := set.MarshalBinary()
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	have, ok, err := d.get(keySet)
	if err != nil {
		return err
	}
	if ok {
		if !bytes.Equal(have, raw) {
			return fmt.Errorf("store: validator set does not match the stored set")
		}
		return nil
	}
	return d.db.Set([]byte(keySet), raw, pebble.Sync)
}

// Committed reports whether id is in a committed block.
func (d *Disk) Committed(id [crypto.DigestSize]byte) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok, err := d.findEvent(id)
	return ok, err
}

func (d *Disk) findEvent(id [crypto.DigestSize]byte) (eventLoc, bool, error) {
	raw, ok, err := d.get(string(append([]byte{'E'}, id[:]...)))
	if err != nil || !ok {
		return eventLoc{}, false, err
	}
	if len(raw) != 8+4+crypto.DigestSize {
		return eventLoc{}, false, fmt.Errorf("%w: event index", ErrCorrupt)
	}
	var loc eventLoc
	loc.Height = binary.BigEndian.Uint64(raw[:8])
	loc.Index = binary.BigEndian.Uint32(raw[8:12])
	copy(loc.Block[:], raw[12:])
	return loc, true, nil
}

// EventsBySubject returns committed event ids for subject, in index order.
func (d *Disk) EventsBySubject(subject []byte) ([][crypto.DigestSize]byte, error) {
	if len(subject) > types.MaxSubjectID {
		return nil, fmt.Errorf("store: subject id length")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	prefix := make([]byte, 1+2+len(subject))
	prefix[0] = 'S'
	binary.BigEndian.PutUint16(prefix[1:3], uint16(len(subject)))
	copy(prefix[3:], subject)
	return d.idsWithPrefix(prefix)
}

func (d *Disk) idsWithPrefix(prefix []byte) ([][crypto.DigestSize]byte, error) {
	iter, err := d.db.NewIter(&pebble.IterOptions{
		LowerBound: prefix,
		UpperBound: prefixEnd(prefix),
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = iter.Close() }()
	var out [][crypto.DigestSize]byte
	for ok := iter.First(); ok; ok = iter.Next() {
		key := iter.Key()
		if len(key) < len(prefix)+crypto.DigestSize {
			return nil, fmt.Errorf("%w: index key", ErrCorrupt)
		}
		var id [crypto.DigestSize]byte
		copy(id[:], key[len(key)-crypto.DigestSize:])
		out = append(out, id)
	}
	return out, nil
}

func prefixEnd(prefix []byte) []byte {
	out := append([]byte(nil), prefix...)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			return out
		}
	}
	return nil
}

// Proof builds an inclusion proof from the stored block and the child
// that certifies it. The certificate is the child's justify QC.
func (d *Disk) Proof(id [crypto.DigestSize]byte) (types.InclusionProof, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	loc, ok, err := d.findEvent(id)
	if err != nil {
		return types.InclusionProof{}, err
	}
	if !ok {
		return types.InclusionProof{}, fmt.Errorf("store: event is not committed")
	}
	block, ok, err := d.log.get(loc.Block)
	if err != nil {
		return types.InclusionProof{}, err
	}
	if !ok || uint32(len(block.Events)) <= loc.Index {
		return types.InclusionProof{}, fmt.Errorf("%w: event block", ErrCorrupt)
	}
	ids := make([][crypto.DigestSize]byte, len(block.Events))
	for i, ev := range block.Events {
		eid, err := ev.ID()
		if err != nil {
			return types.InclusionProof{}, err
		}
		ids[i] = eid
	}
	siblings, err := merkle.Prove(ids, int(loc.Index))
	if err != nil {
		return types.InclusionProof{}, err
	}
	child, ok, err := d.certifyingChild(loc.Block, block.Header.View)
	if err != nil {
		return types.InclusionProof{}, err
	}
	if !ok {
		return types.InclusionProof{}, fmt.Errorf("store: event block is not certified")
	}
	return types.InclusionProof{
		Event:     block.Events[loc.Index],
		Index:     uint64(loc.Index),
		LeafCount: uint64(len(block.Events)),
		Siblings:  siblings,
		Header:    block.Header,
		CommitQC:  child.Header.Justify,
	}, nil
}

func (d *Disk) certifyingChild(parent [crypto.DigestSize]byte, view uint64) (types.Block, bool, error) {
	prefix := make([]byte, 1+crypto.DigestSize)
	prefix[0] = 'C'
	copy(prefix[1:], parent[:])
	iter, err := d.db.NewIter(&pebble.IterOptions{
		LowerBound: prefix,
		UpperBound: prefixEnd(prefix),
	})
	if err != nil {
		return types.Block{}, false, err
	}
	defer func() { _ = iter.Close() }()
	for ok := iter.First(); ok; ok = iter.Next() {
		key := append([]byte(nil), iter.Key()...)
		if len(key) != 1+crypto.DigestSize+crypto.DigestSize {
			continue
		}
		var hash [crypto.DigestSize]byte
		copy(hash[:], key[1+crypto.DigestSize:])
		block, found, err := d.log.get(hash)
		if err != nil {
			return types.Block{}, false, err
		}
		if !found {
			continue
		}
		if block.Header.ParentHash != parent {
			continue
		}
		if block.Header.Justify.BlockHash == parent && block.Header.Justify.View == view {
			return block, true, nil
		}
	}
	return types.Block{}, false, nil
}

// CommitQC is the certificate of the block at hash. It is the justify
// certificate of the child that certified it.
func (d *Disk) CommitQC(hash [crypto.DigestSize]byte, view uint64) (types.QC, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	child, ok, err := d.certifyingChild(hash, view)
	if err != nil {
		return types.QC{}, err
	}
	if !ok {
		return types.QC{}, fmt.Errorf("store: block is not certified")
	}
	return child.Header.Justify, nil
}

// BlockByHeight returns the committed block at height.
func (d *Disk) BlockByHeight(height uint64) (types.Block, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := make([]byte, 1+8)
	key[0] = 'H'
	binary.BigEndian.PutUint64(key[1:], height)
	raw, ok, err := d.get(string(key))
	if err != nil || !ok {
		return types.Block{}, ok, err
	}
	if len(raw) != crypto.DigestSize {
		return types.Block{}, false, fmt.Errorf("%w: height %d", ErrCorrupt, height)
	}
	var hash [crypto.DigestSize]byte
	copy(hash[:], raw)
	return d.log.get(hash)
}

// EventsByDoc returns committed event ids that carry sum.
func (d *Disk) EventsByDoc(sum [crypto.DigestSize]byte) ([][crypto.DigestSize]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	prefix := make([]byte, 1+crypto.DigestSize)
	prefix[0] = 'D'
	copy(prefix[1:], sum[:])
	return d.idsWithPrefix(prefix)
}

// Event returns a committed event and its height.
func (d *Disk) Event(id [crypto.DigestSize]byte) (types.Event, uint64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	loc, ok, err := d.findEvent(id)
	if err != nil {
		return types.Event{}, 0, err
	}
	if !ok {
		return types.Event{}, 0, fmt.Errorf("store: event is not committed")
	}
	block, ok, err := d.log.get(loc.Block)
	if err != nil {
		return types.Event{}, 0, err
	}
	if !ok || uint32(len(block.Events)) <= loc.Index {
		return types.Event{}, 0, fmt.Errorf("%w: event block", ErrCorrupt)
	}
	return block.Events[loc.Index], loc.Height, nil
}

// Suffix returns committed blocks with height greater than after, then
// any stored child of the commit tip. A restarted peer uses this to
// fill a gap. The cap is maxSuffixBlocks.
func (d *Disk) Suffix(after uint64) ([]types.Block, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	snap, have, err := d.snapshot()
	if err != nil || !have {
		return nil, err
	}
	var out []types.Block
	for h := after + 1; h <= snap.CommitHeight; h++ {
		if len(out) >= maxSuffixBlocks {
			return out, nil
		}
		key := make([]byte, 1+8)
		key[0] = 'H'
		binary.BigEndian.PutUint64(key[1:], h)
		raw, ok, err := d.get(string(key))
		if err != nil {
			return nil, err
		}
		if !ok || len(raw) != crypto.DigestSize {
			return nil, fmt.Errorf("%w: height %d", ErrCorrupt, h)
		}
		var hash [crypto.DigestSize]byte
		copy(hash[:], raw)
		block, ok, err := d.log.get(hash)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("%w: height %d", ErrCorrupt, h)
		}
		out = append(out, block)
	}
	kids, err := d.children(snap.CommitHash)
	if err != nil {
		return nil, err
	}
	for _, block := range kids {
		if len(out) >= maxSuffixBlocks {
			break
		}
		if block.Header.Height <= after {
			continue
		}
		out = append(out, block)
	}
	return out, nil
}

const maxSuffixBlocks = 256

func (d *Disk) children(parent [crypto.DigestSize]byte) ([]types.Block, error) {
	prefix := make([]byte, 1+crypto.DigestSize)
	prefix[0] = 'C'
	copy(prefix[1:], parent[:])
	iter, err := d.db.NewIter(&pebble.IterOptions{
		LowerBound: prefix,
		UpperBound: prefixEnd(prefix),
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = iter.Close() }()
	var out []types.Block
	for ok := iter.First(); ok && len(out) < 8; ok = iter.Next() {
		key := append([]byte(nil), iter.Key()...)
		if len(key) != len(prefix)+crypto.DigestSize {
			continue
		}
		var hash [crypto.DigestSize]byte
		copy(hash[:], key[len(prefix):])
		block, found, err := d.log.get(hash)
		if err != nil {
			return nil, err
		}
		if found {
			out = append(out, block)
		}
	}
	return out, nil
}
