package consensus

import (
	"fmt"

	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

// Snapshot is the safety state a restart must not forget. Losing it
// could let a replica vote twice in a view it already voted in.
type Snapshot struct {
	Chain        [32]byte
	View         uint64
	LockQC       types.QC
	LockHash     [32]byte
	CommitHeight uint64
	CommitHash   [32]byte
	Voted        map[uint64][32]byte
	Proposed     map[uint64][32]byte
	TimeoutsSent []uint64
	Failures     uint32
}

// Store is the persistence boundary. MemoryStore keeps unit tests and
// the simulator in memory. internal/store.Disk is the crash-safe
// implementation: it fsyncs before returning, and the replica does not
// change.
type Store interface {
	PutBlock(types.Block) error
	GetBlock([32]byte) (types.Block, bool, error)
	PutSnapshot(Snapshot) error
	GetSnapshot() (Snapshot, bool, error)
}

// MemoryStore is an in-process store. It is safe for one replica step
// at a time; the replica does not call it concurrently.
type MemoryStore struct {
	blocks   map[[32]byte]types.Block
	snapshot Snapshot
	have     bool
}

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{blocks: map[[32]byte]types.Block{}}
}

// PutBlock stores a block by its header hash.
func (m *MemoryStore) PutBlock(b types.Block) error {
	h, err := b.Header.Hash()
	if err != nil {
		return err
	}
	m.blocks[h] = b
	return nil
}

// GetBlock returns a previously stored block.
func (m *MemoryStore) GetBlock(h [32]byte) (types.Block, bool, error) {
	b, ok := m.blocks[h]
	return b, ok, nil
}

// PutSnapshot replaces the safety snapshot.
func (m *MemoryStore) PutSnapshot(s Snapshot) error {
	s.Voted = copyHashes(s.Voted)
	s.Proposed = copyHashes(s.Proposed)
	s.TimeoutsSent = append([]uint64(nil), s.TimeoutsSent...)
	m.snapshot = s
	m.have = true
	return nil
}

// GetSnapshot returns the last snapshot.
func (m *MemoryStore) GetSnapshot() (Snapshot, bool, error) {
	if !m.have {
		return Snapshot{}, false, nil
	}
	s := m.snapshot
	s.Voted = copyHashes(s.Voted)
	s.Proposed = copyHashes(s.Proposed)
	s.TimeoutsSent = append([]uint64(nil), s.TimeoutsSent...)
	return s, true, nil
}

func copyHashes(in map[uint64][32]byte) map[uint64][32]byte {
	out := make(map[uint64][32]byte, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func wrapStore(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrStore, err)
}
