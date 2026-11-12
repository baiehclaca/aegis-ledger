package store

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"

	"github.com/cockroachdb/pebble/v2"

	"github.com/silvergreyhound/silver-grey-ledger/internal/consensus"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

// errClosed is returned when a call arrives after Close. The node waits
// for its connections first; this is the backstop so a late call returns
// an error instead of using a nil log.
var errClosed = errors.New("store: closed")

// Disk is the crash-safe Store. PutBlock and PutSnapshot return only
// after the bytes are fsynced, which is the point at which the replica
// is allowed to vote or otherwise advance safety state.
type Disk struct {
	dir   string
	mu    sync.Mutex
	log   *blockLog
	db    *pebble.DB
	fault faultKind
}

// Open creates dir if needed, truncates a torn block tail, and refuses
// a torn safety file. safety.next is deleted: only safety.bin is
// authoritative.
func Open(dir string) (*Disk, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	log, err := openBlockLog(dir)
	if err != nil {
		return nil, err
	}
	snap, have, err := loadSafety(dir)
	if err != nil {
		_ = log.close()
		return nil, err
	}
	db, err := openState(dir)
	if err != nil {
		_ = log.close()
		return nil, err
	}
	d := &Disk{dir: dir, log: log, db: db}
	if err := d.catchUpLocked(consensusSnapshot{CommitHeight: snap.CommitHeight, CommitHash: snap.CommitHash}, have); err != nil {
		_ = d.Close()
		return nil, err
	}
	// A crash between the state batch and the parent index is healed
	// here. Parent links are not part of the safety snapshot.
	if err := d.indexParents(); err != nil {
		_ = d.Close()
		return nil, err
	}
	return d, nil
}

// Close releases the log and the state database.
func (d *Disk) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	var err error
	if d.log != nil {
		err = d.log.close()
		d.log = nil
	}
	if d.db != nil {
		if cerr := d.db.Close(); err == nil {
			err = cerr
		}
		d.db = nil
	}
	return err
}

// PutBlock appends a block and fsyncs the file and its directory before
// returning. A block already in the log is a no-op success.
func (d *Disk) PutBlock(b types.Block) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.log == nil {
		return errClosed
	}
	if d.fault == faultKillBlock {
		return d.killBlock(b)
	}
	torn := d.fault == faultTornBlock
	skip := d.fault == faultSkipBlockSync
	if err := d.log.put(b, torn, skip); err != nil {
		return err
	}
	return d.noteParent(b)
}

func (d *Disk) killBlock(b types.Block) error {
	raw, err := b.MarshalBinary()
	if err != nil {
		return err
	}
	rec := encodeBlockRecord(raw)
	n := 8
	if n > len(rec) {
		n = len(rec)
	}
	if _, err := d.log.f.WriteAt(rec[:n], d.log.end); err != nil {
		return err
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
		return fmt.Errorf("store: kill: %w", err)
	}
	return fmt.Errorf("store: process was not killed")
}

// GetBlock reads a stored block.
func (d *Disk) GetBlock(hash [32]byte) (types.Block, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.log == nil {
		return types.Block{}, false, errClosed
	}
	return d.log.get(hash)
}

// PutSnapshot atomically replaces the safety file. The temp file is
// fsynced before the rename, and the directory is fsynced after it.
func (d *Disk) PutSnapshot(s consensus.Snapshot) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fault == faultKillSafety {
		return d.killSafety(s)
	}
	// Rebuild derived state before publishing the snapshot. A crash after
	// the rebuild and before the rename leaves the previous safety file,
	// and the next open discards the ahead state.
	view := consensusSnapshot{CommitHeight: s.CommitHeight, CommitHash: s.CommitHash}
	if d.fault != faultTornSafety && d.fault != faultSkipSafetyRename && d.fault != faultKillSafety {
		if err := d.catchUpLocked(view, true); err != nil {
			return err
		}
	}
	torn := d.fault == faultTornSafety
	skip := d.fault == faultSkipSafetyRename
	return writeSafety(d.dir, s, torn, skip)
}

func (d *Disk) killSafety(s consensus.Snapshot) error {
	raw, err := encodeSafety(s)
	if err != nil {
		return err
	}
	n := 8
	if n > len(raw) {
		n = len(raw)
	}
	tmp := safetyTemp(d.dir)
	if err := os.WriteFile(tmp, raw[:n], 0o600); err != nil {
		return err
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
		return fmt.Errorf("store: kill: %w", err)
	}
	return fmt.Errorf("store: process was not killed")
}

// GetSnapshot reads the safety file.
func (d *Disk) GetSnapshot() (consensus.Snapshot, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.snapshot()
}

func (d *Disk) snapshot() (consensus.Snapshot, bool, error) {
	return loadSafety(d.dir)
}

// CatchUp rebuilds Pebble when it is behind the safety snapshot.
// Open already does this. A node calls it again after each commit so
// proofs see the new block without a restart.
func (d *Disk) CatchUp() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	snap, have, err := d.snapshot()
	if err != nil {
		return err
	}
	return d.catchUpLocked(consensusSnapshot{CommitHeight: snap.CommitHeight, CommitHash: snap.CommitHash}, have)
}

func (d *Disk) arm(k faultKind) {
	d.mu.Lock()
	d.fault = k
	d.mu.Unlock()
}
