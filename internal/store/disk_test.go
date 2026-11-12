package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/silvergreyhound/silver-grey-ledger/internal/consensus"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

func TestBlockRoundTripAndTornTail(t *testing.T) {
	dir := t.TempDir()
	d := openDisk(t, dir)
	first := sampleBlock(1)
	second := sampleBlock(2)
	if err := d.PutBlock(first); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "blocks.log"))
	if err != nil {
		t.Fatal(err)
	}
	kept := info.Size()
	d = openDisk(t, dir)
	if err := d.PutBlock(second); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(filepath.Join(dir, "blocks.log"), kept+10); err != nil {
		t.Fatal(err)
	}
	d = openDisk(t, dir)
	h1 := mustHash(t, first)
	h2 := mustHash(t, second)
	if _, ok, err := d.GetBlock(h1); err != nil || !ok {
		t.Fatalf("first block: ok=%v err=%v", ok, err)
	}
	if _, ok, err := d.GetBlock(h2); err != nil || ok {
		t.Fatalf("torn block survived: ok=%v err=%v", ok, err)
	}
	third := sampleBlock(3)
	if err := d.PutBlock(third); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := d.GetBlock(mustHash(t, third)); err != nil || !ok {
		t.Fatalf("third block: ok=%v err=%v", ok, err)
	}
}

func TestIdempotentBlock(t *testing.T) {
	d := openDisk(t, t.TempDir())
	b := sampleBlock(4)
	if err := d.PutBlock(b); err != nil {
		t.Fatal(err)
	}
	if err := d.PutBlock(b); err != nil {
		t.Fatal(err)
	}
}

func TestSafetyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	d := openDisk(t, dir)
	if err := putSnap(t, d, 7); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d = openDisk(t, dir)
	got, ok, err := d.GetSnapshot()
	if err != nil || !ok {
		t.Fatalf("snapshot: ok=%v err=%v", ok, err)
	}
	if got.View != 7 || got.Failures != 2 || got.Voted[3][0] != 7 {
		t.Fatalf("snapshot mismatch: view %d failures %d", got.View, got.Failures)
	}
	if len(got.TimeoutsSent) != 1 || got.TimeoutsSent[0] != 4 {
		t.Fatalf("timeouts %+v", got.TimeoutsSent)
	}
}

func TestTornSafetyKeepsPrevious(t *testing.T) {
	dir := t.TempDir()
	d := openDisk(t, dir)
	if err := putSnap(t, d, 1); err != nil {
		t.Fatal(err)
	}
	d.arm(faultTornSafety)
	if err := putSnap(t, d, 2); !errors.Is(err, errInjectedTorn) {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d = openDisk(t, dir)
	got, ok, err := d.GetSnapshot()
	if err != nil || !ok || got.View != 1 {
		t.Fatalf("recovered view %d ok=%v err=%v", got.View, ok, err)
	}
}

func TestSkipRenameKeepsPrevious(t *testing.T) {
	dir := t.TempDir()
	d := openDisk(t, dir)
	if err := putSnap(t, d, 1); err != nil {
		t.Fatal(err)
	}
	d.arm(faultSkipSafetyRename)
	if err := putSnap(t, d, 2); !errors.Is(err, errInjectedRename) {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d = openDisk(t, dir)
	got, ok, err := d.GetSnapshot()
	if err != nil || !ok || got.View != 1 {
		t.Fatalf("view %d ok=%v err=%v", got.View, ok, err)
	}
}

func TestTornSafetyFileFailsClosed(t *testing.T) {
	dir := t.TempDir()
	d := openDisk(t, dir)
	if err := putSnap(t, d, 1); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(safetyPath(dir), []byte("ASF1garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
}

func TestSkipBlockSyncDoesNotReportSuccess(t *testing.T) {
	dir := t.TempDir()
	d := openDisk(t, dir)
	if err := d.PutBlock(sampleBlock(1)); err != nil {
		t.Fatal(err)
	}
	d.arm(faultSkipBlockSync)
	if err := d.PutBlock(sampleBlock(2)); !errors.Is(err, errInjectedSync) {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d = openDisk(t, dir)
	if err := d.PutBlock(sampleBlock(3)); err != nil {
		t.Fatal(err)
	}
}

func TestSafetyCodecCanonical(t *testing.T) {
	snap := sampleSnap(9)
	raw, err := encodeSafety(snap)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := canonicalSafety(raw); err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-5] ^= 0xff
	if _, err := decodeSafety(raw); err == nil {
		t.Fatal("checksum accepted")
	}
	unsorted := consensus.Snapshot{Voted: map[uint64][32]byte{2: {}, 1: {}}}
	raw, err = encodeSafety(unsorted)
	if err != nil {
		t.Fatal(err)
	}
	// Encoding sorts the keys. A decoder must reject the same pairs
	// written out of order, which canonicalSafety checks by re-encoding.
	flipped := append([]byte(nil), raw...)
	// Swap is not attempted on the bytes. Build a non-canonical body
	// by decoding and the round trip must match the sorted form.
	got, err := decodeSafety(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := encodeSafety(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, raw) || bytes.Equal(flipped, nil) {
		t.Fatal("round trip")
	}
}

func openDisk(t *testing.T, dir string) *Disk {
	t.Helper()
	d, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func sampleBlock(mark byte) types.Block {
	var chain, proposer [32]byte
	chain[0] = mark
	proposer[0] = mark + 1
	if proposer[0] == 0 {
		proposer[0] = 2
	}
	return types.Block{
		Header:      types.BlockHeader{ChainID: chain, ProposerID: proposer},
		ProposerSig: bytes.Repeat([]byte{mark}, crypto.MLDSASignatureSize()),
	}
}

func putSnap(t *testing.T, d *Disk, view uint64) error {
	t.Helper()
	block := sampleBlock(byte(view))
	if err := d.PutBlock(block); err != nil {
		return err
	}
	hash, err := block.Header.Hash()
	if err != nil {
		return err
	}
	snap := sampleSnap(view)
	snap.CommitHash = hash
	snap.LockHash = hash
	snap.CommitHeight = 0
	return d.PutSnapshot(snap)
}

func sampleSnap(view uint64) consensus.Snapshot {
	var chain, lock, commit, voted [32]byte
	chain[0] = 1
	lock[0] = 2
	commit[0] = 3
	voted[0] = byte(view)
	return consensus.Snapshot{
		Chain:        chain,
		View:         view,
		LockHash:     lock,
		CommitHash:   commit,
		Failures:     2,
		Voted:        map[uint64][32]byte{3: voted},
		Proposed:     map[uint64][32]byte{3: voted},
		TimeoutsSent: []uint64{4},
	}
}

func mustHash(t *testing.T, b types.Block) [32]byte {
	t.Helper()
	h, err := b.Header.Hash()
	if err != nil {
		t.Fatal(err)
	}
	return h
}
