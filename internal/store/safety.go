package store

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"slices"

	"github.com/silvergreyhound/silver-grey-ledger/internal/consensus"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

const (
	safetyMagic   = "ASF1"
	safetyVersion = 1
	maxSafetyFile = 8 << 20
	maxSafetyKeys = 1 << 20
)

func safetyPath(dir string) string {
	return filepath.Join(dir, "safety.bin")
}

func safetyTemp(dir string) string {
	return filepath.Join(dir, "safety.next")
}

// loadSafety reads the committed safety file. A missing file is a new
// store. A checksum failure is fatal: replacing the file with an empty
// snapshot would let the replica sign a view it may already have signed.
// safety.next is never authoritative. A crash before rename leaves it
// behind, and the previous safety.bin still stands.
func loadSafety(dir string) (consensus.Snapshot, bool, error) {
	next := safetyTemp(dir)
	if err := os.Remove(next); err != nil && !os.IsNotExist(err) {
		return consensus.Snapshot{}, false, err
	}
	raw, err := os.ReadFile(safetyPath(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return consensus.Snapshot{}, false, nil
		}
		return consensus.Snapshot{}, false, err
	}
	snap, err := decodeSafety(raw)
	if err != nil {
		return consensus.Snapshot{}, false, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	return snap, true, nil
}

func writeSafety(dir string, snap consensus.Snapshot, torn bool, skipRename bool) error {
	raw, err := encodeSafety(snap)
	if err != nil {
		return err
	}
	tmp := safetyTemp(dir)
	write := raw
	if torn {
		if len(write) > 8 {
			write = write[:8]
		}
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(write)
	serr := syncFile(f)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	if cerr != nil {
		return cerr
	}
	if torn {
		return errInjectedTorn
	}
	if serr != nil {
		return serr
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	if skipRename {
		return errInjectedRename
	}
	if err := os.Rename(tmp, safetyPath(dir)); err != nil {
		return err
	}
	return syncDir(dir)
}

func encodeSafety(s consensus.Snapshot) ([]byte, error) {
	qc, err := s.LockQC.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if len(s.Voted) > maxSafetyKeys || len(s.Proposed) > maxSafetyKeys || len(s.TimeoutsSent) > maxSafetyKeys {
		return nil, fmt.Errorf("store: safety snapshot is too large")
	}
	body := make([]byte, 0, 128+len(qc))
	body = append(body, s.Chain[:]...)
	body = binary.BigEndian.AppendUint64(body, s.View)
	body = append(body, s.LockHash[:]...)
	body = binary.BigEndian.AppendUint64(body, s.CommitHeight)
	body = append(body, s.CommitHash[:]...)
	body = binary.BigEndian.AppendUint32(body, s.Failures)
	body = appendPairs(body, s.Voted)
	body = appendPairs(body, s.Proposed)
	body = binary.BigEndian.AppendUint32(body, uint32(len(s.TimeoutsSent)))
	sent := append([]uint64(nil), s.TimeoutsSent...)
	slices.Sort(sent)
	for _, v := range sent {
		body = binary.BigEndian.AppendUint64(body, v)
	}
	body = binary.BigEndian.AppendUint32(body, uint32(len(qc)))
	body = append(body, qc...)
	out := make([]byte, 0, 4+2+len(body)+4)
	out = append(out, safetyMagic...)
	out = binary.BigEndian.AppendUint16(out, safetyVersion)
	out = append(out, body...)
	sum := crc32.ChecksumIEEE(out)
	out = binary.BigEndian.AppendUint32(out, sum)
	if len(out) > maxSafetyFile {
		return nil, fmt.Errorf("store: safety snapshot is too large")
	}
	return out, nil
}

func appendPairs(dst []byte, m map[uint64][32]byte) []byte {
	keys := make([]uint64, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(keys)))
	for _, k := range keys {
		dst = binary.BigEndian.AppendUint64(dst, k)
		h := m[k]
		dst = append(dst, h[:]...)
	}
	return dst
}

func decodeSafety(raw []byte) (consensus.Snapshot, error) {
	if len(raw) < 4+2+4 || len(raw) > maxSafetyFile {
		return consensus.Snapshot{}, fmt.Errorf("store: safety length")
	}
	sum := crc32.ChecksumIEEE(raw[:len(raw)-4])
	if binary.BigEndian.Uint32(raw[len(raw)-4:]) != sum {
		return consensus.Snapshot{}, fmt.Errorf("store: safety checksum")
	}
	if string(raw[:4]) != safetyMagic {
		return consensus.Snapshot{}, fmt.Errorf("store: safety magic")
	}
	if binary.BigEndian.Uint16(raw[4:6]) != safetyVersion {
		return consensus.Snapshot{}, fmt.Errorf("store: safety version")
	}
	body := raw[6 : len(raw)-4]
	var s consensus.Snapshot
	var err error
	if s.Chain, body, err = takeHash(body); err != nil {
		return consensus.Snapshot{}, err
	}
	if s.View, body, err = takeU64(body); err != nil {
		return consensus.Snapshot{}, err
	}
	if s.LockHash, body, err = takeHash(body); err != nil {
		return consensus.Snapshot{}, err
	}
	if s.CommitHeight, body, err = takeU64(body); err != nil {
		return consensus.Snapshot{}, err
	}
	if s.CommitHash, body, err = takeHash(body); err != nil {
		return consensus.Snapshot{}, err
	}
	if len(body) < 4 {
		return consensus.Snapshot{}, fmt.Errorf("store: safety truncated")
	}
	s.Failures = binary.BigEndian.Uint32(body[:4])
	body = body[4:]
	if s.Voted, body, err = takePairs(body); err != nil {
		return consensus.Snapshot{}, err
	}
	if s.Proposed, body, err = takePairs(body); err != nil {
		return consensus.Snapshot{}, err
	}
	if s.TimeoutsSent, body, err = takeU64s(body); err != nil {
		return consensus.Snapshot{}, err
	}
	if len(body) < 4 {
		return consensus.Snapshot{}, fmt.Errorf("store: safety truncated")
	}
	n := binary.BigEndian.Uint32(body[:4])
	body = body[4:]
	if uint32(len(body)) != n {
		return consensus.Snapshot{}, fmt.Errorf("store: safety qc length")
	}
	s.LockQC, err = types.UnmarshalQC(body)
	if err != nil {
		return consensus.Snapshot{}, err
	}
	return s, nil
}

func takeHash(b []byte) ([crypto.DigestSize]byte, []byte, error) {
	var h [crypto.DigestSize]byte
	if len(b) < len(h) {
		return h, nil, fmt.Errorf("store: safety truncated")
	}
	copy(h[:], b[:len(h)])
	return h, b[len(h):], nil
}

func takeU64(b []byte) (uint64, []byte, error) {
	if len(b) < 8 {
		return 0, nil, fmt.Errorf("store: safety truncated")
	}
	return binary.BigEndian.Uint64(b[:8]), b[8:], nil
}

func takePairs(b []byte) (map[uint64][32]byte, []byte, error) {
	if len(b) < 4 {
		return nil, nil, fmt.Errorf("store: safety truncated")
	}
	n := binary.BigEndian.Uint32(b[:4])
	b = b[4:]
	if n > maxSafetyKeys {
		return nil, nil, fmt.Errorf("store: safety snapshot is too large")
	}
	out := make(map[uint64][32]byte, n)
	var prev uint64
	for i := uint32(0); i < n; i++ {
		var view uint64
		var err error
		var h [32]byte
		if view, b, err = takeU64(b); err != nil {
			return nil, nil, err
		}
		if h, b, err = takeHash(b); err != nil {
			return nil, nil, err
		}
		if i > 0 && view <= prev {
			return nil, nil, fmt.Errorf("store: safety keys are not sorted")
		}
		prev = view
		out[view] = h
	}
	return out, b, nil
}

func takeU64s(b []byte) ([]uint64, []byte, error) {
	if len(b) < 4 {
		return nil, nil, fmt.Errorf("store: safety truncated")
	}
	n := binary.BigEndian.Uint32(b[:4])
	b = b[4:]
	if n > maxSafetyKeys {
		return nil, nil, fmt.Errorf("store: safety snapshot is too large")
	}
	out := make([]uint64, n)
	var prev uint64
	for i := uint32(0); i < n; i++ {
		var err error
		if out[i], b, err = takeU64(b); err != nil {
			return nil, nil, err
		}
		if i > 0 && out[i] <= prev {
			return nil, nil, fmt.Errorf("store: safety timeouts are not sorted")
		}
		prev = out[i]
	}
	return out, b, nil
}

// canonicalSafety reports whether raw is the encoding this process would
// write. Fuzz tests use it to reject a non-canonical acceptance.
func canonicalSafety(raw []byte) ([]byte, error) {
	snap, err := decodeSafety(raw)
	if err != nil {
		return nil, err
	}
	out, err := encodeSafety(snap)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(out, raw) {
		return nil, fmt.Errorf("store: safety encoding is not canonical")
	}
	return out, nil
}
