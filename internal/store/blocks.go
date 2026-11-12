package store

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

const (
	blockMagic     = "ABL1"
	blockHeaderLen = 4 + 4
	blockCRCLen    = 4
	// maxBlockRecord bounds one appended record. It is above a full
	// block of 1024 ML-DSA events and below a hostile length field.
	maxBlockRecord = 32 << 20
)

// blockLog is the append-only block file. The first record that does
// not checksum is the end of the trusted prefix: recovery truncates
// there. A later milestone does not edit records in place.
type blockLog struct {
	path  string
	f     *os.File
	index map[[crypto.DigestSize]byte]int64
	end   int64
}

func openBlockLog(dir string) (*blockLog, error) {
	path := filepath.Join(dir, "blocks.log")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	log := &blockLog{path: path, f: f, index: map[[crypto.DigestSize]byte]int64{}}
	if err := log.recover(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return log, nil
}

func (l *blockLog) recover() error {
	info, err := l.f.Stat()
	if err != nil {
		return err
	}
	size := info.Size()
	var pos int64
	good := int64(0)
	for pos < size {
		next, hash, err := l.readRecord(pos, size)
		if err != nil {
			if errors.Is(err, errTorn) {
				break
			}
			return err
		}
		l.index[hash] = pos
		pos = next
		good = next
	}
	if good != size {
		if err := l.f.Truncate(good); err != nil {
			return err
		}
		if err := syncFile(l.f); err != nil {
			return err
		}
		if err := syncDir(dirOf(l.path)); err != nil {
			return err
		}
	}
	l.end = good
	return nil
}

var errTorn = errors.New("store: torn block record")

func (l *blockLog) readRecord(pos, size int64) (int64, [crypto.DigestSize]byte, error) {
	var zero [crypto.DigestSize]byte
	remain := size - pos
	if remain < blockHeaderLen+blockCRCLen {
		return 0, zero, errTorn
	}
	var hdr [blockHeaderLen]byte
	if _, err := l.f.ReadAt(hdr[:], pos); err != nil {
		return 0, zero, err
	}
	if string(hdr[:4]) != blockMagic {
		return 0, zero, errTorn
	}
	n := binary.BigEndian.Uint32(hdr[4:])
	if n == 0 || n > maxBlockRecord {
		return 0, zero, errTorn
	}
	total := int64(blockHeaderLen) + int64(n) + blockCRCLen
	if remain < total {
		return 0, zero, errTorn
	}
	buf := make([]byte, n+blockCRCLen)
	if _, err := l.f.ReadAt(buf, pos+blockHeaderLen); err != nil {
		return 0, zero, err
	}
	payload := buf[:n]
	got := binary.BigEndian.Uint32(buf[n:])
	if crc32.ChecksumIEEE(payload) != got {
		return 0, zero, errTorn
	}
	block, err := types.UnmarshalBlock(payload)
	if err != nil {
		return 0, zero, errTorn
	}
	hash, err := block.Header.Hash()
	if err != nil {
		return 0, zero, err
	}
	return pos + total, hash, nil
}

func (l *blockLog) put(b types.Block, torn bool, skipSync bool) error {
	raw, err := b.MarshalBinary()
	if err != nil {
		return err
	}
	hash, err := b.Header.Hash()
	if err != nil {
		return err
	}
	if _, ok := l.index[hash]; ok {
		return nil
	}
	if len(raw) > maxBlockRecord {
		return fmt.Errorf("store: block record is too large")
	}
	rec := encodeBlockRecord(raw)
	write := rec
	if torn {
		write = rec[:len(rec)/2]
	}
	if _, err := l.f.WriteAt(write, l.end); err != nil {
		return err
	}
	if torn {
		// Leave the partial tail. Recovery truncates the first bad record.
		return errInjectedTorn
	}
	if skipSync {
		// The bytes may be in the file. The caller must not vote, because
		// durability was not confirmed. The index stays unchanged so a
		// retry of this process writes at the same offset.
		return errInjectedSync
	}
	if err := syncFile(l.f); err != nil {
		return err
	}
	if err := syncDir(dirOf(l.path)); err != nil {
		return err
	}
	l.index[hash] = l.end
	l.end += int64(len(rec))
	return nil
}

func encodeBlockRecord(payload []byte) []byte {
	rec := make([]byte, blockHeaderLen+len(payload)+blockCRCLen)
	copy(rec, blockMagic)
	binary.BigEndian.PutUint32(rec[4:], uint32(len(payload)))
	copy(rec[blockHeaderLen:], payload)
	sum := crc32.ChecksumIEEE(payload)
	binary.BigEndian.PutUint32(rec[blockHeaderLen+len(payload):], sum)
	return rec
}

func (l *blockLog) get(hash [crypto.DigestSize]byte) (types.Block, bool, error) {
	pos, ok := l.index[hash]
	if !ok {
		return types.Block{}, false, nil
	}
	info, err := l.f.Stat()
	if err != nil {
		return types.Block{}, false, err
	}
	_, got, err := l.readRecord(pos, info.Size())
	if err != nil {
		return types.Block{}, false, err
	}
	if got != hash {
		return types.Block{}, false, fmt.Errorf("store: block hash mismatch at offset %d", pos)
	}
	// readRecord already unmarshaled to check the hash, then discarded
	// the block. Read the payload again so the caller gets the value.
	var hdr [blockHeaderLen]byte
	if _, err := l.f.ReadAt(hdr[:], pos); err != nil {
		return types.Block{}, false, err
	}
	n := binary.BigEndian.Uint32(hdr[4:])
	buf := make([]byte, n)
	if _, err := l.f.ReadAt(buf, pos+blockHeaderLen); err != nil {
		return types.Block{}, false, err
	}
	block, err := types.UnmarshalBlock(buf)
	if err != nil {
		return types.Block{}, false, err
	}
	return block, true, nil
}

func (l *blockLog) close() error {
	return l.f.Close()
}
