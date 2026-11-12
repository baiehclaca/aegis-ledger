package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/silvergreyhound/silver-grey-ledger/internal/consensus"
)

func FuzzSafety(f *testing.F) {
	raw, err := encodeSafety(consensus.Snapshot{})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte("ASF1"))
	f.Fuzz(func(t *testing.T, data []byte) {
		snap, err := decodeSafety(data)
		if err != nil {
			return
		}
		out, err := encodeSafety(snap)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, data) {
			t.Fatal("non-canonical safety file accepted")
		}
	})
}

func FuzzBlockLog(f *testing.F) {
	f.Add([]byte("ABL1"))
	f.Add([]byte(nil))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "blocks.log"), data, 0o600); err != nil {
			t.Fatal(err)
		}
		log, err := openBlockLog(dir)
		if err != nil {
			return
		}
		defer func() { _ = log.close() }()
		block := sampleBlock(9)
		if err := log.put(block, false, false); err != nil {
			return
		}
		hash, err := block.Header.Hash()
		if err != nil {
			t.Fatal(err)
		}
		got, ok, err := log.get(hash)
		if err != nil || !ok {
			t.Fatalf("get after put: ok=%v err=%v", ok, err)
		}
		if got.Header.ChainID != block.Header.ChainID {
			t.Fatal("chain id")
		}
	})
}
