package pacemaker

import (
	"bytes"
	"testing"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

func TestDurationDoublesUntilCap(t *testing.T) {
	cfg := Config{Base: 10, Cap: 40}
	s := New()
	if d := s.Duration(cfg); d != 10 {
		t.Fatal(d)
	}
	s.NoteEnter(false)
	if d := s.Duration(cfg); d != 20 {
		t.Fatal(d)
	}
	s.NoteEnter(false)
	if d := s.Duration(cfg); d != 40 {
		t.Fatal(d)
	}
	s.NoteEnter(false)
	if d := s.Duration(cfg); d != 40 {
		t.Fatal(d)
	}
	s.NoteEnter(true)
	if d := s.Duration(cfg); d != 10 {
		t.Fatal(d)
	}
}

func TestQuorumFormsOnce(t *testing.T) {
	keys := make([]crypto.PrivateKey, 4)
	pubs := make([]crypto.PublicKey, 4)
	var chain [crypto.DigestSize]byte
	chain[0] = 9
	for i := range keys {
		k, err := crypto.GenerateMLDSA65()
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = k
		pubs[i], err = k.Public()
		if err != nil {
			t.Fatal(err)
		}
	}
	s := New()
	var formed int
	for i := range keys {
		to := types.Timeout{ChainID: chain, View: 3, Signer: uint8(i)}
		if err := to.Sign(keys[i]); err != nil {
			t.Fatal(err)
		}
		if err := to.Verify(pubs); err != nil {
			t.Fatal(err)
		}
		tc, conflict, err := s.Add(to, len(keys))
		if err != nil || conflict != nil {
			t.Fatal(err, conflict)
		}
		if i < 2 && tc != nil {
			t.Fatal("certificate before quorum")
		}
		if tc != nil {
			formed++
			if err := tc.Verify(pubs); err != nil {
				t.Fatal(err)
			}
		}
	}
	if formed != 1 {
		t.Fatal(formed)
	}
	// A hedged re-sign of the same certificate is a duplicate, not a
	// second wish and not a second certificate.
	again := types.Timeout{ChainID: chain, View: 3, Signer: 0}
	if err := again.Sign(keys[0]); err != nil {
		t.Fatal(err)
	}
	tc, conflict, err := s.Add(again, len(keys))
	if err != nil || conflict != nil || tc != nil {
		t.Fatalf("dup: tc=%v conflict=%v err=%v", tc != nil, conflict != nil, err)
	}
}

func TestConflictingTimeout(t *testing.T) {
	k, err := crypto.GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	var chain [crypto.DigestSize]byte
	chain[0] = 4
	s := New()
	first := types.Timeout{ChainID: chain, View: 1, Signer: 0}
	if err := first.Sign(k); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Add(first, 4); err != nil {
		t.Fatal(err)
	}
	var hash [crypto.DigestSize]byte
	hash[0] = 1
	sig := bytes.Repeat([]byte{1}, crypto.MLDSASignatureSize())
	second := types.Timeout{
		ChainID: chain,
		View:    1,
		Signer:  0,
		HighQC:  types.QC{View: 2, BlockHash: hash, SignerBitmap: 1, Signatures: [][]byte{sig}},
	}
	if err := second.Sign(k); err != nil {
		t.Fatal(err)
	}
	_, conflict, err := s.Add(second, 4)
	if err != nil || conflict == nil || conflict.View != 1 {
		t.Fatalf("conflict=%v err=%v", conflict, err)
	}
}

func TestRejectsSchedule(t *testing.T) {
	if err := (Config{Base: 0, Cap: 1}).Validate(); err == nil {
		t.Fatal("zero base")
	}
	if err := (Config{Base: 5, Cap: 4}).Validate(); err == nil {
		t.Fatal("cap below base")
	}
}
