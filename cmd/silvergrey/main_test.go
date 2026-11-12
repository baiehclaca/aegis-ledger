package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/merkle"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
	"github.com/silvergreyhound/silver-grey-ledger/pkg/verify"
)

func TestHashCommand(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "note.txt")
	body := []byte("clearance granted")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"hash", path}, &out); err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(out.String())
	want := crypto.Sum256(body)
	if got != hex(want[:]) {
		t.Fatalf("got %s want %x", got, want)
	}
}

func TestVerifyCommand(t *testing.T) {
	dir := t.TempDir()
	doc := []byte("access log excerpt")
	proof, set, writer := oneProof(t, doc)
	docPath := filepath.Join(dir, "doc.bin")
	proofPath := filepath.Join(dir, "proof.bin")
	setPath := filepath.Join(dir, "validators.bin")
	keyPath := filepath.Join(dir, "writer.pub")
	mustWrite(t, docPath, doc)
	raw, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, proofPath, raw)
	raw, err = set.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, setPath, raw)
	raw, err = types.MarshalPublicKey(writer)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, keyPath, raw)

	var out bytes.Buffer
	args := []string{"verify", "document", docPath, "--proof", proofPath, "--validators", setPath, "--writer", keyPath}
	if err := run(args, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "document hash matches") {
		t.Fatalf("output: %s", out.String())
	}

	mustWrite(t, docPath, []byte("tampered"))
	err = run(args, &bytes.Buffer{})
	if !errors.Is(err, verify.ErrDocument) {
		t.Fatalf("tampered document: %v", err)
	}
}

func TestUsage(t *testing.T) {
	err := run(nil, &bytes.Buffer{})
	var u usageError
	if !errors.As(err, &u) {
		t.Fatalf("got %v", err)
	}
}

func oneProof(t *testing.T, doc []byte) (types.InclusionProof, types.ValidatorSet, crypto.PublicKey) {
	t.Helper()
	writer, err := crypto.GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	wpub, err := writer.Public()
	if err != nil {
		t.Fatal(err)
	}
	wid, err := wpub.ID()
	if err != nil {
		t.Fatal(err)
	}
	var privs []crypto.PrivateKey
	var pubs []crypto.PublicKey
	for range 4 {
		k, err := crypto.GenerateMLDSA65()
		if err != nil {
			t.Fatal(err)
		}
		p, err := k.Public()
		if err != nil {
			t.Fatal(err)
		}
		privs = append(privs, k)
		pubs = append(pubs, p)
	}
	pid, err := pubs[0].ID()
	if err != nil {
		t.Fatal(err)
	}
	var chain [crypto.DigestSize]byte
	chain[0] = 5
	ev := types.Event{
		ChainID:     chain,
		EventType:   types.EventAccessLogin,
		Subject:     []byte("sys-1"),
		Status:      1,
		DocHashes:   []types.DocHash{types.SHA3Doc(crypto.Sum256(doc))},
		ClaimedTime: 100,
		WriterID:    wid,
		Nonce:       1,
		ReadPolicy:  types.ReadAuditors,
	}
	if err := ev.Sign(writer); err != nil {
		t.Fatal(err)
	}
	id, err := ev.ID()
	if err != nil {
		t.Fatal(err)
	}
	root, err := merkle.Root([][crypto.DigestSize]byte{id})
	if err != nil {
		t.Fatal(err)
	}
	header := types.BlockHeader{
		ChainID:      chain,
		Height:       0,
		View:         1,
		EventsRoot:   root,
		ProposerID:   pid,
		ProposerTime: 100,
	}
	hash, err := header.Hash()
	if err != nil {
		t.Fatal(err)
	}
	commit, err := types.AssembleQC(chain, header.View, hash, privs, []int{0, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	return types.InclusionProof{
		Event:     ev,
		Index:     0,
		LeafCount: 1,
		Header:    header,
		CommitQC:  commit,
	}, types.ValidatorSet{Keys: pubs}, wpub
}

func mustWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func hex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = digits[c>>4]
		out[i*2+1] = digits[c&0x0f]
	}
	return string(out)
}
