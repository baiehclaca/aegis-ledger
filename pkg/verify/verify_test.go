package verify

import (
	"bytes"
	"errors"
	"testing"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/merkle"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

func TestInclusionN4AndN7(t *testing.T) {
	for _, n := range []int{4, 7} {
		for _, height := range []uint64{0, 1} {
			t.Run(name(n, height), func(t *testing.T) {
				proof, set, writer, doc, _ := certifiedProof(t, n, height)
				res, err := Inclusion(proof, set, writer)
				if err != nil {
					t.Fatal(err)
				}
				if res.Height != height {
					t.Fatalf("height %d", res.Height)
				}
				sum, err := HashDocument(bytes.NewReader(doc))
				if err != nil {
					t.Fatal(err)
				}
				if err := CheckDocument(proof.Event, sum); err != nil {
					t.Fatal(err)
				}
				if err := CheckDocument(proof.Event, types.SHA3Doc([crypto.DigestSize]byte{1})); !errors.Is(err, ErrDocument) {
					t.Fatalf("mismatch: %v", err)
				}
				raw, err := proof.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				again, err := types.UnmarshalInclusionProof(raw)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Inclusion(again, set, writer); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestQuorumBoundary(t *testing.T) {
	for _, n := range []int{4, 7} {
		proof, set, writer, _, privs := certifiedProof(t, n, 0)
		q, err := types.Quorum(n)
		if err != nil {
			t.Fatal(err)
		}
		signers := make([]int, q-1)
		for i := range signers {
			signers[i] = i
		}
		shortQC, err := types.AssembleQC(proof.Header.ChainID, proof.Header.View, proof.CommitQC.BlockHash, privs, signers)
		if err != nil {
			t.Fatal(err)
		}
		short := proof
		short.CommitQC = shortQC
		if _, err := Inclusion(short, set, writer); !errors.Is(err, types.ErrQuorum) {
			t.Fatalf("n=%d short quorum: %v", n, err)
		}
		swapped := set
		swapped.Keys = append([]crypto.PublicKey(nil), set.Keys...)
		swapped.Keys[0], swapped.Keys[1] = swapped.Keys[1], swapped.Keys[0]
		if _, err := Inclusion(proof, swapped, writer); err == nil {
			t.Fatal("permuted validators were accepted")
		}
	}
}

func TestInclusionTamper(t *testing.T) {
	proof, set, writer, doc, _ := certifiedProof(t, 4, 1)
	bad := proof
	bad.Siblings = append([][crypto.DigestSize]byte(nil), proof.Siblings...)
	if len(bad.Siblings) == 0 {
		t.Fatal("expected a multi-leaf path")
	}
	bad.Siblings[0][0] ^= 0xff
	if _, err := Inclusion(bad, set, writer); err == nil {
		t.Fatal("tampered path accepted")
	}

	other, err := crypto.GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	opub, err := other.Public()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Inclusion(proof, set, opub); err == nil {
		t.Fatal("wrong writer accepted")
	}

	sum, err := HashDocument(bytes.NewReader(append(doc, 'x')))
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckDocument(proof.Event, sum); !errors.Is(err, ErrDocument) {
		t.Fatalf("altered document: %v", err)
	}
}

func name(n int, height uint64) string {
	if height == 0 {
		return "n" + itoa(n) + "-genesis"
	}
	return "n" + itoa(n) + "-height1"
}

func itoa(n int) string {
	if n == 4 {
		return "4"
	}
	return "7"
}

func certifiedProof(t *testing.T, n int, height uint64) (types.InclusionProof, types.ValidatorSet, crypto.PublicKey, []byte, []crypto.PrivateKey) {
	t.Helper()
	doc := []byte("shipment manifest " + itoa(n))
	writer, wpub := mustKey(t)
	wid, err := wpub.ID()
	if err != nil {
		t.Fatal(err)
	}
	privs := make([]crypto.PrivateKey, n)
	pubs := make([]crypto.PublicKey, n)
	for i := range privs {
		privs[i], pubs[i] = mustKey(t)
	}
	pid, err := pubs[0].ID()
	if err != nil {
		t.Fatal(err)
	}
	var chain [crypto.DigestSize]byte
	chain[0] = 0xA1
	chain[1] = byte(n)

	sum := crypto.Sum256(doc)
	base := types.Event{
		ChainID:     chain,
		EventType:   types.EventShipmentDispatched,
		Status:      1,
		DocHashes:   []types.DocHash{types.SHA3Doc(sum)},
		ClaimedTime: 1_763_000_000_000_000_000,
		WriterID:    wid,
		ReadPolicy:  types.ReadAllMembers,
	}
	subjects := [][]byte{[]byte("PN-123"), []byte("PN-456"), []byte("PN-789")}
	events := make([]types.Event, len(subjects))
	ids := make([][crypto.DigestSize]byte, len(subjects))
	for i, subject := range subjects {
		ev := base
		ev.Subject = subject
		ev.Nonce = uint64(i + 1)
		if err := ev.Sign(writer); err != nil {
			t.Fatal(err)
		}
		id, err := ev.ID()
		if err != nil {
			t.Fatal(err)
		}
		events[i] = ev
		ids[i] = id
	}
	root, err := merkle.Root(ids)
	if err != nil {
		t.Fatal(err)
	}
	var state [crypto.DigestSize]byte
	state[0] = 9
	header := types.BlockHeader{
		ChainID:      chain,
		Height:       height,
		EventsRoot:   root,
		StateRoot:    state,
		ProposerID:   pid,
		ProposerTime: base.ClaimedTime,
	}
	quorum, err := types.Quorum(n)
	if err != nil {
		t.Fatal(err)
	}
	signers := make([]int, quorum)
	for i := range signers {
		signers[i] = i
	}
	if height == 0 {
		header.View = 1
	} else {
		var parent [crypto.DigestSize]byte
		parent[0] = 0x44
		header.ParentHash = parent
		header.View = 4
		justify, err := types.AssembleQC(chain, 2, parent, privs, signers)
		if err != nil {
			t.Fatal(err)
		}
		header.Justify = justify
	}
	block := types.Block{Header: header, Events: events}
	if err := block.Sign(privs[0]); err != nil {
		t.Fatal(err)
	}
	if err := block.VerifyProposer(pubs[0]); err != nil {
		t.Fatal(err)
	}
	hash, err := header.Hash()
	if err != nil {
		t.Fatal(err)
	}
	commit, err := types.AssembleQC(chain, header.View, hash, privs, signers)
	if err != nil {
		t.Fatal(err)
	}
	sibs, err := merkle.Prove(ids, 0)
	if err != nil {
		t.Fatal(err)
	}
	proof := types.InclusionProof{
		Event:     events[0],
		Index:     0,
		LeafCount: uint64(len(events)),
		Siblings:  sibs,
		Header:    header,
		CommitQC:  commit,
	}
	if _, err := Inclusion(proof, types.ValidatorSet{Keys: pubs}, wpub); err != nil {
		t.Fatal(err)
	}
	return proof, types.ValidatorSet{Keys: pubs}, wpub, doc, privs
}

func mustKey(t *testing.T) (crypto.PrivateKey, crypto.PublicKey) {
	t.Helper()
	priv, err := crypto.GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := priv.Public()
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}
