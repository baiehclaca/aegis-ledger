package mempool

import (
	"testing"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

func TestPoolCapsAndNonce(t *testing.T) {
	p := New()
	pub := testPub(t)
	ev := testEvent(t, pub, 1, 1)
	if err := p.Add(pub, ev); err != nil {
		t.Fatal(err)
	}
	if err := p.Add(pub, ev); err != nil {
		t.Fatal(err)
	}
	if err := p.Add(pub, testEvent(t, pub, 1, 2)); err != ErrConflict {
		t.Fatalf("conflict: %v", err)
	}
	for n := uint64(2); n <= MaxPerWriter; n++ {
		if err := p.Add(pub, testEvent(t, pub, n, byte(n))); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Add(pub, testEvent(t, pub, MaxPerWriter+1, 9)); err != ErrFull {
		t.Fatalf("writer cap: %v", err)
	}
	for p.Len() < MaxEvents {
		key := testPub(t)
		if err := p.Add(key, testEvent(t, key, 1, 1)); err != nil {
			t.Fatal(err)
		}
	}
	extra := testPub(t)
	if err := p.Add(extra, testEvent(t, extra, 1, 1)); err != ErrFull {
		t.Fatalf("pool cap: %v", err)
	}
}

func TestReadyGapAndForget(t *testing.T) {
	p := New()
	pub := testPub(t)
	if err := p.Add(pub, testEvent(t, pub, 1, 1)); err != nil {
		t.Fatal(err)
	}
	if err := p.Add(pub, testEvent(t, pub, 3, 3)); err != nil {
		t.Fatal(err)
	}
	id, err := pub.ID()
	if err != nil {
		t.Fatal(err)
	}
	ready := p.Ready(id, 0)
	if len(ready) != 1 || ready[0].Nonce != 1 {
		t.Fatalf("ready %v", nonces(ready))
	}
	if got := p.Ready(id, 1); len(got) != 0 {
		t.Fatalf("gap released %d", len(got))
	}
	if err := p.Add(pub, testEvent(t, pub, 2, 2)); err != nil {
		t.Fatal(err)
	}
	ready = p.Ready(id, 1)
	if len(ready) != 2 || ready[0].Nonce != 2 || ready[1].Nonce != 3 {
		t.Fatalf("run %v", nonces(ready))
	}
	first, err := ready[0].ID()
	if err != nil {
		t.Fatal(err)
	}
	p.Forget([][crypto.DigestSize]byte{first})
	if p.Has(first) {
		t.Fatal("forgotten event is still stored")
	}
}

func TestAnnounceRoundTrip(t *testing.T) {
	writer, err := crypto.GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := writer.Public()
	if err != nil {
		t.Fatal(err)
	}
	wid, err := pub.ID()
	if err != nil {
		t.Fatal(err)
	}
	var chain, doc [crypto.DigestSize]byte
	chain[0] = 1
	ev := types.Event{
		ChainID:     chain,
		EventType:   types.EventShipmentDispatched,
		Subject:     []byte("crate"),
		Status:      1,
		DocHashes:   []types.DocHash{types.SHA3Doc(doc)},
		ClaimedTime: 10,
		WriterID:    wid,
		Nonce:       1,
		ReadPolicy:  types.ReadAllMembers,
	}
	if err := ev.Sign(writer); err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalBody(pub, ev)
	if err != nil {
		t.Fatal(err)
	}
	gotPub, got, err := UnmarshalBody(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !gotPub.Equal(pub) || got.Nonce != 1 {
		t.Fatal("body changed")
	}
	eid, err := ev.ID()
	if err != nil {
		t.Fatal(err)
	}
	ids, err := MarshalIDs([][crypto.DigestSize]byte{eid})
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalIDs(ids)
	if err != nil || len(back) != 1 || back[0] != eid {
		t.Fatalf("%v", err)
	}
}

func testPub(t *testing.T) crypto.PublicKey {
	t.Helper()
	key, err := crypto.GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.Public()
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func testEvent(t *testing.T, pub crypto.PublicKey, nonce uint64, tag byte) types.Event {
	t.Helper()
	id, err := pub.ID()
	if err != nil {
		t.Fatal(err)
	}
	var doc [crypto.DigestSize]byte
	doc[0] = tag
	doc[1] = byte(nonce)
	return types.Event{
		ChainID:     [crypto.DigestSize]byte{1},
		EventType:   types.EventShipmentDispatched,
		Subject:     []byte("s"),
		Status:      1,
		DocHashes:   []types.DocHash{types.SHA3Doc(doc)},
		ClaimedTime: 1,
		WriterID:    id,
		Nonce:       nonce,
		ReadPolicy:  types.ReadAllMembers,
	}
}

func nonces(evs []types.Event) []uint64 {
	out := make([]uint64, len(evs))
	for i, ev := range evs {
		out[i] = ev.Nonce
	}
	return out
}
