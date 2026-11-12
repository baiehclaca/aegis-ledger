package types

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"testing"

	"github.com/silvergreyhound/silver-grey-ledger/internal/codec"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/merkle"
)

func TestQuorum(t *testing.T) {
	ok := map[int]int{4: 3, 7: 5, 10: 7, 31: 21}
	for n, q := range ok {
		got, err := Quorum(n)
		if err != nil || got != q {
			t.Fatalf("n=%d: got %d err %v", n, got, err)
		}
	}
	for _, n := range []int{0, 1, 2, 3, 5, 6, 8, 30, 32, 34} {
		if _, err := Quorum(n); !errors.Is(err, ErrInvalid) {
			t.Fatalf("n=%d: %v", n, err)
		}
	}
}

func TestEmptyQCEncoding(t *testing.T) {
	raw, err := QC{}.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, 0, 49)
	want = binary.BigEndian.AppendUint16(want, TypeQC)
	want = binary.BigEndian.AppendUint16(want, Version)
	want = append(want, make([]byte, 8+32+4)...)
	want = append(want, 0x00) // DER length 0
	if !bytes.Equal(raw, want) {
		t.Fatalf("empty QC\n got %x\nwant %x", raw, want)
	}
	got, err := UnmarshalQC(raw)
	if err != nil || !got.IsEmpty() {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	raw = append(raw, 0x00)
	if _, err := UnmarshalQC(raw); !errors.Is(err, codec.ErrTrailing) {
		t.Fatalf("trailing: %v", err)
	}
}

func TestQCRejectsPartialEmpty(t *testing.T) {
	q := QC{View: 1}
	if _, err := q.MarshalBinary(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v", err)
	}
	raw, err := QC{}.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	// Flip the view to 1 without adding signatures.
	raw[5] = 1
	if _, err := UnmarshalQC(raw); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-canonical empty: %v", err)
	}
}

func TestEventLayoutAndRoundTrip(t *testing.T) {
	ev := sampleEvent()
	body, err := ev.signingBytes()
	if err != nil {
		t.Fatal(err)
	}
	want := manualEventBody(ev)
	if !bytes.Equal(body, want) {
		t.Fatalf("layout\n got %x\nwant %x", body, want)
	}
	raw, err := ev.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw[:len(body)], body) {
		t.Fatal("signature was not a suffix")
	}
	got, err := UnmarshalEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := got.MarshalBinary()
	if err != nil || !bytes.Equal(again, raw) {
		t.Fatalf("round trip %v", err)
	}
	id1, err := ev.ID()
	if err != nil {
		t.Fatal(err)
	}
	ev.Signature[0] ^= 0xff
	id2, err := ev.ID()
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatal("signature changed the event id")
	}
	ev.Subject = append([]byte{}, ev.Subject...)
	ev.Subject[0] ^= 0xff
	id3, err := ev.ID()
	if err != nil {
		t.Fatal(err)
	}
	if id3 == id1 {
		t.Fatal("subject did not change the event id")
	}
}

func TestEventRejects(t *testing.T) {
	ev := sampleEvent()
	ev.Subject = nil
	if _, err := ev.MarshalBinary(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty subject: %v", err)
	}
	ev = sampleEvent()
	ev.EventType = 0
	if _, err := ev.signingBytes(); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	ev = sampleEvent()
	ev.ReadPolicy = 0
	if _, err := ev.signingBytes(); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	ev = sampleEvent()
	ev.DocHashes[0].Alg = 9
	if _, err := ev.signingBytes(); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	raw, err := sampleEvent().MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	raw[4] = 0 // version byte's neighbour: flip the version high... header is type then version
	// version is bytes 2 and 3. Set version to 2.
	raw[2], raw[3] = 0, 2
	if _, err := UnmarshalEvent(raw); !errors.Is(err, codec.ErrVersion) {
		t.Fatalf("version: %v", err)
	}
}

func TestBlockRoundTrip(t *testing.T) {
	b := sampleBlock()
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := b.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalBlock(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := got.MarshalBinary()
	if err != nil || !bytes.Equal(again, raw) {
		t.Fatal(err)
	}
	got.Header.EventsRoot[0] ^= 0xff
	if err := got.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad root: %v", err)
	}
}

func TestGenesisHeaderRules(t *testing.T) {
	h := sampleBlock().Header
	if err := h.Validate(); err != nil {
		t.Fatal(err)
	}
	h.ParentHash[0] = 1
	if err := h.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	h = sampleBlock().Header
	h.Height = 1
	if err := h.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

func TestInt64Edges(t *testing.T) {
	ev := sampleEvent()
	for _, tm := range []int64{math.MinInt64, -1, 0, 1, math.MaxInt64} {
		ev.ClaimedTime = tm
		raw, err := ev.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		got, err := UnmarshalEvent(raw)
		if err != nil || got.ClaimedTime != tm {
			t.Fatalf("%d: %v %d", tm, err, got.ClaimedTime)
		}
	}
}

func sampleEvent() Event {
	var chain, writer, prev, doc [crypto.DigestSize]byte
	chain[0] = 1
	writer[0] = 2
	prev[0] = 3
	doc[0] = 4
	return Event{
		ChainID:     chain,
		EventType:   EventShipmentDispatched,
		Subject:     []byte("PN-123"),
		Status:      7,
		PrevEvent:   prev,
		DocHashes:   []DocHash{SHA3Doc(doc)},
		ClaimedTime: 42,
		WriterID:    writer,
		Nonce:       1,
		ReadPolicy:  ReadAllMembers,
		Signature:   bytes.Repeat([]byte{0x11}, crypto.MLDSASignatureSize()),
	}
}

func sampleBlock() Block {
	ev := sampleEvent()
	id, err := ev.ID()
	if err != nil {
		panic(err)
	}
	root, err := merkle.Root([][crypto.DigestSize]byte{id})
	if err != nil {
		panic(err)
	}
	return Block{
		Header: BlockHeader{
			ChainID:      ev.ChainID,
			Height:       0,
			View:         1,
			EventsRoot:   root,
			StateRoot:    id,
			ProposerID:   ev.WriterID,
			ProposerTime: ev.ClaimedTime,
		},
		Events:      []Event{ev},
		ProposerSig: bytes.Repeat([]byte{0x22}, crypto.MLDSASignatureSize()),
	}
}

func manualEventBody(ev Event) []byte {
	var buf []byte
	buf = binary.BigEndian.AppendUint16(buf, TypeEvent)
	buf = binary.BigEndian.AppendUint16(buf, Version)
	buf = append(buf, ev.ChainID[:]...)
	buf = binary.BigEndian.AppendUint16(buf, ev.EventType)
	buf = append(buf, byte(len(ev.Subject)))
	buf = append(buf, ev.Subject...)
	buf = binary.BigEndian.AppendUint16(buf, ev.Status)
	buf = append(buf, ev.PrevEvent[:]...)
	buf = append(buf, byte(len(ev.DocHashes)))
	for _, h := range ev.DocHashes {
		buf = append(buf, h.Alg)
		buf = append(buf, h.Sum[:]...)
	}
	var num [8]byte
	binary.BigEndian.PutUint64(num[:], uint64(ev.ClaimedTime))
	buf = append(buf, num[:]...)
	buf = append(buf, ev.WriterID[:]...)
	binary.BigEndian.PutUint64(num[:], ev.Nonce)
	buf = append(buf, num[:]...)
	buf = binary.BigEndian.AppendUint16(buf, ev.ReadPolicy)
	return buf
}
