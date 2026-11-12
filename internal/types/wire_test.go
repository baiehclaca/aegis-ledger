package types

import (
	"bytes"
	"slices"
	"testing"
	"testing/quick"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
)

func TestVoteRoundTrip(t *testing.T) {
	cfg := &quick.Config{MaxCount: 40}
	err := quick.Check(func(view uint64, signer uint8, b0 byte) bool {
		v := Vote{
			View:      view,
			Signer:    signer % MaxValidators,
			Signature: bytes.Repeat([]byte{0x5a}, crypto.MLDSASignatureSize()),
		}
		v.ChainID[0] = b0
		v.BlockHash[1] = b0
		raw, err := v.MarshalBinary()
		if err != nil {
			return false
		}
		got, err := UnmarshalVote(raw)
		if err != nil {
			return false
		}
		again, err := got.MarshalBinary()
		return err == nil && bytes.Equal(raw, again) && got.View == v.View && got.Signer == v.Signer
	}, cfg)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVoteSignerLimit(t *testing.T) {
	v := Vote{Signer: MaxValidators, Signature: bytes.Repeat([]byte{1}, crypto.MLDSASignatureSize())}
	if _, err := v.MarshalBinary(); err == nil {
		t.Fatal("accepted a signer past the bitmap")
	}
}

func TestTimeoutRoundTrip(t *testing.T) {
	cfg := &quick.Config{MaxCount: 20}
	err := quick.Check(func(view uint64, signer uint8, b0 byte) bool {
		if view == 0 {
			view = 1
		}
		to := Timeout{
			View:      view,
			Signer:    signer % MaxValidators,
			Signature: bytes.Repeat([]byte{0x5a}, crypto.MLDSASignatureSize()),
		}
		to.ChainID[0] = b0
		raw, err := to.MarshalBinary()
		if err != nil {
			return false
		}
		got, err := UnmarshalTimeout(raw)
		if err != nil {
			return false
		}
		again, err := got.MarshalBinary()
		return err == nil && bytes.Equal(raw, again) && got.View == view
	}, cfg)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTimeoutRejectsViewZeroAndSigner(t *testing.T) {
	sig := bytes.Repeat([]byte{1}, crypto.MLDSASignatureSize())
	if _, err := (Timeout{View: 0, Signature: sig}).MarshalBinary(); err == nil {
		t.Fatal("accepted a timeout of the genesis view")
	}
	if _, err := (Timeout{View: 1, Signer: MaxValidators, Signature: sig}).MarshalBinary(); err == nil {
		t.Fatal("accepted a timeout signer past the bitmap")
	}
}

func TestEmptyTCRoundTrip(t *testing.T) {
	raw, err := (TC{}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalTC(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsEmpty() {
		t.Fatal("empty certificate gained a timeout")
	}
	again, err := got.MarshalBinary()
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal(err)
	}
	if _, err := (TC{View: 1}).MarshalBinary(); err == nil {
		t.Fatal("accepted an empty certificate with a non-zero view")
	}
}

func TestProposalRoundTrip(t *testing.T) {
	var parent, chain, proposer [crypto.DigestSize]byte
	parent[0] = 3
	chain[0] = 4
	proposer[0] = 5
	sig := bytes.Repeat([]byte{2}, crypto.MLDSASignatureSize())
	p := Proposal{
		Block: Block{
			Header: BlockHeader{
				ChainID:    chain,
				Height:     1,
				View:       2,
				ParentHash: parent,
				Justify:    QC{View: 1, BlockHash: parent, SignerBitmap: 1, Signatures: [][]byte{sig}},
				ProposerID: proposer,
			},
			ProposerSig: sig,
		},
	}
	raw, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalProposal(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := got.MarshalBinary()
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatalf("proposal bytes changed: %v", err)
	}
	consec, err := got.Consecutive()
	if err != nil || !consec {
		t.Fatalf("consecutive: %v %v", consec, err)
	}
	genesis := Proposal{Block: sampleBlock()}
	if _, err := genesis.Consecutive(); err == nil {
		t.Fatal("a height-0 block was treated as a proposal")
	}
}

func TestEquivocationRoundTrip(t *testing.T) {
	a := voteBytes(t, 1)
	b := voteBytes(t, 2)
	e := Equivocation{Kind: EquivocationVote, First: a, Second: b}
	raw, err := e.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalEquivocation(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := got.MarshalBinary()
	if err != nil || !bytes.Equal(raw, again) || got.Kind != EquivocationVote {
		t.Fatal(err)
	}
	if _, err := (Equivocation{Kind: 9, First: a, Second: b}).MarshalBinary(); err == nil {
		t.Fatal("accepted an unknown equivocation kind")
	}
	if _, err := (Equivocation{Kind: EquivocationVote, First: a, Second: a}).MarshalBinary(); err == nil {
		t.Fatal("accepted identical messages")
	}
}

func TestGenesisRoundTrip(t *testing.T) {
	g := signTestGenesis(t, 42)
	raw, err := g.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalGenesis(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Verify(); err != nil {
		t.Fatal(err)
	}
	again, err := got.MarshalBinary()
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("genesis bytes changed")
	}
	id, err := g.ChainID()
	if err != nil {
		t.Fatal(err)
	}
	gotID, err := got.ChainID()
	if err != nil || gotID != id || gotID == [crypto.DigestSize]byte{} {
		t.Fatal("chain id changed")
	}
	var zero [crypto.DigestSize]byte
	if id == zero {
		t.Fatal("chain id is zero")
	}
}

func voteBytes(t testing.TB, mark byte) []byte {
	t.Helper()
	v := Vote{
		View:      uint64(mark),
		Signer:    1,
		Signature: bytes.Repeat([]byte{mark}, crypto.MLDSASignatureSize()),
	}
	v.BlockHash[0] = mark
	raw, err := v.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// signTestGenesis is two SLH-DSA founders and four ML-DSA-65 seats.
func signTestGenesis(tb testing.TB, created int64) Genesis {
	tb.Helper()
	founders := make([]crypto.PrivateKey, MinFounders)
	fs := make([]Founder, MinFounders)
	for i := range founders {
		key, err := crypto.GenerateSLHDSA(nil)
		if err != nil {
			tb.Fatal(err)
		}
		founders[i] = key
		pub, err := key.Public()
		if err != nil {
			tb.Fatal(err)
		}
		fs[i] = Founder{Org: []string{"founding-0", "founding-1"}[i], Key: pub}
	}
	seats := make([]Seat, 4)
	grants := make([]Grant, 4)
	kinds := []uint16{EventShipmentDispatched, EventClearanceGranted, EventAccessLogin}
	for i := range seats {
		key, err := crypto.GenerateMLDSA65()
		if err != nil {
			tb.Fatal(err)
		}
		pub, err := key.Public()
		if err != nil {
			tb.Fatal(err)
		}
		org := fs[i%len(fs)].Org
		seats[i] = Seat{Key: pub, Org: org, Address: "local"}
		grants[i] = Grant{Key: pub, Org: org, Roles: RoleKnown, EventTypes: append([]uint16(nil), kinds...)}
	}
	slices.SortFunc(grants, func(a, b Grant) int {
		aid, _ := a.Key.ID()
		bid, _ := b.Key.ID()
		return bytes.Compare(aid[:], bid[:])
	})
	th, err := DefaultThreshold(len(fs))
	if err != nil {
		tb.Fatal(err)
	}
	g := Genesis{
		Created:    created,
		EpochDelay: 2,
		Threshold:  th,
		Founders:   fs,
		Seats:      seats,
		Grants:     grants,
		Registry: []RegEntry{
			{Type: EventShipmentDispatched, Name: "shipment"},
			{Type: EventClearanceGranted, Name: "clearance"},
			{Type: EventAccessLogin, Name: "access"},
		},
	}
	if err := g.Sign(founders); err != nil {
		tb.Fatal(err)
	}
	return g
}
