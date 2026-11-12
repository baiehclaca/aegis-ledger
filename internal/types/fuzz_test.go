package types

import (
	"bytes"
	"testing"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
)

func FuzzEvent(f *testing.F) {
	raw, err := sampleEvent().MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Fuzz(func(t *testing.T, data []byte) {
		ev, err := UnmarshalEvent(data)
		if err != nil {
			return
		}
		out, err := ev.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, data) {
			t.Fatal("accepted a non-canonical event")
		}
	})
}

func FuzzBlockHeader(f *testing.F) {
	raw, err := sampleBlock().Header.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := UnmarshalBlockHeader(data)
		if err != nil {
			return
		}
		out, err := h.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, data) {
			t.Fatal("accepted a non-canonical header")
		}
	})
}

func FuzzQC(f *testing.F) {
	raw, err := QC{}.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Fuzz(func(t *testing.T, data []byte) {
		q, err := UnmarshalQC(data)
		if err != nil {
			return
		}
		out, err := q.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, data) {
			t.Fatal("accepted a non-canonical QC")
		}
	})
}

func FuzzBlock(f *testing.F) {
	raw, err := sampleBlock().MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := UnmarshalBlock(data)
		if err != nil {
			return
		}
		out, err := b.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, data) {
			t.Fatal("accepted a non-canonical block")
		}
	})
}

func FuzzInclusionProof(f *testing.F) {
	b := sampleBlock()
	q := QC{
		View:         b.Header.View,
		BlockHash:    b.Header.EventsRoot,
		SignerBitmap: 1,
		Signatures:   [][]byte{bytes.Repeat([]byte{0x33}, crypto.MLDSASignatureSize())},
	}
	p := InclusionProof{
		Event:     b.Events[0],
		Index:     0,
		LeafCount: 1,
		Header:    b.Header,
		CommitQC:  q,
	}
	raw, err := p.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := UnmarshalInclusionProof(data)
		if err != nil {
			return
		}
		out, err := got.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, data) {
			t.Fatal("accepted a non-canonical proof")
		}
	})
}

func FuzzPublicKey(f *testing.F) {
	priv, err := crypto.GenerateMLDSA65()
	if err != nil {
		f.Fatal(err)
	}
	pub, err := priv.Public()
	if err != nil {
		f.Fatal(err)
	}
	raw, err := MarshalPublicKey(pub)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Fuzz(func(t *testing.T, data []byte) {
		pk, err := UnmarshalPublicKey(data)
		if err != nil {
			return
		}
		out, err := MarshalPublicKey(pk)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, data) {
			t.Fatal("accepted a non-canonical public key")
		}
	})
}

func FuzzValidatorSet(f *testing.F) {
	priv, err := crypto.GenerateMLDSA65()
	if err != nil {
		f.Fatal(err)
	}
	pub, err := priv.Public()
	if err != nil {
		f.Fatal(err)
	}
	raw, err := (ValidatorSet{Keys: []crypto.PublicKey{pub}}).MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Fuzz(func(t *testing.T, data []byte) {
		set, err := UnmarshalValidatorSet(data)
		if err != nil {
			return
		}
		out, err := set.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, data) {
			t.Fatal("accepted a non-canonical validator set")
		}
	})
}

func FuzzVote(f *testing.F) {
	raw := voteBytes(f, 1)
	f.Add(raw)
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := UnmarshalVote(data)
		if err != nil {
			return
		}
		out, err := v.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, data) {
			t.Fatal("accepted a non-canonical vote")
		}
	})
}

func FuzzTimeout(f *testing.F) {
	sig := bytes.Repeat([]byte{0x5a}, crypto.MLDSASignatureSize())
	raw, err := (Timeout{View: 1, Signer: 2, Signature: sig}).MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := UnmarshalTimeout(data)
		if err != nil {
			return
		}
		out, err := msg.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, data) {
			t.Fatal("accepted a non-canonical timeout")
		}
	})
}

func FuzzTC(f *testing.F) {
	raw, err := (TC{}).MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Fuzz(func(t *testing.T, data []byte) {
		tc, err := UnmarshalTC(data)
		if err != nil {
			return
		}
		out, err := tc.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, data) {
			t.Fatal("accepted a non-canonical timeout certificate")
		}
	})
}

func FuzzProposal(f *testing.F) {
	p := Proposal{Block: sampleBlock()}
	raw, err := p.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Fuzz(func(t *testing.T, data []byte) {
		prop, err := UnmarshalProposal(data)
		if err != nil {
			return
		}
		out, err := prop.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, data) {
			t.Fatal("accepted a non-canonical proposal")
		}
	})
}

func FuzzEquivocation(f *testing.F) {
	a := voteBytes(f, 1)
	b := voteBytes(f, 2)
	raw, err := (Equivocation{Kind: EquivocationVote, First: a, Second: b}).MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Fuzz(func(t *testing.T, data []byte) {
		e, err := UnmarshalEquivocation(data)
		if err != nil {
			return
		}
		out, err := e.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, data) {
			t.Fatal("accepted a non-canonical equivocation proof")
		}
	})
}

func FuzzGovTx(f *testing.F) {
	key, err := crypto.GenerateMLDSA65()
	if err != nil {
		f.Fatal(err)
	}
	pub, err := key.Public()
	if err != nil {
		f.Fatal(err)
	}
	var chain [crypto.DigestSize]byte
	chain[0] = 1
	id, err := pub.ID()
	if err != nil {
		f.Fatal(err)
	}
	tx := GovTx{ChainID: chain, Actions: []GovAction{{Kind: GovRevokeKey, KeyID: id}}}
	if err := tx.SignAdmin(key); err != nil {
		f.Fatal(err)
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := UnmarshalGovTx(data)
		if err != nil {
			return
		}
		out, err := got.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, data) {
			t.Fatal("accepted a non-canonical governance transaction")
		}
	})
}

func FuzzGenesis(f *testing.F) {
	g := signTestGenesis(f, 7)
	raw, err := g.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := UnmarshalGenesis(data)
		if err != nil {
			return
		}
		out, err := got.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, data) {
			t.Fatal("accepted a non-canonical genesis")
		}
	})
}
