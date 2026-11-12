package types

import (
	"fmt"

	"github.com/silvergreyhound/silver-grey-ledger/internal/codec"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/merkle"
)

// InclusionProof is the offline evidence that an event sits in a block.
// CommitQC is the certificate the next block carries for this block.
// One certificate shows the block was certified. HotStuff-2 finality is
// the two-chain rule and is not claimed here.
type InclusionProof struct {
	Event     Event
	Index     uint64
	LeafCount uint64
	Siblings  [][crypto.DigestSize]byte
	Header    BlockHeader
	CommitQC  QC
}

// MarshalBinary encodes the proof.
func (p InclusionProof) MarshalBinary() ([]byte, error) {
	if err := p.checkShape(); err != nil {
		return nil, err
	}
	if err := p.Header.checkFields(); err != nil {
		return nil, err
	}
	e := codec.NewEncoder()
	e.Header(TypeInclusionProof, Version)
	ev, err := p.Event.MarshalBinary()
	if err != nil {
		return nil, err
	}
	e.Fixed(ev)
	e.Uint64(p.Index)
	e.Uint64(p.LeafCount)
	e.Length(len(p.Siblings))
	for _, s := range p.Siblings {
		e.Fixed(s[:])
	}
	if err := encodeHeader(e, p.Header); err != nil {
		return nil, err
	}
	if err := encodeQC(e, p.CommitQC); err != nil {
		return nil, err
	}
	return e.Bytes(), nil
}

// UnmarshalInclusionProof decodes a proof. Signatures and the Merkle
// root are checked by the verifier, not here.
func UnmarshalInclusionProof(b []byte) (InclusionProof, error) {
	d := codec.NewDecoder(b)
	if err := d.ExpectHeader(TypeInclusionProof, Version); err != nil {
		return InclusionProof{}, err
	}
	ev, err := decodeEvent(d)
	if err != nil {
		return InclusionProof{}, err
	}
	var p InclusionProof
	p.Event = ev
	if p.Index, err = d.Uint64(); err != nil {
		return InclusionProof{}, err
	}
	if p.LeafCount, err = d.Uint64(); err != nil {
		return InclusionProof{}, err
	}
	n, err := d.Length(MaxMerkleSiblings)
	if err != nil {
		return InclusionProof{}, err
	}
	p.Siblings = make([][crypto.DigestSize]byte, n)
	for i := range p.Siblings {
		p.Siblings[i], err = d.Hash()
		if err != nil {
			return InclusionProof{}, err
		}
	}
	if p.Header, err = decodeHeader(d); err != nil {
		return InclusionProof{}, err
	}
	if p.CommitQC, err = decodeQC(d); err != nil {
		return InclusionProof{}, err
	}
	if err := d.Finish(); err != nil {
		return InclusionProof{}, err
	}
	if err := p.checkShape(); err != nil {
		return InclusionProof{}, err
	}
	return p, nil
}

func (p InclusionProof) checkShape() error {
	if p.LeafCount == 0 || p.LeafCount > uint64(MaxEventsPerBlock) {
		return fmt.Errorf("types: leaf count: %w", ErrInvalid)
	}
	if p.Index >= p.LeafCount {
		return fmt.Errorf("types: leaf index: %w", ErrInvalid)
	}
	if len(p.Siblings) > MaxMerkleSiblings {
		return fmt.Errorf("types: merkle path: %w", ErrInvalid)
	}
	if p.CommitQC.IsEmpty() {
		return fmt.Errorf("types: inclusion proof needs a commit QC: %w", ErrInvalid)
	}
	return nil
}

// MerkleOK reports whether the event id sits at Index under Header.EventsRoot.
func (p InclusionProof) MerkleOK(eventID [crypto.DigestSize]byte) error {
	if err := p.checkShape(); err != nil {
		return err
	}
	return merkle.Verify(eventID, int(p.Index), int(p.LeafCount), p.Siblings, p.Header.EventsRoot)
}
