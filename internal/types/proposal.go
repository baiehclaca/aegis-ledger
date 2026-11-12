package types

import (
	"fmt"

	"github.com/silvergreyhound/silver-grey-ledger/internal/codec"
)

// Proposal is a signed block plus the timeout certificate that justifies
// a view jump. When the block's view is exactly one higher than its
// justify certificate, TC is the empty certificate: the quorum
// certificate alone is the justification.
type Proposal struct {
	Block Block
	TC    TC
}

// MarshalBinary encodes a proposal.
func (p Proposal) MarshalBinary() ([]byte, error) {
	block, err := p.Block.MarshalBinary()
	if err != nil {
		return nil, err
	}
	tc, err := p.TC.MarshalBinary()
	if err != nil {
		return nil, err
	}
	e := codec.NewEncoder()
	e.Header(TypeProposal, Version)
	e.Fixed(block)
	e.Fixed(tc)
	return e.Bytes(), nil
}

// UnmarshalProposal decodes a proposal. Signatures are not checked.
func UnmarshalProposal(b []byte) (Proposal, error) {
	d := codec.NewDecoder(b)
	if err := d.ExpectHeader(TypeProposal, Version); err != nil {
		return Proposal{}, err
	}
	block, err := decodeBlock(d)
	if err != nil {
		return Proposal{}, err
	}
	tc, err := decodeTC(d)
	if err != nil {
		return Proposal{}, err
	}
	if err := d.Finish(); err != nil {
		return Proposal{}, err
	}
	return Proposal{Block: block, TC: tc}, nil
}

// Consecutive reports whether the block view follows its justify view
// with no gap. A consecutive proposal carries an empty timeout certificate.
func (p Proposal) Consecutive() (bool, error) {
	if p.Block.Header.Height == 0 {
		return false, fmt.Errorf("types: genesis is not a proposal: %w", ErrInvalid)
	}
	return p.Block.Header.View == p.Block.Header.Justify.View+1, nil
}
