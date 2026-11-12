package types

import (
	"bytes"
	"fmt"

	"github.com/silvergreyhound/silver-grey-ledger/internal/codec"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
)

// Equivocation kinds. A proof contains two signed messages from one
// validator in one view that name different blocks.
const (
	EquivocationVote     uint8 = 1
	EquivocationProposal uint8 = 2
	EquivocationTimeout  uint8 = 3
)

// Equivocation is stored evidence. First and Second are canonical
// encodings of the two messages. Governance consumes the proof later;
// M1 only builds and checks it.
type Equivocation struct {
	Kind   uint8
	First  []byte
	Second []byte
}

// MaxEvidenceBytes bounds one side of a proof. It is large enough for a
// block header plus a quorum certificate, and small enough that a
// decoder will not allocate without a limit.
const MaxEvidenceBytes = 1 << 20

// MarshalBinary encodes a proof.
func (e Equivocation) MarshalBinary() ([]byte, error) {
	if err := e.checkShape(); err != nil {
		return nil, err
	}
	enc := codec.NewEncoder()
	enc.Header(TypeEquivocation, Version)
	enc.Uint8(e.Kind)
	enc.BytesField(e.First)
	enc.BytesField(e.Second)
	return enc.Bytes(), nil
}

// UnmarshalEquivocation decodes a proof. Verify checks the signatures.
func UnmarshalEquivocation(b []byte) (Equivocation, error) {
	d := codec.NewDecoder(b)
	if err := d.ExpectHeader(TypeEquivocation, Version); err != nil {
		return Equivocation{}, err
	}
	var e Equivocation
	var err error
	if e.Kind, err = d.Uint8(); err != nil {
		return Equivocation{}, err
	}
	if e.First, err = d.BytesField(MaxEvidenceBytes); err != nil {
		return Equivocation{}, err
	}
	if e.Second, err = d.BytesField(MaxEvidenceBytes); err != nil {
		return Equivocation{}, err
	}
	if err := d.Finish(); err != nil {
		return Equivocation{}, err
	}
	if err := e.checkShape(); err != nil {
		return Equivocation{}, err
	}
	return e, nil
}

// Verify checks that the two messages are signed by one validator, share
// a view, and name different blocks.
func (e Equivocation) Verify(keys []crypto.PublicKey) error {
	if err := e.checkShape(); err != nil {
		return err
	}
	switch e.Kind {
	case EquivocationVote:
		return verifyVoteEquivocation(e, keys)
	case EquivocationProposal:
		return verifyProposalEquivocation(e, keys)
	case EquivocationTimeout:
		return verifyTimeoutEquivocation(e, keys)
	default:
		return fmt.Errorf("types: equivocation kind: %w", ErrInvalid)
	}
}

func verifyVoteEquivocation(e Equivocation, keys []crypto.PublicKey) error {
	a, err := UnmarshalVote(e.First)
	if err != nil {
		return err
	}
	b, err := UnmarshalVote(e.Second)
	if err != nil {
		return err
	}
	if a.Signer != b.Signer || a.View != b.View || a.ChainID != b.ChainID {
		return fmt.Errorf("types: vote equivocation identity: %w", ErrInvalid)
	}
	if a.BlockHash == b.BlockHash {
		return fmt.Errorf("types: vote equivocation is the same block: %w", ErrInvalid)
	}
	if err := a.Verify(keys); err != nil {
		return err
	}
	if err := b.Verify(keys); err != nil {
		return err
	}
	return nil
}

func verifyProposalEquivocation(e Equivocation, keys []crypto.PublicKey) error {
	a, err := UnmarshalProposal(e.First)
	if err != nil {
		return err
	}
	b, err := UnmarshalProposal(e.Second)
	if err != nil {
		return err
	}
	ha, err := a.Block.Header.Hash()
	if err != nil {
		return err
	}
	hb, err := b.Block.Header.Hash()
	if err != nil {
		return err
	}
	if ha == hb {
		return fmt.Errorf("types: proposal equivocation is the same block: %w", ErrInvalid)
	}
	if a.Block.Header.View != b.Block.Header.View || a.Block.Header.ChainID != b.Block.Header.ChainID || a.Block.Header.ProposerID != b.Block.Header.ProposerID {
		return fmt.Errorf("types: proposal equivocation identity: %w", ErrInvalid)
	}
	pub, err := proposerKey(keys, a.Block.Header.ProposerID)
	if err != nil {
		return err
	}
	if err := a.Block.VerifyProposer(pub); err != nil {
		return err
	}
	if err := b.Block.VerifyProposer(pub); err != nil {
		return err
	}
	return nil
}

func verifyTimeoutEquivocation(e Equivocation, keys []crypto.PublicKey) error {
	a, err := UnmarshalTimeout(e.First)
	if err != nil {
		return err
	}
	b, err := UnmarshalTimeout(e.Second)
	if err != nil {
		return err
	}
	if a.Signer != b.Signer || a.View != b.View || a.ChainID != b.ChainID {
		return fmt.Errorf("types: timeout equivocation identity: %w", ErrInvalid)
	}
	if a.HighQC.View == b.HighQC.View && a.HighQC.BlockHash == b.HighQC.BlockHash {
		return fmt.Errorf("types: timeout equivocation names one certificate: %w", ErrInvalid)
	}
	if err := a.Verify(keys); err != nil {
		return err
	}
	if err := b.Verify(keys); err != nil {
		return err
	}
	return nil
}

func proposerKey(keys []crypto.PublicKey, id [crypto.DigestSize]byte) (crypto.PublicKey, error) {
	for _, k := range keys {
		got, err := k.ID()
		if err != nil {
			return crypto.PublicKey{}, err
		}
		if got == id {
			return k, nil
		}
	}
	return crypto.PublicKey{}, fmt.Errorf("types: proposer is not a validator: %w", ErrInvalid)
}

func (e Equivocation) checkShape() error {
	switch e.Kind {
	case EquivocationVote, EquivocationProposal, EquivocationTimeout:
	default:
		return fmt.Errorf("types: equivocation kind: %w", ErrInvalid)
	}
	if len(e.First) == 0 || len(e.Second) == 0 || len(e.First) > MaxEvidenceBytes || len(e.Second) > MaxEvidenceBytes {
		return fmt.Errorf("types: equivocation size: %w", ErrInvalid)
	}
	if bytes.Equal(e.First, e.Second) {
		return fmt.Errorf("types: equivocation messages are identical: %w", ErrInvalid)
	}
	return nil
}
