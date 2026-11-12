package types

import (
	"fmt"

	"github.com/silvergreyhound/silver-grey-ledger/internal/codec"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
)

// Vote is one validator's signature over a block in a view. The digest
// is VoteDigest, the same bytes a quorum certificate checks, so a vote
// can be aggregated without reinterpreting it.
type Vote struct {
	ChainID   [crypto.DigestSize]byte
	View      uint64
	BlockHash [crypto.DigestSize]byte
	Signer    uint8
	Signature []byte
}

// Sign sets Signature with the vote context.
func (v *Vote) Sign(key crypto.PrivateKey) error {
	if key.Algorithm() != crypto.AlgMLDSA65 {
		return fmt.Errorf("types: vote key must be ML-DSA-65: %w", ErrSignature)
	}
	sum := VoteDigest(v.ChainID, v.View, v.BlockHash)
	sig, err := key.SignDigest(sum, crypto.ContextVote)
	if err != nil {
		return err
	}
	v.Signature = sig
	return nil
}

// Verify checks the signature against the validator key at Signer.
func (v Vote) Verify(keys []crypto.PublicKey) error {
	if int(v.Signer) >= len(keys) {
		return fmt.Errorf("types: vote signer: %w", ErrInvalid)
	}
	sum := VoteDigest(v.ChainID, v.View, v.BlockHash)
	if err := crypto.VerifyDigest(keys[v.Signer], sum, v.Signature, crypto.ContextVote); err != nil {
		return fmt.Errorf("types: vote signature: %w", ErrSignature)
	}
	return nil
}

// MarshalBinary encodes a vote.
func (v Vote) MarshalBinary() ([]byte, error) {
	if err := v.check(); err != nil {
		return nil, err
	}
	e := codec.NewEncoder()
	v.encode(e)
	return e.Bytes(), nil
}

// UnmarshalVote decodes a vote. The signature is not checked.
func UnmarshalVote(b []byte) (Vote, error) {
	d := codec.NewDecoder(b)
	v, err := decodeVote(d)
	if err != nil {
		return Vote{}, err
	}
	if err := d.Finish(); err != nil {
		return Vote{}, err
	}
	return v, nil
}

func (v Vote) encode(e *codec.Encoder) {
	e.Header(TypeVote, Version)
	e.Fixed(v.ChainID[:])
	e.Uint64(v.View)
	e.Fixed(v.BlockHash[:])
	e.Uint8(v.Signer)
	e.Fixed(v.Signature)
}

func decodeVote(d *codec.Decoder) (Vote, error) {
	if err := d.ExpectHeader(TypeVote, Version); err != nil {
		return Vote{}, err
	}
	var v Vote
	var err error
	if v.ChainID, err = d.Hash(); err != nil {
		return Vote{}, err
	}
	if v.View, err = d.Uint64(); err != nil {
		return Vote{}, err
	}
	if v.BlockHash, err = d.Hash(); err != nil {
		return Vote{}, err
	}
	if v.Signer, err = d.Uint8(); err != nil {
		return Vote{}, err
	}
	if v.Signature, err = d.Fixed(crypto.MLDSASignatureSize()); err != nil {
		return Vote{}, err
	}
	if err := v.check(); err != nil {
		return Vote{}, err
	}
	return v, nil
}

func (v Vote) check() error {
	if len(v.Signature) != crypto.MLDSASignatureSize() {
		return fmt.Errorf("types: vote signature length: %w", ErrInvalid)
	}
	if int(v.Signer) >= MaxValidators {
		return fmt.Errorf("types: vote signer: %w", ErrInvalid)
	}
	return nil
}
