package types

import (
	"fmt"

	"github.com/silvergreyhound/silver-grey-ledger/internal/codec"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
)

// Timeout is a validator's signed wish to leave a view. HighQC is the
// highest quorum certificate that validator knew; an empty certificate
// means it knew none. The signature covers the canonical body, so a
// different certificate is a different signed message.
type Timeout struct {
	ChainID   [crypto.DigestSize]byte
	View      uint64
	Signer    uint8
	HighQC    QC
	Signature []byte
}

// Digest is SHA3-256("silvergrey/timeout" || canonical body).
func (t Timeout) Digest() ([crypto.DigestSize]byte, error) {
	body, err := t.signingBytes()
	if err != nil {
		return [crypto.DigestSize]byte{}, err
	}
	return crypto.DomainSum(crypto.DomainTimeout, body), nil
}

// Sign sets Signature with the timeout context.
func (t *Timeout) Sign(key crypto.PrivateKey) error {
	if key.Algorithm() != crypto.AlgMLDSA65 {
		return fmt.Errorf("types: timeout key must be ML-DSA-65: %w", ErrSignature)
	}
	sum, err := t.Digest()
	if err != nil {
		return err
	}
	sig, err := key.SignDigest(sum, crypto.ContextTimeout)
	if err != nil {
		return err
	}
	t.Signature = sig
	return nil
}

// Verify checks the timeout signature and, when HighQC carries
// signatures, those signatures too.
func (t Timeout) Verify(keys []crypto.PublicKey) error {
	if err := t.check(); err != nil {
		return err
	}
	if int(t.Signer) >= len(keys) {
		return fmt.Errorf("types: timeout signer: %w", ErrInvalid)
	}
	if !t.HighQC.IsEmpty() {
		if err := t.HighQC.Verify(t.ChainID, keys); err != nil {
			return err
		}
	}
	sum, err := t.Digest()
	if err != nil {
		return err
	}
	if err := crypto.VerifyDigest(keys[t.Signer], sum, t.Signature, crypto.ContextTimeout); err != nil {
		return fmt.Errorf("types: timeout signature: %w", ErrSignature)
	}
	return nil
}

// MarshalBinary encodes a timeout.
func (t Timeout) MarshalBinary() ([]byte, error) {
	body, err := t.signingBytes()
	if err != nil {
		return nil, err
	}
	if len(t.Signature) != crypto.MLDSASignatureSize() {
		return nil, fmt.Errorf("types: timeout signature length: %w", ErrInvalid)
	}
	out := make([]byte, 0, len(body)+len(t.Signature))
	out = append(out, body...)
	out = append(out, t.Signature...)
	return out, nil
}

// UnmarshalTimeout decodes a timeout. Signatures are not checked.
func UnmarshalTimeout(b []byte) (Timeout, error) {
	d := codec.NewDecoder(b)
	t, err := decodeTimeout(d)
	if err != nil {
		return Timeout{}, err
	}
	if err := d.Finish(); err != nil {
		return Timeout{}, err
	}
	return t, nil
}

func (t Timeout) signingBytes() ([]byte, error) {
	if err := t.checkBody(); err != nil {
		return nil, err
	}
	e := codec.NewEncoder()
	e.Header(TypeTimeout, Version)
	e.Fixed(t.ChainID[:])
	e.Uint64(t.View)
	e.Uint8(t.Signer)
	if err := encodeQC(e, t.HighQC); err != nil {
		return nil, err
	}
	return e.Bytes(), nil
}

func decodeTimeout(d *codec.Decoder) (Timeout, error) {
	if err := d.ExpectHeader(TypeTimeout, Version); err != nil {
		return Timeout{}, err
	}
	var t Timeout
	var err error
	if t.ChainID, err = d.Hash(); err != nil {
		return Timeout{}, err
	}
	if t.View, err = d.Uint64(); err != nil {
		return Timeout{}, err
	}
	if t.Signer, err = d.Uint8(); err != nil {
		return Timeout{}, err
	}
	if t.HighQC, err = decodeQC(d); err != nil {
		return Timeout{}, err
	}
	if t.Signature, err = d.Fixed(crypto.MLDSASignatureSize()); err != nil {
		return Timeout{}, err
	}
	if err := t.check(); err != nil {
		return Timeout{}, err
	}
	return t, nil
}

func (t Timeout) check() error {
	if err := t.checkBody(); err != nil {
		return err
	}
	if len(t.Signature) != crypto.MLDSASignatureSize() {
		return fmt.Errorf("types: timeout signature length: %w", ErrInvalid)
	}
	return nil
}

func (t Timeout) checkBody() error {
	// View 0 is the genesis view. There is nothing to time out of.
	if t.View == 0 {
		return fmt.Errorf("types: timeout view: %w", ErrInvalid)
	}
	if int(t.Signer) >= MaxValidators {
		return fmt.Errorf("types: timeout signer: %w", ErrInvalid)
	}
	return t.HighQC.check()
}
