package types

import (
	"fmt"

	"github.com/silvergreyhound/silver-grey-ledger/internal/codec"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
)

// ValidatorSet is the ordered set a quorum bitmap indexes. Order is
// the membership order; it is part of the certificate, not a display
// preference.
type ValidatorSet struct {
	Keys []crypto.PublicKey
}

// MarshalBinary encodes the set. Every key must be ML-DSA-65.
func (s ValidatorSet) MarshalBinary() ([]byte, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	e := codec.NewEncoder()
	e.Header(TypeValidatorSet, Version)
	e.Length(len(s.Keys))
	for _, k := range s.Keys {
		if err := encodePublicKey(e, k); err != nil {
			return nil, err
		}
	}
	return e.Bytes(), nil
}

// UnmarshalValidatorSet decodes a validator set.
func UnmarshalValidatorSet(b []byte) (ValidatorSet, error) {
	d := codec.NewDecoder(b)
	if err := d.ExpectHeader(TypeValidatorSet, Version); err != nil {
		return ValidatorSet{}, err
	}
	n, err := d.Length(MaxValidators)
	if err != nil {
		return ValidatorSet{}, err
	}
	keys := make([]crypto.PublicKey, n)
	for i := range keys {
		keys[i], err = decodePublicKey(d)
		if err != nil {
			return ValidatorSet{}, err
		}
		if keys[i].Algorithm() != crypto.AlgMLDSA65 {
			return ValidatorSet{}, fmt.Errorf("types: validator key must be ML-DSA-65: %w", ErrInvalid)
		}
	}
	if err := d.Finish(); err != nil {
		return ValidatorSet{}, err
	}
	s := ValidatorSet{Keys: keys}
	if err := s.check(); err != nil {
		return ValidatorSet{}, err
	}
	return s, nil
}

func (s ValidatorSet) check() error {
	if len(s.Keys) == 0 || len(s.Keys) > MaxValidators {
		return fmt.Errorf("types: validator set size: %w", ErrInvalid)
	}
	for _, k := range s.Keys {
		if k.Algorithm() != crypto.AlgMLDSA65 {
			return fmt.Errorf("types: validator key must be ML-DSA-65: %w", ErrInvalid)
		}
	}
	return nil
}

// MarshalPublicKey encodes one public key for a file or a message.
func MarshalPublicKey(pk crypto.PublicKey) ([]byte, error) {
	e := codec.NewEncoder()
	e.Header(TypePublicKey, Version)
	if err := encodePublicKey(e, pk); err != nil {
		return nil, err
	}
	return e.Bytes(), nil
}

// UnmarshalPublicKey decodes one public key.
func UnmarshalPublicKey(b []byte) (crypto.PublicKey, error) {
	d := codec.NewDecoder(b)
	if err := d.ExpectHeader(TypePublicKey, Version); err != nil {
		return crypto.PublicKey{}, err
	}
	pk, err := decodePublicKey(d)
	if err != nil {
		return crypto.PublicKey{}, err
	}
	if err := d.Finish(); err != nil {
		return crypto.PublicKey{}, err
	}
	return pk, nil
}

// ReadPublicKey reads one MarshalPublicKey value from the front of d.
func ReadPublicKey(d *codec.Decoder) (crypto.PublicKey, error) {
	if err := d.ExpectHeader(TypePublicKey, Version); err != nil {
		return crypto.PublicKey{}, err
	}
	return decodePublicKey(d)
}

func encodePublicKey(e *codec.Encoder, pk crypto.PublicKey) error {
	raw := pk.Bytes()
	switch pk.Algorithm() {
	case crypto.AlgMLDSA65:
		if len(raw) != crypto.MLDSAPublicKeySize() {
			return fmt.Errorf("types: ML-DSA public key: %w", ErrInvalid)
		}
	case crypto.AlgSLHDSAShake128s:
		if len(raw) != crypto.SLHPublicKeySize() {
			return fmt.Errorf("types: SLH-DSA public key: %w", ErrInvalid)
		}
	default:
		return fmt.Errorf("types: public key algorithm: %w", ErrInvalid)
	}
	e.Uint8(uint8(pk.Algorithm()))
	e.Fixed(raw)
	return nil
}

func decodePublicKey(d *codec.Decoder) (crypto.PublicKey, error) {
	algByte, err := d.Uint8()
	if err != nil {
		return crypto.PublicKey{}, err
	}
	alg := crypto.Algorithm(algByte)
	var n int
	switch alg {
	case crypto.AlgMLDSA65:
		n = crypto.MLDSAPublicKeySize()
	case crypto.AlgSLHDSAShake128s:
		n = crypto.SLHPublicKeySize()
	default:
		return crypto.PublicKey{}, fmt.Errorf("types: public key algorithm: %w", ErrInvalid)
	}
	raw, err := d.Fixed(n)
	if err != nil {
		return crypto.PublicKey{}, err
	}
	pk, err := crypto.ParsePublicKey(alg, raw)
	if err != nil {
		return crypto.PublicKey{}, fmt.Errorf("types: public key: %w", ErrInvalid)
	}
	return pk, nil
}
