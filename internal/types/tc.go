package types

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/silvergreyhound/silver-grey-ledger/internal/codec"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
)

// TC is a timeout certificate: a quorum of timeouts for one view. The
// empty value is the only absent certificate, used when a proposal is
// justified by the previous view's quorum certificate alone.
type TC struct {
	View     uint64
	Timeouts []Timeout
}

// IsEmpty reports whether t is the single canonical absent certificate.
func (t TC) IsEmpty() bool {
	return t.View == 0 && len(t.Timeouts) == 0
}

// HighestQC returns the preferred certificate carried by the timeouts.
// An empty HighQC ranks below every real certificate, including a
// view-0 certificate of the genesis block. Two real certificates for
// the same view and different blocks are rejected. If every HighQC is
// empty, the result is an empty certificate and a nil error.
func (t TC) HighestQC() (QC, error) {
	if t.IsEmpty() {
		return QC{}, fmt.Errorf("types: empty timeout certificate: %w", ErrInvalid)
	}
	var best QC
	have := false
	for _, to := range t.Timeouts {
		if to.HighQC.IsEmpty() {
			continue
		}
		if !have || to.HighQC.View > best.View {
			best = to.HighQC
			have = true
			continue
		}
		if to.HighQC.View == best.View && to.HighQC.BlockHash != best.BlockHash {
			return QC{}, fmt.Errorf("types: conflicting certificates in timeout certificate: %w", ErrInvalid)
		}
	}
	if !have {
		return QC{}, nil
	}
	return best, nil
}

// Verify checks every timeout and that they reach quorum for len(keys).
func (t TC) Verify(keys []crypto.PublicKey) error {
	if t.IsEmpty() {
		return fmt.Errorf("types: empty timeout certificate: %w", ErrQuorum)
	}
	if err := t.check(); err != nil {
		return err
	}
	quorum, err := Quorum(len(keys))
	if err != nil {
		return err
	}
	if len(t.Timeouts) < quorum {
		return fmt.Errorf("types: %d timeouts, quorum %d: %w", len(t.Timeouts), quorum, ErrQuorum)
	}
	for _, to := range t.Timeouts {
		if to.View != t.View {
			return fmt.Errorf("types: timeout view: %w", ErrInvalid)
		}
		if err := to.Verify(keys); err != nil {
			return err
		}
	}
	if _, err := t.HighestQC(); err != nil {
		return err
	}
	return nil
}

// MarshalBinary encodes a certificate. Timeouts are ordered by signer.
func (t TC) MarshalBinary() ([]byte, error) {
	ordered, err := t.ordered()
	if err != nil {
		return nil, err
	}
	e := codec.NewEncoder()
	e.Header(TypeTC, Version)
	e.Uint64(t.View)
	e.Length(len(ordered))
	for _, to := range ordered {
		raw, err := to.MarshalBinary()
		if err != nil {
			return nil, err
		}
		e.Fixed(raw)
	}
	return e.Bytes(), nil
}

// UnmarshalTC decodes a certificate. Signatures are not checked.
// Signers must already be strictly increasing; the encoder's order is
// the only accepted order.
func UnmarshalTC(b []byte) (TC, error) {
	d := codec.NewDecoder(b)
	t, err := decodeTC(d)
	if err != nil {
		return TC{}, err
	}
	if err := d.Finish(); err != nil {
		return TC{}, err
	}
	return t, nil
}

func decodeTC(d *codec.Decoder) (TC, error) {
	if err := d.ExpectHeader(TypeTC, Version); err != nil {
		return TC{}, err
	}
	var t TC
	var err error
	if t.View, err = d.Uint64(); err != nil {
		return TC{}, err
	}
	n, err := d.Length(MaxValidators)
	if err != nil {
		return TC{}, err
	}
	t.Timeouts = make([]Timeout, n)
	for i := range t.Timeouts {
		t.Timeouts[i], err = decodeTimeout(d)
		if err != nil {
			return TC{}, err
		}
	}
	if err := t.check(); err != nil {
		return TC{}, err
	}
	return t, nil
}

func (t TC) ordered() ([]Timeout, error) {
	if err := t.checkShape(); err != nil {
		return nil, err
	}
	if t.IsEmpty() {
		return nil, nil
	}
	out := append([]Timeout(nil), t.Timeouts...)
	slices.SortFunc(out, func(a, b Timeout) int {
		return cmp.Compare(a.Signer, b.Signer)
	})
	for i := 1; i < len(out); i++ {
		if out[i].Signer == out[i-1].Signer {
			return nil, fmt.Errorf("types: duplicate timeout signer: %w", ErrInvalid)
		}
	}
	for _, to := range out {
		if to.View != t.View {
			return nil, fmt.Errorf("types: timeout view: %w", ErrInvalid)
		}
	}
	return out, nil
}

func (t TC) check() error {
	ordered, err := t.ordered()
	if err != nil {
		return err
	}
	// The wire form is sorted. A decoded value that is not already in
	// that order would re-encode to different bytes.
	for i := range ordered {
		if t.Timeouts[i].Signer != ordered[i].Signer {
			return fmt.Errorf("types: timeout signers are not sorted: %w", ErrInvalid)
		}
	}
	return nil
}

func (t TC) checkShape() error {
	if len(t.Timeouts) > MaxValidators {
		return fmt.Errorf("types: too many timeouts: %w", ErrInvalid)
	}
	if len(t.Timeouts) == 0 {
		if t.View != 0 {
			return fmt.Errorf("types: empty timeout certificate must have view 0: %w", ErrInvalid)
		}
		return nil
	}
	if t.View == 0 {
		return fmt.Errorf("types: timeout certificate view: %w", ErrInvalid)
	}
	return nil
}
