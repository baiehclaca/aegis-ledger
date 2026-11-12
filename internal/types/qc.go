package types

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"slices"

	"github.com/silvergreyhound/silver-grey-ledger/internal/codec"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
)

// QC is a quorum certificate. SignerBitmap bit i is validator i, and
// Signatures are in ascending bit order. An empty certificate (the
// genesis justify) is the zero value: view 0, zero hash, no signers.
type QC struct {
	View         uint64
	BlockHash    [crypto.DigestSize]byte
	SignerBitmap uint32
	Signatures   [][]byte
}

// IsEmpty reports whether q is the single canonical absent certificate.
func (q QC) IsEmpty() bool {
	return q.View == 0 && zero32(q.BlockHash) && q.SignerBitmap == 0 && len(q.Signatures) == 0
}

// VoteDigest is the 32-byte message a vote signature covers:
// SHA3-256("silvergrey/vote" || chain_id || view_be || block_hash).
func VoteDigest(chainID [crypto.DigestSize]byte, view uint64, blockHash [crypto.DigestSize]byte) [crypto.DigestSize]byte {
	var viewBytes [8]byte
	binary.BigEndian.PutUint64(viewBytes[:], view)
	return crypto.DomainSum(crypto.DomainVote, chainID[:], viewBytes[:], blockHash[:])
}

// AssembleQC signs a certificate. signers are indexes into keys, which
// is the validator set in bitmap order. The result is not required to
// meet quorum; Verify checks that against the set it is given.
func AssembleQC(chainID [crypto.DigestSize]byte, view uint64, blockHash [crypto.DigestSize]byte, keys []crypto.PrivateKey, signers []int) (QC, error) {
	if len(signers) == 0 {
		return QC{}, fmt.Errorf("types: refusing to assemble an empty QC: %w", ErrInvalid)
	}
	if len(keys) == 0 || len(keys) > MaxValidators {
		return QC{}, fmt.Errorf("types: validator set size: %w", ErrInvalid)
	}
	order := append([]int(nil), signers...)
	slices.Sort(order)
	var bitmap uint32
	sigs := make([][]byte, 0, len(order))
	digest := VoteDigest(chainID, view, blockHash)
	prev := -1
	for _, idx := range order {
		if idx < 0 || idx >= len(keys) || idx >= MaxValidators {
			return QC{}, fmt.Errorf("types: signer index %d: %w", idx, ErrInvalid)
		}
		if idx == prev {
			return QC{}, fmt.Errorf("types: duplicate signer %d: %w", idx, ErrInvalid)
		}
		prev = idx
		if keys[idx].Algorithm() != crypto.AlgMLDSA65 {
			return QC{}, fmt.Errorf("types: vote key must be ML-DSA-65: %w", ErrSignature)
		}
		sig, err := keys[idx].SignDigest(digest, crypto.ContextVote)
		if err != nil {
			return QC{}, err
		}
		bitmap |= 1 << uint(idx)
		sigs = append(sigs, sig)
	}
	q := QC{View: view, BlockHash: blockHash, SignerBitmap: bitmap, Signatures: sigs}
	if err := q.check(); err != nil {
		return QC{}, err
	}
	return q, nil
}

// Verify checks every signature in the bitmap and that they reach quorum
// for len(keys). keys[i] is validator i.
func (q QC) Verify(chainID [crypto.DigestSize]byte, keys []crypto.PublicKey) error {
	if q.IsEmpty() {
		return fmt.Errorf("types: empty QC: %w", ErrQuorum)
	}
	if err := q.check(); err != nil {
		return err
	}
	quorum, err := Quorum(len(keys))
	if err != nil {
		return err
	}
	if len(q.Signatures) < quorum {
		return fmt.Errorf("types: %d signatures, quorum %d: %w", len(q.Signatures), quorum, ErrQuorum)
	}
	mask := signerMask(len(keys))
	if q.SignerBitmap&^mask != 0 {
		return fmt.Errorf("types: bitmap names a validator outside the set: %w", ErrInvalid)
	}
	digest := VoteDigest(chainID, q.View, q.BlockHash)
	sigIndex := 0
	for i := range keys {
		if q.SignerBitmap&(1<<uint(i)) == 0 {
			continue
		}
		if keys[i].Algorithm() != crypto.AlgMLDSA65 {
			return fmt.Errorf("types: validator %d is not ML-DSA-65: %w", i, ErrSignature)
		}
		if err := crypto.VerifyDigest(keys[i], digest, q.Signatures[sigIndex], crypto.ContextVote); err != nil {
			return fmt.Errorf("types: validator %d vote: %w", i, ErrSignature)
		}
		sigIndex++
	}
	if sigIndex != len(q.Signatures) {
		return fmt.Errorf("types: bitmap and signature count diverged: %w", ErrInvalid)
	}
	return nil
}

func signerMask(n int) uint32 {
	if n >= MaxValidators {
		return maxSignerBits
	}
	return uint32(1)<<uint(n) - 1
}

// MarshalBinary encodes q.
func (q QC) MarshalBinary() ([]byte, error) {
	if err := q.check(); err != nil {
		return nil, err
	}
	e := codec.NewEncoder()
	if err := encodeQC(e, q); err != nil {
		return nil, err
	}
	return e.Bytes(), nil
}

// UnmarshalQC decodes a certificate.
func UnmarshalQC(b []byte) (QC, error) {
	d := codec.NewDecoder(b)
	q, err := decodeQC(d)
	if err != nil {
		return QC{}, err
	}
	if err := d.Finish(); err != nil {
		return QC{}, err
	}
	return q, nil
}

func encodeQC(e *codec.Encoder, q QC) error {
	e.Header(TypeQC, Version)
	e.Uint64(q.View)
	e.Fixed(q.BlockHash[:])
	e.Uint32(q.SignerBitmap)
	e.Length(len(q.Signatures))
	for _, sig := range q.Signatures {
		e.Fixed(sig)
	}
	return nil
}

func decodeQC(d *codec.Decoder) (QC, error) {
	if err := d.ExpectHeader(TypeQC, Version); err != nil {
		return QC{}, err
	}
	var q QC
	var err error
	if q.View, err = d.Uint64(); err != nil {
		return QC{}, err
	}
	if q.BlockHash, err = d.Hash(); err != nil {
		return QC{}, err
	}
	if q.SignerBitmap, err = d.Uint32(); err != nil {
		return QC{}, err
	}
	n, err := d.Length(MaxValidators)
	if err != nil {
		return QC{}, err
	}
	q.Signatures = make([][]byte, n)
	for i := range q.Signatures {
		q.Signatures[i], err = d.Fixed(crypto.MLDSASignatureSize())
		if err != nil {
			return QC{}, err
		}
	}
	if err := q.check(); err != nil {
		return QC{}, err
	}
	return q, nil
}

func (q QC) check() error {
	if q.SignerBitmap&^maxSignerBits != 0 {
		return fmt.Errorf("types: signer bitmap uses a reserved bit: %w", ErrInvalid)
	}
	if bits.OnesCount32(q.SignerBitmap) != len(q.Signatures) {
		return fmt.Errorf("types: signer bitmap does not match signatures: %w", ErrInvalid)
	}
	if len(q.Signatures) == 0 {
		if !q.IsEmpty() {
			return fmt.Errorf("types: empty QC must have a zero view and hash: %w", ErrInvalid)
		}
		return nil
	}
	for _, sig := range q.Signatures {
		if len(sig) != crypto.MLDSASignatureSize() {
			return fmt.Errorf("types: vote signature length: %w", ErrInvalid)
		}
	}
	return nil
}
