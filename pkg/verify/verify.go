package verify

import (
	"crypto/sha3"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

// ErrDocument means the document's SHA3-256 digest is not one of the
// event's document hashes.
var ErrDocument = errors.New("verify: document hash mismatch")

// Result is what a certified inclusion proof establishes.
type Result struct {
	EventID   [crypto.DigestSize]byte
	BlockHash [crypto.DigestSize]byte
	Height    uint64
	View      uint64
}

// HashDocument is SHA3-256 of the document bytes, with no domain tag.
// The file never needs to be buffered: the hash is updated as it is read.
func HashDocument(r io.Reader) (types.DocHash, error) {
	h := sha3.New256()
	if _, err := io.Copy(h, r); err != nil {
		return types.DocHash{}, err
	}
	var sum [crypto.DigestSize]byte
	h.Sum(sum[:0])
	return types.SHA3Doc(sum), nil
}

// CheckDocument reports whether doc is among the event's document hashes.
func CheckDocument(event types.Event, doc types.DocHash) error {
	if doc.Alg != types.AlgSHA3_256 {
		return ErrDocument
	}
	match := 0
	for _, h := range event.DocHashes {
		if h.Alg != types.AlgSHA3_256 {
			continue
		}
		match |= subtle.ConstantTimeCompare(h.Sum[:], doc.Sum[:])
	}
	if match != 1 {
		return ErrDocument
	}
	return nil
}

// Inclusion checks proof against validators and the writer key.
// validators must be the membership at that height, in bitmap order.
func Inclusion(proof types.InclusionProof, validators types.ValidatorSet, writer crypto.PublicKey) (Result, error) {
	if err := proof.Event.Verify(writer); err != nil {
		return Result{}, err
	}
	if proof.Event.ChainID != proof.Header.ChainID {
		return Result{}, fmt.Errorf("verify: event chain id: %w", types.ErrInvalid)
	}
	if err := proof.Header.Validate(); err != nil {
		return Result{}, err
	}
	eventID, err := proof.Event.ID()
	if err != nil {
		return Result{}, err
	}
	if err := proof.MerkleOK(eventID); err != nil {
		return Result{}, err
	}
	blockHash, err := proof.Header.Hash()
	if err != nil {
		return Result{}, err
	}
	if proof.CommitQC.BlockHash != blockHash {
		return Result{}, fmt.Errorf("verify: commit QC is for a different block: %w", types.ErrInvalid)
	}
	if proof.CommitQC.View != proof.Header.View {
		return Result{}, fmt.Errorf("verify: commit QC view does not match the block: %w", types.ErrInvalid)
	}
	if err := proof.CommitQC.Verify(proof.Header.ChainID, validators.Keys); err != nil {
		return Result{}, err
	}
	return Result{
		EventID:   eventID,
		BlockHash: blockHash,
		Height:    proof.Header.Height,
		View:      proof.Header.View,
	}, nil
}
