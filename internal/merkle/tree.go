package merkle

import (
	"errors"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
)

const (
	// prefixLeaf and prefixNode are the RFC 6962 domain bytes.
	prefixLeaf byte = 0x00
	prefixNode byte = 0x01

	// MaxLeaves is the largest tree a block or a proof may use.
	// 1024 is the v1 event-batch cap: it bounds both the block and the
	// inclusion path a decoder will accept.
	MaxLeaves = 1024

	// MaxSiblings is above the longest RFC 6962 path for MaxLeaves.
	// A longer path is rejected before it is hashed.
	MaxSiblings = 64
)

// Proof and tree errors. Callers use errors.Is.
var (
	ErrIndex = errors.New("merkle: leaf index out of range")
	ErrSize  = errors.New("merkle: tree exceeds maximum leaves")
	ErrProof = errors.New("merkle: inclusion proof rejected")
)

// Root is the Merkle root of event IDs. An empty list hashes to
// SHA3-256 of the empty input, which is the RFC 6962 empty tree with
// the hash function changed.
func Root(eventIDs [][crypto.DigestSize]byte) ([crypto.DigestSize]byte, error) {
	if len(eventIDs) > MaxLeaves {
		return [crypto.DigestSize]byte{}, ErrSize
	}
	return hashTree(eventIDs), nil
}

// Prove returns the sibling hashes from the leaf toward the root.
func Prove(eventIDs [][crypto.DigestSize]byte, index int) ([][crypto.DigestSize]byte, error) {
	if len(eventIDs) > MaxLeaves {
		return nil, ErrSize
	}
	if index < 0 || index >= len(eventIDs) {
		return nil, ErrIndex
	}
	_, path, err := prove(eventIDs, index)
	return path, err
}

// Verify checks that eventID is the leaf at index in a tree of count
// leaves whose root is root. siblings are the path returned by Prove.
func Verify(eventID [crypto.DigestSize]byte, index, count int, siblings [][crypto.DigestSize]byte, root [crypto.DigestSize]byte) error {
	if count <= 0 || count > MaxLeaves {
		return ErrSize
	}
	if index < 0 || index >= count {
		return ErrIndex
	}
	if len(siblings) > MaxSiblings {
		return ErrProof
	}
	got, used, err := fold(count, index, leafHash(eventID), siblings)
	if err != nil {
		return err
	}
	if used != len(siblings) || got != root {
		return ErrProof
	}
	return nil
}

func hashTree(leaves [][crypto.DigestSize]byte) [crypto.DigestSize]byte {
	n := len(leaves)
	if n == 0 {
		return crypto.Sum256()
	}
	if n == 1 {
		return leafHash(leaves[0])
	}
	k := splitPoint(n)
	return nodeHash(hashTree(leaves[:k]), hashTree(leaves[k:]))
}

func prove(leaves [][crypto.DigestSize]byte, index int) ([crypto.DigestSize]byte, [][crypto.DigestSize]byte, error) {
	n := len(leaves)
	if n == 1 {
		return leafHash(leaves[0]), nil, nil
	}
	k := splitPoint(n)
	if index < k {
		left, path, err := prove(leaves[:k], index)
		if err != nil {
			return [crypto.DigestSize]byte{}, nil, err
		}
		right := hashTree(leaves[k:])
		return nodeHash(left, right), append(path, right), nil
	}
	left := hashTree(leaves[:k])
	right, path, err := prove(leaves[k:], index-k)
	if err != nil {
		return [crypto.DigestSize]byte{}, nil, err
	}
	return nodeHash(left, right), append(path, left), nil
}

func fold(count, index int, leaf [crypto.DigestSize]byte, siblings [][crypto.DigestSize]byte) ([crypto.DigestSize]byte, int, error) {
	if count == 1 {
		if index != 0 {
			return [crypto.DigestSize]byte{}, 0, ErrIndex
		}
		return leaf, 0, nil
	}
	k := splitPoint(count)
	if index < k {
		child, used, err := fold(k, index, leaf, siblings)
		if err != nil {
			return [crypto.DigestSize]byte{}, 0, err
		}
		if used >= len(siblings) {
			return [crypto.DigestSize]byte{}, 0, ErrProof
		}
		return nodeHash(child, siblings[used]), used + 1, nil
	}
	child, used, err := fold(count-k, index-k, leaf, siblings)
	if err != nil {
		return [crypto.DigestSize]byte{}, 0, err
	}
	if used >= len(siblings) {
		return [crypto.DigestSize]byte{}, 0, ErrProof
	}
	return nodeHash(siblings[used], child), used + 1, nil
}

func leafHash(eventID [crypto.DigestSize]byte) [crypto.DigestSize]byte {
	return crypto.Sum256([]byte{prefixLeaf}, eventID[:])
}

func nodeHash(left, right [crypto.DigestSize]byte) [crypto.DigestSize]byte {
	return crypto.Sum256([]byte{prefixNode}, left[:], right[:])
}

// splitPoint returns the largest power of two strictly less than n.
// n is at least 2 and at most MaxLeaves, so the shift cannot overflow.
func splitPoint(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}
