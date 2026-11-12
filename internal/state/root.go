package state

import (
	"bytes"
	"sort"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
)

// commitRoot is an RFC 6962 tree over already-hashed leaves, with no
// event-batch cap. The event tree in internal/merkle stops at 1024
// leaves; membership state is not an event batch.
func commitRoot(leaves [][crypto.DigestSize]byte) [crypto.DigestSize]byte {
	n := len(leaves)
	if n == 0 {
		return crypto.Sum256()
	}
	if n == 1 {
		return crypto.Sum256([]byte{0x00}, leaves[0][:])
	}
	k := split(n)
	left := commitRoot(leaves[:k])
	right := commitRoot(leaves[k:])
	return crypto.Sum256([]byte{0x01}, left[:], right[:])
}

func split(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

type pair struct {
	key []byte
	val []byte
}

func stateRoot(pairs []pair) [crypto.DigestSize]byte {
	sort.Slice(pairs, func(i, j int) bool {
		return bytes.Compare(pairs[i].key, pairs[j].key) < 0
	})
	leaves := make([][crypto.DigestSize]byte, len(pairs))
	for i, p := range pairs {
		leaves[i] = crypto.Sum256(p.key, []byte{0}, p.val)
	}
	return commitRoot(leaves)
}
