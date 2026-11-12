package merkle

import (
	"testing"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
)

func FuzzVerify(f *testing.F) {
	f.Add([]byte{0, 1, 0})
	f.Fuzz(func(_ *testing.T, data []byte) {
		if len(data) < cryptoDigest {
			return
		}
		var leaf [cryptoDigest]byte
		copy(leaf[:], data[:cryptoDigest])
		rest := data[cryptoDigest:]
		count := 1
		index := 0
		if len(rest) > 0 {
			count = int(rest[0])%MaxLeaves + 1
			rest = rest[1:]
		}
		if len(rest) > 0 {
			index = int(rest[0]) % count
			rest = rest[1:]
		}
		var sibs [][cryptoDigest]byte
		for len(rest) >= cryptoDigest && len(sibs) < MaxSiblings+2 {
			var s [cryptoDigest]byte
			copy(s[:], rest[:cryptoDigest])
			sibs = append(sibs, s)
			rest = rest[cryptoDigest:]
		}
		var root [cryptoDigest]byte
		if len(rest) >= cryptoDigest {
			copy(root[:], rest[:cryptoDigest])
		}
		_ = Verify(leaf, index, count, sibs, root)
	})
}

func FuzzProveVerify(f *testing.F) {
	f.Add([]byte{3, 1, 2, 3, 4})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 2 {
			return
		}
		n := int(data[0])%17 + 1
		leaves := make([][cryptoDigest]byte, n)
		for i := range leaves {
			leaves[i][0] = data[1]
			leaves[i][1] = byte(i)
			if len(data) > 2+i {
				leaves[i][2] = data[2+i%(len(data)-2)]
			}
		}
		index := int(data[1]) % n
		root, err := Root(leaves)
		if err != nil {
			t.Fatal(err)
		}
		sibs, err := Prove(leaves, index)
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(leaves[index], index, n, sibs, root); err != nil {
			t.Fatal(err)
		}
	})
}

// cryptoDigest is the leaf width the fuzzer slices on. It has to stay
// equal to the hash the tree uses, or a proof built here would not match.
const cryptoDigest = crypto.DigestSize

func TestDigestSize(t *testing.T) {
	if cryptoDigest != crypto.DigestSize {
		t.Fatal(cryptoDigest)
	}
}
