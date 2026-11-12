package merkle

import (
	"bytes"
	"crypto/sha3"
	"errors"
	"testing"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
)

func hash(parts ...[]byte) [crypto.DigestSize]byte {
	h := sha3.New256()
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	var out [crypto.DigestSize]byte
	h.Sum(out[:0])
	return out
}

func id(b byte) [crypto.DigestSize]byte {
	var out [crypto.DigestSize]byte
	out[0] = b
	return out
}

func TestEmptyAndSmallTrees(t *testing.T) {
	empty, err := Root(nil)
	if err != nil {
		t.Fatal(err)
	}
	if empty != hash() {
		t.Fatalf("empty root %x", empty)
	}

	a := id(1)
	one, err := Root([][crypto.DigestSize]byte{a})
	if err != nil {
		t.Fatal(err)
	}
	leafA := hash([]byte{prefixLeaf}, a[:])
	if one != leafA {
		t.Fatalf("single leaf")
	}

	b := id(2)
	two, err := Root([][crypto.DigestSize]byte{a, b})
	if err != nil {
		t.Fatal(err)
	}
	leafB := hash([]byte{prefixLeaf}, b[:])
	if two != hash([]byte{prefixNode}, leafA[:], leafB[:]) {
		t.Fatalf("two leaves")
	}

	c := id(3)
	three, err := Root([][crypto.DigestSize]byte{a, b, c})
	if err != nil {
		t.Fatal(err)
	}
	leafC := hash([]byte{prefixLeaf}, c[:])
	left := hash([]byte{prefixNode}, leafA[:], leafB[:])
	if three != hash([]byte{prefixNode}, left[:], leafC[:]) {
		t.Fatalf("three leaves: split must put the first power-of-two on the left")
	}
}

func TestProveEveryIndex(t *testing.T) {
	for n := 1; n <= 32; n++ {
		leaves := make([][crypto.DigestSize]byte, n)
		for i := range leaves {
			leaves[i] = id(byte(i + 1))
		}
		root, err := Root(leaves)
		if err != nil {
			t.Fatal(err)
		}
		for i := range leaves {
			sibs, err := Prove(leaves, i)
			if err != nil {
				t.Fatalf("n=%d i=%d prove: %v", n, i, err)
			}
			if len(sibs) > MaxSiblings {
				t.Fatalf("n=%d path %d", n, len(sibs))
			}
			if err := Verify(leaves[i], i, n, sibs, root); err != nil {
				t.Fatalf("n=%d i=%d verify: %v", n, i, err)
			}
			if i+1 < n {
				if err := Verify(leaves[i], i+1, n, sibs, root); !errors.Is(err, ErrProof) && !errors.Is(err, ErrIndex) {
					t.Fatalf("n=%d wrong index: %v", n, err)
				}
			}
			tampered := leaves[i]
			tampered[31] ^= 0xff
			if err := Verify(tampered, i, n, sibs, root); !errors.Is(err, ErrProof) {
				t.Fatalf("n=%d tampered leaf: %v", n, err)
			}
			if len(sibs) > 0 {
				bad := append([][crypto.DigestSize]byte(nil), sibs...)
				bad[0][0] ^= 0xff
				if err := Verify(leaves[i], i, n, bad, root); !errors.Is(err, ErrProof) {
					t.Fatalf("n=%d tampered sibling: %v", n, err)
				}
				extra := make([][crypto.DigestSize]byte, len(sibs)+1)
				copy(extra, sibs)
				extra[len(sibs)] = id(9)
				if err := Verify(leaves[i], i, n, extra, root); !errors.Is(err, ErrProof) {
					t.Fatalf("n=%d extra sibling: %v", n, err)
				}
			}
		}
	}
}

func TestAwkwardSizes(t *testing.T) {
	for _, n := range []int{5, 6, 7, 9, 17, 31, 33, 100, 127, 128, 255, 256, 1024} {
		leaves := make([][crypto.DigestSize]byte, n)
		for i := range leaves {
			leaves[i][0] = byte(i)
			leaves[i][1] = byte(i >> 8)
		}
		root, err := Root(leaves)
		if err != nil {
			t.Fatal(err)
		}
		for _, i := range []int{0, 1, n / 2, n - 1} {
			sibs, err := Prove(leaves, i)
			if err != nil {
				t.Fatal(err)
			}
			if err := Verify(leaves[i], i, n, sibs, root); err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
		}
	}
}

func TestLimits(t *testing.T) {
	if _, err := Root(make([][crypto.DigestSize]byte, MaxLeaves+1)); !errors.Is(err, ErrSize) {
		t.Fatalf("size: %v", err)
	}
	if _, err := Prove([][crypto.DigestSize]byte{id(1)}, 1); !errors.Is(err, ErrIndex) {
		t.Fatalf("index: %v", err)
	}
	if err := Verify(id(1), 0, 0, nil, [crypto.DigestSize]byte{}); !errors.Is(err, ErrSize) {
		t.Fatalf("count: %v", err)
	}
}

func TestLeafIsNotANode(t *testing.T) {
	a, b := id(1), id(2)
	root, err := Root([][crypto.DigestSize]byte{a, b})
	if err != nil {
		t.Fatal(err)
	}
	// A second-preimage attempt: treat the node hash input as a leaf id.
	left := hash([]byte{prefixLeaf}, a[:])
	right := hash([]byte{prefixLeaf}, b[:])
	raw := append([]byte{prefixNode}, left[:]...)
	raw = append(raw, right[:]...)
	if bytes.Equal(raw[:1], []byte{prefixLeaf}) {
		t.Fatal("prefixes collided")
	}
	var fake [crypto.DigestSize]byte
	copy(fake[:], raw)
	if err := Verify(fake, 0, 1, nil, root); err == nil {
		t.Fatal("node bytes verified as a leaf")
	}
}
