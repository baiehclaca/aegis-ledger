package crypto

import (
	"crypto/sha3"
	"hash"
)

// Sum256 is SHA3-256 over the concatenation of parts, with no domain tag.
// Document hashes use this: the stored hash has to match a standalone
// hash of the file.
func Sum256(parts ...[]byte) [DigestSize]byte {
	return sum(nil, parts...)
}

// DomainSum is SHA3-256(domain || parts...). domain must be one of the
// Domain* constants. An empty domain is rejected by returning a zero
// digest only when the caller forgot the tag; callers pass constants.
func DomainSum(domain string, parts ...[]byte) [DigestSize]byte {
	return sum([]byte(domain), parts...)
}

func sum(prefix []byte, parts ...[]byte) [DigestSize]byte {
	h := sha3.New256()
	writeAll(h, prefix)
	for _, p := range parts {
		writeAll(h, p)
	}
	var out [DigestSize]byte
	h.Sum(out[:0])
	return out
}

func writeAll(h hash.Hash, p []byte) {
	// crypto/sha3 Hash.Write returns a nil error. A non-nil error means
	// the process cannot hash, and a truncated digest would be worse
	// than stopping.
	if _, err := h.Write(p); err != nil {
		panic("crypto: sha3 write: " + err.Error())
	}
}
