// Package merkle is the event-id tree used in block headers.
//
// The shape is RFC 6962: the split point is the largest power of two
// strictly below the leaf count, so a proof is unambiguous. The hash is
// SHA3-256, not SHA-256. Leaf and node prefixes (0x00 and 0x01) stop a
// node hash from being reused as a leaf hash.
package merkle
