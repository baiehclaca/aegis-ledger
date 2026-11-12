// Package crypto wraps the signature and hash algorithms Silver Grey Ledger uses.
//
// It does not implement cryptographic primitives. ML-DSA-65 is Go's
// crypto/mldsa (FIPS 204). SLH-DSA-SHAKE-128s is cloudflare.org/circl
// (FIPS 205). SHA3-256 is crypto/sha3 (FIPS 202).
//
// Ledger signatures cover a 32-byte digest plus a FIPS context string.
// The context stops a signature on one kind of object from verifying as
// another. Production private keys are held in an HSM. This package can
// export key bytes for tests; it does not write a key file.
package crypto
