package crypto

import (
	stdcrypto "crypto"
	"crypto/subtle"
	"fmt"
	"io"
)

// Algorithm identifies a signature parameter set on the wire.
type Algorithm uint8

const (
	// AlgMLDSA65 is ML-DSA-65 (FIPS 204). Event, vote, and proposal
	// signatures use this parameter set.
	AlgMLDSA65 Algorithm = 1
	// AlgSLHDSAShake128s is SLH-DSA-SHAKE-128s (FIPS 205). Long-lived
	// root and genesis keys use this parameter set.
	AlgSLHDSAShake128s Algorithm = 2
)

func (a Algorithm) String() string {
	switch a {
	case AlgMLDSA65:
		return "ML-DSA-65"
	case AlgSLHDSAShake128s:
		return "SLH-DSA-SHAKE-128s"
	default:
		return fmt.Sprintf("algorithm %d", a)
	}
}

// PublicKey is a parsed public key. The raw encoding is the canonical
// byte string from the implementing library.
type PublicKey struct {
	alg Algorithm
	raw []byte
}

// Algorithm returns the parameter set.
func (p PublicKey) Algorithm() Algorithm {
	return p.alg
}

// Bytes returns a copy of the canonical raw public key.
func (p PublicKey) Bytes() []byte {
	out := make([]byte, len(p.raw))
	copy(out, p.raw)
	return out
}

// ID is SHA3-256("silvergrey/key" || alg || raw). Writer and proposer
// identifiers both use this, so one key has one id.
func (p PublicKey) ID() ([DigestSize]byte, error) {
	if p.alg == 0 || len(p.raw) == 0 {
		return [DigestSize]byte{}, ErrKey
	}
	return DomainSum(DomainKey, []byte{byte(p.alg)}, p.raw), nil
}

// Equal reports whether the keys are the same parameter set and encoding.
func (p PublicKey) Equal(o PublicKey) bool {
	if p.alg != o.alg || len(p.raw) != len(o.raw) {
		return false
	}
	return subtle.ConstantTimeCompare(p.raw, o.raw) == 1
}

// ParsePublicKey checks raw against the parameter set and rejects a
// non-canonical encoding.
func ParsePublicKey(alg Algorithm, raw []byte) (PublicKey, error) {
	switch alg {
	case AlgMLDSA65:
		return parseMLDSAPublic(raw)
	case AlgSLHDSAShake128s:
		return parseSLHPublic(raw)
	default:
		return PublicKey{}, ErrAlgorithm
	}
}

// PrivateKey holds an in-memory signing key. The zero value cannot sign.
// Bytes from MarshalBinary are seed or expanded key material. Production
// deployments keep that material in an HSM. An encrypted file is allowed
// only for test networks, and this package does not write one.
type PrivateKey struct {
	impl keyImpl
}

type keyImpl interface {
	algorithm() Algorithm
	public() (PublicKey, error)
	sign(message []byte, context string, deterministic bool) ([]byte, error)
	marshal() ([]byte, error)
	signer() (stdcrypto.Signer, error)
}

// TLSSigner returns the ML-DSA key as a crypto.Signer so a test or a
// node can mint a TLS certificate. SLH-DSA is not a TLS signature scheme.
func (k PrivateKey) TLSSigner() (stdcrypto.Signer, error) {
	if k.impl == nil {
		return nil, ErrKey
	}
	return k.impl.signer()
}

// Algorithm returns the parameter set.
func (k PrivateKey) Algorithm() Algorithm {
	if k.impl == nil {
		return 0
	}
	return k.impl.algorithm()
}

// Public returns the corresponding public key.
func (k PrivateKey) Public() (PublicKey, error) {
	if k.impl == nil {
		return PublicKey{}, ErrKey
	}
	return k.impl.public()
}

// MarshalBinary returns the library's private key encoding.
func (k PrivateKey) MarshalBinary() ([]byte, error) {
	if k.impl == nil {
		return nil, ErrKey
	}
	return k.impl.marshal()
}

// SignDigest signs a 32-byte digest with the hedged FIPS variant.
// Hedged signatures mix fresh randomness, which FIPS 204 recommends
// against fault attacks. context must be a ledger context whose
// preimage is already defined.
func (k PrivateKey) SignDigest(digest [DigestSize]byte, context string) ([]byte, error) {
	if !knownSignContext(context) {
		return nil, ErrContext
	}
	return k.signMessage(digest[:], context, false)
}

// SignDigestDeterministic signs a 32-byte digest with the deterministic
// FIPS variant (all-zero randomness). Known-answer tests use it. Ledger
// code uses SignDigest.
func (k PrivateKey) SignDigestDeterministic(digest [DigestSize]byte, context string) ([]byte, error) {
	if !knownSignContext(context) {
		return nil, ErrContext
	}
	return k.signMessage(digest[:], context, true)
}

// VerifyDigest checks a signature over a 32-byte digest.
func VerifyDigest(pub PublicKey, digest [DigestSize]byte, sig []byte, context string) error {
	if !knownSignContext(context) {
		return ErrContext
	}
	return verifyMessage(pub, digest[:], sig, context)
}

// signMessage is the primitive used by known-answer tests. The message
// may be any length. An empty context is legal here because FIPS allows
// it; SignDigest does not.
func (k PrivateKey) signMessage(message []byte, context string, deterministic bool) ([]byte, error) {
	if err := checkContextBytes(context); err != nil {
		return nil, err
	}
	if k.impl == nil {
		return nil, ErrKey
	}
	return k.impl.sign(message, context, deterministic)
}

func verifyMessage(pub PublicKey, message, sig []byte, context string) error {
	if err := checkContextBytes(context); err != nil {
		return err
	}
	if pub.alg == 0 || len(pub.raw) == 0 {
		return ErrKey
	}
	switch pub.alg {
	case AlgMLDSA65:
		return verifyMLDSA(pub, message, sig, context)
	case AlgSLHDSAShake128s:
		return verifySLH(pub, message, sig, context)
	default:
		return ErrAlgorithm
	}
}

// GenerateMLDSA65 draws a new ML-DSA-65 key from crypto/rand.
func GenerateMLDSA65() (PrivateKey, error) {
	return generateMLDSA()
}

// NewMLDSA65FromSeed reconstructs a key from a FIPS 204 seed.
func NewMLDSA65FromSeed(seed []byte) (PrivateKey, error) {
	return mldsaFromSeed(seed)
}

// GenerateSLHDSA draws a new SLH-DSA-SHAKE-128s key. random supplies
// skSeed || skPrf || pkSeed when the caller needs a known-answer key.
// A nil reader uses crypto/rand.
func GenerateSLHDSA(random io.Reader) (PrivateKey, error) {
	return generateSLH(random)
}

// NewSLHDSAPrivate parses the circl private key encoding.
func NewSLHDSAPrivate(raw []byte) (PrivateKey, error) {
	return slhFromBytes(raw)
}
