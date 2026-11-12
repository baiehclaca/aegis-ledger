package crypto

import (
	"bytes"
	stdcrypto "crypto"
	"crypto/mldsa"
	"crypto/rand"
)

func mldsaParams() mldsa.Parameters {
	return mldsa.MLDSA65()
}

// MLDSAPublicKeySize is the FIPS 204 ML-DSA-65 public key size.
func MLDSAPublicKeySize() int { return mldsa.MLDSA65PublicKeySize }

// MLDSASignatureSize is the FIPS 204 ML-DSA-65 signature size.
func MLDSASignatureSize() int { return mldsa.MLDSA65SignatureSize }

// MLDSASeedSize is the FIPS 204 private seed size.
func MLDSASeedSize() int { return mldsa.PrivateKeySize }

type mldsaPriv struct {
	k *mldsa.PrivateKey
}

func generateMLDSA() (PrivateKey, error) {
	k, err := mldsa.GenerateKey(mldsaParams())
	if err != nil {
		return PrivateKey{}, err
	}
	return PrivateKey{impl: &mldsaPriv{k: k}}, nil
}

func mldsaFromSeed(seed []byte) (PrivateKey, error) {
	if len(seed) != MLDSASeedSize() {
		return PrivateKey{}, ErrKey
	}
	k, err := mldsa.NewPrivateKey(mldsaParams(), seed)
	if err != nil {
		return PrivateKey{}, ErrKey
	}
	return PrivateKey{impl: &mldsaPriv{k: k}}, nil
}

func (p *mldsaPriv) algorithm() Algorithm { return AlgMLDSA65 }

func (p *mldsaPriv) signer() (stdcrypto.Signer, error) { return p.k, nil }

func (p *mldsaPriv) public() (PublicKey, error) {
	return parseMLDSAPublic(p.k.PublicKey().Bytes())
}

func (p *mldsaPriv) marshal() ([]byte, error) {
	seed := p.k.Bytes()
	out := make([]byte, len(seed))
	copy(out, seed)
	return out, nil
}

func (p *mldsaPriv) sign(message []byte, context string, deterministic bool) ([]byte, error) {
	opts := &mldsa.Options{Context: context}
	var (
		sig []byte
		err error
	)
	if deterministic {
		sig, err = p.k.SignDeterministic(message, opts)
	} else {
		// The reader is ignored by crypto/mldsa. Randomness comes from
		// the process DRBG, which is the hedged FIPS 204 variant.
		sig, err = p.k.Sign(rand.Reader, message, opts)
	}
	if err != nil {
		return nil, err
	}
	if len(sig) != MLDSASignatureSize() {
		return nil, ErrSignature
	}
	return sig, nil
}

func parseMLDSAPublic(raw []byte) (PublicKey, error) {
	if len(raw) != MLDSAPublicKeySize() {
		return PublicKey{}, ErrKey
	}
	pk, err := mldsa.NewPublicKey(mldsaParams(), raw)
	if err != nil {
		return PublicKey{}, ErrKey
	}
	canon := pk.Bytes()
	if !bytes.Equal(canon, raw) {
		return PublicKey{}, ErrKey
	}
	out := make([]byte, len(canon))
	copy(out, canon)
	return PublicKey{alg: AlgMLDSA65, raw: out}, nil
}

func verifyMLDSA(pub PublicKey, message, sig []byte, context string) error {
	if len(sig) != MLDSASignatureSize() {
		return ErrSignature
	}
	pk, err := mldsa.NewPublicKey(mldsaParams(), pub.raw)
	if err != nil {
		return ErrKey
	}
	if err := mldsa.Verify(pk, message, sig, &mldsa.Options{Context: context}); err != nil {
		return ErrSignature
	}
	return nil
}
