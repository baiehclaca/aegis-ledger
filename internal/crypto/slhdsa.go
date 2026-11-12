package crypto

import (
	"bytes"
	stdcrypto "crypto"
	"crypto/rand"
	"io"

	"github.com/cloudflare/circl/sign/slhdsa"
)

func slhID() slhdsa.ID { return slhdsa.SHAKE_128s }

// SLHPublicKeySize is the FIPS 205 SLH-DSA-SHAKE-128s public key size.
func SLHPublicKeySize() int { return slhID().Scheme().PublicKeySize() }

// SLHPrivateKeySize is the circl encoding size of an SLH-DSA-SHAKE-128s
// private key (skSeed || skPrf || public key).
func SLHPrivateKeySize() int { return slhID().Scheme().PrivateKeySize() }

// SLHSignatureSize is the FIPS 205 SLH-DSA-SHAKE-128s signature size.
func SLHSignatureSize() int { return slhID().Scheme().SignatureSize() }

type slhPriv struct {
	k slhdsa.PrivateKey
}

func generateSLH(random io.Reader) (PrivateKey, error) {
	if random == nil {
		random = rand.Reader
	}
	_, sk, err := slhdsa.GenerateKey(random, slhID())
	if err != nil {
		return PrivateKey{}, err
	}
	return PrivateKey{impl: &slhPriv{k: sk}}, nil
}

func slhFromBytes(raw []byte) (PrivateKey, error) {
	if len(raw) != SLHPrivateKeySize() {
		return PrivateKey{}, ErrKey
	}
	sk := slhdsa.PrivateKey{ID: slhID()}
	if err := sk.UnmarshalBinary(raw); err != nil {
		return PrivateKey{}, ErrKey
	}
	canon, err := sk.MarshalBinary()
	if err != nil {
		return PrivateKey{}, ErrKey
	}
	if !bytes.Equal(canon, raw) {
		return PrivateKey{}, ErrKey
	}
	return PrivateKey{impl: &slhPriv{k: sk}}, nil
}

func (p *slhPriv) algorithm() Algorithm { return AlgSLHDSAShake128s }

func (p *slhPriv) signer() (stdcrypto.Signer, error) {
	return nil, ErrAlgorithm
}

func (p *slhPriv) public() (PublicKey, error) {
	raw, err := p.k.PublicKey().MarshalBinary()
	if err != nil {
		return PublicKey{}, ErrKey
	}
	return parseSLHPublic(raw)
}

func (p *slhPriv) marshal() ([]byte, error) {
	raw, err := p.k.MarshalBinary()
	if err != nil {
		return nil, ErrKey
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	return out, nil
}

func (p *slhPriv) sign(message []byte, context string, deterministic bool) ([]byte, error) {
	msg := slhdsa.NewMessage(message)
	ctx := []byte(context)
	var (
		sig []byte
		err error
	)
	if deterministic {
		sig, err = slhdsa.SignDeterministic(&p.k, msg, ctx)
	} else {
		sig, err = slhdsa.SignRandomized(&p.k, rand.Reader, msg, ctx)
	}
	if err != nil {
		return nil, err
	}
	if len(sig) != SLHSignatureSize() {
		return nil, ErrSignature
	}
	return sig, nil
}

func parseSLHPublic(raw []byte) (PublicKey, error) {
	if len(raw) != SLHPublicKeySize() {
		return PublicKey{}, ErrKey
	}
	pk := slhdsa.PublicKey{ID: slhID()}
	if err := pk.UnmarshalBinary(raw); err != nil {
		return PublicKey{}, ErrKey
	}
	canon, err := pk.MarshalBinary()
	if err != nil {
		return PublicKey{}, ErrKey
	}
	if !bytes.Equal(canon, raw) {
		return PublicKey{}, ErrKey
	}
	out := make([]byte, len(canon))
	copy(out, canon)
	return PublicKey{alg: AlgSLHDSAShake128s, raw: out}, nil
}

func verifySLH(pub PublicKey, message, sig []byte, context string) error {
	if len(sig) != SLHSignatureSize() {
		return ErrSignature
	}
	pk := slhdsa.PublicKey{ID: slhID()}
	if err := pk.UnmarshalBinary(pub.raw); err != nil {
		return ErrKey
	}
	if !slhdsa.Verify(&pk, slhdsa.NewMessage(message), sig, []byte(context)) {
		return ErrSignature
	}
	return nil
}
