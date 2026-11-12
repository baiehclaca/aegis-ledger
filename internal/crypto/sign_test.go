package crypto

import (
	"bytes"
	"errors"
	"sync"
	"testing"
)

func TestMLDSAHedgedAndDeterministic(t *testing.T) {
	priv, err := GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := priv.Public()
	if err != nil {
		t.Fatal(err)
	}
	var digest [DigestSize]byte
	digest[0] = 7
	a, err := priv.SignDigest(digest, ContextEvent)
	if err != nil {
		t.Fatal(err)
	}
	b, err := priv.SignDigest(digest, ContextEvent)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("hedged signatures were identical")
	}
	if err := VerifyDigest(pub, digest, a, ContextEvent); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDigest(pub, digest, a, ContextVote); err == nil {
		t.Fatal("vote context accepted an event signature")
	}
	d2 := digest
	d2[1] = 1
	if err := VerifyDigest(pub, d2, a, ContextEvent); err == nil {
		t.Fatal("wrong digest accepted")
	}
	det1, err := priv.SignDigestDeterministic(digest, ContextVote)
	if err != nil {
		t.Fatal(err)
	}
	det2, err := priv.SignDigestDeterministic(digest, ContextVote)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(det1, det2) {
		t.Fatal("deterministic signatures differed")
	}
	if err := VerifyDigest(pub, digest, det1, ContextVote); err != nil {
		t.Fatal(err)
	}
	gov, err := priv.SignDigest(digest, ContextGovernance)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDigest(pub, digest, gov, ContextGovernance); err != nil {
		t.Fatal(err)
	}
	if _, err := priv.SignDigest(digest, ""); !errors.Is(err, ErrContext) {
		t.Fatalf("empty context: %v", err)
	}
}

func TestSLHDSARoundTrip(t *testing.T) {
	priv, err := GenerateSLHDSA(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := priv.Public()
	if err != nil {
		t.Fatal(err)
	}
	if pub.Algorithm() != AlgSLHDSAShake128s {
		t.Fatal(pub.Algorithm())
	}
	raw, err := priv.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	again, err := NewSLHDSAPrivate(raw)
	if err != nil {
		t.Fatal(err)
	}
	pub2, err := again.Public()
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(pub2) {
		t.Fatal("public key changed across marshal")
	}
	var digest [DigestSize]byte
	digest[0] = 3
	sig, err := again.SignDigestDeterministic(digest, ContextProposal)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDigest(pub, digest, sig, ContextProposal); err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 0xff
	if err := VerifyDigest(pub, digest, sig, ContextProposal); err == nil {
		t.Fatal("tampered SLH signature accepted")
	}
}

func TestKeyIDBindsAlgorithm(t *testing.T) {
	m, err := GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	s, err := GenerateSLHDSA(nil)
	if err != nil {
		t.Fatal(err)
	}
	mp, err := m.Public()
	if err != nil {
		t.Fatal(err)
	}
	sp, err := s.Public()
	if err != nil {
		t.Fatal(err)
	}
	mid, err := mp.ID()
	if err != nil {
		t.Fatal(err)
	}
	sid, err := sp.ID()
	if err != nil {
		t.Fatal(err)
	}
	if mid == sid {
		t.Fatal("distinct keys produced one id")
	}
	if _, err := ParsePublicKey(AlgMLDSA65, sp.Bytes()); err == nil {
		t.Fatal("SLH key parsed as ML-DSA")
	}
	if _, err := ParsePublicKey(9, mp.Bytes()); !errors.Is(err, ErrAlgorithm) {
		t.Fatalf("unknown alg: %v", err)
	}
}

func TestConcurrentMLDSASign(t *testing.T) {
	priv, err := GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := priv.Public()
	if err != nil {
		t.Fatal(err)
	}
	var digest [DigestSize]byte
	var wg sync.WaitGroup
	errc := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sig, err := priv.SignDigest(digest, ContextEvent)
			if err != nil {
				errc <- err
				return
			}
			if err := VerifyDigest(pub, digest, sig, ContextEvent); err != nil {
				errc <- err
			}
		}()
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Fatal(err)
	}
}

func TestZeroKeyRejected(t *testing.T) {
	var k PrivateKey
	var digest [DigestSize]byte
	if _, err := k.SignDigest(digest, ContextEvent); !errors.Is(err, ErrKey) {
		t.Fatalf("sign: %v", err)
	}
	var p PublicKey
	if err := VerifyDigest(p, digest, make([]byte, MLDSASignatureSize()), ContextEvent); !errors.Is(err, ErrSignature) && !errors.Is(err, ErrKey) {
		t.Fatalf("verify: %v", err)
	}
}
