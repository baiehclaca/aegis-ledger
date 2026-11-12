package crypto

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"strings"
	"testing"
)

// FIPS 202 known answers for SHA3-256.
func TestSHA3KnownAnswers(t *testing.T) {
	cases := []struct {
		msg  string
		want string
	}{
		{"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
		{"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"},
		{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"},
	}
	for _, tc := range cases {
		got := Sum256([]byte(tc.msg))
		raw, err := hex.DecodeString(tc.want)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got[:], raw) {
			t.Fatalf("%q: got %x", tc.msg, got)
		}
	}
}

func TestDomainSumMatchesConcatenation(t *testing.T) {
	body := []byte("payload")
	got := DomainSum(DomainEvent, body)
	h := sha3.New256()
	_, _ = h.Write([]byte(DomainEvent))
	_, _ = h.Write(body)
	var want [DigestSize]byte
	h.Sum(want[:0])
	if got != want {
		t.Fatal("domain sum drifted from SHA3-256(domain || body)")
	}
	if DomainSum(DomainEvent, body) == DomainSum(DomainBlock, body) {
		t.Fatal("event and block domains collided")
	}
}

func TestTagsArePrefixFree(t *testing.T) {
	domains := []string{
		DomainEvent, DomainBlock, DomainVote, DomainKey,
		DomainTimeout, DomainGenesis, DomainGovernance,
	}
	contexts := []string{
		ContextEvent, ContextProposal, ContextVote,
		ContextTimeout, ContextGenesis, ContextGovernance,
	}
	assertPrefixFree(t, domains)
	assertPrefixFree(t, contexts)
}

func assertPrefixFree(t *testing.T, tags []string) {
	t.Helper()
	for i, a := range tags {
		if a == "" {
			t.Fatal("empty tag")
		}
		for j, b := range tags {
			if i != j && strings.HasPrefix(a, b) {
				t.Fatalf("%q is a prefix of %q", b, a)
			}
		}
	}
}

func TestPublishedSizes(t *testing.T) {
	// FIPS 204 Table 2, ML-DSA-65.
	if MLDSAPublicKeySize() != 1952 || MLDSASignatureSize() != 3309 || MLDSASeedSize() != 32 {
		t.Fatalf("ML-DSA-65 sizes pk=%d sig=%d seed=%d", MLDSAPublicKeySize(), MLDSASignatureSize(), MLDSASeedSize())
	}
	// FIPS 205, SLH-DSA-SHAKE-128s.
	if SLHPublicKeySize() != 32 || SLHSignatureSize() != 7856 || SLHPrivateKeySize() != 64 {
		t.Fatalf("SLH-DSA sizes pk=%d sig=%d sk=%d", SLHPublicKeySize(), SLHSignatureSize(), SLHPrivateKeySize())
	}
}
