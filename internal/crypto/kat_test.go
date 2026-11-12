package crypto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type mldsaFile struct {
	Sign   []mldsaSign   `json:"sign"`
	Verify []mldsaVerify `json:"verify"`
}

type mldsaSign struct {
	TcID        int    `json:"tcId"`
	Comment     string `json:"comment"`
	PrivateSeed string `json:"privateSeed"`
	PublicKey   string `json:"publicKey"`
	Msg         string `json:"msg"`
	Ctx         string `json:"ctx"`
	Sig         string `json:"sig"`
}

type mldsaVerify struct {
	TcID      int    `json:"tcId"`
	Comment   string `json:"comment"`
	PublicKey string `json:"publicKey"`
	Msg       string `json:"msg"`
	Ctx       string `json:"ctx"`
	Sig       string `json:"sig"`
	Result    string `json:"result"`
}

func TestMLDSAWycheproof(t *testing.T) {
	var file mldsaFile
	mustJSON(t, "testdata/mldsa65_wycheproof.json", &file)
	if len(file.Sign) == 0 || len(file.Verify) == 0 {
		t.Fatal("missing vectors")
	}
	for _, tc := range file.Sign {
		t.Run(tc.Comment, func(t *testing.T) {
			priv, err := NewMLDSA65FromSeed(mustHex(t, tc.PrivateSeed))
			if err != nil {
				t.Fatal(err)
			}
			pub, err := priv.Public()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(pub.Bytes(), mustHex(t, tc.PublicKey)) {
				t.Fatal("public key does not match the vector")
			}
			msg := mustHex(t, tc.Msg)
			ctx := string(mustHex(t, tc.Ctx))
			sig, err := priv.signMessage(msg, ctx, true)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(sig, mustHex(t, tc.Sig)) {
				t.Fatalf("tc %d signature mismatch", tc.TcID)
			}
			if err := verifyMessage(pub, msg, sig, ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, tc := range file.Verify {
		t.Run(tc.Comment, func(t *testing.T) {
			if tc.Result != "invalid" {
				t.Fatalf("expected a rejection vector, got %s", tc.Result)
			}
			pub, err := ParsePublicKey(AlgMLDSA65, mustHex(t, tc.PublicKey))
			if err != nil {
				return
			}
			err = verifyMessage(pub, mustHex(t, tc.Msg), mustHex(t, tc.Sig), string(mustHex(t, tc.Ctx)))
			if err == nil {
				t.Fatal("invalid vector was accepted")
			}
		})
	}
}

func TestSLHDSAKeygenKAT(t *testing.T) {
	var tc struct {
		SkSeed string `json:"skSeed"`
		SkPrf  string `json:"skPrf"`
		PkSeed string `json:"pkSeed"`
		Sk     string `json:"sk"`
		Pk     string `json:"pk"`
	}
	mustJSON(t, "testdata/slhdsa_shake128s_keygen.json", &tc)
	seed := append(append(mustHex(t, tc.SkSeed), mustHex(t, tc.SkPrf)...), mustHex(t, tc.PkSeed)...)
	priv, err := GenerateSLHDSA(bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := priv.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, mustHex(t, tc.Sk)) {
		t.Fatal("private key mismatch")
	}
	pub, err := priv.Public()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub.Bytes(), mustHex(t, tc.Pk)) {
		t.Fatal("public key mismatch")
	}
}

func TestSLHDSASignKAT(t *testing.T) {
	var tc struct {
		Sk        string `json:"sk"`
		Message   string `json:"message"`
		Context   string `json:"context"`
		Signature string `json:"signature"`
	}
	mustJSON(t, "testdata/slhdsa_shake128s_sign.json", &tc)
	priv, err := NewSLHDSAPrivate(mustHex(t, tc.Sk))
	if err != nil {
		t.Fatal(err)
	}
	msg := mustHex(t, tc.Message)
	ctx := string(mustHex(t, tc.Context))
	sig, err := priv.signMessage(msg, ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig, mustHex(t, tc.Signature)) {
		t.Fatal("signature mismatch")
	}
	pub, err := priv.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyMessage(pub, msg, sig, ctx); err != nil {
		t.Fatal(err)
	}
}

func TestSLHDSAVerifyKAT(t *testing.T) {
	var file struct {
		Cases []struct {
			TcID       int    `json:"tcId"`
			Pk         string `json:"pk"`
			Message    string `json:"message"`
			Context    string `json:"context"`
			Signature  string `json:"signature"`
			TestPassed bool   `json:"testPassed"`
		} `json:"cases"`
	}
	mustJSON(t, "testdata/slhdsa_shake128s_verify.json", &file)
	if len(file.Cases) < 2 {
		t.Fatal("need a valid and an invalid case")
	}
	sawPass, sawFail := false, false
	for _, tc := range file.Cases {
		pub, err := ParsePublicKey(AlgSLHDSAShake128s, mustHex(t, tc.Pk))
		if err != nil {
			t.Fatal(err)
		}
		err = verifyMessage(pub, mustHex(t, tc.Message), mustHex(t, tc.Signature), string(mustHex(t, tc.Context)))
		if tc.TestPassed {
			sawPass = true
			if err != nil {
				t.Fatalf("tc %d: %v", tc.TcID, err)
			}
			continue
		}
		sawFail = true
		if err == nil {
			t.Fatalf("tc %d was accepted", tc.TcID)
		}
	}
	if !sawPass || !sawFail {
		t.Fatalf("pass=%v fail=%v", sawPass, sawFail)
	}
}

func mustJSON(t *testing.T, path string, dest any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, dest); err != nil {
		t.Fatal(err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	if s == "" {
		return []byte{}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
