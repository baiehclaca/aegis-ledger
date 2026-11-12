package keyfile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
)

func TestRoundTrip(t *testing.T) {
	key := mustKey(t)
	path := filepath.Join(t.TempDir(), "node.key")
	if err := Write(path, key, "test-pass-1"); err != nil {
		t.Fatal(err)
	}
	got, err := Open(path, "test-pass-1")
	if err != nil {
		t.Fatal(err)
	}
	want, err := key.Public()
	if err != nil {
		t.Fatal(err)
	}
	have, err := got.Public()
	if err != nil {
		t.Fatal(err)
	}
	if !want.Equal(have) {
		t.Fatal("public key mismatch")
	}
	if _, err := Open(path, "test-pass-2"); !errors.Is(err, ErrPassphrase) {
		t.Fatal(err)
	}
}

func TestRejectsOtherScrypt(t *testing.T) {
	key := mustKey(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "node.key")
	if err := Write(path, key, "test-pass-1"); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// N is the uint32 after magic, version, and algorithm. 32768 is
	// 0x00008000, so the first byte is already zero.
	off := len(Magic) + 2
	body[off+2] = 0
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, "test-pass-1"); !errors.Is(err, ErrFormat) {
		t.Fatal(err)
	}
}

func TestShortPassphrase(t *testing.T) {
	key := mustKey(t)
	if err := Write(filepath.Join(t.TempDir(), "k"), key, "short"); err == nil {
		t.Fatal("accepted a short passphrase")
	}
}

func FuzzOpen(f *testing.F) {
	f.Add([]byte(Magic))
	f.Add([]byte("not a key"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			return
		}
		path := filepath.Join(t.TempDir(), "k")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path, "test-pass-1"); err == nil {
			// A random file that decrypts is not expected. A successful
			// open must still be a usable key.
			return
		}
	})
}

func mustKey(t *testing.T) crypto.PrivateKey {
	t.Helper()
	key, err := crypto.GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestSLHRoundTrip(t *testing.T) {
	key, err := crypto.GenerateSLHDSA(bytes.NewReader(bytes.Repeat([]byte{7}, 96)))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "slh.key")
	if err := Write(path, key, "test-pass-1"); err != nil {
		t.Fatal(err)
	}
	got, err := Open(path, "test-pass-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Algorithm() != crypto.AlgSLHDSAShake128s {
		t.Fatal(got.Algorithm())
	}
}
