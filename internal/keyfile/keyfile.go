// Package keyfile reads and writes encrypted test-network private keys.
//
// The file is forbidden in production. Production keys stay in an HSM.
// The parameters are fixed so a file cannot ask for a multi-gigabyte
// scrypt. This package does not talk to an HSM and does not implement one.
package keyfile

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/scrypt"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
)

const (
	// Magic is the first line of every test-network key file.
	Magic = "silvergrey-test-key-v1\n"

	version = 1

	// scryptN, scryptR and scryptP are the only parameters this package
	// accepts. A different N is rejected before any work is done.
	scryptN uint32 = 1 << 15
	scryptR uint32 = 8
	scryptP uint32 = 1

	saltLen  = 16
	nonceLen = 12
	keyLen   = 32

	// MinPassphrase is the shortest passphrase Write accepts.
	MinPassphrase = 8
	// MaxPassphrase bounds the passphrase so a caller cannot feed scrypt
	// an unbounded string.
	MaxPassphrase = 1024
	maxFile       = 1 << 20
)

// ErrPassphrase means the passphrase was wrong or the file was altered.
var ErrPassphrase = errors.New("keyfile: passphrase rejected")

// ErrFormat means the file is not a test-network key, or its scrypt
// parameters are not the fixed set this package accepts.
var ErrFormat = errors.New("keyfile: format")

// Write encrypts key with passphrase and writes path in mode 0600.
// The file is a test-network key. It must not be used in production.
func Write(path string, key crypto.PrivateKey, passphrase string) error {
	if len(passphrase) < MinPassphrase || len(passphrase) > MaxPassphrase {
		return fmt.Errorf("keyfile: passphrase length")
	}
	raw, err := key.MarshalBinary()
	if err != nil {
		return err
	}
	if key.Algorithm() != crypto.AlgMLDSA65 && key.Algorithm() != crypto.AlgSLHDSAShake128s {
		return crypto.ErrAlgorithm
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	aead, err := newAEAD(passphrase, salt)
	if err != nil {
		return err
	}
	head := header(key.Algorithm(), salt, nonce)
	sealed := aead.Seal(nil, nonce, raw, head)
	body := make([]byte, 0, len(head)+len(sealed))
	body = append(body, head...)
	body = append(body, sealed...)
	return writeNew(path, body)
}

// Open decrypts path. A wrong passphrase and a torn file both fail.
// The file is a test-network key. It must not be used in production.
func Open(path, passphrase string) (crypto.PrivateKey, error) {
	if len(passphrase) < MinPassphrase || len(passphrase) > MaxPassphrase {
		return crypto.PrivateKey{}, fmt.Errorf("keyfile: passphrase length")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return crypto.PrivateKey{}, err
	}
	if len(body) > maxFile {
		return crypto.PrivateKey{}, fmt.Errorf("%w: too large", ErrFormat)
	}
	alg, salt, nonce, sealed, header, err := parse(body)
	if err != nil {
		return crypto.PrivateKey{}, err
	}
	aead, err := newAEAD(passphrase, salt)
	if err != nil {
		return crypto.PrivateKey{}, err
	}
	raw, err := aead.Open(nil, nonce, sealed, header)
	if err != nil {
		return crypto.PrivateKey{}, ErrPassphrase
	}
	switch alg {
	case crypto.AlgMLDSA65:
		if len(raw) != crypto.MLDSASeedSize() {
			return crypto.PrivateKey{}, fmt.Errorf("%w: seed length", ErrFormat)
		}
		return crypto.NewMLDSA65FromSeed(raw)
	case crypto.AlgSLHDSAShake128s:
		if len(raw) != crypto.SLHPrivateKeySize() {
			return crypto.PrivateKey{}, fmt.Errorf("%w: seed length", ErrFormat)
		}
		return crypto.NewSLHDSAPrivate(raw)
	default:
		return crypto.PrivateKey{}, crypto.ErrAlgorithm
	}
}

func header(alg crypto.Algorithm, salt, nonce []byte) []byte {
	out := make([]byte, 0, len(Magic)+1+1+12+saltLen+nonceLen)
	out = append(out, Magic...)
	out = append(out, version, byte(alg))
	out = binary.BigEndian.AppendUint32(out, scryptN)
	out = binary.BigEndian.AppendUint32(out, scryptR)
	out = binary.BigEndian.AppendUint32(out, scryptP)
	out = append(out, salt...)
	out = append(out, nonce...)
	return out
}

func parse(body []byte) (crypto.Algorithm, []byte, []byte, []byte, []byte, error) {
	if len(body) < len(Magic)+2+12+saltLen+nonceLen {
		return 0, nil, nil, nil, nil, fmt.Errorf("%w: short", ErrFormat)
	}
	if string(body[:len(Magic)]) != Magic {
		return 0, nil, nil, nil, nil, fmt.Errorf("%w: magic", ErrFormat)
	}
	rest := body[len(Magic):]
	if rest[0] != version {
		return 0, nil, nil, nil, nil, fmt.Errorf("%w: version", ErrFormat)
	}
	alg := crypto.Algorithm(rest[1])
	n := binary.BigEndian.Uint32(rest[2:6])
	r := binary.BigEndian.Uint32(rest[6:10])
	p := binary.BigEndian.Uint32(rest[10:14])
	if n != scryptN || r != scryptR || p != scryptP {
		return 0, nil, nil, nil, nil, fmt.Errorf("%w: scrypt parameters", ErrFormat)
	}
	off := 14
	salt := rest[off : off+saltLen]
	off += saltLen
	nonce := rest[off : off+nonceLen]
	off += nonceLen
	sealed := rest[off:]
	if len(sealed) < 16 {
		return 0, nil, nil, nil, nil, fmt.Errorf("%w: short", ErrFormat)
	}
	headLen := len(Magic) + off
	return alg, salt, nonce, sealed, body[:headLen], nil
}

func newAEAD(passphrase string, salt []byte) (cipher.AEAD, error) {
	dk, err := scrypt.Key([]byte(passphrase), salt, int(scryptN), int(scryptR), int(scryptP), keyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func writeNew(path string, body []byte) error {
	tmp := path + ".next"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(body)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	if cerr != nil {
		return cerr
	}
	if serr != nil {
		return serr
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	derr := dir.Sync()
	dclose := dir.Close()
	if derr != nil {
		return derr
	}
	return dclose
}
