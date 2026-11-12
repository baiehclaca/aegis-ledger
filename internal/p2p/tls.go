package p2p

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
)

const (
	alpnP2P = "silvergrey/1"
	// certSkew is how far a peer clock may sit from ours before the
	// certificate is rejected. The certificate itself is valid for years;
	// the check exists so a stale file is not immortal.
	certSkew = 5 * time.Minute
	certLife = 10 * 365 * 24 * time.Hour
)

// ErrIdentity means the peer certificate is not an ML-DSA-65 key this
// process is willing to talk to.
var ErrIdentity = errors.New("p2p: peer certificate was rejected")

// Certificate mints a self-signed ML-DSA-65 certificate for key.
// The subject name is not an identity. Callers authenticate the key.
func Certificate(key crypto.PrivateKey) (tls.Certificate, error) {
	signer, err := key.TLSSigner()
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "silvergrey"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(certLife),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate:                  [][]byte{der},
		PrivateKey:                   signer,
		Leaf:                         leaf,
		SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.MLDSA65},
	}, nil
}

// PeerServerConfig is the TLS config for a validator listener.
// Any validator other than self is accepted. A process does not
// complete a handshake with its own key.
func PeerServerConfig(cert tls.Certificate, pubs []crypto.PublicKey, self int) *tls.Config {
	return PeerServerConfigSource(cert, func() []crypto.PublicKey { return pubs }, self)
}

// PeerServerConfigSource is PeerServerConfig with a live key set.
// Rotation replaces the keys the next handshake will accept.
func PeerServerConfigSource(cert tls.Certificate, keys func() []crypto.PublicKey, self int) *tls.Config {
	return peerConfig(cert, keys, self, -1)
}

// PeerClientConfig is the TLS config for a dial to validator expect.
func PeerClientConfig(cert tls.Certificate, pubs []crypto.PublicKey, self, expect int) *tls.Config {
	return PeerClientConfigSource(cert, func() []crypto.PublicKey { return pubs }, self, expect)
}

// PeerClientConfigSource is PeerClientConfig with a live key set.
func PeerClientConfigSource(cert tls.Certificate, keys func() []crypto.PublicKey, self, expect int) *tls.Config {
	return peerConfig(cert, keys, self, expect)
}

func peerConfig(cert tls.Certificate, keys func() []crypto.PublicKey, self, expect int) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{tls.X25519MLKEM768},
		Certificates:           []tls.Certificate{cert},
		ClientAuth:             tls.RequireAnyClientCert,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		NextProtos:             []string{alpnP2P},
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyPeer(cs, keys(), self, expect, alpnP2P)
		},
	}
}

// APIServerConfig accepts any self-signed ML-DSA-65 certificate.
// The ledger, not this handshake, decides whether that key may read or
// write. A write still requires the certificate key to equal the signer.
func APIServerConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{tls.X25519MLKEM768},
		Certificates:           []tls.Certificate{cert},
		ClientAuth:             tls.RequireAnyClientCert,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		NextProtos:             []string{"h2", "http/1.1"},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if err := checkHandshake(cs, ""); err != nil {
				return err
			}
			_, err := PublicFromCert(cs.PeerCertificates[0])
			return err
		},
	}
}

// APIClientObserve accepts any ML-DSA-65 server certificate and reports it.
// The ledger proof, not this handshake, decides whether that key is a
// current validator. note may run on the handshake goroutine.
func APIClientObserve(cert tls.Certificate, note func(crypto.PublicKey)) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{tls.X25519MLKEM768},
		Certificates:           []tls.Certificate{cert},
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		NextProtos:             []string{"h2"},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if err := checkHandshake(cs, ""); err != nil {
				return err
			}
			key, err := PublicFromCert(cs.PeerCertificates[0])
			if err != nil {
				return err
			}
			note(key)
			return nil
		},
	}
}

// APIClientConfig checks that the server certificate is one of pubs.
func APIClientConfig(cert tls.Certificate, pubs []crypto.PublicKey) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{tls.X25519MLKEM768},
		Certificates:           []tls.Certificate{cert},
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		NextProtos:             []string{"h2"},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if err := checkHandshake(cs, ""); err != nil {
				return err
			}
			key, err := PublicFromCert(cs.PeerCertificates[0])
			if err != nil {
				return err
			}
			if _, ok := Index(pubs, key); !ok {
				return ErrIdentity
			}
			return nil
		},
	}
}

func verifyPeer(cs tls.ConnectionState, pubs []crypto.PublicKey, self, expect int, alpn string) error {
	if err := checkHandshake(cs, alpn); err != nil {
		return err
	}
	key, err := PublicFromCert(cs.PeerCertificates[0])
	if err != nil {
		return err
	}
	idx, ok := Index(pubs, key)
	if !ok || idx == self {
		return ErrIdentity
	}
	if expect >= 0 && idx != expect {
		return ErrIdentity
	}
	return nil
}

func checkHandshake(cs tls.ConnectionState, alpn string) error {
	if cs.Version != tls.VersionTLS13 {
		return fmt.Errorf("%w: tls version %x", ErrIdentity, cs.Version)
	}
	if cs.CurveID != tls.X25519MLKEM768 {
		return fmt.Errorf("%w: curve %d", ErrIdentity, cs.CurveID)
	}
	if alpn != "" && cs.NegotiatedProtocol != alpn {
		return fmt.Errorf("%w: alpn %q", ErrIdentity, cs.NegotiatedProtocol)
	}
	if len(cs.PeerCertificates) == 0 {
		return fmt.Errorf("%w: no peer certificate", ErrIdentity)
	}
	return nil
}

// PublicFromCert returns the ML-DSA-65 key in a self-signed certificate.
func PublicFromCert(cert *x509.Certificate) (crypto.PublicKey, error) {
	if cert == nil {
		return crypto.PublicKey{}, ErrIdentity
	}
	now := time.Now()
	if now.Add(certSkew).Before(cert.NotBefore) || now.Add(-certSkew).After(cert.NotAfter) {
		return crypto.PublicKey{}, ErrIdentity
	}
	// CheckSignature proves the certificate is self-signed. CheckSignatureFrom
	// also requires the cA bit, and these certificates are not issuers.
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return crypto.PublicKey{}, fmt.Errorf("%w: %v", ErrIdentity, err)
	}
	raw, err := certPublic(cert)
	if err != nil {
		return crypto.PublicKey{}, err
	}
	key, err := crypto.ParsePublicKey(crypto.AlgMLDSA65, raw)
	if err != nil {
		return crypto.PublicKey{}, fmt.Errorf("%w: %v", ErrIdentity, err)
	}
	return key, nil
}

func certPublic(cert *x509.Certificate) ([]byte, error) {
	type byter interface{ Bytes() []byte }
	b, ok := cert.PublicKey.(byter)
	if !ok {
		return nil, ErrIdentity
	}
	return b.Bytes(), nil
}

// Index returns the position of key in pubs.
func Index(pubs []crypto.PublicKey, key crypto.PublicKey) (int, bool) {
	for i, pub := range pubs {
		if pub.Equal(key) {
			return i, true
		}
	}
	return 0, false
}
