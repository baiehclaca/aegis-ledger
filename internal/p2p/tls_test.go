package p2p

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
)

func TestHandshakeMLDSA(t *testing.T) {
	pubs := make([]crypto.PublicKey, 2)
	certs := make([]tls.Certificate, 2)
	for i := range pubs {
		key, err := crypto.GenerateMLDSA65()
		if err != nil {
			t.Fatal(err)
		}
		pub, err := key.Public()
		if err != nil {
			t.Fatal(err)
		}
		cert, err := Certificate(key)
		if err != nil {
			t.Fatal(err)
		}
		pubs[i] = pub
		certs[i] = cert
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	errCh := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		conn := tls.Server(raw, PeerServerConfig(certs[0], pubs, 0))
		errCh <- conn.Handshake()
		_ = conn.Close()
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := tls.Client(raw, PeerClientConfig(certs[1], pubs, 1, 0))
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	state := client.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		t.Fatalf("version %x", state.Version)
	}
	if state.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("curve %d", state.CurveID)
	}
	if state.NegotiatedProtocol != "silvergrey/1" {
		t.Fatalf("alpn %q", state.NegotiatedProtocol)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
}

func TestHandshakeRejectsOutsider(t *testing.T) {
	key, err := crypto.GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.Public()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := Certificate(key)
	if err != nil {
		t.Fatal(err)
	}
	other, err := crypto.GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	otherCert, err := Certificate(other)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	errCh := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		conn := tls.Server(raw, PeerServerConfig(cert, []crypto.PublicKey{pub}, 0))
		errCh <- conn.Handshake()
		_ = conn.Close()
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := tls.Client(raw, PeerClientConfig(otherCert, []crypto.PublicKey{pub}, -1, 0))
	err = client.Handshake()
	_ = client.Close()
	srvErr := <-errCh
	if err == nil && srvErr == nil {
		t.Fatal("outsider handshake succeeded")
	}
}

func TestHandshakeRejectsClassicCurve(t *testing.T) {
	pubs := make([]crypto.PublicKey, 2)
	certs := make([]tls.Certificate, 2)
	for i := range pubs {
		key, err := crypto.GenerateMLDSA65()
		if err != nil {
			t.Fatal(err)
		}
		pub, err := key.Public()
		if err != nil {
			t.Fatal(err)
		}
		cert, err := Certificate(key)
		if err != nil {
			t.Fatal(err)
		}
		pubs[i] = pub
		certs[i] = cert
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	errCh := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		conn := tls.Server(raw, PeerServerConfig(certs[0], pubs, 0))
		errCh <- conn.Handshake()
		_ = conn.Close()
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cfg := PeerClientConfig(certs[1], pubs, 1, 0)
	cfg.CurvePreferences = []tls.CurveID{tls.X25519}
	client := tls.Client(raw, cfg)
	err = client.Handshake()
	_ = client.Close()
	if serr := <-errCh; err == nil && serr == nil {
		t.Fatal("X25519-only handshake succeeded")
	}
}

func TestHandshakeRejectsMLDSA44(t *testing.T) {
	key, err := crypto.GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.Public()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := Certificate(key)
	if err != nil {
		t.Fatal(err)
	}
	other, err := mldsa44Cert()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	errCh := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		conn := tls.Server(raw, PeerServerConfig(cert, []crypto.PublicKey{pub}, 0))
		errCh <- conn.Handshake()
		_ = conn.Close()
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768},
		Certificates:       []tls.Certificate{other},
		InsecureSkipVerify: true,
		NextProtos:         []string{"silvergrey/1"},
	}
	client := tls.Client(raw, cfg)
	err = client.Handshake()
	_ = client.Close()
	srvErr := <-errCh
	if err == nil && srvErr == nil {
		t.Fatal("ML-DSA-44 certificate was accepted")
	}
}

func mldsa44Cert() (tls.Certificate, error) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "silvergrey"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.PublicKey(), priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}
