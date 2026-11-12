package node

import (
	"context"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/silvergreyhound/silver-grey-ledger/internal/api"
	"github.com/silvergreyhound/silver-grey-ledger/internal/consensus"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
	"github.com/silvergreyhound/silver-grey-ledger/pkg/verify"
)

func TestClusterCommitsAndRejoins(t *testing.T) {
	keys := make([]crypto.PrivateKey, 4)
	for i := range keys {
		key, err := crypto.GenerateMLDSA65()
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = key
	}
	writer, err := crypto.GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	writerPub, err := writer.Public()
	if err != nil {
		t.Fatal(err)
	}
	g, block, qc, err := consensus.BuildGenesisWith(consensus.GenesisWith{
		Created:    1_700_000_000,
		Validators: keys,
		Extra:      []consensus.Extra{{Key: writer, Roles: types.RoleWriter | types.RoleReader}},
	})
	if err != nil {
		t.Fatal(err)
	}
	chain, err := g.ChainID()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	genesisPath := dir + "/genesis.bin"
	if err := WriteGenesis(genesisPath, g, block, qc); err != nil {
		t.Fatal(err)
	}
	peers := make([]string, 4)
	clients := make([]string, 4)
	for i := range peers {
		peers[i] = freeAddr(t)
		clients[i] = freeAddr(t)
	}
	root, stop := context.WithCancel(context.Background())
	defer stop()
	errCh := make(chan error, 8)
	start := func(ctx context.Context, i int) <-chan struct{} {
		done := make(chan struct{})
		cfg := Config{
			Dir:         filepath.Join(dir, "n"+strconv.Itoa(i)),
			Listen:      peers[i],
			Client:      clients[i],
			Peers:       peers,
			Index:       i,
			GenesisPath: genesisPath,
			Key:         keys[i],
			KeyPath:     "test-only",
		}
		go func() {
			defer close(done)
			if err := Run(ctx, cfg, nil); err != nil {
				select {
				case errCh <- err:
				default:
				}
			}
		}()
		return done
	}
	var stops []context.CancelFunc
	var dones []<-chan struct{}
	for i := range 4 {
		ctx, cancel := context.WithCancel(root)
		stops = append(stops, cancel)
		dones = append(dones, start(ctx, i))
	}
	client := dialAPI(t, clients[0], writer, g, block, qc)
	leader := dialAPI(t, clients[1], writer, g, block, qc)
	waitListening(t, client, leader)
	id := submitEvent(t, leader, chain, writer, 1, "PN-1")
	proof := waitProof(t, client, id)
	if _, err := verify.Inclusion(proof, g.Validators(), writerPub); err != nil {
		t.Fatal(err)
	}
	stops[0]()
	select {
	case <-dones[0]:
	case <-time.After(10 * time.Second):
		t.Fatal("node did not stop")
	}
	ctx, cancel := context.WithCancel(root)
	defer cancel()
	dones[0] = start(ctx, 0)
	waitListening(t, client)
	id2 := submitEvent(t, leader, chain, writer, 2, "PN-2")
	proof = waitProof(t, client, id2)
	if _, err := verify.Inclusion(proof, g.Validators(), writerPub); err != nil {
		t.Fatal(err)
	}
	if proof.Event.Nonce != 2 {
		t.Fatalf("nonce %d", proof.Event.Nonce)
	}
	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}
	stop()
	for _, cancel := range stops {
		cancel()
	}
	for i, done := range dones {
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Fatalf("node %d did not stop", i)
		}
	}
}

func dialPinned(t *testing.T, addr string, key crypto.PrivateKey, pubs []crypto.PublicKey) *api.Client {
	t.Helper()
	c, err := api.Dial(addr, key, pubs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func dialAPI(t *testing.T, addr string, key crypto.PrivateKey, g types.Genesis, block types.Block, qc types.QC) *api.Session {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		c, err := api.DialChain(ctx, addr, key, g, block, qc)
		cancel()
		if err == nil {
			t.Cleanup(func() { _ = c.Close() })
			return c
		}
		last = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal(last)
	return nil
}

func waitListening(t *testing.T, clients ...*api.Session) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for _, c := range clients {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_, err := c.Status(ctx)
			cancel()
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("node did not listen: %v", err)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}

func submitEvent(t *testing.T, c *api.Session, chain [32]byte, writer crypto.PrivateKey, nonce uint64, subject string) [32]byte {
	t.Helper()
	pub, err := writer.Public()
	if err != nil {
		t.Fatal(err)
	}
	wid, err := pub.ID()
	if err != nil {
		t.Fatal(err)
	}
	var doc [32]byte
	doc[0] = byte(nonce)
	ev := types.Event{
		ChainID:     chain,
		EventType:   types.EventShipmentDispatched,
		Subject:     []byte(subject),
		Status:      1,
		DocHashes:   []types.DocHash{types.SHA3Doc(doc)},
		ClaimedTime: 1_700_000_000,
		WriterID:    wid,
		Nonce:       nonce,
		ReadPolicy:  types.ReadAllMembers,
	}
	if err := ev.Sign(writer); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	id, _, err := c.Submit(ctx, pub, ev)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func waitProof(t *testing.T, c *api.Session, id [32]byte) types.InclusionProof {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		proof, err := c.Proof(ctx, id)
		cancel()
		if err == nil {
			return proof
		}
		last = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("proof: %v", last)
	return types.InclusionProof{}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestConfigRoundTrip(t *testing.T) {
	text := "datadir /tmp/d\nlisten 127.0.0.1:1\nclient 127.0.0.1:2\npeers 127.0.0.1:1,127.0.0.1:3\nindex 0\ngenesis /tmp/g\nkeyfile /tmp/k\n"
	cfg, err := ParseConfig(text)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Index != 0 || len(cfg.Peers) != 2 || cfg.Dir != "/tmp/d" {
		t.Fatalf("%+v", cfg)
	}
	if _, err := ParseConfig(text + "nope 1\n"); err == nil {
		t.Fatal("unknown key accepted")
	}
}
