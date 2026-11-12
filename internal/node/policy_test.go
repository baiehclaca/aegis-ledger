package node

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/silvergreyhound/silver-grey-ledger/internal/consensus"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

func TestReadPolicyEnforced(t *testing.T) {
	keys := make([]crypto.PrivateKey, 4)
	for i := range keys {
		key, err := crypto.GenerateMLDSA65()
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = key
	}
	founders := make([]crypto.PrivateKey, 2)
	for i := range founders {
		key, err := crypto.GenerateSLHDSA(nil)
		if err != nil {
			t.Fatal(err)
		}
		founders[i] = key
	}
	readerA, err := crypto.GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	readerB, err := crypto.GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := crypto.GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	outsider, err := crypto.GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	g, block, qc, err := consensus.BuildGenesisWith(consensus.GenesisWith{
		Created:    1_700_000_000,
		Founders:   founders,
		Validators: keys,
		Extra: []consensus.Extra{
			{Key: readerA, Org: "founding-0", Roles: types.RoleReader},
			{Key: readerB, Org: "founding-1", Roles: types.RoleReader},
			{Key: auditor, Org: "founding-0", Roles: types.RoleAuditor | types.RoleReader},
		},
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
	errCh := make(chan error, 4)
	for i := range 4 {
		cfg := Config{
			Dir: filepath.Join(dir, "n"+strconv.Itoa(i)), Listen: peers[i], Client: clients[i],
			Peers: peers, Index: i, GenesisPath: genesisPath, Key: keys[i], KeyPath: "test-only",
		}
		go func() {
			if err := Run(root, cfg, nil); err != nil {
				select {
				case errCh <- err:
				default:
				}
			}
		}()
	}
	writer := dialAPI(t, clients[1], keys[0], g, block, qc)
	same := dialAPI(t, clients[0], readerA, g, block, qc)
	other := dialAPI(t, clients[0], readerB, g, block, qc)
	audit := dialAPI(t, clients[0], auditor, g, block, qc)
	none := dialPinned(t, clients[0], outsider, g.Validators().Keys)
	waitListening(t, writer, same)
	pub, err := keys[0].Public()
	if err != nil {
		t.Fatal(err)
	}
	wid, err := pub.ID()
	if err != nil {
		t.Fatal(err)
	}
	ev := types.Event{
		ChainID: chain, EventType: types.EventShipmentDispatched,
		Subject: []byte("org-only"), Status: 1,
		DocHashes:   []types.DocHash{types.SHA3Doc([32]byte{3})},
		ClaimedTime: 1_700_000_000, WriterID: wid, Nonce: 1,
		ReadPolicy: types.ReadOrgOnly,
	}
	if err := ev.Sign(keys[0]); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	id, _, err := writer.Submit(ctx, pub, ev)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	waitProof(t, writer, id)
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	if _, _, _, err := same.Event(ctx, id); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	if _, _, _, err := audit.Event(ctx, id); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	_, _, _, err = other.Event(ctx, id)
	cancel()
	if status.Code(err) != codes.NotFound {
		t.Fatalf("other organisation: %v", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	_, err = none.Status(ctx)
	cancel()
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-member status: %v", err)
	}
	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}
}
