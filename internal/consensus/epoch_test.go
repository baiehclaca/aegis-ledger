package consensus

import (
	"testing"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

func TestEpochSwitch(t *testing.T) {
	keys := testKeys(t, 4)
	g, block, qc, err := BuildGenesis(1_000, keys)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := g.ChainID()
	if err != nil {
		t.Fatal(err)
	}
	sim := &net{
		nodes:   make([]*Replica, 4),
		timers:  make([]Timer, 4),
		armed:   make([]int64, 4),
		now:     1_000,
		base:    20,
		commits: make([]map[uint64][crypto.DigestSize]byte, 4),
		voted:   map[voteKey][crypto.DigestSize]byte{},
	}
	for i := range sim.nodes {
		sim.commits[i] = map[uint64][crypto.DigestSize]byte{}
		sim.nodes[i] = newReplica(t, i, keys, g, block, qc)
	}
	old := keys[3]
	oldPub, err := old.Public()
	if err != nil {
		t.Fatal(err)
	}
	oldID, err := oldPub.ID()
	if err != nil {
		t.Fatal(err)
	}
	neu := testKeys(t, 1)[0]
	newPub, err := neu.Public()
	if err != nil {
		t.Fatal(err)
	}
	action := types.GovAction{Kind: types.GovRotate, KeyID: oldID}
	if err := action.SignRotate(chain, oldID, old, neu); err != nil {
		t.Fatal(err)
	}
	tx := types.GovTx{ChainID: chain, Actions: []types.GovAction{action}}
	if err := tx.SignAdmin(keys[0]); err != nil {
		t.Fatal(err)
	}
	if err := tx.SignAdmin(keys[1]); err != nil {
		t.Fatal(err)
	}
	for _, node := range sim.nodes {
		if err := node.SubmitGov([]types.GovTx{tx}); err != nil {
			t.Fatal(err)
		}
		out, err := node.Start(sim.now)
		if err != nil {
			t.Fatal(err)
		}
		sim.take(iOf(sim, node), out)
	}
	sim.driveUntil(t, 400, nil, func() bool { return sim.allCommitted(3) })
	if !sim.allCommitted(3) {
		t.Fatal("epoch height did not commit")
	}
	led, err := sim.nodes[0].CommittedLedger()
	if err != nil {
		t.Fatal(err)
	}
	seats, err := led.ValidatorKeys()
	if err != nil {
		t.Fatal(err)
	}
	if !seats[3].Equal(newPub) {
		t.Fatal("committed validator set did not rotate")
	}
	if err := sim.nodes[3].AdoptKey(neu); err != nil {
		t.Fatal(err)
	}
	ev := eventWith(t, chain, neu, 1)
	id, err := ev.ID()
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range sim.nodes {
		if err := node.Submit([]types.Event{ev}); err != nil {
			t.Fatal(err)
		}
	}
	sim.driveUntil(t, 400, nil, func() bool {
		for _, node := range sim.nodes {
			if countEvent(node, id) != 1 {
				return false
			}
		}
		return true
	})
	for i, node := range sim.nodes {
		if countEvent(node, id) != 1 {
			t.Fatalf("node %d did not commit the rotated key's event", i)
		}
	}
	stale := types.Vote{
		ChainID:   chain,
		View:      sim.nodes[0].View(),
		BlockHash: sim.nodes[0].CommitHash(),
		Signer:    3,
	}
	if err := stale.Sign(old); err != nil {
		t.Fatal(err)
	}
	out, err := sim.nodes[0].Step(Input{Now: sim.now, Vote: &stale})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Dropped {
		t.Fatal("a revoked key's vote was accepted")
	}
	again := eventWith(t, chain, old, 1)
	for _, node := range sim.nodes {
		if err := node.Submit([]types.Event{again}); err != nil {
			t.Fatal(err)
		}
	}
	sim.driveUntil(t, 80, nil, func() bool { return false })
	bad, err := again.ID()
	if err != nil {
		t.Fatal(err)
	}
	for i, node := range sim.nodes {
		if countEvent(node, bad) != 0 {
			t.Fatalf("node %d committed an event from a revoked key", i)
		}
	}
}

func TestEpochSwitchRevokeAndAdd(t *testing.T) {
	keys := testKeys(t, 4)
	g, block, qc, err := BuildGenesis(1_000, keys)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := g.ChainID()
	if err != nil {
		t.Fatal(err)
	}
	sim := &net{
		nodes:   make([]*Replica, 4),
		timers:  make([]Timer, 4),
		armed:   make([]int64, 4),
		now:     1_000,
		base:    20,
		commits: make([]map[uint64][crypto.DigestSize]byte, 4),
		voted:   map[voteKey][crypto.DigestSize]byte{},
	}
	for i := range sim.nodes {
		sim.commits[i] = map[uint64][crypto.DigestSize]byte{}
		sim.nodes[i] = newReplica(t, i, keys, g, block, qc)
	}
	old := keys[3]
	oldPub, err := old.Public()
	if err != nil {
		t.Fatal(err)
	}
	oldID, err := oldPub.ID()
	if err != nil {
		t.Fatal(err)
	}
	neu := testKeys(t, 1)[0]
	newPub, err := neu.Public()
	if err != nil {
		t.Fatal(err)
	}
	kinds := []uint16{types.EventShipmentDispatched, types.EventClearanceGranted, types.EventAccessLogin}
	tx := types.GovTx{ChainID: chain, Actions: []types.GovAction{
		{Kind: types.GovRevokeKey, KeyID: oldID},
		{Kind: types.GovAddValidator, Key: newPub, Org: "founding-0", Address: "local"},
		{Kind: types.GovGrantRole, Key: newPub, Org: "founding-0", Roles: types.RoleKnown, EventTypes: kinds},
	}}
	if err := tx.SignAdmin(keys[0]); err != nil {
		t.Fatal(err)
	}
	if err := tx.SignAdmin(keys[1]); err != nil {
		t.Fatal(err)
	}
	for _, node := range sim.nodes {
		if err := node.SubmitGov([]types.GovTx{tx}); err != nil {
			t.Fatal(err)
		}
		out, err := node.Start(sim.now)
		if err != nil {
			t.Fatal(err)
		}
		sim.take(iOf(sim, node), out)
	}
	sim.driveUntil(t, 400, nil, func() bool { return sim.allCommitted(3) })
	if !sim.allCommitted(3) {
		t.Fatal("epoch height did not commit")
	}
	led, err := sim.nodes[0].CommittedLedger()
	if err != nil {
		t.Fatal(err)
	}
	seats, err := led.ValidatorKeys()
	if err != nil || len(seats) != 4 || !seats[3].Equal(newPub) {
		t.Fatal("revocation did not replace the seat")
	}
	if err := sim.nodes[3].AdoptKey(neu); err != nil {
		t.Fatal(err)
	}
	stale := types.Vote{ChainID: chain, View: sim.nodes[0].View(), BlockHash: sim.nodes[0].CommitHash(), Signer: 3}
	if err := stale.Sign(old); err != nil {
		t.Fatal(err)
	}
	out, err := sim.nodes[0].Step(Input{Now: sim.now, Vote: &stale})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Dropped {
		t.Fatal("a removed seat's old key voted")
	}
	ev := eventWith(t, chain, neu, 1)
	id, err := ev.ID()
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range sim.nodes {
		if err := node.Submit([]types.Event{ev}); err != nil {
			t.Fatal(err)
		}
	}
	sim.driveUntil(t, 400, nil, func() bool {
		for _, node := range sim.nodes {
			if countEvent(node, id) != 1 {
				return false
			}
		}
		return true
	})
	for i, node := range sim.nodes {
		if countEvent(node, id) != 1 {
			t.Fatalf("node %d did not commit the replacement key's event", i)
		}
	}
}

func iOf(n *net, node *Replica) int {
	for i, have := range n.nodes {
		if have == node {
			return i
		}
	}
	return 0
}

func eventWith(t *testing.T, chain [32]byte, writer crypto.PrivateKey, nonce uint64) types.Event {
	t.Helper()
	pub, err := writer.Public()
	if err != nil {
		t.Fatal(err)
	}
	id, err := pub.ID()
	if err != nil {
		t.Fatal(err)
	}
	ev := types.Event{
		ChainID: chain, EventType: types.EventShipmentDispatched,
		Subject: []byte("crate-epoch"), Status: 1,
		DocHashes:   []types.DocHash{types.SHA3Doc([32]byte{9})},
		ClaimedTime: 1_000, WriterID: id, Nonce: nonce,
		ReadPolicy: types.ReadAllMembers,
	}
	if err := ev.Sign(writer); err != nil {
		t.Fatal(err)
	}
	return ev
}
