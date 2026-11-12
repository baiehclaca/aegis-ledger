package store

import (
	"errors"
	"testing"

	"github.com/silvergreyhound/silver-grey-ledger/internal/consensus"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

func TestTornBlockDoesNotPublishVote(t *testing.T) {
	keys := testKeys(t, 4)
	g, block, qc, err := consensus.BuildGenesis(1_000, keys)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	d := openDisk(t, dir)
	r, err := consensus.Init(1, keys[1], g, block, qc, testCfg(), d)
	if err != nil {
		t.Fatal(err)
	}
	d.arm(faultTornBlock)
	if _, err := r.Start(1_000); !errors.Is(err, errInjectedTorn) {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d = openDisk(t, dir)
	_, have, err := d.GetSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if have {
		t.Fatal("safety file was published after a torn block write")
	}
}

func TestRestartDoesNotDoubleSign(t *testing.T) {
	keys := testKeys(t, 4)
	g, block, qc, err := consensus.BuildGenesis(1_000, keys)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	d := openDisk(t, dir)
	r, err := consensus.Init(1, keys[1], g, block, qc, testCfg(), d)
	if err != nil {
		t.Fatal(err)
	}
	started, err := r.Start(1_000)
	if err != nil {
		t.Fatal(err)
	}
	prop := proposalOf(started)
	if prop == nil {
		t.Fatal("leader did not propose")
	}
	d.arm(faultTornSafety)
	if _, err := r.Step(consensus.Input{Now: 5_000, Timeout: true}); !errors.Is(err, errInjectedTorn) {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d = openDisk(t, dir)
	r, err = consensus.Load(1, keys[1], g, testCfg(), d)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := r.Step(consensus.Input{Now: 5_000, Proposal: prop})
	if err != nil {
		t.Fatal(err)
	}
	if countVotes(replay) != 0 || countProposals(replay) != 0 {
		t.Fatal("restart signed again for a view already in the snapshot")
	}
	first, err := r.Step(consensus.Input{Now: 6_000, Timeout: true})
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.Step(consensus.Input{Now: 7_000, Timeout: true})
	if err != nil {
		t.Fatal(err)
	}
	if countTimeouts(first) == 0 {
		t.Fatal("the torn timeout was treated as already sent")
	}
	if countTimeouts(second) != 0 || countVotes(first) != 0 || countVotes(second) != 0 {
		t.Fatal("second signature after restart")
	}
	snap, ok, err := d.GetSnapshot()
	if err != nil || !ok {
		t.Fatal(err)
	}
	if _, ok := snap.Voted[1]; !ok {
		t.Fatal("vote record missing")
	}
	if len(snap.TimeoutsSent) != 1 || snap.TimeoutsSent[0] != 1 {
		t.Fatalf("timeouts %+v", snap.TimeoutsSent)
	}
}

func testKeys(t *testing.T, n int) []crypto.PrivateKey {
	t.Helper()
	keys := make([]crypto.PrivateKey, n)
	for i := range keys {
		key, err := crypto.GenerateMLDSA65()
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = key
	}
	return keys
}

func testCfg() consensus.Config {
	return consensus.Config{BaseTimeout: 20, MaxTimeout: 200, Skew: 1_000_000}
}

func proposalOf(out consensus.Output) *types.Proposal {
	for _, m := range out.Messages {
		if m.Proposal != nil {
			p := *m.Proposal
			return &p
		}
	}
	return nil
}

func countVotes(out consensus.Output) int {
	n := 0
	for _, m := range out.Messages {
		if m.Vote != nil {
			n++
		}
	}
	return n
}

func countProposals(out consensus.Output) int {
	n := 0
	for _, m := range out.Messages {
		if m.Proposal != nil {
			n++
		}
	}
	return n
}

func countTimeouts(out consensus.Output) int {
	n := 0
	for _, m := range out.Messages {
		if m.Timeout != nil {
			n++
		}
	}
	return n
}
