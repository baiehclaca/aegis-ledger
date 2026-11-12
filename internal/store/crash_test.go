package store

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/silvergreyhound/silver-grey-ledger/internal/consensus"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

func TestKillMidBlock(t *testing.T) {
	if os.Getenv("SILVERGREY_CRASH") == "block" {
		crashMidBlock()
		return
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestKillMidBlock$", "-test.count=1")
	cmd.Env = append(os.Environ(), "SILVERGREY_CRASH=block", "SILVERGREY_DIR="+dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if !killed(err) {
		t.Fatalf("child exit %v\n%s", err, stderr.String())
	}
	d := openDisk(t, dir)
	if _, ok, err := d.GetBlock(mustHash(t, sampleBlock(1))); err != nil || !ok {
		t.Fatalf("prefix: ok=%v err=%v", ok, err)
	}
	if _, ok, err := d.GetBlock(mustHash(t, sampleBlock(2))); err != nil || ok {
		t.Fatalf("partial record survived: ok=%v err=%v", ok, err)
	}
	if err := d.PutBlock(sampleBlock(3)); err != nil {
		t.Fatal(err)
	}
}

func TestKillMidVote(t *testing.T) {
	if os.Getenv("SILVERGREY_CRASH") == "vote" {
		crashMidVote()
		return
	}
	dir := t.TempDir()
	keys := testKeys(t, 4)
	if err := writeSeeds(filepath.Join(dir, "seeds"), keys); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestKillMidVote$", "-test.count=1")
	cmd.Env = append(os.Environ(), "SILVERGREY_CRASH=vote", "SILVERGREY_DIR="+dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if !killed(err) {
		t.Fatalf("child exit %v\n%s", err, stderr.String())
	}
	keys, err = readSeeds(filepath.Join(dir, "seeds"))
	if err != nil {
		t.Fatal(err)
	}
	g, _, _, err := readBundle(filepath.Join(dir, "genesis.bin"))
	if err != nil {
		t.Fatal(err)
	}
	d := openDisk(t, dir)
	r, err := consensus.Load(1, keys[1], g, testCfg(), d)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := r.Step(consensus.Input{Now: 5_000, Timeout: true})
	if err != nil {
		t.Fatal(err)
	}
	again, err := r.Step(consensus.Input{Now: 6_000, Timeout: true})
	if err != nil {
		t.Fatal(err)
	}
	if countVotes(replay) != 0 || countVotes(again) != 0 || countProposals(replay) != 0 {
		t.Fatal("restart signed a second vote or proposal")
	}
	if countTimeouts(replay) == 0 || countTimeouts(again) != 0 {
		t.Fatalf("timeouts first=%d second=%d", countTimeouts(replay), countTimeouts(again))
	}
	snap, ok, err := d.GetSnapshot()
	if err != nil || !ok {
		t.Fatal(err)
	}
	if _, voted := snap.Voted[1]; !voted {
		t.Fatal("durable vote missing after kill")
	}
}

func crashMidBlock() {
	dir := os.Getenv("SILVERGREY_DIR")
	d, err := Open(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := d.PutBlock(sampleBlock(1)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	d.arm(faultKillBlock)
	if err := d.PutBlock(sampleBlock(2)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "kill returned")
	os.Exit(2)
}

func crashMidVote() {
	dir := os.Getenv("SILVERGREY_DIR")
	keys, err := readSeeds(filepath.Join(dir, "seeds"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	g, block, qc, err := consensus.BuildGenesis(1_000, keys)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := writeBundle(filepath.Join(dir, "genesis.bin"), g, block, qc); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	d, err := Open(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	r, err := consensus.Init(1, keys[1], g, block, qc, testCfg(), d)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if _, err := r.Start(1_000); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	d.arm(faultKillSafety)
	if _, err := r.Step(consensus.Input{Now: 5_000, Timeout: true}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "kill returned")
	os.Exit(2)
}

func killed(err error) bool {
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return false
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == syscall.SIGKILL
}

func writeSeeds(path string, keys []crypto.PrivateKey) error {
	var buf bytes.Buffer
	for _, key := range keys {
		raw, err := key.MarshalBinary()
		if err != nil {
			return err
		}
		if len(raw) != crypto.MLDSASeedSize() {
			return fmt.Errorf("store: seed length")
		}
		if _, err := buf.Write(raw); err != nil {
			return err
		}
	}
	return os.WriteFile(path, buf.Bytes(), 0o600)
}

func readSeeds(path string) ([]crypto.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw)%crypto.MLDSASeedSize() != 0 || len(raw) == 0 {
		return nil, fmt.Errorf("store: seeds")
	}
	keys := make([]crypto.PrivateKey, 0, len(raw)/crypto.MLDSASeedSize())
	for off := 0; off < len(raw); off += crypto.MLDSASeedSize() {
		key, err := crypto.NewMLDSA65FromSeed(raw[off : off+crypto.MLDSASeedSize()])
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func writeBundle(path string, g types.Genesis, block types.Block, qc types.QC) error {
	parts := make([][]byte, 3)
	var err error
	if parts[0], err = g.MarshalBinary(); err != nil {
		return err
	}
	if parts[1], err = block.MarshalBinary(); err != nil {
		return err
	}
	if parts[2], err = qc.MarshalBinary(); err != nil {
		return err
	}
	buf := make([]byte, 0, 64)
	buf = append(buf, 'A', 'G', 'B', '1')
	for _, p := range parts {
		var n [4]byte
		n[0] = byte(len(p) >> 24)
		n[1] = byte(len(p) >> 16)
		n[2] = byte(len(p) >> 8)
		n[3] = byte(len(p))
		buf = append(buf, n[:]...)
		buf = append(buf, p...)
	}
	return os.WriteFile(path, buf, 0o600)
}

func readBundle(path string) (types.Genesis, types.Block, types.QC, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return types.Genesis{}, types.Block{}, types.QC{}, err
	}
	if len(raw) < 4 || string(raw[:4]) != "AGB1" {
		return types.Genesis{}, types.Block{}, types.QC{}, fmt.Errorf("store: genesis bundle")
	}
	rest := raw[4:]
	take := func() ([]byte, error) {
		if len(rest) < 4 {
			return nil, fmt.Errorf("store: genesis bundle")
		}
		n := int(rest[0])<<24 | int(rest[1])<<16 | int(rest[2])<<8 | int(rest[3])
		rest = rest[4:]
		if n < 0 || len(rest) < n {
			return nil, fmt.Errorf("store: genesis bundle")
		}
		out := rest[:n]
		rest = rest[n:]
		return out, nil
	}
	gb, err := take()
	if err != nil {
		return types.Genesis{}, types.Block{}, types.QC{}, err
	}
	bb, err := take()
	if err != nil {
		return types.Genesis{}, types.Block{}, types.QC{}, err
	}
	qb, err := take()
	if err != nil {
		return types.Genesis{}, types.Block{}, types.QC{}, err
	}
	g, err := types.UnmarshalGenesis(gb)
	if err != nil {
		return types.Genesis{}, types.Block{}, types.QC{}, err
	}
	block, err := types.UnmarshalBlock(bb)
	if err != nil {
		return types.Genesis{}, types.Block{}, types.QC{}, err
	}
	qc, err := types.UnmarshalQC(qb)
	if err != nil {
		return types.Genesis{}, types.Block{}, types.QC{}, err
	}
	return g, block, qc, nil
}
