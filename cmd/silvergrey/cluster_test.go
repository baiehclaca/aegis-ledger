package main

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCLICluster(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "silvergrey")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	dir := t.TempDir()
	pass := filepath.Join(dir, "pass")
	if err := os.WriteFile(pass, []byte("test-pass-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var keys, pubs []string
	for i := range 5 {
		k := filepath.Join(dir, "k"+strconv.Itoa(i)+".key")
		p := filepath.Join(dir, "k"+strconv.Itoa(i)+".pub")
		mustRun(t, bin, "keygen", "--alg", "ml-dsa-65", "--out", k, "--pub", p, "--passphrase-file", pass)
		keys = append(keys, k)
		pubs = append(pubs, p)
	}
	founderA := filepath.Join(dir, "founder-a.key")
	founderB := filepath.Join(dir, "founder-b.key")
	mustRun(t, bin, "keygen", "--alg", "slh-dsa-shake-128s", "--out", founderA, "--pub", filepath.Join(dir, "founder-a.pub"), "--passphrase-file", pass)
	mustRun(t, bin, "keygen", "--alg", "slh-dsa-shake-128s", "--out", founderB, "--pub", filepath.Join(dir, "founder-b.pub"), "--passphrase-file", pass)
	genesis := filepath.Join(dir, "genesis.bin")
	validators := filepath.Join(dir, "validators.bin")
	mustRun(t, bin, "node", "genesis", "--out", genesis, "--validators-out", validators,
		"--founders", founderA+","+founderB, "--keys", strings.Join(keys[:4], ","),
		"--writers", keys[4], "--passphrase-file", pass, "--time", "1700000000")
	peers := make([]string, 4)
	clients := make([]string, 4)
	for i := range 4 {
		peers[i] = freeListen(t)
		clients[i] = freeListen(t)
	}
	for i := range 4 {
		nodeDir := filepath.Join(dir, "n"+strconv.Itoa(i))
		mustRun(t, bin, "node", "init",
			"--dir", nodeDir,
			"--index", strconv.Itoa(i),
			"--listen", peers[i],
			"--client", clients[i],
			"--peers", strings.Join(peers, ","),
			"--genesis", genesis,
			"--keyfile", keys[i],
		)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	procs := make([]*exec.Cmd, 4)
	for i := range 4 {
		procs[i] = startNode(ctx, t, bin, filepath.Join(dir, "n"+strconv.Itoa(i)), pass)
	}
	doc := filepath.Join(dir, "note.txt")
	if err := os.WriteFile(doc, []byte("shipment note"), 0o644); err != nil {
		t.Fatal(err)
	}
	id := strings.TrimSpace(mustRun(t, bin, "event", "submit",
		"--node", clients[1], "--key", keys[4], "--passphrase-file", pass,
		"--genesis", genesis,
		"--type", "shipment", "--subject", "PN-1", "--doc", doc, "--nonce", "1"))
	proof := filepath.Join(dir, "proof.bin")
	waitCLI(t, bin, proof, clients[0], keys[4], pass, genesis, id)
	mustRun(t, bin, "verify", "document", doc, "--proof", proof, "--validators", validators, "--writer", pubs[4])
	if err := procs[0].Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_, _ = procs[0].Process.Wait()
	procs[0] = startNode(ctx, t, bin, filepath.Join(dir, "n0"), pass)
	id2 := strings.TrimSpace(mustRun(t, bin, "event", "submit",
		"--node", clients[1], "--key", keys[4], "--passphrase-file", pass,
		"--genesis", genesis,
		"--type", "shipment", "--subject", "PN-2", "--doc", doc, "--nonce", "2"))
	proof2 := filepath.Join(dir, "proof2.bin")
	waitCLI(t, bin, proof2, clients[0], keys[4], pass, genesis, id2)
	mustRun(t, bin, "verify", "document", doc, "--proof", proof2, "--validators", validators, "--writer", pubs[4])
	mustRun(t, bin, "verify", "document", doc,
		"--node", clients[0], "--key", keys[4], "--passphrase-file", pass,
		"--genesis", genesis, "--writer", pubs[4])
	got := mustRun(t, bin, "event", "get", "--node", clients[0],
		"--key", keys[4], "--passphrase-file", pass, "--genesis", genesis, id2)
	if !strings.Contains(got, "subject PN-2") {
		t.Fatalf("get: %s", got)
	}
	for _, p := range procs {
		if p.Process != nil {
			_ = p.Process.Kill()
		}
	}
}

func mustRun(t *testing.T, bin string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String()
}

func startNode(ctx context.Context, t *testing.T, bin, dir, pass string) *exec.Cmd {
	t.Helper()
	cmd := exec.CommandContext(ctx, bin, "node", "start", "--dir", dir, "--passphrase-file", pass)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		signaled := false
		for sc.Scan() {
			if !signaled && strings.Contains(sc.Text(), "listening") {
				ready <- true
				signaled = true
			}
		}
		if !signaled {
			ready <- false
		}
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatalf("node exited before listening\n%s", stderr.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("node did not listen\n%s", stderr.String())
	}
	return cmd
}

func waitCLI(t *testing.T, bin, proof, addr, key, pass, genesis, id string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		cmd := exec.Command(bin, "event", "proof",
			"--node", addr, "--key", key, "--passphrase-file", pass,
			"--genesis", genesis, "--out", proof, id)
		out, err := cmd.CombinedOutput()
		if err == nil {
			return
		}
		last = string(out)
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("proof: %s", last)
}

func freeListen(t *testing.T) string {
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
