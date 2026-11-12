package e2e

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/silvergreyhound/silver-grey-ledger/internal/api"
	"github.com/silvergreyhound/silver-grey-ledger/internal/keyfile"
	"github.com/silvergreyhound/silver-grey-ledger/internal/node"
)

func TestNetemFour(t *testing.T) {
	runNetem(t, 4, 1)
}

func TestNetemSeven(t *testing.T) {
	runNetem(t, 7, 2)
}

// runNetem starts one process per validator, each in its own network
// namespace, and drives delay, loss, reorder, a partition, and recovery.
// isolate is how many nodes to cut (f). The submit target stays reachable.
func runNetem(t *testing.T, n, isolate int) {
	t.Helper()
	if _, err := exec.Command("sudo", "-n", "true").CombinedOutput(); err != nil {
		t.Skip("sudo -n is not available")
	}
	if err := exec.Command("sudo", "-n", "ethtool", "--version").Run(); err != nil {
		t.Skip("ethtool is not available")
	}
	if err := exec.Command("sudo", "-n", "iptables-legacy", "--version").Run(); err != nil {
		t.Skip("iptables-legacy is not available")
	}
	bin := buildSilverGrey(t)
	dir := t.TempDir()
	pass := filepath.Join(dir, "pass")
	if err := os.WriteFile(pass, []byte("test-pass-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var keys, pubs []string
	for i := range n + 1 {
		k := filepath.Join(dir, "k"+strconv.Itoa(i)+".key")
		p := filepath.Join(dir, "k"+strconv.Itoa(i)+".pub")
		must(t, bin, "keygen", "--alg", "ml-dsa-65", "--out", k, "--pub", p, "--passphrase-file", pass)
		keys = append(keys, k)
		pubs = append(pubs, p)
	}
	founderA := filepath.Join(dir, "founder-a.key")
	founderB := filepath.Join(dir, "founder-b.key")
	must(t, bin, "keygen", "--alg", "slh-dsa-shake-128s", "--out", founderA, "--pub", filepath.Join(dir, "founder-a.pub"), "--passphrase-file", pass)
	must(t, bin, "keygen", "--alg", "slh-dsa-shake-128s", "--out", founderB, "--pub", filepath.Join(dir, "founder-b.pub"), "--passphrase-file", pass)
	genesis := filepath.Join(dir, "genesis.bin")
	validators := filepath.Join(dir, "validators.bin")
	must(t, bin, "node", "genesis", "--out", genesis, "--validators-out", validators,
		"--founders", founderA+","+founderB, "--keys", strings.Join(keys[:n], ","),
		"--writers", keys[n], "--passphrase-file", pass, "--time", "1700000000")
	tag := os.Getpid()%10000 + n
	gw := fmt.Sprintf("agw%d", tag)
	gwPeer := fmt.Sprintf("agp%d", tag)
	nsName := func(i int) string { return fmt.Sprintf("agn%d%d", tag, i) }
	hostPeer := func(i int) string { return fmt.Sprintf("agh%d%d", tag, i) }
	pidfile := filepath.Join(dir, "impaird.pid")
	ctrl := filepath.Join(dir, "impaird.sock")
	cleanupNet(gw, n, nsName, hostPeer)
	t.Cleanup(func() {
		if t.Failed() {
			for i := range n {
				t.Logf("node %d stderr:\n%s", i, readLog(filepath.Join(dir, "n"+strconv.Itoa(i))))
			}
		}
		stopImpair(pidfile)
		cleanupNet(gw, n, nsName, hostPeer)
		sudoDrop("rm", "-rf", dir)
	})
	// CONFIG_NET_SCH_NETEM is unset in this kernel, and the legacy FORWARD
	// chain drops bridged frames. A userspace forwarder on the veth peers
	// carries the packets and applies the netem parameters when asked.
	sudo(t, "ip", "link", "add", gw, "type", "veth", "peer", "name", gwPeer)
	sudo(t, "ip", "addr", "add", "10.90.0.1/24", "dev", gw)
	sudo(t, "ip", "link", "set", gw, "up")
	sudo(t, "ip", "link", "set", gwPeer, "promisc", "on")
	sudo(t, "ip", "link", "set", gwPeer, "up")
	// veth checksum offload leaves TCP checksums incomplete. A userspace
	// forwarder copies the frame as it stands, so the offload has to be off
	// or the peer drops every TCP segment.
	disableOffload(t, "", gw)
	disableOffload(t, "", gwPeer)
	peers := make([]string, n)
	clients := make([]string, n)
	for i := range n {
		ip := fmt.Sprintf("10.90.0.%d", 10+i)
		peers[i] = net.JoinHostPort(ip, "19000")
		clients[i] = net.JoinHostPort(ip, "19001")
	}
	for i := range n {
		ip := fmt.Sprintf("10.90.0.%d", 10+i)
		sudo(t, "ip", "netns", "add", nsName(i))
		// The peer is created under a free name. A runner that already
		// has eth0 in the root namespace rejects "peer name eth0" with
		// EEXIST. The interface is renamed after it moves into the new
		// namespace.
		peer := fmt.Sprintf("agx%d%d", tag, i)
		sudo(t, "ip", "link", "add", hostPeer(i), "type", "veth", "peer", "name", peer)
		sudo(t, "ip", "link", "set", hostPeer(i), "promisc", "on")
		sudo(t, "ip", "link", "set", hostPeer(i), "up")
		disableOffload(t, "", hostPeer(i))
		sudo(t, "ip", "link", "set", peer, "netns", nsName(i))
		sudo(t, "ip", "netns", "exec", nsName(i), "ip", "link", "set", peer, "name", "eth0")
		sudo(t, "ip", "netns", "exec", nsName(i), "ip", "addr", "add", ip+"/24", "dev", "eth0")
		sudo(t, "ip", "netns", "exec", nsName(i), "ip", "link", "set", "eth0", "up")
		sudo(t, "ip", "netns", "exec", nsName(i), "ip", "link", "set", "lo", "up")
		disableOffload(t, nsName(i), "eth0")
		nodeDir := filepath.Join(dir, "n"+strconv.Itoa(i))
		must(t, bin, "node", "init",
			"--dir", nodeDir,
			"--index", strconv.Itoa(i),
			"--listen", peers[i],
			"--client", clients[i],
			"--peers", strings.Join(peers, ","),
			"--genesis", genesis,
			"--keyfile", keys[i],
		)
	}
	var nodeIfs []string
	for i := range n {
		nodeIfs = append(nodeIfs, hostPeer(i))
	}
	startImpair(t, ctrl, pidfile, gwPeer, nodeIfs)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	procs := make([]*exec.Cmd, n)
	for i := range n {
		procs[i] = startNS(ctx, t, bin, nsName(i), filepath.Join(dir, "n"+strconv.Itoa(i)), pass)
	}
	t.Cleanup(func() {
		for i := range n {
			killNS(nsName(i))
		}
	})
	writer := n
	doc := filepath.Join(dir, "note.txt")
	if err := os.WriteFile(doc, []byte("shipment note"), 0o644); err != nil {
		t.Fatal(err)
	}
	submit := func(nonce int, node int) string {
		t.Helper()
		return strings.TrimSpace(must(t, bin, "event", "submit",
			"--node", clients[node],
			"--key", keys[writer],
			"--passphrase-file", pass,
			"--genesis", genesis,
			"--type", "shipment",
			"--subject", "PN-"+strconv.Itoa(nonce),
			"--doc", doc,
			"--nonce", strconv.Itoa(nonce),
		))
	}
	prove := func(id string, node int) string {
		t.Helper()
		out := filepath.Join(dir, "proof-"+id[:8]+"-"+strconv.Itoa(node)+".bin")
		waitProof(t, bin, out, clients[node], keys[writer], pass, genesis, id)
		must(t, bin, "verify", "document", doc, "--proof", out, "--validators", validators, "--writer", pubs[writer])
		return out
	}
	t.Log("commit 1, clear network")
	id1 := submit(1, 1)
	prove(id1, 0)
	t.Log("commit 2, impaired")
	impairCmd(t, ctrl, "on")
	id2 := submit(2, 1)
	prove(id2, 0)
	t.Log("commit 3, partition")
	// The cut is a separate phase. Loss and a black hole together make
	// the live quorum's commit time depend on TCP buffers. REJECT resets
	// those connections so the remaining n-f nodes can keep voting.
	impairCmd(t, ctrl, "off")
	for i := n - isolate; i < n; i++ {
		sudo(t, "ip", "netns", "exec", nsName(i), "iptables-legacy", "-A", "INPUT", "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset")
		sudo(t, "ip", "netns", "exec", nsName(i), "iptables-legacy", "-A", "OUTPUT", "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset")
	}
	id3 := submit(3, 1)
	prove(id3, 1)
	for i := n - isolate; i < n; i++ {
		sudo(t, "ip", "netns", "exec", nsName(i), "iptables-legacy", "-F")
	}
	t.Log("healed, waiting for height")
	waitHeight(t, clients[n-1], keys[writer], pass, genesis, clients[1])
	t.Log("commit 4 from the healed node")
	id4 := submit(4, 1)
	prove(id4, n-1)
}

func buildSilverGrey(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "silvergrey")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/silvergreyhound/silver-grey-ledger/cmd/silvergrey")
	cmd.Dir = filepath.Join("..", "..")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func startNS(ctx context.Context, t *testing.T, bin, ns, dir, pass string) *exec.Cmd {
	t.Helper()
	cmd := exec.CommandContext(ctx, "sudo", "-n", "ip", "netns", "exec", ns, bin, "node", "start", "--dir", dir, "--passphrase-file", pass)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	logf, err := os.Create(filepath.Join(dir, "stderr.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = logf
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
			t.Fatalf("node exited before listening\n%s", readLog(dir))
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("node did not listen\n%s", readLog(dir))
	}
	return cmd
}

func waitProof(t *testing.T, bin, proof, addr, key, pass, genesis, id string) {
	t.Helper()
	deadline := time.Now().Add(120 * time.Second)
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
		time.Sleep(200 * time.Millisecond)
	}
	c := dialNode(t, addr, key, pass, genesis)
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	st, serr := c.Status(ctx)
	cancel()
	t.Fatalf("proof from %s: %s (status height=%d view=%d err=%v)", addr, last, st.Height, st.View, serr)
}

func readLog(dir string) string {
	raw, err := os.ReadFile(filepath.Join(dir, "stderr.log"))
	if err != nil {
		return err.Error()
	}
	if len(raw) > 4000 {
		raw = raw[len(raw)-4000:]
	}
	return string(raw)
}

func waitHeight(t *testing.T, healed, key, pass, genesis, live string) {
	t.Helper()
	healedC := dialNode(t, healed, key, pass, genesis)
	liveC := dialNode(t, live, key, pass, genesis)
	defer func() { _ = healedC.Close() }()
	defer func() { _ = liveC.Close() }()
	deadline := time.Now().Add(120 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		got, err := healedC.Status(ctx)
		want, err2 := liveC.Status(ctx)
		cancel()
		if err == nil && err2 == nil && got.Height > 0 && got.Height >= want.Height {
			return
		}
		if err != nil {
			last = err
		} else {
			last = err2
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("catch-up: %v", last)
}

func dialNode(t *testing.T, addr, keyPath, passPath, genesisPath string) *api.Session {
	t.Helper()
	phrase, err := os.ReadFile(passPath)
	if err != nil {
		t.Fatal(err)
	}
	key, err := keyfile.Open(keyPath, strings.TrimRight(string(phrase), "\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	g, block, qc, err := node.ReadGenesis(genesisPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := api.DialChain(ctx, addr, key, g, block, qc)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func must(t *testing.T, bin string, args ...string) string {
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

func disableOffload(t *testing.T, ns, dev string) {
	t.Helper()
	args := []string{}
	if ns != "" {
		args = append(args, "ip", "netns", "exec", ns)
	}
	args = append(args, "ethtool", "-K", dev, "tx", "off", "rx", "off", "tso", "off", "gso", "off", "gro", "off", "sg", "off")
	sudo(t, args...)
}

func startImpair(t *testing.T, ctrl, pidfile, host string, nodes []string) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "impaird")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/silvergreyhound/silver-grey-ledger/test/e2e/impaird")
	cmd.Dir = filepath.Join("..", "..")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build impaird: %v\n%s", err, out)
	}
	proc := exec.Command("sudo", "-n", bin,
		"--ctrl", ctrl,
		"--host", host,
		"--nodes", strings.Join(nodes, ","),
		"--pidfile", pidfile,
		"--delay", "20ms",
		"--jitter", "5ms",
		"--loss", "0.01",
		"--reorder", "0.05",
		"--correlation", "0.5",
	)
	stdout, err := proc.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	proc.Stderr = &stderr
	if err := proc.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		if sc.Scan() {
			ready <- sc.Text()
			return
		}
		ready <- ""
	}()
	select {
	case line := <-ready:
		if line != "impair ready" {
			t.Fatalf("impaird did not start: %q\n%s", line, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("impaird did not start\n%s", stderr.String())
	}
}

func impairCmd(t *testing.T, ctrl, command string) {
	t.Helper()
	conn, err := net.Dial("unix", ctrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte(command + "\n")); err != nil {
		t.Fatal(err)
	}
}

func stopImpair(pidfile string) {
	raw, err := os.ReadFile(pidfile)
	if err != nil {
		return
	}
	pid := strings.TrimSpace(string(raw))
	if pid == "" {
		return
	}
	sudoDrop("kill", "-9", pid)
}

func sudo(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command("sudo", append([]string{"-n"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func cleanupNet(gw string, n int, nsName func(int) string, hostPeer func(int) string) {
	for i := range n {
		killNS(nsName(i))
		sudoDrop("ip", "netns", "del", nsName(i))
		sudoDrop("ip", "link", "del", hostPeer(i))
	}
	sudoDrop("ip", "link", "del", gw)
}

func killNS(ns string) {
	out, err := exec.Command("sudo", "-n", "ip", "netns", "pids", ns).Output()
	if err != nil {
		return
	}
	for _, pid := range strings.Fields(string(out)) {
		sudoDrop("kill", "-9", pid)
	}
}

func sudoDrop(args ...string) {
	cmd := exec.Command("sudo", append([]string{"-n"}, args...)...)
	_ = cmd.Run()
}
