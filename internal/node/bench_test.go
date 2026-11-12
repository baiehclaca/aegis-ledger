package node

import (
	"context"
	"crypto/sha3"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/silvergreyhound/silver-grey-ledger/internal/api"
	"github.com/silvergreyhound/silver-grey-ledger/internal/consensus"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/p2p"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
	"github.com/silvergreyhound/silver-grey-ledger/pkg/verify"
)

// TestBenchmarkM3 records the M3 figures. It does not run under
// scripts/check.sh. scripts/bench.sh sets SILVERGREY_BENCH=1.
func TestBenchmarkM3(t *testing.T) {
	if os.Getenv("SILVERGREY_BENCH") != "1" {
		t.Skip("set SILVERGREY_BENCH=1")
	}
	reportMachine(t)
	benchSign(t)
	benchHash(t)
	benchCluster(t)
}

func reportMachine(t *testing.T) {
	t.Helper()
	model := "unknown"
	body, err := os.ReadFile("/proc/cpuinfo")
	if err == nil {
		for _, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(line, "model name") {
				_, name, ok := strings.Cut(line, ":")
				if ok {
					model = strings.TrimSpace(name)
				}
				break
			}
		}
	}
	uname, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("go %s %s/%s cpu %q cores %d gomaxprocs %d kernel %s",
		runtime.Version(), runtime.GOOS, runtime.GOARCH, model, runtime.NumCPU(), runtime.GOMAXPROCS(0), strings.TrimSpace(string(uname)))
}

func benchSign(t *testing.T) {
	t.Helper()
	key, err := crypto.GenerateMLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.Public()
	if err != nil {
		t.Fatal(err)
	}
	var digest [crypto.DigestSize]byte
	digest[0] = 1
	const signs = 32
	const checks = 128
	cpu0 := rusage(t)
	wall0 := time.Now()
	var sig []byte
	for range signs {
		sig, err = key.SignDigest(digest, crypto.ContextEvent)
		if err != nil {
			t.Fatal(err)
		}
	}
	signCPU := rusage(t) - cpu0
	signWall := time.Since(wall0)
	cpu0 = rusage(t)
	wall0 = time.Now()
	for range checks {
		if err := crypto.VerifyDigest(pub, digest, sig, crypto.ContextEvent); err != nil {
			t.Fatal(err)
		}
	}
	verifyCPU := rusage(t) - cpu0
	verifyWall := time.Since(wall0)
	t.Logf("mldsa65 sign n=%d digest=32B wall=%s cpu=%s", signs, signWall, time.Duration(signCPU))
	t.Logf("mldsa65 sign per op wall=%s cpu=%s", signWall/signs, time.Duration(signCPU/signs))
	t.Logf("mldsa65 verify n=%d digest=32B wall=%s cpu=%s", checks, verifyWall, time.Duration(verifyCPU))
	t.Logf("mldsa65 verify per op wall=%s cpu=%s", verifyWall/checks, time.Duration(verifyCPU/checks))
}

func benchHash(t *testing.T) {
	t.Helper()
	buf := make([]byte, 1<<20)
	const rounds = 64
	cpu0 := rusage(t)
	wall0 := time.Now()
	var sum [crypto.DigestSize]byte
	for range rounds {
		sum = sha3.Sum256(buf)
	}
	cpu := rusage(t) - cpu0
	wall := time.Since(wall0)
	if sum == ([crypto.DigestSize]byte{}) && buf[0] == 1 {
		t.Fatal("hash")
	}
	t.Logf("sha3-256 n=%d payload=1MiB wall=%s cpu=%s per op wall=%s cpu=%s",
		rounds, wall, time.Duration(cpu), wall/rounds, time.Duration(cpu/rounds))
}

func benchCluster(t *testing.T) {
	t.Helper()
	const n = 4
	keys := make([]crypto.PrivateKey, n)
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
	peers := make([]string, n)
	clients := make([]string, n)
	for i := range n {
		peers[i] = freeAddr(t)
		clients[i] = freeAddr(t)
	}
	meter := &p2p.Meter{}
	root, stop := context.WithCancel(context.Background())
	defer stop()
	for i := range n {
		cfg := Config{
			Dir:         dir + "/n" + strconv.Itoa(i),
			Listen:      peers[i],
			Client:      clients[i],
			Peers:       peers,
			Index:       i,
			GenesisPath: genesisPath,
			Key:         keys[i],
			KeyPath:     "test-only",
			Meter:       meter,
		}
		go func() {
			_ = Run(root, cfg, nil)
		}()
	}
	client := dialAPI(t, clients[0], writer, g, block, qc)
	leader := dialAPI(t, clients[1], writer, g, block, qc)
	waitListening(t, client, leader)
	before := waitEmpty(t, client)
	meter.Reset()
	wall0 := time.Now()
	id := submitEvent(t, leader, chain, writer, 1, "bench")
	proof := waitProof(t, client, id)
	wall := time.Since(wall0)
	if _, err := verify.Inclusion(proof, g.Validators(), writerPub); err != nil {
		t.Fatal(err)
	}
	sent, recv := meter.Snapshot()
	t.Logf("cluster n=%d subject=%q subject_len=%d doc_preimage=32B nonce=1 wall=%s ciphertext_sent=%d ciphertext_recv=%d height_before=%d height_commit=%d",
		n, string(proof.Event.Subject), len(proof.Event.Subject), wall, sent, recv, before, proof.Header.Height)
	t.Logf("cluster event id %x", id)
}

func waitEmpty(t *testing.T, c *api.Session) uint64 {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		st, err := c.Status(ctx)
		cancel()
		if err == nil && st.Height >= 1 {
			return st.Height
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("empty blocks did not commit")
	return 0
}

func rusage(t *testing.T) int64 {
	t.Helper()
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		t.Fatal(err)
	}
	return timeval(ru.Utime) + timeval(ru.Stime)
}

func timeval(tv syscall.Timeval) int64 {
	return int64(tv.Sec)*int64(time.Second) + int64(tv.Usec)*int64(time.Microsecond)
}
