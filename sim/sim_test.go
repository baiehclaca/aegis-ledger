package sim

import (
	"os"
	"testing"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
)

func TestCheckerCatchesConflict(t *testing.T) {
	var a, b [crypto.DigestSize]byte
	a[0] = 1
	b[0] = 2
	r := Result{Commits: [][]Commit{
		{{Height: 1, Hash: a}},
		{{Height: 1, Hash: b}},
	}}
	if err := r.CheckSafety(); err == nil {
		t.Fatal("conflict was accepted")
	}
	r.Commits[1][0].Hash = a
	if err := r.CheckSafety(); err != nil {
		t.Fatal(err)
	}
	r.Commits[0] = []Commit{{Height: 2, Hash: a}}
	if err := r.CheckSafety(); err == nil {
		t.Fatal("a gap was accepted")
	}
}

func TestScheduleHeightsMatch(t *testing.T) {
	opt := Options{Seed: 7, N: 4, Ticks: 80, GST: 30, Drop: true, MaxDelay: 3, BaseTimeout: 12, MaxTimeout: 48}
	a, err := Run(opt)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Run(opt)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.CheckSafety(); err != nil {
		t.Fatal(err)
	}
	if len(a.Final) != len(b.Final) {
		t.Fatal("height vectors differ in length")
	}
	for i := range a.Final {
		if a.Final[i] != b.Final[i] {
			t.Fatalf("seed %d node %d height %d then %d", opt.Seed, i, a.Final[i], b.Final[i])
		}
	}
}

func TestSafetyCampaign(t *testing.T) {
	for _, n := range []int{4, 7} {
		seeds := campaignSeeds(t, "safety", n)
		committed := false
		for _, seed := range seeds {
			opt := Options{Seed: seed, N: n, Ticks: 140, GST: 50, Drop: true}
			res, err := Run(opt)
			if err != nil {
				t.Fatalf("n=%d seed %d: %v", n, seed, err)
			}
			if err := res.CheckSafety(); err != nil {
				t.Fatalf("n=%d seed %d finals %v: %v", n, seed, res.Final, err)
			}
			for _, h := range res.Final {
				if h >= 1 {
					committed = true
				}
			}
		}
		if !committed {
			t.Fatalf("n=%d safety seeds %v produced no commits", n, seeds)
		}
		t.Logf("safety n=%d seeds %d..%d (%d runs)", n, seeds[0], seeds[len(seeds)-1], len(seeds))
	}
}

func TestLivenessCampaign(t *testing.T) {
	for _, n := range []int{4, 7} {
		seeds := campaignSeeds(t, "liveness", n)
		for _, seed := range seeds {
			opt := Options{Seed: seed, N: n, Ticks: 260, GST: 60, Drop: false}
			res, err := Run(opt)
			if err != nil {
				t.Fatalf("n=%d seed %d: %v", n, seed, err)
			}
			if err := res.CheckSafety(); err != nil {
				t.Fatalf("n=%d seed %d: %v", n, seed, err)
			}
			if err := res.CheckLiveness(); err != nil {
				t.Fatalf("n=%d seed %d atGST %v final %v: %v", n, seed, res.AtGST, res.Final, err)
			}
		}
		t.Logf("liveness n=%d seeds %d..%d (%d runs)", n, seeds[0], seeds[len(seeds)-1], len(seeds))
	}
}

func campaignSeeds(t *testing.T, kind string, n int) []int64 {
	t.Helper()
	if testing.Short() {
		return []int64{1}
	}
	large := os.Getenv("SILVERGREY_SIM_BUDGET") == "large"
	switch {
	case kind == "safety" && n == 4 && large:
		return seq(1, 120)
	case kind == "safety" && n == 7 && large:
		return seq(1001, 60)
	case kind == "liveness" && n == 4 && large:
		return seq(2001, 48)
	case kind == "liveness" && n == 7 && large:
		return seq(3001, 24)
	case kind == "safety" && n == 4:
		return seq(1, 6)
	case kind == "safety" && n == 7:
		return seq(101, 3)
	case kind == "liveness" && n == 4:
		return seq(201, 4)
	case kind == "liveness" && n == 7:
		return seq(301, 2)
	default:
		t.Fatalf("campaign %s n=%d", kind, n)
		return nil
	}
}

func seq(start int64, count int) []int64 {
	out := make([]int64, count)
	for i := range out {
		out[i] = start + int64(i)
	}
	return out
}
