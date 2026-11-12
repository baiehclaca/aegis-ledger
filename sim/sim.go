package sim

import (
	"fmt"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

// Options selects one run. N must be 3f+1. Faulty nodes default to f.
// Ticks is the length of the run. GST is the stabilisation tick.
// Drop allows permanent loss before GST, which safety runs use and
// liveness runs must not. MaxDelay is the extra delay before GST, in
// ticks. BaseTimeout is the pacemaker base.
type Options struct {
	Seed        int64
	N           int
	Ticks       int64
	GST         int64
	Drop        bool
	MaxDelay    int64
	BaseTimeout uint64
	MaxTimeout  uint64
}

// Commit is one final block, in the order the replica committed it.
type Commit struct {
	Height uint64
	Hash   [crypto.DigestSize]byte
}

// Result is the observable outcome of one run.
type Result struct {
	Seed    int64
	N       int
	Honest  []int
	Final   []uint64
	AtGST   []uint64
	Commits [][]Commit
	Double  string
}

// CheckSafety fails when two replicas commit different hashes at one
// height, a commit sequence skips a height, or an honest replica voted
// twice. Byzantine replicas run the same core, so their commits count.
func (r Result) CheckSafety() error {
	if r.Double != "" {
		return fmt.Errorf("sim: %s", r.Double)
	}
	seen := map[uint64][crypto.DigestSize]byte{}
	for i, chain := range r.Commits {
		var prev uint64
		for _, c := range chain {
			if c.Height == 0 || (prev == 0 && c.Height != 1) || (prev != 0 && c.Height != prev+1) {
				return fmt.Errorf("sim: node %d commit height %d after %d", i, c.Height, prev)
			}
			prev = c.Height
			if old, ok := seen[c.Height]; ok && old != c.Hash {
				return fmt.Errorf("sim: height %d committed twice", c.Height)
			}
			seen[c.Height] = c.Hash
		}
	}
	return nil
}

// CheckLiveness fails unless every honest replica's commit height grew
// after GST. A replica that had not committed yet must commit at least
// once. Progress is measured against the height recorded at GST, before
// that tick's messages are delivered.
func (r Result) CheckLiveness() error {
	for _, i := range r.Honest {
		if r.Final[i] > r.AtGST[i] {
			continue
		}
		return fmt.Errorf("sim: honest node %d height %d did not pass its GST height %d", i, r.Final[i], r.AtGST[i])
	}
	return nil
}

// Run executes one seeded schedule. The same seed yields the same
// delivery choices. Block hashes still differ between processes because
// signatures are hedged.
func Run(opt Options) (Result, error) {
	if err := opt.prepare(); err != nil {
		return Result{}, err
	}
	w, err := newWorld(opt)
	if err != nil {
		return Result{}, err
	}
	if err := w.start(); err != nil {
		return Result{}, err
	}
	for tick := int64(1); tick <= opt.Ticks; tick++ {
		w.tick = tick
		if tick == opt.GST {
			w.markGST()
		}
		if tick == w.partEnd {
			w.flush()
		}
		if err := w.deliver(); err != nil {
			return Result{}, err
		}
		if err := w.timeouts(); err != nil {
			return Result{}, err
		}
		if len(w.queue) > maxQueue {
			return Result{}, fmt.Errorf("sim: message queue exceeded %d", maxQueue)
		}
	}
	return w.result(), nil
}

func (o *Options) prepare() error {
	if _, err := types.Quorum(o.N); err != nil {
		return err
	}
	if o.Ticks <= 0 || o.GST <= 0 || o.GST > o.Ticks {
		return fmt.Errorf("sim: ticks and GST")
	}
	if o.MaxDelay <= 0 {
		o.MaxDelay = 4
	}
	if o.BaseTimeout == 0 {
		o.BaseTimeout = 10
	}
	if o.MaxTimeout == 0 {
		o.MaxTimeout = 80
	}
	if o.MaxTimeout < o.BaseTimeout {
		return fmt.Errorf("sim: timeout cap")
	}
	return nil
}

// maxQueue stops a schedule that is amplifying messages.
const maxQueue = 100_000
