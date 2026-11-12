package pacemaker

import (
	"fmt"
	"slices"

	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

// maxTimeoutExp caps consecutive failed views so the interval cannot
// overflow a uint64. Sixteen doublings is far past any configured cap.
const maxTimeoutExp = 16

// Config is the timer schedule. Intervals are in the caller's tick,
// which is not wall time.
type Config struct {
	Base uint64
	Cap  uint64
}

// Validate rejects a schedule that would never fire or would shrink.
func (c Config) Validate() error {
	if c.Base == 0 || c.Cap < c.Base {
		return fmt.Errorf("pacemaker: timeout schedule")
	}
	return nil
}

// State is the view-synchronisation state of one replica.
type State struct {
	failures uint32
	sent     map[uint64]struct{}
	bag      map[uint64]map[uint8]types.Timeout
	formed   map[uint64]struct{}
}

// New returns an empty pacemaker state.
func New() *State {
	return &State{
		sent:   map[uint64]struct{}{},
		bag:    map[uint64]map[uint8]types.Timeout{},
		formed: map[uint64]struct{}{},
	}
}

// Duration is the timer for a freshly entered view. A view entered
// because a quorum certificate was formed uses the base interval.
// Each view entered only because of timeouts doubles the interval, up
// to Cap.
func (s *State) Duration(cfg Config) uint64 {
	d := cfg.Base
	exp := s.failures
	if exp > maxTimeoutExp {
		exp = maxTimeoutExp
	}
	for range exp {
		if d > cfg.Cap/2 {
			return cfg.Cap
		}
		d *= 2
	}
	if d > cfg.Cap {
		return cfg.Cap
	}
	return d
}

// Signed returns the timeout stored for signer in view. A retried timer
// rebroadcasts it instead of signing a second wish.
func (s *State) Signed(view uint64, signer uint8) (types.Timeout, bool) {
	by := s.bag[view]
	if by == nil {
		return types.Timeout{}, false
	}
	t, ok := by[signer]
	return t, ok
}

// MarkSent reports whether this replica should broadcast a timeout for
// view. The second call for the same view is false, so a retried timer
// cannot produce a second signed wish.
func (s *State) MarkSent(view uint64) bool {
	if _, ok := s.sent[view]; ok {
		return false
	}
	s.sent[view] = struct{}{}
	return true
}

// Add records a verified timeout. A second timeout from the same signer
// for the same view is a duplicate when it names the same certificate,
// and a conflict when it names another. When the bag reaches a quorum
// for the first time, tc is that certificate.
func (s *State) Add(t types.Timeout, n int) (tc *types.TC, conflict *types.Timeout, err error) {
	quorum, err := types.Quorum(n)
	if err != nil {
		return nil, nil, err
	}
	bySigner := s.bag[t.View]
	if bySigner == nil {
		bySigner = map[uint8]types.Timeout{}
		s.bag[t.View] = bySigner
	}
	if prev, ok := bySigner[t.Signer]; ok {
		if prev.HighQC.View == t.HighQC.View && prev.HighQC.BlockHash == t.HighQC.BlockHash {
			return nil, nil, nil
		}
		return nil, &prev, nil
	}
	bySigner[t.Signer] = t
	if len(bySigner) < quorum {
		return nil, nil, nil
	}
	if _, ok := s.formed[t.View]; ok {
		return nil, nil, nil
	}
	built, err := certificate(t.View, bySigner)
	if err != nil {
		return nil, nil, err
	}
	s.formed[t.View] = struct{}{}
	return &built, nil, nil
}

// NoteEnter updates the backoff. A quorum certificate is progress and
// clears it. A timeout certificate counts as a failed view.
func (s *State) NoteEnter(viaQC bool) {
	if viaQC {
		s.failures = 0
		return
	}
	if s.failures < maxTimeoutExp {
		s.failures++
	}
}

// ForgetBefore drops timeout bags for views the replica has left.
// Sent-marks are kept: a replica must not sign a second timeout for a
// view it already left and might be asked about again.
func (s *State) ForgetBefore(view uint64) {
	for v := range s.bag {
		if v < view {
			delete(s.bag, v)
		}
	}
	for v := range s.formed {
		if v < view {
			delete(s.formed, v)
		}
	}
}

// Failures is the consecutive timeout-driven view entries.
func (s *State) Failures() uint32 { return s.failures }

// SentViews lists the views this replica already signed a timeout for.
func (s *State) SentViews() []uint64 {
	out := make([]uint64, 0, len(s.sent))
	for v := range s.sent {
		out = append(out, v)
	}
	slices.Sort(out)
	return out
}

// Restore replaces the backoff and the sent-marks. The timeout bags are
// not part of durable safety state: losing them only delays the next
// certificate.
func (s *State) Restore(failures uint32, sent []uint64) {
	if failures > maxTimeoutExp {
		failures = maxTimeoutExp
	}
	s.failures = failures
	s.sent = map[uint64]struct{}{}
	for _, v := range sent {
		s.sent[v] = struct{}{}
	}
	s.bag = map[uint64]map[uint8]types.Timeout{}
	s.formed = map[uint64]struct{}{}
}

func certificate(view uint64, bySigner map[uint8]types.Timeout) (types.TC, error) {
	tos := make([]types.Timeout, 0, len(bySigner))
	for _, t := range bySigner {
		tos = append(tos, t)
	}
	tc := types.TC{View: view, Timeouts: tos}
	// Marshal and decode so the value we hand back is the canonical one
	// the wire would carry, including signer order.
	raw, err := tc.MarshalBinary()
	if err != nil {
		return types.TC{}, err
	}
	return types.UnmarshalTC(raw)
}
