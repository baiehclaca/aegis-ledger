package mempool

import (
	"errors"
	"sync"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

const (
	// MaxEvents is the pool cap across every writer.
	MaxEvents = 4096
	// MaxPerWriter is the cap for one writer. A single writer cannot
	// fill the pool.
	MaxPerWriter = 64
	// MaxIDs is the most event ids one announce or request carries.
	MaxIDs = 64
)

var (
	// ErrFull means the pool or the writer cap would be exceeded.
	ErrFull = errors.New("mempool: full")
	// ErrConflict means this writer already has a different event at
	// that nonce.
	ErrConflict = errors.New("mempool: nonce conflict")
	// ErrFrame means an announce, request, or body is not decodable.
	ErrFrame = errors.New("mempool: frame")
)

type item struct {
	pub crypto.PublicKey
	ev  types.Event
}

// Pool is safe for concurrent use.
type Pool struct {
	mu       sync.Mutex
	byID     map[[crypto.DigestSize]byte]item
	byWriter map[[crypto.DigestSize]byte]map[uint64][crypto.DigestSize]byte
}

// New returns an empty pool.
func New() *Pool {
	return &Pool{
		byID:     map[[crypto.DigestSize]byte]item{},
		byWriter: map[[crypto.DigestSize]byte]map[uint64][crypto.DigestSize]byte{},
	}
}

// Add stores ev under its id. Adding the same id again is a no-op.
func (p *Pool) Add(pub crypto.PublicKey, ev types.Event) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ev.Nonce == 0 {
		return ErrConflict
	}
	id, err := ev.ID()
	if err != nil {
		return err
	}
	if have, ok := p.byID[id]; ok {
		if have.ev.Nonce != ev.Nonce || have.ev.WriterID != ev.WriterID {
			return ErrConflict
		}
		return nil
	}
	if len(p.byID) >= MaxEvents {
		return ErrFull
	}
	nonces := p.byWriter[ev.WriterID]
	if nonces == nil {
		nonces = map[uint64][crypto.DigestSize]byte{}
		p.byWriter[ev.WriterID] = nonces
	}
	if prev, ok := nonces[ev.Nonce]; ok && prev != id {
		return ErrConflict
	}
	if len(nonces) >= MaxPerWriter {
		return ErrFull
	}
	nonces[ev.Nonce] = id
	p.byID[id] = item{pub: pub, ev: ev}
	return nil
}

// Has reports whether id is in the pool.
func (p *Pool) Has(id [crypto.DigestSize]byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.byID[id]
	return ok
}

// Get returns a stored event.
func (p *Pool) Get(id [crypto.DigestSize]byte) (crypto.PublicKey, types.Event, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	it, ok := p.byID[id]
	if !ok {
		return crypto.PublicKey{}, types.Event{}, false
	}
	return it.pub, it.ev, true
}

// IDs returns up to limit stored ids.
func (p *Pool) IDs(limit int) [][crypto.DigestSize]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	if limit <= 0 {
		return nil
	}
	out := make([][crypto.DigestSize]byte, 0, limit)
	for id := range p.byID {
		out = append(out, id)
		if len(out) == limit {
			break
		}
	}
	return out
}

// Writers returns the writers that have at least one stored event.
func (p *Pool) Writers() [][crypto.DigestSize]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([][crypto.DigestSize]byte, 0, len(p.byWriter))
	for w, nonces := range p.byWriter {
		if len(nonces) > 0 {
			out = append(out, w)
		}
	}
	return out
}

// Ready returns events for writer whose nonces form a run starting at
// last+1. A gap holds back the higher nonces so a reordered gossip
// message cannot commit nonce 2 before nonce 1.
func (p *Pool) Ready(writer [crypto.DigestSize]byte, last uint64) []types.Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	nonces := p.byWriter[writer]
	if len(nonces) == 0 {
		return nil
	}
	var out []types.Event
	next := last + 1
	for {
		id, ok := nonces[next]
		if !ok {
			return out
		}
		out = append(out, p.byID[id].ev)
		next++
	}
}

// Forget removes ids. Missing ids are ignored.
func (p *Pool) Forget(ids [][crypto.DigestSize]byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, id := range ids {
		it, ok := p.byID[id]
		if !ok {
			continue
		}
		delete(p.byID, id)
		if nonces := p.byWriter[it.ev.WriterID]; nonces != nil {
			if nonces[it.ev.Nonce] == id {
				delete(nonces, it.ev.Nonce)
			}
			if len(nonces) == 0 {
				delete(p.byWriter, it.ev.WriterID)
			}
		}
	}
}

// Len is the number of stored events.
func (p *Pool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.byID)
}
