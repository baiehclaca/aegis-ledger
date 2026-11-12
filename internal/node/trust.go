package node

import (
	"sync"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
)

// keyRing is the validator set a handshake checks. The replica loop
// replaces it when a rotation commits. Dial and accept read it.
type keyRing struct {
	mu   sync.RWMutex
	keys []crypto.PublicKey
}

func newKeyRing(keys []crypto.PublicKey) *keyRing {
	r := &keyRing{}
	r.replace(keys)
	return r
}

func (r *keyRing) snapshot() []crypto.PublicKey {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]crypto.PublicKey(nil), r.keys...)
}

func (r *keyRing) replace(keys []crypto.PublicKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys = append([]crypto.PublicKey(nil), keys...)
}
