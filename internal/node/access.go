package node

import (
	"context"

	"github.com/silvergreyhound/silver-grey-ledger/internal/api"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

func (n *Node) syncLedger() error {
	led, err := n.replica.CommittedLedger()
	if err != nil {
		return err
	}
	n.led = led
	keys, err := led.ValidatorKeys()
	if err != nil {
		return err
	}
	changed := len(keys) == len(n.pubs)
	if changed {
		for i := range keys {
			if !keys[i].Equal(n.pubs[i]) {
				changed = true
				break
			}
			if i == len(keys)-1 {
				changed = false
			}
		}
	}
	next := append([]crypto.PublicKey(nil), keys...)
	if len(keys) == len(n.peers) && n.trust != nil {
		n.trust.replace(next)
		if changed {
			n.dropPeers()
		}
	}
	n.pubs = next
	return nil
}

func (n *Node) dropPeers() {
	for _, p := range n.peers {
		if p != nil {
			p.close()
		}
	}
	n.dropInbound()
}

func (n *Node) member(caller crypto.PublicKey) (bool, error) {
	if n.led == nil {
		return false, api.ErrUnavailable
	}
	_, roles, revoked, ok := n.led.Identity(caller, n.replica.CommitHeight())
	if !ok || revoked || roles == 0 {
		return false, api.ErrDenied
	}
	return roles&types.RoleAuditor != 0, nil
}

func (n *Node) canSee(caller crypto.PublicKey, ev types.Event, height uint64) bool {
	id, err := caller.ID()
	if err != nil {
		return false
	}
	if id == ev.WriterID {
		return true
	}
	if n.led == nil {
		return false
	}
	return n.led.CanRead(caller, ev, height)
}

func (n *Node) finalityOf(ev types.Event, height uint64, pending bool) string {
	if pending {
		return "pending"
	}
	if n.led != nil && n.led.Suspect(ev.WriterID, height) {
		return "suspect"
	}
	return "final"
}

// Visible reports whether caller may be told that id committed, and
// whether the event is suspect.
func (n *Node) Visible(ctx context.Context, caller crypto.PublicKey, id [crypto.DigestSize]byte) (string, bool, error) {
	var (
		finality string
		ok       bool
	)
	err := n.call(ctx, func() error {
		if _, err := n.member(caller); err != nil {
			return err
		}
		ev, height, err := n.disk.Event(id)
		if err != nil {
			if missingEvent(err) {
				return nil
			}
			return err
		}
		if !n.canSee(caller, ev, height) {
			return nil
		}
		finality = n.finalityOf(ev, height, false)
		ok = true
		return nil
	})
	return finality, ok, err
}

func (n *Node) redact(caller crypto.PublicKey, block types.Block, auditor bool) types.Block {
	if auditor {
		return block
	}
	out := block
	out.Events = nil
	out.Gov = nil
	for _, ev := range block.Events {
		if n.canSee(caller, ev, block.Header.Height) {
			out.Events = append(out.Events, ev)
		}
	}
	return out
}
