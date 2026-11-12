package node

import (
	"context"
	"errors"

	"github.com/silvergreyhound/silver-grey-ledger/internal/api"
	"github.com/silvergreyhound/silver-grey-ledger/internal/consensus"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/p2p"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

const maxProposals = 64

// ProposeGov stores a governance transaction from an admin.
// A transaction that already has enough signatures is submitted.
func (n *Node) ProposeGov(ctx context.Context, caller crypto.PublicKey, raw []byte) ([crypto.DigestSize]byte, int, bool, error) {
	var (
		id        [crypto.DigestSize]byte
		sigs      int
		submitted bool
	)
	err := n.call(ctx, func() error {
		if _, err := n.admin(caller); err != nil {
			return err
		}
		tx, err := types.UnmarshalGovTx(raw)
		if err != nil || tx.ChainID != n.chain {
			return api.ErrRejected
		}
		got, err := tx.ID()
		if err != nil {
			return api.ErrRejected
		}
		if have, ok := n.office[got]; ok {
			tx = have
		} else {
			if len(n.office) >= maxProposals {
				return api.ErrRejected
			}
			n.office[got] = tx
		}
		id = got
		sigs = len(tx.Admins)
		submitted, err = n.maybeSubmit(tx)
		return err
	})
	return id, sigs, submitted, err
}

// SignGov appends this admin's signature to a stored proposal.
func (n *Node) SignGov(ctx context.Context, caller crypto.PublicKey, id [crypto.DigestSize]byte, sig []byte) (int, bool, error) {
	var (
		sigs      int
		submitted bool
	)
	err := n.call(ctx, func() error {
		if _, err := n.admin(caller); err != nil {
			return err
		}
		tx, ok := n.office[id]
		if !ok {
			return api.ErrNotFound
		}
		cid, err := caller.ID()
		if err != nil {
			return api.ErrRejected
		}
		sum, err := tx.ID()
		if err != nil {
			return api.ErrRejected
		}
		if err := crypto.VerifyDigest(caller, sum, sig, crypto.ContextGovernance); err != nil {
			return api.ErrRejected
		}
		if err := tx.AddAdminSig(cid, sig); err != nil {
			return api.ErrRejected
		}
		n.office[id] = tx
		sigs = len(tx.Admins)
		submitted, err = n.maybeSubmit(tx)
		return err
	})
	return sigs, submitted, err
}

// ListGov returns stored proposal ids. Admins and auditors may list them.
func (n *Node) ListGov(ctx context.Context, caller crypto.PublicKey) ([][crypto.DigestSize]byte, error) {
	var ids [][crypto.DigestSize]byte
	err := n.call(ctx, func() error {
		auditor, err := n.member(caller)
		if err != nil {
			return err
		}
		if !auditor {
			if _, err := n.admin(caller); err != nil {
				return err
			}
		}
		ids = make([][crypto.DigestSize]byte, 0, len(n.office))
		for id := range n.office {
			ids = append(ids, id)
		}
		return nil
	})
	return ids, err
}

func (n *Node) admin(caller crypto.PublicKey) (string, error) {
	if n.led == nil {
		return "", api.ErrUnavailable
	}
	org, roles, revoked, ok := n.led.Identity(caller, n.replica.CommitHeight())
	if !ok || revoked || roles&types.RoleAdmin == 0 {
		return "", api.ErrDenied
	}
	return org, nil
}

func (n *Node) maybeSubmit(tx types.GovTx) (bool, error) {
	if !n.govReady(tx) {
		return false, nil
	}
	if err := n.replica.SubmitGov([]types.GovTx{tx}); err != nil {
		if errors.Is(err, consensus.ErrQueueFull) {
			return false, api.ErrRejected
		}
		return false, api.ErrRejected
	}
	n.rememberGov(tx)
	n.broadcastGov(tx, -1)
	id, err := tx.ID()
	if err == nil {
		delete(n.office, id)
	}
	return true, nil
}

func (n *Node) govReady(tx types.GovTx) bool {
	if n.led == nil {
		return false
	}
	sum, err := tx.ID()
	if err != nil {
		return false
	}
	height := n.replica.CommitHeight()
	orgs := map[string]struct{}{}
	for _, a := range tx.Admins {
		key, org, roles, revoked, ok := n.led.IdentityByID(a.KeyID, height)
		if !ok || revoked || roles&types.RoleAdmin == 0 {
			return false
		}
		if _, dup := orgs[org]; dup {
			return false
		}
		if err := crypto.VerifyDigest(key, sum, a.Sig, crypto.ContextGovernance); err != nil {
			return false
		}
		orgs[org] = struct{}{}
	}
	return len(orgs) >= n.led.Threshold()
}

func (n *Node) acceptGov(tx types.GovTx, from int) {
	if tx.ChainID != n.chain || !n.govReady(tx) {
		return
	}
	id, err := tx.ID()
	if err != nil {
		return
	}
	if _, ok := n.seenGov[id]; ok {
		return
	}
	if err := n.replica.SubmitGov([]types.GovTx{tx}); err != nil {
		return
	}
	n.rememberGov(tx)
	n.broadcastGov(tx, from)
}

func (n *Node) rememberGov(tx types.GovTx) {
	id, err := tx.ID()
	if err != nil {
		return
	}
	if len(n.seenGov) >= 256 {
		n.seenGov = map[[crypto.DigestSize]byte]struct{}{}
	}
	n.seenGov[id] = struct{}{}
}

func (n *Node) broadcastGov(tx types.GovTx, skip int) {
	raw, err := tx.MarshalBinary()
	if err != nil {
		return
	}
	frame, err := frameKind(p2p.KindGov, raw)
	if err != nil {
		return
	}
	for i, p := range n.peers {
		if p == nil || i == skip {
			continue
		}
		p.send(frame)
	}
}
