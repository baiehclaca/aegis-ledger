package node

import (
	"context"
	"errors"
	"strings"

	"github.com/silvergreyhound/silver-grey-ledger/internal/api"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/store"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
	"github.com/silvergreyhound/silver-grey-ledger/pkg/verify"
)

// apiCall is work the replica loop runs so the API never touches the
// replica from another goroutine.
type apiCall struct {
	fn   func() error
	resp chan error
}

func (n *Node) call(ctx context.Context, fn func() error) error {
	resp := make(chan error, 1)
	select {
	case n.apiCh <- apiCall{fn: fn, resp: resp}:
	case <-ctx.Done():
		return ctx.Err()
	case <-n.ctx.Done():
		return api.ErrUnavailable
	}
	select {
	case err := <-resp:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-n.ctx.Done():
		return api.ErrUnavailable
	}
}

// Submit accepts a signed event. A committed id is reported final and
// is not written again.
func (n *Node) Submit(ctx context.Context, pub crypto.PublicKey, ev types.Event) ([crypto.DigestSize]byte, string, error) {
	var (
		id       [crypto.DigestSize]byte
		finality string
	)
	err := n.call(ctx, func() error {
		var err error
		id, finality, err = n.submitLocal(pub, ev)
		return err
	})
	return id, finality, err
}

func (n *Node) submitLocal(pub crypto.PublicKey, ev types.Event) ([crypto.DigestSize]byte, string, error) {
	id, err := ev.ID()
	if err != nil {
		return [crypto.DigestSize]byte{}, "", err
	}
	if err := n.acceptEvent(pub, ev); err != nil {
		if errors.Is(err, errSignature) {
			return [crypto.DigestSize]byte{}, "", api.ErrRejected
		}
		return [crypto.DigestSize]byte{}, "", err
	}
	committed, err := n.disk.Committed(id)
	if err != nil {
		return [crypto.DigestSize]byte{}, "", err
	}
	if committed {
		return id, "final", nil
	}
	return id, "pending", nil
}

// Event returns a pending pool entry or a committed event.
func (n *Node) Event(ctx context.Context, caller crypto.PublicKey, id [crypto.DigestSize]byte) (types.Event, uint64, string, error) {
	var (
		ev       types.Event
		height   uint64
		finality string
	)
	err := n.call(ctx, func() error {
		if _, err := n.member(caller); err != nil {
			return err
		}
		if _, have, ok := n.pool.Get(id); ok {
			if !n.canSee(caller, have, n.replica.CommitHeight()) {
				return api.ErrNotFound
			}
			ev = have
			finality = n.finalityOf(have, n.replica.CommitHeight(), true)
			return nil
		}
		got, h, err := n.disk.Event(id)
		if err != nil {
			return asMissing(err)
		}
		if !n.canSee(caller, got, h) {
			return api.ErrNotFound
		}
		ev = got
		height = h
		finality = n.finalityOf(got, h, false)
		return nil
	})
	return ev, height, finality, err
}

// Proof returns the inclusion proof of a committed event.
func (n *Node) Proof(ctx context.Context, caller crypto.PublicKey, id [crypto.DigestSize]byte) (types.InclusionProof, error) {
	var proof types.InclusionProof
	err := n.call(ctx, func() error {
		if _, err := n.member(caller); err != nil {
			return err
		}
		got, err := n.disk.Proof(id)
		if err != nil {
			return asMissing(err)
		}
		if !n.canSee(caller, got.Event, got.Header.Height) {
			return api.ErrNotFound
		}
		proof = got
		return nil
	})
	return proof, err
}

// History returns committed event ids for a subject that caller may read.
func (n *Node) History(ctx context.Context, caller crypto.PublicKey, subject []byte) ([][crypto.DigestSize]byte, error) {
	var ids [][crypto.DigestSize]byte
	err := n.call(ctx, func() error {
		if _, err := n.member(caller); err != nil {
			return err
		}
		got, err := n.disk.EventsBySubject(subject)
		if err != nil {
			return err
		}
		for _, id := range got {
			ev, height, err := n.disk.Event(id)
			if err != nil {
				return err
			}
			if n.canSee(caller, ev, height) {
				ids = append(ids, id)
			}
		}
		return nil
	})
	return ids, err
}

// LookupDoc finds a committed event by this writer that carries sum and
// returns a proof the caller can check itself.
func (n *Node) LookupDoc(ctx context.Context, caller crypto.PublicKey, sum [crypto.DigestSize]byte, writer crypto.PublicKey) (api.DocMatch, error) {
	var match api.DocMatch
	err := n.call(ctx, func() error {
		if _, err := n.member(caller); err != nil {
			return err
		}
		got, err := n.lookupDoc(caller, sum, writer)
		if err != nil {
			return err
		}
		match = got
		return nil
	})
	return match, err
}

func (n *Node) lookupDoc(caller crypto.PublicKey, sum [crypto.DigestSize]byte, writer crypto.PublicKey) (api.DocMatch, error) {
	wid, err := writer.ID()
	if err != nil {
		return api.DocMatch{}, err
	}
	ids, err := n.disk.EventsByDoc(sum)
	if err != nil {
		return api.DocMatch{}, err
	}
	doc := types.SHA3Doc(sum)
	for _, id := range ids {
		ev, height, err := n.disk.Event(id)
		if err != nil {
			return api.DocMatch{}, err
		}
		if ev.WriterID != wid || !n.canSee(caller, ev, height) {
			continue
		}
		if err := verify.CheckDocument(ev, doc); err != nil {
			continue
		}
		proof, err := n.disk.Proof(id)
		if err != nil {
			if missingEvent(err) {
				continue
			}
			return api.DocMatch{}, err
		}
		hash, err := proof.Header.Hash()
		if err != nil {
			continue
		}
		voters, err := n.replica.BlockVoters(hash)
		if err != nil {
			continue
		}
		res, err := verify.Inclusion(proof, types.ValidatorSet{Keys: voters}, writer)
		if err != nil {
			continue
		}
		raw, err := proof.MarshalBinary()
		if err != nil {
			return api.DocMatch{}, err
		}
		return api.DocMatch{
			Height:  res.Height,
			View:    res.View,
			Claimed: ev.ClaimedTime,
			EventID: id,
			Proof:   raw,
		}, nil
	}
	return api.DocMatch{}, api.ErrNotFound
}

// Block returns the committed block at height.
func (n *Node) Block(ctx context.Context, caller crypto.PublicKey, height uint64) (types.Block, error) {
	var block types.Block
	err := n.call(ctx, func() error {
		auditor, err := n.member(caller)
		if err != nil {
			return err
		}
		got, ok, err := n.disk.BlockByHeight(height)
		if err != nil {
			return err
		}
		if !ok {
			return api.ErrNotFound
		}
		block = n.redact(caller, got, auditor)
		return nil
	})
	return block, err
}

// Latest returns the committed tip.
func (n *Node) Latest(ctx context.Context, caller crypto.PublicKey) (types.Block, error) {
	var block types.Block
	err := n.call(ctx, func() error {
		auditor, err := n.member(caller)
		if err != nil {
			return err
		}
		got, ok, err := n.disk.BlockByHeight(n.replica.CommitHeight())
		if err != nil {
			return err
		}
		if !ok {
			return api.ErrNotFound
		}
		block = n.redact(caller, got, auditor)
		return nil
	})
	return block, err
}

// Membership returns the certified headers and state witnesses from
// genesis through the commit, plus the certificate of the tip. A client
// recomputes the validator set from that history. Height 0 has no child
// certificate; the caller already holds the view-0 certificate.
func (n *Node) Membership(ctx context.Context, caller crypto.PublicKey) ([]byte, [][]byte, [][]byte, error) {
	var (
		qc        []byte
		headers   [][]byte
		witnesses [][]byte
	)
	err := n.call(ctx, func() error {
		if _, err := n.member(caller); err != nil {
			return err
		}
		height := n.replica.CommitHeight()
		if height > 4095 {
			return api.ErrRejected
		}
		headers = make([][]byte, height+1)
		witnesses = make([][]byte, height+1)
		for h := uint64(0); h <= height; h++ {
			block, ok, err := n.disk.BlockByHeight(h)
			if err != nil {
				return err
			}
			if !ok {
				return api.ErrNotFound
			}
			hash, err := block.Header.Hash()
			if err != nil {
				return err
			}
			raw, err := block.Header.MarshalBinary()
			if err != nil {
				return err
			}
			wit, err := n.replica.Witness(hash)
			if err != nil {
				return err
			}
			headers[h] = raw
			witnesses[h] = wit
			if h == height && height > 0 {
				cert, err := n.disk.CommitQC(hash, block.Header.View)
				if err != nil {
					return err
				}
				qc, err = cert.MarshalBinary()
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
	return qc, headers, witnesses, err
}

// Members returns the canonical validator set.
func (n *Node) Members(ctx context.Context, caller crypto.PublicKey) ([]byte, error) {
	var raw []byte
	err := n.call(ctx, func() error {
		if _, err := n.member(caller); err != nil {
			return err
		}
		got, err := (types.ValidatorSet{Keys: n.pubs}).MarshalBinary()
		if err != nil {
			return err
		}
		raw = got
		return nil
	})
	return raw, err
}

// Status returns the commit point.
func (n *Node) Status(ctx context.Context, caller crypto.PublicKey) (api.Status, error) {
	var st api.Status
	err := n.call(ctx, func() error {
		if _, err := n.member(caller); err != nil {
			return err
		}
		st.Chain = n.chain
		st.Height = n.replica.CommitHeight()
		st.Hash = n.replica.CommitHash()
		st.View = n.replica.View()
		return nil
	})
	return st, err
}

func asMissing(err error) error {
	if missingEvent(err) {
		return api.ErrNotFound
	}
	return err
}

func missingEvent(err error) bool {
	if err == nil || errors.Is(err, store.ErrCorrupt) {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "not committed") || strings.Contains(msg, "not certified")
}
