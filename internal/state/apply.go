package state

import (
	"fmt"
	"slices"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/merkle"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

func (s *Ledger) openEpoch(height uint64) error {
	acts := s.pending[height]
	if len(acts) == 0 {
		return nil
	}
	delete(s.pending, height)
	for _, a := range acts {
		if err := s.effect(a, height); err != nil {
			return err
		}
	}
	if err := s.checkEpoch(); err != nil {
		return err
	}
	return nil
}

func (s *Ledger) seal(gov []types.GovTx) error {
	ids := make([][crypto.DigestSize]byte, len(gov))
	for i, tx := range gov {
		id, err := tx.ID()
		if err != nil {
			return err
		}
		ids[i] = id
	}
	root, err := merkle.Root(ids)
	if err != nil {
		return err
	}
	s.govRoot = root
	return nil
}

func (s *Ledger) admitEvent(ev types.Event, height uint64) error {
	if err := s.checkEvent(ev, height); err != nil {
		return err
	}
	s.nonces[ev.WriterID] = ev.Nonce
	return nil
}

func (s *Ledger) checkEvent(ev types.Event, height uint64) error {
	if ev.ChainID != s.chain {
		return fmt.Errorf("%w: event chain", ErrTransition)
	}
	switch ev.ReadPolicy {
	case types.ReadAllMembers, types.ReadOrgOnly, types.ReadAuditors:
	default:
		return fmt.Errorf("%w: read policy", ErrTransition)
	}
	if _, ok := s.registry[ev.EventType]; !ok {
		return fmt.Errorf("%w: event type", ErrTransition)
	}
	ent := s.ids[ev.WriterID]
	if ent == nil {
		return fmt.Errorf("%w: writer", ErrTransition)
	}
	if ent.revoked != 0 && height >= ent.revoked {
		return fmt.Errorf("%w: writer revoked", ErrTransition)
	}
	if ent.roles&types.RoleWriter == 0 || !slices.Contains(ent.types, ev.EventType) {
		return fmt.Errorf("%w: writer role", ErrTransition)
	}
	if ev.Nonce == 0 || ev.Nonce <= s.nonces[ev.WriterID] {
		return fmt.Errorf("%w: nonce", ErrTransition)
	}
	if err := ev.Verify(ent.key); err != nil {
		return fmt.Errorf("%w: event signature", ErrTransition)
	}
	return nil
}

func (s *Ledger) admitGov(tx types.GovTx, height uint64) error {
	if tx.ChainID != s.chain {
		return fmt.Errorf("%w: governance chain", ErrTransition)
	}
	id, err := tx.ID()
	if err != nil {
		return err
	}
	if _, ok := s.applied[id]; ok {
		return fmt.Errorf("%w: governance replay", ErrTransition)
	}
	if err := s.checkThreshold(tx, height); err != nil {
		return err
	}
	epoch := height + s.delay
	if epoch < height {
		return fmt.Errorf("%w: epoch overflow", ErrTransition)
	}
	if err := s.preview(epoch, tx.Actions); err != nil {
		return err
	}
	s.pending[epoch] = append(s.pending[epoch], tx.Actions...)
	s.applied[id] = struct{}{}
	return nil
}

func (s *Ledger) checkThreshold(tx types.GovTx, height uint64) error {
	sum, err := tx.ID()
	if err != nil {
		return err
	}
	orgs := map[string]struct{}{}
	if len(tx.Admins) == 0 {
		return fmt.Errorf("%w: no admin signature", ErrTransition)
	}
	for _, a := range tx.Admins {
		ent := s.ids[a.KeyID]
		if ent == nil || ent.roles&types.RoleAdmin == 0 {
			return fmt.Errorf("%w: admin", ErrTransition)
		}
		if ent.revoked != 0 && height >= ent.revoked {
			return fmt.Errorf("%w: admin revoked", ErrTransition)
		}
		if _, ok := s.founderOrg[ent.org]; !ok {
			return fmt.Errorf("%w: admin organisation", ErrTransition)
		}
		if _, ok := orgs[ent.org]; ok {
			return fmt.Errorf("%w: duplicate admin organisation", ErrTransition)
		}
		if err := crypto.VerifyDigest(ent.key, sum, a.Sig, crypto.ContextGovernance); err != nil {
			return fmt.Errorf("%w: admin signature", ErrTransition)
		}
		orgs[ent.org] = struct{}{}
	}
	if len(orgs) < s.threshold {
		return fmt.Errorf("%w: governance threshold", ErrTransition)
	}
	return nil
}

// preview applies every pending effect at or before epoch, then extra,
// and requires the validator set to stay a legal size.
func (s *Ledger) preview(epoch uint64, extra []types.GovAction) error {
	n := s.clone()
	heights := make([]uint64, 0, len(n.pending)+1)
	seen := map[uint64]struct{}{}
	for h := range n.pending {
		if h <= epoch {
			heights = append(heights, h)
			seen[h] = struct{}{}
		}
	}
	if _, ok := seen[epoch]; !ok {
		heights = append(heights, epoch)
	}
	slices.Sort(heights)
	for _, h := range heights {
		acts := append([]types.GovAction{}, n.pending[h]...)
		delete(n.pending, h)
		if h == epoch {
			acts = append(acts, extra...)
		}
		for _, a := range acts {
			if err := n.effect(a, h); err != nil {
				return err
			}
		}
	}
	if err := n.checkEpoch(); err != nil {
		return err
	}
	return nil
}

// checkEpoch is the rule after a whole batch: n = 3f+1 in [4, 31], and
// at least two founding organisations still have a live admin.
func (s *Ledger) checkEpoch() error {
	if _, err := types.Quorum(len(s.order)); err != nil {
		return fmt.Errorf("%w: validator set size", ErrTransition)
	}
	if s.liveFounders() < types.MinFounders {
		return fmt.Errorf("%w: founding organisations", ErrTransition)
	}
	return nil
}

func (s *Ledger) liveFounders() int {
	orgs := map[string]struct{}{}
	for _, ent := range s.ids {
		if ent == nil || ent.revoked != 0 || ent.roles&types.RoleAdmin == 0 {
			continue
		}
		if _, ok := s.founderOrg[ent.org]; !ok {
			continue
		}
		orgs[ent.org] = struct{}{}
	}
	return len(orgs)
}

func (s *Ledger) effect(a types.GovAction, height uint64) error {
	switch a.Kind {
	case types.GovAddValidator:
		return s.addValidator(a)
	case types.GovRemoveValidator:
		return s.removeValidator(a.KeyID)
	case types.GovGrantRole:
		return s.grant(a)
	case types.GovRevokeKey:
		return s.revoke(a, height)
	case types.GovRotate:
		return s.rotate(a, height)
	case types.GovExtendRegistry:
		return s.extend(a)
	default:
		return fmt.Errorf("%w: action", ErrTransition)
	}
}

func (s *Ledger) addValidator(a types.GovAction) error {
	id, err := a.Key.ID()
	if err != nil {
		return err
	}
	for _, have := range s.order {
		if have == id {
			return fmt.Errorf("%w: validator exists", ErrTransition)
		}
	}
	ent := s.ids[id]
	if ent == nil {
		ent = &ident{key: a.Key, org: a.Org, address: a.Address, roles: types.RoleValidator}
		s.ids[id] = ent
	} else {
		if ent.revoked != 0 || ent.org != a.Org {
			return fmt.Errorf("%w: validator identity", ErrTransition)
		}
		ent.roles |= types.RoleValidator
		ent.address = a.Address
	}
	s.order = append(s.order, id)
	return nil
}

func (s *Ledger) removeValidator(id [crypto.DigestSize]byte) error {
	idx := -1
	for i, have := range s.order {
		if have == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("%w: validator is not seated", ErrTransition)
	}
	s.order = append(s.order[:idx], s.order[idx+1:]...)
	if ent := s.ids[id]; ent != nil {
		ent.roles &^= types.RoleValidator
	}
	return nil
}

func (s *Ledger) grant(a types.GovAction) error {
	for _, t := range a.EventTypes {
		if _, ok := s.registry[t]; !ok {
			return fmt.Errorf("%w: grant type", ErrTransition)
		}
	}
	if a.Roles&types.RoleAdmin != 0 {
		if _, ok := s.founderOrg[a.Org]; !ok {
			return fmt.Errorf("%w: admin organisation", ErrTransition)
		}
	}
	id, err := a.Key.ID()
	if err != nil {
		return err
	}
	ent := s.ids[id]
	if ent == nil {
		if a.Roles&types.RoleValidator != 0 {
			return fmt.Errorf("%w: validator role needs a seat", ErrTransition)
		}
		s.ids[id] = &ident{
			key:   a.Key,
			org:   a.Org,
			roles: a.Roles,
			types: append([]uint16(nil), a.EventTypes...),
		}
		return nil
	}
	if ent.revoked != 0 || ent.org != a.Org {
		return fmt.Errorf("%w: grant identity", ErrTransition)
	}
	if a.Roles&types.RoleValidator != 0 && !slices.Contains(s.order, id) {
		return fmt.Errorf("%w: validator role needs a seat", ErrTransition)
	}
	if a.Roles&types.RoleValidator == 0 && slices.Contains(s.order, id) {
		return fmt.Errorf("%w: seated key keeps the validator role", ErrTransition)
	}
	ent.roles = a.Roles
	ent.types = append([]uint16(nil), a.EventTypes...)
	return nil
}

func (s *Ledger) revoke(a types.GovAction, height uint64) error {
	ent := s.ids[a.KeyID]
	if ent == nil || ent.revoked != 0 {
		return fmt.Errorf("%w: revoke", ErrTransition)
	}
	if a.SuspectSince != 0 && a.SuspectSince > height {
		return fmt.Errorf("%w: suspect height", ErrTransition)
	}
	ent.revoked = height
	ent.suspect = a.SuspectSince
	if slices.Contains(s.order, a.KeyID) {
		return s.removeValidator(a.KeyID)
	}
	return nil
}

func (s *Ledger) rotate(a types.GovAction, height uint64) error {
	ent := s.ids[a.KeyID]
	if ent == nil || ent.revoked != 0 {
		return fmt.Errorf("%w: rotate source", ErrTransition)
	}
	newID, err := a.NewKey.ID()
	if err != nil {
		return err
	}
	if newID == a.KeyID || s.ids[newID] != nil {
		return fmt.Errorf("%w: rotate destination", ErrTransition)
	}
	sum, err := types.RotateDigest(s.chain, a.KeyID, a.NewKey)
	if err != nil {
		return err
	}
	if err := crypto.VerifyDigest(ent.key, sum, a.OldSig, crypto.ContextGovernance); err != nil {
		return fmt.Errorf("%w: rotate old signature", ErrTransition)
	}
	if err := crypto.VerifyDigest(a.NewKey, sum, a.NewSig, crypto.ContextGovernance); err != nil {
		return fmt.Errorf("%w: rotate new signature", ErrTransition)
	}
	s.ids[newID] = &ident{
		key:     a.NewKey,
		org:     ent.org,
		address: ent.address,
		roles:   ent.roles,
		types:   append([]uint16(nil), ent.types...),
	}
	ent.revoked = height
	ent.roles = 0
	for i, id := range s.order {
		if id == a.KeyID {
			s.order[i] = newID
		}
	}
	return nil
}

func (s *Ledger) extend(a types.GovAction) error {
	if _, ok := s.registry[a.EventType]; ok {
		return fmt.Errorf("%w: event type exists", ErrTransition)
	}
	s.registry[a.EventType] = a.Name
	return nil
}
