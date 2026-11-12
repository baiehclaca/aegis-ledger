package state

import (
	"encoding/binary"
	"fmt"

	"github.com/silvergreyhound/silver-grey-ledger/internal/codec"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

const maxWitnessPairs = 8192

// Witness is the state pairs committed by Root. It carries membership,
// roles, nonces, and pending governance. It does not carry events.
func (s *Ledger) Witness() ([]byte, error) {
	pairs := s.pairs()
	e := codec.NewEncoder()
	e.Length(len(pairs))
	for _, p := range pairs {
		e.BytesField(p.key)
		e.BytesField(p.val)
	}
	return e.Bytes(), nil
}

// RestoreWitness rebuilds a ledger from Witness. The caller checks Root
// against a certified header before trusting the result.
func RestoreWitness(b []byte) (*Ledger, error) {
	if len(b) == 0 || len(b) > 1<<20 {
		return nil, fmt.Errorf("%w: witness size", ErrTransition)
	}
	d := codec.NewDecoder(b)
	n, err := d.Length(maxWitnessPairs)
	if err != nil {
		return nil, err
	}
	pairs := make([]pair, n)
	for i := range pairs {
		key, err := d.BytesField(128)
		if err != nil {
			return nil, err
		}
		val, err := d.BytesField(1 << 20)
		if err != nil {
			return nil, err
		}
		pairs[i] = pair{key: key, val: val}
	}
	if err := d.Finish(); err != nil {
		return nil, err
	}
	led, err := ledgerFromPairs(pairs)
	if err != nil {
		return nil, err
	}
	if led.Root() != stateRoot(pairs) {
		return nil, fmt.Errorf("%w: witness does not round-trip", ErrTransition)
	}
	return led, nil
}

func ledgerFromPairs(pairs []pair) (*Ledger, error) {
	s := &Ledger{
		founderOrg: map[string]struct{}{},
		registry:   map[uint16]string{},
		ids:        map[[crypto.DigestSize]byte]*ident{},
		nonces:     map[[crypto.DigestSize]byte]uint64{},
		pending:    map[uint64][]types.GovAction{},
		applied:    map[[crypto.DigestSize]byte]struct{}{},
	}
	var (
		haveChain bool
		haveParam bool
		haveGov   bool
		seats     = map[uint16][crypto.DigestSize]byte{}
	)
	for _, p := range pairs {
		if len(p.key) == 0 {
			return nil, fmt.Errorf("%w: witness key", ErrTransition)
		}
		switch p.key[0] {
		case 0x00:
			if haveChain || len(p.key) != 1 || len(p.val) != crypto.DigestSize {
				return nil, fmt.Errorf("%w: witness chain", ErrTransition)
			}
			copy(s.chain[:], p.val)
			haveChain = true
		case 0x01:
			if len(p.val) != 1 || p.val[0] != 1 {
				return nil, fmt.Errorf("%w: witness founder", ErrTransition)
			}
			org := string(p.key[1:])
			if org == "" || len(org) > types.MaxOrgLen {
				return nil, fmt.Errorf("%w: witness founder", ErrTransition)
			}
			if _, ok := s.founderOrg[org]; ok {
				return nil, fmt.Errorf("%w: witness founder", ErrTransition)
			}
			s.founderOrg[org] = struct{}{}
		case 0x02:
			if haveParam || len(p.key) != 1 || len(p.val) != 10 {
				return nil, fmt.Errorf("%w: witness parameters", ErrTransition)
			}
			s.delay = binary.BigEndian.Uint64(p.val[:8])
			s.threshold = int(binary.BigEndian.Uint16(p.val[8:]))
			haveParam = true
		case 0x03:
			if len(p.key) != 3 {
				return nil, fmt.Errorf("%w: witness registry", ErrTransition)
			}
			t := binary.BigEndian.Uint16(p.key[1:])
			if _, ok := s.registry[t]; ok || len(p.val) == 0 || len(p.val) > types.MaxRegName {
				return nil, fmt.Errorf("%w: witness registry", ErrTransition)
			}
			s.registry[t] = string(p.val)
		case 0x04:
			if len(p.key) != 1+crypto.DigestSize {
				return nil, fmt.Errorf("%w: witness identity", ErrTransition)
			}
			var id [crypto.DigestSize]byte
			copy(id[:], p.key[1:])
			ent, err := decodeIdent(p.val)
			if err != nil {
				return nil, err
			}
			got, err := ent.key.ID()
			if err != nil || got != id {
				return nil, fmt.Errorf("%w: witness identity", ErrTransition)
			}
			if _, ok := s.ids[id]; ok {
				return nil, fmt.Errorf("%w: witness identity", ErrTransition)
			}
			s.ids[id] = ent
		case 0x05:
			if len(p.key) != 1+crypto.DigestSize || len(p.val) != 8 {
				return nil, fmt.Errorf("%w: witness nonce", ErrTransition)
			}
			var id [crypto.DigestSize]byte
			copy(id[:], p.key[1:])
			nonce := binary.BigEndian.Uint64(p.val)
			if nonce == 0 {
				return nil, fmt.Errorf("%w: witness nonce", ErrTransition)
			}
			if _, ok := s.nonces[id]; ok {
				return nil, fmt.Errorf("%w: witness nonce", ErrTransition)
			}
			s.nonces[id] = nonce
		case 0x06:
			if len(p.key) != 3 || len(p.val) != crypto.DigestSize {
				return nil, fmt.Errorf("%w: witness seat", ErrTransition)
			}
			idx := binary.BigEndian.Uint16(p.key[1:])
			var id [crypto.DigestSize]byte
			copy(id[:], p.val)
			if _, ok := seats[idx]; ok {
				return nil, fmt.Errorf("%w: witness seat", ErrTransition)
			}
			seats[idx] = id
		case 0x07:
			if len(p.key) != 9 {
				return nil, fmt.Errorf("%w: witness pending", ErrTransition)
			}
			h := binary.BigEndian.Uint64(p.key[1:])
			_, actions, err := types.ParsePendingBody(p.val)
			if err != nil {
				return nil, err
			}
			if _, ok := s.pending[h]; ok {
				return nil, fmt.Errorf("%w: witness pending", ErrTransition)
			}
			s.pending[h] = actions
		case 0x08:
			if haveGov || len(p.key) != 1 || len(p.val) != crypto.DigestSize {
				return nil, fmt.Errorf("%w: witness governance root", ErrTransition)
			}
			copy(s.govRoot[:], p.val)
			haveGov = true
		case 0x09:
			if len(p.key) != 1+crypto.DigestSize || len(p.val) != 1 || p.val[0] != 1 {
				return nil, fmt.Errorf("%w: witness applied", ErrTransition)
			}
			var id [crypto.DigestSize]byte
			copy(id[:], p.key[1:])
			if _, ok := s.applied[id]; ok {
				return nil, fmt.Errorf("%w: witness applied", ErrTransition)
			}
			s.applied[id] = struct{}{}
		default:
			return nil, fmt.Errorf("%w: witness key", ErrTransition)
		}
	}
	if !haveChain || !haveParam || !haveGov {
		return nil, fmt.Errorf("%w: witness is incomplete", ErrTransition)
	}
	if len(seats) == 0 || len(seats) > types.MaxValidators {
		return nil, fmt.Errorf("%w: witness seats", ErrTransition)
	}
	s.order = make([][crypto.DigestSize]byte, len(seats))
	for i := range s.order {
		id, ok := seats[uint16(i)]
		if !ok {
			return nil, fmt.Errorf("%w: witness seats", ErrTransition)
		}
		if s.ids[id] == nil {
			return nil, fmt.Errorf("%w: witness seats", ErrTransition)
		}
		s.order[i] = id
	}
	return s, nil
}

func decodeIdent(b []byte) (*ident, error) {
	d := codec.NewDecoder(b)
	key, err := types.ReadPublicKey(d)
	if err != nil {
		return nil, err
	}
	org, err := d.BytesField(types.MaxOrgLen)
	if err != nil {
		return nil, err
	}
	addr, err := d.BytesField(types.MaxAddressLen)
	if err != nil {
		return nil, err
	}
	roles, err := d.Uint16()
	if err != nil {
		return nil, err
	}
	n, err := d.Length(types.MaxGrantTypes)
	if err != nil {
		return nil, err
	}
	kinds := make([]uint16, n)
	for i := range kinds {
		kinds[i], err = d.Uint16()
		if err != nil {
			return nil, err
		}
	}
	revoked, err := d.Uint64()
	if err != nil {
		return nil, err
	}
	suspect, err := d.Uint64()
	if err != nil {
		return nil, err
	}
	if err := d.Finish(); err != nil {
		return nil, err
	}
	return &ident{
		key:     key,
		org:     string(org),
		address: string(addr),
		roles:   roles,
		types:   kinds,
		revoked: revoked,
		suspect: suspect,
	}, nil
}
