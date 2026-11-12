package types

import (
	"bytes"
	"fmt"

	"github.com/silvergreyhound/silver-grey-ledger/internal/codec"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
)

// Founder is one founding organisation and its SLH-DSA-SHAKE-128s root key.
type Founder struct {
	Org string
	Key crypto.PublicKey
}

// Seat is one validator in bitmap order: an ML-DSA-65 key, its organisation,
// and the address other operators use to reach it.
type Seat struct {
	Key     crypto.PublicKey
	Org     string
	Address string
}

// Grant is one identity and the roles it holds at genesis.
type Grant struct {
	Key        crypto.PublicKey
	Org        string
	Roles      uint16
	EventTypes []uint16
}

// RegEntry is one event type the ledger accepts.
type RegEntry struct {
	Type uint16
	Name string
}

// Genesis is the signed description of a chain. Every founding organisation
// signs it with its SLH-DSA root key. A node refuses a genesis that is
// missing a founding signature. Validator votes stay ML-DSA-65.
type Genesis struct {
	Created    int64
	EpochDelay uint64
	Threshold  uint16
	Founders   []Founder
	Seats      []Seat
	Grants     []Grant
	Registry   []RegEntry
	Signatures [][]byte
}

// Validators is the bitmap order of the genesis seats.
func (g Genesis) Validators() ValidatorSet {
	keys := make([]crypto.PublicKey, len(g.Seats))
	for i, s := range g.Seats {
		keys[i] = s.Key
	}
	return ValidatorSet{Keys: keys}
}

// ChainID is SHA3-256("silvergrey/genesis" || canonical body). The body does
// not contain the chain id or the founding signatures.
func (g Genesis) ChainID() ([crypto.DigestSize]byte, error) {
	body, err := g.signingBytes()
	if err != nil {
		return [crypto.DigestSize]byte{}, err
	}
	return crypto.DomainSum(crypto.DomainGenesis, body), nil
}

// Sign replaces Signatures with one SLH-DSA signature per founder, in order.
func (g *Genesis) Sign(keys []crypto.PrivateKey) error {
	if len(keys) != len(g.Founders) {
		return fmt.Errorf("types: founder key count: %w", ErrInvalid)
	}
	body, err := g.signingBytes()
	if err != nil {
		return err
	}
	sum := crypto.DomainSum(crypto.DomainGenesis, body)
	sigs := make([][]byte, len(keys))
	for i, key := range keys {
		if key.Algorithm() != crypto.AlgSLHDSAShake128s {
			return fmt.Errorf("types: founding key must be SLH-DSA-SHAKE-128s: %w", ErrInvalid)
		}
		pub, err := key.Public()
		if err != nil {
			return err
		}
		if !pub.Equal(g.Founders[i].Key) {
			return fmt.Errorf("types: founder key %d: %w", i, ErrInvalid)
		}
		sig, err := key.SignDigest(sum, crypto.ContextGenesis)
		if err != nil {
			return err
		}
		sigs[i] = sig
	}
	g.Signatures = sigs
	return nil
}

// Verify checks every founding signature. A missing signature is rejected.
func (g Genesis) Verify() error {
	if err := g.checkBody(); err != nil {
		return err
	}
	if err := g.checkSigs(); err != nil {
		return err
	}
	sum, err := g.ChainID()
	if err != nil {
		return err
	}
	for i, f := range g.Founders {
		if err := crypto.VerifyDigest(f.Key, sum, g.Signatures[i], crypto.ContextGenesis); err != nil {
			return fmt.Errorf("types: founding signature %d: %w", i, ErrSignature)
		}
	}
	return nil
}

// MarshalBinary encodes a genesis record.
func (g Genesis) MarshalBinary() ([]byte, error) {
	body, err := g.signingBytes()
	if err != nil {
		return nil, err
	}
	if err := g.checkSigs(); err != nil {
		return nil, err
	}
	e := codec.NewEncoder()
	e.Fixed(body)
	e.Length(len(g.Signatures))
	for _, sig := range g.Signatures {
		e.Fixed(sig)
	}
	return e.Bytes(), nil
}

// UnmarshalGenesis decodes a genesis record. Signatures are not checked
// for validity here; Verify does that. The length of each signature is checked.
func UnmarshalGenesis(b []byte) (Genesis, error) {
	d := codec.NewDecoder(b)
	g, err := decodeGenesis(d)
	if err != nil {
		return Genesis{}, err
	}
	if err := d.Finish(); err != nil {
		return Genesis{}, err
	}
	return g, nil
}

func (g Genesis) signingBytes() ([]byte, error) {
	if err := g.checkBody(); err != nil {
		return nil, err
	}
	e := codec.NewEncoder()
	e.Header(TypeGenesis, GenesisVersion)
	e.Int64(g.Created)
	e.Uint64(g.EpochDelay)
	e.Uint16(g.Threshold)
	e.Length(len(g.Founders))
	for _, f := range g.Founders {
		e.BytesField([]byte(f.Org))
		if err := encodePublicKey(e, f.Key); err != nil {
			return nil, err
		}
	}
	e.Length(len(g.Seats))
	for _, s := range g.Seats {
		if err := encodePublicKey(e, s.Key); err != nil {
			return nil, err
		}
		e.BytesField([]byte(s.Org))
		e.BytesField([]byte(s.Address))
	}
	e.Length(len(g.Grants))
	for _, gr := range g.Grants {
		if err := encodePublicKey(e, gr.Key); err != nil {
			return nil, err
		}
		e.BytesField([]byte(gr.Org))
		e.Uint16(gr.Roles)
		e.Length(len(gr.EventTypes))
		for _, t := range gr.EventTypes {
			e.Uint16(t)
		}
	}
	e.Length(len(g.Registry))
	for _, r := range g.Registry {
		e.Uint16(r.Type)
		e.BytesField([]byte(r.Name))
	}
	return e.Bytes(), nil
}

func decodeGenesis(d *codec.Decoder) (Genesis, error) {
	if err := d.ExpectHeader(TypeGenesis, GenesisVersion); err != nil {
		return Genesis{}, err
	}
	var g Genesis
	var err error
	if g.Created, err = d.Int64(); err != nil {
		return Genesis{}, err
	}
	if g.EpochDelay, err = d.Uint64(); err != nil {
		return Genesis{}, err
	}
	if g.Threshold, err = d.Uint16(); err != nil {
		return Genesis{}, err
	}
	nf, err := d.Length(MaxFounders)
	if err != nil {
		return Genesis{}, err
	}
	g.Founders = make([]Founder, nf)
	for i := range g.Founders {
		org, err := d.BytesField(MaxOrgLen)
		if err != nil {
			return Genesis{}, err
		}
		key, err := decodePublicKey(d)
		if err != nil {
			return Genesis{}, err
		}
		g.Founders[i] = Founder{Org: string(org), Key: key}
	}
	ns, err := d.Length(MaxValidators)
	if err != nil {
		return Genesis{}, err
	}
	g.Seats = make([]Seat, ns)
	for i := range g.Seats {
		key, err := decodePublicKey(d)
		if err != nil {
			return Genesis{}, err
		}
		org, err := d.BytesField(MaxOrgLen)
		if err != nil {
			return Genesis{}, err
		}
		addr, err := d.BytesField(MaxAddressLen)
		if err != nil {
			return Genesis{}, err
		}
		g.Seats[i] = Seat{Key: key, Org: string(org), Address: string(addr)}
	}
	ng, err := d.Length(MaxGrants)
	if err != nil {
		return Genesis{}, err
	}
	g.Grants = make([]Grant, ng)
	for i := range g.Grants {
		key, err := decodePublicKey(d)
		if err != nil {
			return Genesis{}, err
		}
		org, err := d.BytesField(MaxOrgLen)
		if err != nil {
			return Genesis{}, err
		}
		roles, err := d.Uint16()
		if err != nil {
			return Genesis{}, err
		}
		nt, err := d.Length(MaxGrantTypes)
		if err != nil {
			return Genesis{}, err
		}
		ts := make([]uint16, nt)
		for j := range ts {
			ts[j], err = d.Uint16()
			if err != nil {
				return Genesis{}, err
			}
		}
		g.Grants[i] = Grant{Key: key, Org: string(org), Roles: roles, EventTypes: ts}
	}
	nr, err := d.Length(MaxRegistry)
	if err != nil {
		return Genesis{}, err
	}
	g.Registry = make([]RegEntry, nr)
	for i := range g.Registry {
		typ, err := d.Uint16()
		if err != nil {
			return Genesis{}, err
		}
		name, err := d.BytesField(MaxRegName)
		if err != nil {
			return Genesis{}, err
		}
		g.Registry[i] = RegEntry{Type: typ, Name: string(name)}
	}
	nSig, err := d.Length(MaxFounders)
	if err != nil {
		return Genesis{}, err
	}
	g.Signatures = make([][]byte, nSig)
	for i := range g.Signatures {
		g.Signatures[i], err = d.Fixed(crypto.SLHSignatureSize())
		if err != nil {
			return Genesis{}, err
		}
	}
	if err := g.checkBody(); err != nil {
		return Genesis{}, err
	}
	if err := g.checkSigs(); err != nil {
		return Genesis{}, err
	}
	return g, nil
}

func (g Genesis) checkBody() error {
	if g.EpochDelay < MinEpochDelay || g.EpochDelay > MaxEpochDelay {
		return fmt.Errorf("types: epoch delay: %w", ErrInvalid)
	}
	want, err := DefaultThreshold(len(g.Founders))
	if err != nil || g.Threshold != want {
		return fmt.Errorf("types: governance threshold: %w", ErrInvalid)
	}
	if _, err := Quorum(len(g.Seats)); err != nil {
		return err
	}
	orgs := make(map[string]struct{}, len(g.Founders))
	for _, f := range g.Founders {
		if f.Org == "" || len(f.Org) > MaxOrgLen || f.Key.Algorithm() != crypto.AlgSLHDSAShake128s {
			return fmt.Errorf("types: founder: %w", ErrInvalid)
		}
		if _, ok := orgs[f.Org]; ok {
			return fmt.Errorf("types: duplicate founder organisation: %w", ErrInvalid)
		}
		orgs[f.Org] = struct{}{}
	}
	seatIDs := make(map[[crypto.DigestSize]byte]string, len(g.Seats))
	for _, s := range g.Seats {
		if s.Key.Algorithm() != crypto.AlgMLDSA65 || s.Org == "" || s.Address == "" {
			return fmt.Errorf("types: seat: %w", ErrInvalid)
		}
		if len(s.Org) > MaxOrgLen || len(s.Address) > MaxAddressLen {
			return fmt.Errorf("types: seat length: %w", ErrInvalid)
		}
		id, err := s.Key.ID()
		if err != nil {
			return err
		}
		if _, ok := seatIDs[id]; ok {
			return fmt.Errorf("types: duplicate validator: %w", ErrInvalid)
		}
		seatIDs[id] = s.Org
	}
	if len(g.Registry) == 0 || len(g.Registry) > MaxRegistry {
		return fmt.Errorf("types: registry: %w", ErrInvalid)
	}
	reg := make(map[uint16]struct{}, len(g.Registry))
	var prev uint16
	for i, r := range g.Registry {
		if r.Type == 0 || r.Name == "" || len(r.Name) > MaxRegName || (i > 0 && r.Type <= prev) {
			return fmt.Errorf("types: registry entry: %w", ErrInvalid)
		}
		prev = r.Type
		reg[r.Type] = struct{}{}
	}
	for _, need := range []uint16{EventShipmentDispatched, EventClearanceGranted, EventAccessLogin} {
		if _, ok := reg[need]; !ok {
			return fmt.Errorf("types: registry is missing a standard event type: %w", ErrInvalid)
		}
	}
	if len(g.Grants) == 0 || len(g.Grants) > MaxGrants {
		return fmt.Errorf("types: grant count: %w", ErrInvalid)
	}
	var prevID [crypto.DigestSize]byte
	valGrants := map[[crypto.DigestSize]byte]struct{}{}
	adminOrgs := map[string]struct{}{}
	for i, gr := range g.Grants {
		if gr.Key.Algorithm() != crypto.AlgMLDSA65 || gr.Org == "" || len(gr.Org) > MaxOrgLen {
			return fmt.Errorf("types: grant: %w", ErrInvalid)
		}
		if gr.Roles == 0 || gr.Roles&^RoleKnown != 0 {
			return fmt.Errorf("types: grant roles: %w", ErrInvalid)
		}
		if err := sortedTypes(gr.EventTypes); err != nil {
			return err
		}
		if gr.Roles&RoleWriter != 0 && len(gr.EventTypes) == 0 {
			return fmt.Errorf("types: writer grant needs event types: %w", ErrInvalid)
		}
		if gr.Roles&RoleWriter == 0 && len(gr.EventTypes) != 0 {
			return fmt.Errorf("types: event types without writer role: %w", ErrInvalid)
		}
		for _, t := range gr.EventTypes {
			if _, ok := reg[t]; !ok {
				return fmt.Errorf("types: grant names an unregistered event type: %w", ErrInvalid)
			}
		}
		if gr.Roles&RoleAdmin != 0 {
			if _, ok := orgs[gr.Org]; !ok {
				return fmt.Errorf("types: admin organisation is not a founder: %w", ErrInvalid)
			}
			adminOrgs[gr.Org] = struct{}{}
		}
		id, err := gr.Key.ID()
		if err != nil {
			return err
		}
		if i > 0 && bytes.Compare(prevID[:], id[:]) >= 0 {
			return fmt.Errorf("types: grants are not strictly increasing: %w", ErrInvalid)
		}
		prevID = id
		if gr.Roles&RoleValidator != 0 {
			org, ok := seatIDs[id]
			if !ok || org != gr.Org {
				return fmt.Errorf("types: validator grant does not match a seat: %w", ErrInvalid)
			}
			valGrants[id] = struct{}{}
		}
	}
	if len(valGrants) != len(g.Seats) {
		return fmt.Errorf("types: every seat needs a validator grant: %w", ErrInvalid)
	}
	if len(adminOrgs) < MinFounders {
		return fmt.Errorf("types: live founding organisations: %w", ErrInvalid)
	}
	return nil
}

func (g Genesis) checkSigs() error {
	if len(g.Signatures) != len(g.Founders) {
		return fmt.Errorf("types: founding signature count: %w", ErrInvalid)
	}
	for _, sig := range g.Signatures {
		if len(sig) != crypto.SLHSignatureSize() {
			return fmt.Errorf("types: founding signature length: %w", ErrInvalid)
		}
	}
	return nil
}
