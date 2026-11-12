package types

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/silvergreyhound/silver-grey-ledger/internal/codec"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
)

// GovAction is one effect inside a governance transaction. Only the
// fields for Kind are encoded. The effect is applied at the epoch
// boundary, not in the block that carries the transaction.
type GovAction struct {
	Kind         uint8
	Key          crypto.PublicKey
	Org          string
	Address      string
	KeyID        [crypto.DigestSize]byte
	Roles        uint16
	EventTypes   []uint16
	SuspectSince uint64
	NewKey       crypto.PublicKey
	OldSig       []byte
	NewSig       []byte
	EventType    uint16
	Name         string
}

// AdminSig is one admin organisation's signature over the transaction id.
type AdminSig struct {
	KeyID [crypto.DigestSize]byte
	Sig   []byte
}

// GovTx is a threshold-signed governance transaction. ID covers every
// byte except the admin signatures, so an admin signs a fixed preimage.
type GovTx struct {
	ChainID [crypto.DigestSize]byte
	Actions []GovAction
	Admins  []AdminSig
}

// ID is SHA3-256("silvergrey/governance" || canonical body without admin signatures).
func (g GovTx) ID() ([crypto.DigestSize]byte, error) {
	body, err := g.signingBytes()
	if err != nil {
		return [crypto.DigestSize]byte{}, err
	}
	return crypto.DomainSum(crypto.DomainGovernance, body), nil
}

// RotateDigest is what the old key and the new key both sign.
// Admins then sign the transaction that contains those two signatures.
func RotateDigest(chain, oldID [crypto.DigestSize]byte, neu crypto.PublicKey) ([crypto.DigestSize]byte, error) {
	if neu.Algorithm() != crypto.AlgMLDSA65 {
		return [crypto.DigestSize]byte{}, fmt.Errorf("types: rotate key: %w", ErrInvalid)
	}
	raw, err := MarshalPublicKey(neu)
	if err != nil {
		return [crypto.DigestSize]byte{}, err
	}
	return crypto.DomainSum(crypto.DomainGovernance, chain[:], oldID[:], raw), nil
}

// SignRotate fills OldSig and NewSig. Both keys sign RotateDigest.
func (a *GovAction) SignRotate(chain [crypto.DigestSize]byte, oldID [crypto.DigestSize]byte, oldKey, newKey crypto.PrivateKey) error {
	if a.Kind != GovRotate {
		return fmt.Errorf("types: rotate kind: %w", ErrInvalid)
	}
	pub, err := newKey.Public()
	if err != nil {
		return err
	}
	a.NewKey = pub
	a.KeyID = oldID
	sum, err := RotateDigest(chain, oldID, pub)
	if err != nil {
		return err
	}
	oldSig, err := oldKey.SignDigest(sum, crypto.ContextGovernance)
	if err != nil {
		return err
	}
	newSig, err := newKey.SignDigest(sum, crypto.ContextGovernance)
	if err != nil {
		return err
	}
	a.OldSig = oldSig
	a.NewSig = newSig
	return nil
}

// SignAdmin appends this admin's signature, keeping the list ordered by key id.
func (g *GovTx) SignAdmin(key crypto.PrivateKey) error {
	pub, err := key.Public()
	if err != nil {
		return err
	}
	if pub.Algorithm() != crypto.AlgMLDSA65 {
		return fmt.Errorf("types: admin key: %w", ErrInvalid)
	}
	id, err := pub.ID()
	if err != nil {
		return err
	}
	sum, err := g.ID()
	if err != nil {
		return err
	}
	sig, err := key.SignDigest(sum, crypto.ContextGovernance)
	if err != nil {
		return err
	}
	next := append([]AdminSig(nil), g.Admins...)
	for _, have := range next {
		if have.KeyID == id {
			return fmt.Errorf("types: admin already signed: %w", ErrInvalid)
		}
	}
	next = append(next, AdminSig{KeyID: id, Sig: sig})
	slices.SortFunc(next, func(a, b AdminSig) int {
		return bytes.Compare(a.KeyID[:], b.KeyID[:])
	})
	g.Admins = next
	return nil
}

// AddAdminSig appends a signature the caller has already checked.
// The list stays ordered by key id.
func (g *GovTx) AddAdminSig(id [crypto.DigestSize]byte, sig []byte) error {
	if zero32(id) || len(sig) != crypto.MLDSASignatureSize() {
		return fmt.Errorf("types: admin signature: %w", ErrInvalid)
	}
	for _, have := range g.Admins {
		if have.KeyID == id {
			return fmt.Errorf("types: admin already signed: %w", ErrInvalid)
		}
	}
	if len(g.Admins) >= MaxAdminSigs {
		return fmt.Errorf("types: admin signature count: %w", ErrInvalid)
	}
	g.Admins = append(g.Admins, AdminSig{KeyID: id, Sig: append([]byte(nil), sig...)})
	slices.SortFunc(g.Admins, func(a, b AdminSig) int {
		return bytes.Compare(a.KeyID[:], b.KeyID[:])
	})
	return nil
}

// MarshalBinary encodes a signed governance transaction.
func (g GovTx) MarshalBinary() ([]byte, error) {
	body, err := g.signingBytes()
	if err != nil {
		return nil, err
	}
	if err := g.checkAdmins(); err != nil {
		return nil, err
	}
	e := codec.NewEncoder()
	e.Fixed(body)
	e.Length(len(g.Admins))
	for _, a := range g.Admins {
		e.Fixed(a.KeyID[:])
		e.Fixed(a.Sig)
	}
	return e.Bytes(), nil
}

// UnmarshalGovTx decodes a governance transaction. Signatures are not checked.
func UnmarshalGovTx(b []byte) (GovTx, error) {
	d := codec.NewDecoder(b)
	g, err := decodeGov(d)
	if err != nil {
		return GovTx{}, err
	}
	if err := d.Finish(); err != nil {
		return GovTx{}, err
	}
	return g, nil
}

// PendingBody is the canonical encoding of actions that have been
// admitted and are waiting for their epoch. Admin signatures are not
// included: they were checked at admission and are not part of the effect.
func PendingBody(chain [crypto.DigestSize]byte, actions []GovAction) ([]byte, error) {
	return GovTx{ChainID: chain, Actions: actions}.signingBytes()
}

// ParsePendingBody is the inverse of PendingBody.
func ParsePendingBody(b []byte) ([crypto.DigestSize]byte, []GovAction, error) {
	var zero [crypto.DigestSize]byte
	d := codec.NewDecoder(b)
	if err := d.ExpectHeader(TypeGovernance, GovVersion); err != nil {
		return zero, nil, err
	}
	chain, err := d.Hash()
	if err != nil {
		return zero, nil, err
	}
	n, err := d.Length(MaxGovActions)
	if err != nil {
		return zero, nil, err
	}
	if n == 0 {
		return zero, nil, fmt.Errorf("types: governance has no actions: %w", ErrInvalid)
	}
	actions := make([]GovAction, n)
	for i := range actions {
		actions[i], err = decodeAction(d)
		if err != nil {
			return zero, nil, err
		}
	}
	if err := d.Finish(); err != nil {
		return zero, nil, err
	}
	g := GovTx{ChainID: chain, Actions: actions}
	if err := g.checkActions(); err != nil {
		return zero, nil, err
	}
	return chain, actions, nil
}

func (g GovTx) signingBytes() ([]byte, error) {
	if err := g.checkActions(); err != nil {
		return nil, err
	}
	e := codec.NewEncoder()
	e.Header(TypeGovernance, GovVersion)
	e.Fixed(g.ChainID[:])
	e.Length(len(g.Actions))
	for _, a := range g.Actions {
		if err := encodeAction(e, a); err != nil {
			return nil, err
		}
	}
	return e.Bytes(), nil
}

func encodeAction(e *codec.Encoder, a GovAction) error {
	e.Uint8(a.Kind)
	switch a.Kind {
	case GovAddValidator:
		if err := encodePublicKey(e, a.Key); err != nil {
			return err
		}
		e.BytesField([]byte(a.Org))
		e.BytesField([]byte(a.Address))
	case GovRemoveValidator:
		e.Fixed(a.KeyID[:])
	case GovGrantRole:
		if err := encodePublicKey(e, a.Key); err != nil {
			return err
		}
		e.BytesField([]byte(a.Org))
		e.Uint16(a.Roles)
		e.Length(len(a.EventTypes))
		for _, t := range a.EventTypes {
			e.Uint16(t)
		}
	case GovRevokeKey:
		e.Fixed(a.KeyID[:])
		e.Uint64(a.SuspectSince)
	case GovRotate:
		e.Fixed(a.KeyID[:])
		if err := encodePublicKey(e, a.NewKey); err != nil {
			return err
		}
		e.Fixed(a.OldSig)
		e.Fixed(a.NewSig)
	case GovExtendRegistry:
		e.Uint16(a.EventType)
		e.BytesField([]byte(a.Name))
	default:
		return fmt.Errorf("types: governance action: %w", ErrInvalid)
	}
	return nil
}

func decodeGov(d *codec.Decoder) (GovTx, error) {
	if err := d.ExpectHeader(TypeGovernance, GovVersion); err != nil {
		return GovTx{}, err
	}
	var g GovTx
	var err error
	if g.ChainID, err = d.Hash(); err != nil {
		return GovTx{}, err
	}
	n, err := d.Length(MaxGovActions)
	if err != nil {
		return GovTx{}, err
	}
	if n == 0 {
		return GovTx{}, fmt.Errorf("types: governance has no actions: %w", ErrInvalid)
	}
	g.Actions = make([]GovAction, n)
	for i := range g.Actions {
		g.Actions[i], err = decodeAction(d)
		if err != nil {
			return GovTx{}, err
		}
	}
	ns, err := d.Length(MaxAdminSigs)
	if err != nil {
		return GovTx{}, err
	}
	g.Admins = make([]AdminSig, ns)
	for i := range g.Admins {
		if g.Admins[i].KeyID, err = d.Hash(); err != nil {
			return GovTx{}, err
		}
		g.Admins[i].Sig, err = d.Fixed(crypto.MLDSASignatureSize())
		if err != nil {
			return GovTx{}, err
		}
	}
	if err := g.checkActions(); err != nil {
		return GovTx{}, err
	}
	if err := g.checkAdmins(); err != nil {
		return GovTx{}, err
	}
	return g, nil
}

func decodeAction(d *codec.Decoder) (GovAction, error) {
	kind, err := d.Uint8()
	if err != nil {
		return GovAction{}, err
	}
	var a GovAction
	a.Kind = kind
	switch kind {
	case GovAddValidator:
		if a.Key, err = decodePublicKey(d); err != nil {
			return GovAction{}, err
		}
		org, err := d.BytesField(MaxOrgLen)
		if err != nil {
			return GovAction{}, err
		}
		addr, err := d.BytesField(MaxAddressLen)
		if err != nil {
			return GovAction{}, err
		}
		a.Org = string(org)
		a.Address = string(addr)
	case GovRemoveValidator:
		if a.KeyID, err = d.Hash(); err != nil {
			return GovAction{}, err
		}
	case GovGrantRole:
		if a.Key, err = decodePublicKey(d); err != nil {
			return GovAction{}, err
		}
		org, err := d.BytesField(MaxOrgLen)
		if err != nil {
			return GovAction{}, err
		}
		a.Org = string(org)
		if a.Roles, err = d.Uint16(); err != nil {
			return GovAction{}, err
		}
		n, err := d.Length(MaxGrantTypes)
		if err != nil {
			return GovAction{}, err
		}
		a.EventTypes = make([]uint16, n)
		for i := range a.EventTypes {
			if a.EventTypes[i], err = d.Uint16(); err != nil {
				return GovAction{}, err
			}
		}
	case GovRevokeKey:
		if a.KeyID, err = d.Hash(); err != nil {
			return GovAction{}, err
		}
		if a.SuspectSince, err = d.Uint64(); err != nil {
			return GovAction{}, err
		}
	case GovRotate:
		if a.KeyID, err = d.Hash(); err != nil {
			return GovAction{}, err
		}
		if a.NewKey, err = decodePublicKey(d); err != nil {
			return GovAction{}, err
		}
		if a.OldSig, err = d.Fixed(crypto.MLDSASignatureSize()); err != nil {
			return GovAction{}, err
		}
		if a.NewSig, err = d.Fixed(crypto.MLDSASignatureSize()); err != nil {
			return GovAction{}, err
		}
	case GovExtendRegistry:
		if a.EventType, err = d.Uint16(); err != nil {
			return GovAction{}, err
		}
		name, err := d.BytesField(MaxRegName)
		if err != nil {
			return GovAction{}, err
		}
		a.Name = string(name)
	default:
		return GovAction{}, fmt.Errorf("types: governance action: %w", ErrInvalid)
	}
	return a, nil
}

func (g GovTx) checkActions() error {
	if zero32(g.ChainID) {
		return fmt.Errorf("types: governance chain id: %w", ErrInvalid)
	}
	if len(g.Actions) == 0 || len(g.Actions) > MaxGovActions {
		return fmt.Errorf("types: governance action count: %w", ErrInvalid)
	}
	for _, a := range g.Actions {
		if err := checkAction(a); err != nil {
			return err
		}
	}
	return nil
}

func checkAction(a GovAction) error {
	switch a.Kind {
	case GovAddValidator:
		if a.Key.Algorithm() != crypto.AlgMLDSA65 || a.Org == "" || a.Address == "" {
			return fmt.Errorf("types: add validator: %w", ErrInvalid)
		}
		if len(a.Org) > MaxOrgLen || len(a.Address) > MaxAddressLen {
			return fmt.Errorf("types: add validator length: %w", ErrInvalid)
		}
	case GovRemoveValidator:
		if zero32(a.KeyID) {
			return fmt.Errorf("types: remove validator: %w", ErrInvalid)
		}
	case GovGrantRole:
		if a.Key.Algorithm() != crypto.AlgMLDSA65 || a.Org == "" || len(a.Org) > MaxOrgLen {
			return fmt.Errorf("types: grant role: %w", ErrInvalid)
		}
		if a.Roles == 0 || a.Roles&^RoleKnown != 0 {
			return fmt.Errorf("types: grant roles: %w", ErrInvalid)
		}
		if err := sortedTypes(a.EventTypes); err != nil {
			return err
		}
		if a.Roles&RoleWriter != 0 && len(a.EventTypes) == 0 {
			return fmt.Errorf("types: writer grant needs event types: %w", ErrInvalid)
		}
		if a.Roles&RoleWriter == 0 && len(a.EventTypes) != 0 {
			return fmt.Errorf("types: event types without writer role: %w", ErrInvalid)
		}
	case GovRevokeKey:
		if zero32(a.KeyID) {
			return fmt.Errorf("types: revoke key: %w", ErrInvalid)
		}
	case GovRotate:
		if zero32(a.KeyID) || a.NewKey.Algorithm() != crypto.AlgMLDSA65 {
			return fmt.Errorf("types: rotate: %w", ErrInvalid)
		}
		if len(a.OldSig) != crypto.MLDSASignatureSize() || len(a.NewSig) != crypto.MLDSASignatureSize() {
			return fmt.Errorf("types: rotate signature: %w", ErrInvalid)
		}
	case GovExtendRegistry:
		if a.EventType == 0 || a.Name == "" || len(a.Name) > MaxRegName {
			return fmt.Errorf("types: registry: %w", ErrInvalid)
		}
	default:
		return fmt.Errorf("types: governance action: %w", ErrInvalid)
	}
	return nil
}

func sortedTypes(ts []uint16) error {
	if len(ts) > MaxGrantTypes {
		return fmt.Errorf("types: event type count: %w", ErrInvalid)
	}
	var prev uint16
	for i, t := range ts {
		if t == 0 || (i > 0 && t <= prev) {
			return fmt.Errorf("types: event types are not strictly increasing: %w", ErrInvalid)
		}
		prev = t
	}
	return nil
}

func (g GovTx) checkAdmins() error {
	if len(g.Admins) > MaxAdminSigs {
		return fmt.Errorf("types: admin signature count: %w", ErrInvalid)
	}
	var prev [crypto.DigestSize]byte
	for i, a := range g.Admins {
		if zero32(a.KeyID) || len(a.Sig) != crypto.MLDSASignatureSize() {
			return fmt.Errorf("types: admin signature: %w", ErrInvalid)
		}
		if i > 0 && bytes.Compare(prev[:], a.KeyID[:]) >= 0 {
			return fmt.Errorf("types: admin signatures are not strictly increasing: %w", ErrInvalid)
		}
		prev = a.KeyID
	}
	return nil
}
