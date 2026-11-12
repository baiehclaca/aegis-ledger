package types

import (
	"fmt"

	"github.com/silvergreyhound/silver-grey-ledger/internal/codec"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
)

// DocHash is one supporting-document digest. The document itself is not
// stored. Alg selects the hash; only SHA3-256 is accepted.
type DocHash struct {
	Alg uint8
	Sum [crypto.DigestSize]byte
}

// SHA3Doc builds a document hash from a raw SHA3-256 digest.
func SHA3Doc(sum [crypto.DigestSize]byte) DocHash {
	return DocHash{Alg: AlgSHA3_256, Sum: sum}
}

// Event is one ledger record. Signature is the writer's ML-DSA-65
// signature over ID(), with context silvergrey/v1/event.
type Event struct {
	ChainID     [crypto.DigestSize]byte
	EventType   uint16
	Subject     []byte
	Status      uint16
	PrevEvent   [crypto.DigestSize]byte
	DocHashes   []DocHash
	ClaimedTime int64
	WriterID    [crypto.DigestSize]byte
	Nonce       uint64
	ReadPolicy  uint16
	Signature   []byte
}

// ID is SHA3-256("silvergrey/event" || canonical body). The signature is not
// part of the id: the id is what the signature covers.
func (e Event) ID() ([crypto.DigestSize]byte, error) {
	body, err := e.signingBytes()
	if err != nil {
		return [crypto.DigestSize]byte{}, err
	}
	return crypto.DomainSum(crypto.DomainEvent, body), nil
}

// Sign sets Signature. The key's id must already be WriterID.
func (e *Event) Sign(priv crypto.PrivateKey) error {
	if err := e.checkBody(); err != nil {
		return err
	}
	pub, err := priv.Public()
	if err != nil {
		return err
	}
	if pub.Algorithm() != crypto.AlgMLDSA65 {
		return fmt.Errorf("types: writer key must be ML-DSA-65: %w", ErrSignature)
	}
	id, err := pub.ID()
	if err != nil {
		return err
	}
	if id != e.WriterID {
		return fmt.Errorf("types: writer id does not match key: %w", ErrSignature)
	}
	eid, err := e.ID()
	if err != nil {
		return err
	}
	sig, err := priv.SignDigest(eid, crypto.ContextEvent)
	if err != nil {
		return err
	}
	e.Signature = sig
	return nil
}

// Verify checks the writer signature and that pub is the declared writer.
func (e Event) Verify(pub crypto.PublicKey) error {
	if pub.Algorithm() != crypto.AlgMLDSA65 {
		return fmt.Errorf("types: writer key must be ML-DSA-65: %w", ErrSignature)
	}
	id, err := pub.ID()
	if err != nil {
		return err
	}
	if id != e.WriterID {
		return fmt.Errorf("types: writer id does not match key: %w", ErrSignature)
	}
	eid, err := e.ID()
	if err != nil {
		return err
	}
	if err := crypto.VerifyDigest(pub, eid, e.Signature, crypto.ContextEvent); err != nil {
		return fmt.Errorf("types: event signature: %w", ErrSignature)
	}
	return nil
}

// MarshalBinary encodes a signed event.
func (e Event) MarshalBinary() ([]byte, error) {
	if err := e.checkSigned(); err != nil {
		return nil, err
	}
	body, err := e.signingBytes()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(body)+len(e.Signature))
	out = append(out, body...)
	out = append(out, e.Signature...)
	return out, nil
}

// UnmarshalEvent decodes a signed event. The signature is not checked
// for validity here; Verify does that. The length is checked.
func UnmarshalEvent(b []byte) (Event, error) {
	d := codec.NewDecoder(b)
	e, err := decodeEvent(d)
	if err != nil {
		return Event{}, err
	}
	if err := d.Finish(); err != nil {
		return Event{}, err
	}
	return e, nil
}

func (e Event) signingBytes() ([]byte, error) {
	if err := e.checkBody(); err != nil {
		return nil, err
	}
	enc := codec.NewEncoder()
	enc.Header(TypeEvent, Version)
	enc.Fixed(e.ChainID[:])
	enc.Uint16(e.EventType)
	enc.BytesField(e.Subject)
	enc.Uint16(e.Status)
	enc.Fixed(e.PrevEvent[:])
	enc.Length(len(e.DocHashes))
	for _, h := range e.DocHashes {
		enc.Uint8(h.Alg)
		enc.Fixed(h.Sum[:])
	}
	enc.Int64(e.ClaimedTime)
	enc.Fixed(e.WriterID[:])
	enc.Uint64(e.Nonce)
	enc.Uint16(e.ReadPolicy)
	return enc.Bytes(), nil
}

func decodeEvent(d *codec.Decoder) (Event, error) {
	if err := d.ExpectHeader(TypeEvent, Version); err != nil {
		return Event{}, err
	}
	var e Event
	var err error
	if e.ChainID, err = d.Hash(); err != nil {
		return Event{}, err
	}
	if e.EventType, err = d.Uint16(); err != nil {
		return Event{}, err
	}
	if e.Subject, err = d.BytesField(MaxSubjectID); err != nil {
		return Event{}, err
	}
	if e.Status, err = d.Uint16(); err != nil {
		return Event{}, err
	}
	if e.PrevEvent, err = d.Hash(); err != nil {
		return Event{}, err
	}
	n, err := d.Length(MaxDocHashes)
	if err != nil {
		return Event{}, err
	}
	e.DocHashes = make([]DocHash, n)
	for i := range e.DocHashes {
		if e.DocHashes[i].Alg, err = d.Uint8(); err != nil {
			return Event{}, err
		}
		if e.DocHashes[i].Sum, err = d.Hash(); err != nil {
			return Event{}, err
		}
	}
	if e.ClaimedTime, err = d.Int64(); err != nil {
		return Event{}, err
	}
	if e.WriterID, err = d.Hash(); err != nil {
		return Event{}, err
	}
	if e.Nonce, err = d.Uint64(); err != nil {
		return Event{}, err
	}
	if e.ReadPolicy, err = d.Uint16(); err != nil {
		return Event{}, err
	}
	e.Signature, err = d.Fixed(crypto.MLDSASignatureSize())
	if err != nil {
		return Event{}, err
	}
	if err := e.checkSigned(); err != nil {
		return Event{}, err
	}
	return e, nil
}

func (e Event) checkSigned() error {
	if err := e.checkBody(); err != nil {
		return err
	}
	if len(e.Signature) != crypto.MLDSASignatureSize() {
		return fmt.Errorf("types: event signature length: %w", ErrInvalid)
	}
	return nil
}

func (e Event) checkBody() error {
	if zero32(e.ChainID) {
		return fmt.Errorf("types: chain id is zero: %w", ErrInvalid)
	}
	if e.EventType == 0 {
		return fmt.Errorf("types: event type is zero: %w", ErrInvalid)
	}
	if len(e.Subject) == 0 || len(e.Subject) > MaxSubjectID {
		return fmt.Errorf("types: subject id length: %w", ErrInvalid)
	}
	if len(e.DocHashes) > MaxDocHashes {
		return fmt.Errorf("types: too many document hashes: %w", ErrInvalid)
	}
	for _, h := range e.DocHashes {
		if h.Alg != AlgSHA3_256 {
			return fmt.Errorf("types: unknown document hash algorithm: %w", ErrInvalid)
		}
	}
	if zero32(e.WriterID) {
		return fmt.Errorf("types: writer id is zero: %w", ErrInvalid)
	}
	if e.ReadPolicy == 0 {
		return fmt.Errorf("types: read policy is zero: %w", ErrInvalid)
	}
	return nil
}

func zero32(h [crypto.DigestSize]byte) bool {
	var z [crypto.DigestSize]byte
	return h == z
}
