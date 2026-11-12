package mempool

import (
	"encoding/binary"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

// MarshalIDs encodes up to MaxIDs event ids.
func MarshalIDs(ids [][crypto.DigestSize]byte) ([]byte, error) {
	if len(ids) == 0 || len(ids) > MaxIDs {
		return nil, ErrFrame
	}
	out := make([]byte, 2+len(ids)*crypto.DigestSize)
	binary.BigEndian.PutUint16(out[:2], uint16(len(ids)))
	for i, id := range ids {
		copy(out[2+i*crypto.DigestSize:], id[:])
	}
	return out, nil
}

// UnmarshalIDs decodes an announce or a request.
func UnmarshalIDs(b []byte) ([][crypto.DigestSize]byte, error) {
	if len(b) < 2 {
		return nil, ErrFrame
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if n == 0 || n > MaxIDs || len(b) != n*crypto.DigestSize {
		return nil, ErrFrame
	}
	out := make([][crypto.DigestSize]byte, n)
	for i := range out {
		copy(out[i][:], b[:crypto.DigestSize])
		b = b[crypto.DigestSize:]
	}
	return out, nil
}

// MarshalBody encodes one event and the writer key that verifies it.
func MarshalBody(pub crypto.PublicKey, ev types.Event) ([]byte, error) {
	kb, err := types.MarshalPublicKey(pub)
	if err != nil {
		return nil, err
	}
	eb, err := ev.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if len(kb) > 8<<10 || len(eb) > 24<<10 {
		return nil, ErrFrame
	}
	out := binary.BigEndian.AppendUint32(nil, uint32(len(kb)))
	out = append(out, kb...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(eb)))
	out = append(out, eb...)
	return out, nil
}

// UnmarshalBody decodes a gossip body. The signature is not checked.
func UnmarshalBody(b []byte) (crypto.PublicKey, types.Event, error) {
	if len(b) < 4 {
		return crypto.PublicKey{}, types.Event{}, ErrFrame
	}
	kn := binary.BigEndian.Uint32(b[:4])
	b = b[4:]
	if kn == 0 || kn > 8<<10 || uint32(len(b)) < kn {
		return crypto.PublicKey{}, types.Event{}, ErrFrame
	}
	kb := b[:kn]
	b = b[kn:]
	if len(b) < 4 {
		return crypto.PublicKey{}, types.Event{}, ErrFrame
	}
	en := binary.BigEndian.Uint32(b[:4])
	b = b[4:]
	if en == 0 || en > 24<<10 || uint32(len(b)) != en {
		return crypto.PublicKey{}, types.Event{}, ErrFrame
	}
	pub, err := types.UnmarshalPublicKey(kb)
	if err != nil {
		return crypto.PublicKey{}, types.Event{}, err
	}
	ev, err := types.UnmarshalEvent(b)
	if err != nil {
		return crypto.PublicKey{}, types.Event{}, err
	}
	return pub, ev, nil
}
