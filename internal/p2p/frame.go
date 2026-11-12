package p2p

import (
	"encoding/binary"
	"errors"
	"io"
)

var (
	// ErrFrame means the bytes are not a frame this process will accept.
	ErrFrame = errors.New("p2p: frame")
	// ErrUnknown means the kind is not part of this milestone.
	ErrUnknown = errors.New("p2p: unknown frame")
)

// WriteFrame writes a length-prefixed frame. The length covers the kind
// byte and the payload.
func WriteFrame(w io.Writer, kind byte, payload []byte) error {
	limit, ok := PayloadLimit(kind)
	if !ok || len(payload) > limit {
		return ErrFrame
	}
	var hdr [5]byte
	binary.BigEndian.PutUint32(hdr[:4], uint32(1+len(payload)))
	hdr[4] = kind
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame reads one frame. The kind's own cap is applied after the
// kind byte so a vote cannot reserve the absolute maximum.
func ReadFrame(r io.Reader) (byte, []byte, error) {
	var nbuf [4]byte
	if _, err := io.ReadFull(r, nbuf[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(nbuf[:])
	if n == 0 || n > AbsoluteMax {
		return 0, nil, ErrFrame
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	kind := buf[0]
	payload := buf[1:]
	limit, ok := PayloadLimit(kind)
	if !ok {
		return kind, nil, ErrUnknown
	}
	if len(payload) > limit {
		return kind, nil, ErrFrame
	}
	return kind, payload, nil
}
