package codec

import "errors"

// Sentinel errors. Callers use errors.Is. The text is safe to show:
// it names the class of failure and not the bytes that caused it.
var (
	ErrShortBuffer  = errors.New("codec: short buffer")
	ErrTrailing     = errors.New("codec: trailing bytes")
	ErrNonCanonical = errors.New("codec: non-canonical length")
	ErrOversize     = errors.New("codec: oversize field")
	ErrVersion      = errors.New("codec: unknown version")
	ErrType         = errors.New("codec: unexpected type")
	ErrInvalid      = errors.New("codec: invalid value")
)
