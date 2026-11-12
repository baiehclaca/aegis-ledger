package codec

import "encoding/binary"

// DER definite-length bounds from X.690. Short form is a single byte for
// 0..127. Longer values use the smallest big-endian width with no leading
// zero. Indefinite length (0x80) is rejected, as is any width above uint32,
// which this codec never produces.
const (
	derLongFormBit     = 0x80
	derShortFormMax    = 127
	derMaxLengthOctets = 4
)

// Encoder appends one canonical value. It does not retain caller slices.
type Encoder struct {
	buf []byte
}

// NewEncoder returns an empty encoder.
func NewEncoder() *Encoder {
	return &Encoder{}
}

// Bytes returns a copy of the encoded bytes.
func (e *Encoder) Bytes() []byte {
	out := make([]byte, len(e.buf))
	copy(out, e.buf)
	return out
}

// Header writes the type id and version that begin every versioned value.
func (e *Encoder) Header(typeID, version uint16) {
	e.Uint16(typeID)
	e.Uint16(version)
}

// Uint8 writes one byte.
func (e *Encoder) Uint8(v uint8) {
	e.buf = append(e.buf, v)
}

// Uint16 writes a big-endian uint16.
func (e *Encoder) Uint16(v uint16) {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	e.buf = append(e.buf, b[:]...)
}

// Uint32 writes a big-endian uint32.
func (e *Encoder) Uint32(v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	e.buf = append(e.buf, b[:]...)
}

// Uint64 writes a big-endian uint64.
func (e *Encoder) Uint64(v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	e.buf = append(e.buf, b[:]...)
}

// Int64 writes a big-endian two's-complement int64.
func (e *Encoder) Int64(v int64) {
	e.Uint64(uint64(v))
}

// Fixed writes raw bytes with no length prefix. The caller chooses the width.
func (e *Encoder) Fixed(b []byte) {
	e.buf = append(e.buf, b...)
}

// BytesField writes a length-prefixed byte string.
func (e *Encoder) BytesField(b []byte) {
	e.Length(len(b))
	e.buf = append(e.buf, b...)
}

// Length writes a canonical DER length or count.
func (e *Encoder) Length(n int) {
	e.buf = appendLength(e.buf, n)
}

func appendLength(dst []byte, n int) []byte {
	if n < 0 {
		// A negative length is a programmer error, not a decoded value.
		panic("codec: negative length")
	}
	if n <= derShortFormMax {
		return append(dst, byte(n))
	}
	var tmp [derMaxLengthOctets]byte
	binary.BigEndian.PutUint32(tmp[:], uint32(n))
	start := 0
	for start < len(tmp)-1 && tmp[start] == 0 {
		start++
	}
	width := len(tmp) - start
	dst = append(dst, derLongFormBit|byte(width))
	return append(dst, tmp[start:]...)
}

// Decoder reads one canonical value from a fixed buffer.
type Decoder struct {
	buf []byte
	pos int
}

// NewDecoder returns a decoder over b. b is not retained past the returned
// copies of variable-length fields.
func NewDecoder(b []byte) *Decoder {
	return &Decoder{buf: b}
}

// Remaining reports unread bytes. Used by tests.
func (d *Decoder) Remaining() int {
	return len(d.buf) - d.pos
}

// Finish rejects trailing bytes. A decoded value must consume its buffer.
func (d *Decoder) Finish() error {
	if d.pos != len(d.buf) {
		return ErrTrailing
	}
	return nil
}

// ExpectHeader reads a type id and version and rejects anything else.
func (d *Decoder) ExpectHeader(typeID, version uint16) error {
	gotType, err := d.Uint16()
	if err != nil {
		return err
	}
	gotVer, err := d.Uint16()
	if err != nil {
		return err
	}
	if gotType != typeID {
		return ErrType
	}
	if gotVer != version {
		return ErrVersion
	}
	return nil
}

// Uint8 reads one byte.
func (d *Decoder) Uint8() (uint8, error) {
	b, err := d.next(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

// Uint16 reads a big-endian uint16.
func (d *Decoder) Uint16() (uint16, error) {
	b, err := d.next(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

// Uint32 reads a big-endian uint32.
func (d *Decoder) Uint32() (uint32, error) {
	b, err := d.next(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

// Uint64 reads a big-endian uint64.
func (d *Decoder) Uint64() (uint64, error) {
	b, err := d.next(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}

// Int64 reads a big-endian two's-complement int64.
func (d *Decoder) Int64() (int64, error) {
	u, err := d.Uint64()
	if err != nil {
		return 0, err
	}
	return int64(u), nil
}

// Fixed reads n bytes and returns a copy.
func (d *Decoder) Fixed(n int) ([]byte, error) {
	return d.nextCopy(n)
}

// Hash reads a 32-byte value into an array.
func (d *Decoder) Hash() ([32]byte, error) {
	var out [32]byte
	b, err := d.next(len(out))
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}

// BytesField reads a length-prefixed byte string. limit is the largest
// accepted length, inclusive.
func (d *Decoder) BytesField(limit int) ([]byte, error) {
	n, err := d.Length(limit)
	if err != nil {
		return nil, err
	}
	return d.nextCopy(n)
}

// Length reads a canonical DER length. limit is the largest accepted value.
func (d *Decoder) Length(limit int) (int, error) {
	if limit < 0 {
		return 0, ErrInvalid
	}
	first, err := d.Uint8()
	if err != nil {
		return 0, err
	}
	if first&derLongFormBit == 0 {
		n := int(first)
		if n > limit {
			return 0, ErrOversize
		}
		return n, nil
	}
	width := int(first &^ derLongFormBit)
	// width 0 is the BER indefinite form. Widths above four bytes cannot
	// be a length this codec emits, and a smaller value encoded that wide
	// would have leading zero bytes.
	if width == 0 || width > derMaxLengthOctets {
		return 0, ErrNonCanonical
	}
	raw, err := d.next(width)
	if err != nil {
		return 0, err
	}
	if raw[0] == 0 {
		return 0, ErrNonCanonical
	}
	var v uint64
	for _, c := range raw {
		v = v<<8 | uint64(c)
	}
	if v <= derShortFormMax {
		return 0, ErrNonCanonical
	}
	if v > uint64(limit) {
		return 0, ErrOversize
	}
	return int(v), nil
}

func (d *Decoder) next(n int) ([]byte, error) {
	if n < 0 {
		return nil, ErrInvalid
	}
	if n > len(d.buf)-d.pos {
		return nil, ErrShortBuffer
	}
	out := d.buf[d.pos : d.pos+n]
	d.pos += n
	return out, nil
}

func (d *Decoder) nextCopy(n int) ([]byte, error) {
	b, err := d.next(n)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return []byte{}, nil
	}
	out := make([]byte, n)
	copy(out, b)
	return out, nil
}
