package codec

import (
	"bytes"
	"errors"
	"math"
	"testing"
	"testing/quick"
)

func TestIntegersRoundTrip(t *testing.T) {
	e := NewEncoder()
	e.Uint8(0)
	e.Uint8(255)
	e.Uint16(0)
	e.Uint16(0xABCD)
	e.Uint32(0x01020304)
	e.Uint64(0x0102030405060708)
	e.Int64(math.MinInt64)
	e.Int64(-1)
	e.Int64(0)
	e.Int64(math.MaxInt64)

	d := NewDecoder(e.Bytes())
	u8, err := d.Uint8()
	if err != nil || u8 != 0 {
		t.Fatalf("uint8 0: %v %d", err, u8)
	}
	u8, err = d.Uint8()
	if err != nil || u8 != 255 {
		t.Fatalf("uint8 255: %v %d", err, u8)
	}
	u16, err := d.Uint16()
	if err != nil || u16 != 0 {
		t.Fatalf("uint16 0: %v %d", err, u16)
	}
	u16, err = d.Uint16()
	if err != nil || u16 != 0xABCD {
		t.Fatalf("uint16: %v %x", err, u16)
	}
	u32, err := d.Uint32()
	if err != nil || u32 != 0x01020304 {
		t.Fatalf("uint32: %v %x", err, u32)
	}
	u64, err := d.Uint64()
	if err != nil || u64 != 0x0102030405060708 {
		t.Fatalf("uint64: %v %x", err, u64)
	}
	for _, want := range []int64{math.MinInt64, -1, 0, math.MaxInt64} {
		got, err := d.Int64()
		if err != nil || got != want {
			t.Fatalf("int64 %d: got %d err %v", want, got, err)
		}
	}
	if err := d.Finish(); err != nil {
		t.Fatal(err)
	}
}

func TestLengthCanonical(t *testing.T) {
	cases := []struct {
		n    int
		want []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{127, []byte{0x7f}},
		{128, []byte{0x81, 0x80}},
		{255, []byte{0x81, 0xff}},
		{256, []byte{0x82, 0x01, 0x00}},
		{65535, []byte{0x82, 0xff, 0xff}},
		{65536, []byte{0x83, 0x01, 0x00, 0x00}},
	}
	for _, tc := range cases {
		e := NewEncoder()
		e.Length(tc.n)
		if !bytes.Equal(e.Bytes(), tc.want) {
			t.Fatalf("encode %d: got %x want %x", tc.n, e.Bytes(), tc.want)
		}
		d := NewDecoder(tc.want)
		got, err := d.Length(tc.n)
		if err != nil || got != tc.n {
			t.Fatalf("decode %d: got %d err %v", tc.n, got, err)
		}
		if err := d.Finish(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLengthRejected(t *testing.T) {
	// Each input is a non-canonical or oversized length prefix.
	rejected := []struct {
		in  []byte
		max int
		err error
	}{
		{[]byte{0x80}, 1000, ErrNonCanonical},             // indefinite
		{[]byte{0x81, 0x05}, 1000, ErrNonCanonical},       // long form of a short value
		{[]byte{0x81, 0x7f}, 1000, ErrNonCanonical},       // 127 must be short form
		{[]byte{0x82, 0x00, 0xc8}, 1000, ErrNonCanonical}, // leading zero
		{[]byte{0x85, 0x01, 0x00, 0x00, 0x00, 0x00}, 1000, ErrNonCanonical},
		{[]byte{0x81, 0x80}, 127, ErrOversize},
		{[]byte{0x0a}, 9, ErrOversize},
		{[]byte{0x81}, 1000, ErrShortBuffer},
	}
	for _, tc := range rejected {
		d := NewDecoder(tc.in)
		_, err := d.Length(tc.max)
		if !errors.Is(err, tc.err) {
			t.Fatalf("%x: got %v want %v", tc.in, err, tc.err)
		}
	}
}

func TestBytesRoundTripAndTrailing(t *testing.T) {
	e := NewEncoder()
	e.BytesField(nil)
	e.BytesField([]byte{})
	e.BytesField([]byte{1, 2, 3})
	d := NewDecoder(e.Bytes())
	for _, want := range [][]byte{nil, {}, {1, 2, 3}} {
		got, err := d.BytesField(3)
		if err != nil {
			t.Fatal(err)
		}
		if want == nil {
			want = []byte{}
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("got %x want %x", got, want)
		}
	}
	if err := d.Finish(); err != nil {
		t.Fatal(err)
	}

	raw := e.Bytes()
	raw = append(raw, 0x00)
	d = NewDecoder(raw)
	for range 3 {
		if _, err := d.BytesField(3); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.Finish(); !errors.Is(err, ErrTrailing) {
		t.Fatalf("trailing: %v", err)
	}
}

func TestHeaderMismatch(t *testing.T) {
	e := NewEncoder()
	e.Header(7, 1)
	d := NewDecoder(e.Bytes())
	if err := d.ExpectHeader(8, 1); !errors.Is(err, ErrType) {
		t.Fatalf("type: %v", err)
	}
	d = NewDecoder(e.Bytes())
	if err := d.ExpectHeader(7, 2); !errors.Is(err, ErrVersion) {
		t.Fatalf("version: %v", err)
	}
}

func TestBytesFieldDoesNotAlias(t *testing.T) {
	in := []byte{9, 8, 7}
	e := NewEncoder()
	e.BytesField(in)
	d := NewDecoder(e.Bytes())
	got, err := d.BytesField(3)
	if err != nil {
		t.Fatal(err)
	}
	got[0] = 0
	if in[0] != 9 {
		t.Fatal("decoder aliased the input")
	}
	// Mutating the source after encoding must not change the encoding.
	in[0] = 1
	d = NewDecoder(e.Bytes())
	got, err = d.BytesField(3)
	if err != nil || got[0] != 9 {
		t.Fatalf("encoder aliased the input: %v %x", err, got)
	}
}

func TestQuickIntegerRoundTrip(t *testing.T) {
	f := func(a uint16, b uint32, c uint64, d int64) bool {
		e := NewEncoder()
		e.Uint16(a)
		e.Uint32(b)
		e.Uint64(c)
		e.Int64(d)
		dec := NewDecoder(e.Bytes())
		ga, err1 := dec.Uint16()
		gb, err2 := dec.Uint32()
		gc, err3 := dec.Uint64()
		gd, err4 := dec.Int64()
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
			return false
		}
		return ga == a && gb == b && gc == c && gd == d && dec.Finish() == nil
	}
	if err := quick.Check(f, nil); err != nil {
		t.Fatal(err)
	}
}

func TestShortBuffer(t *testing.T) {
	d := NewDecoder([]byte{0x00, 0x01})
	if _, err := d.Uint32(); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("got %v", err)
	}
}
