package codec

import (
	"bytes"
	"testing"
)

func FuzzLength(f *testing.F) {
	for _, n := range []int{0, 1, 127, 128, 255, 256, 1000, 65535} {
		e := NewEncoder()
		e.Length(n)
		f.Add(e.Bytes())
	}
	f.Add([]byte{0x81, 0x05})
	f.Add([]byte{0x82, 0x00, 0x80})
	f.Fuzz(func(t *testing.T, data []byte) {
		d := NewDecoder(data)
		n, err := d.Length(1 << 20)
		if err != nil {
			return
		}
		if err := d.Finish(); err != nil {
			return
		}
		e := NewEncoder()
		e.Length(n)
		if !bytes.Equal(e.Bytes(), data) {
			t.Fatalf("accepted non-canonical length %x", data)
		}
	})
}

func FuzzBytesField(f *testing.F) {
	e := NewEncoder()
	e.BytesField([]byte("silvergrey"))
	f.Add(e.Bytes())
	f.Add([]byte{0x00})
	f.Add([]byte{0x81, 0x01, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		const fieldLimit = 1 << 16
		d := NewDecoder(data)
		b, err := d.BytesField(fieldLimit)
		if err != nil {
			return
		}
		if err := d.Finish(); err != nil {
			return
		}
		out := NewEncoder()
		out.BytesField(b)
		if !bytes.Equal(out.Bytes(), data) {
			t.Fatalf("accepted non-canonical bytes %x", data)
		}
	})
}

func FuzzRecord(f *testing.F) {
	e := NewEncoder()
	e.Header(1, 1)
	e.Uint64(99)
	e.BytesField([]byte("silvergrey"))
	e.Int64(-7)
	f.Add(e.Bytes())
	f.Fuzz(func(t *testing.T, data []byte) {
		d := NewDecoder(data)
		if err := d.ExpectHeader(1, 1); err != nil {
			return
		}
		u, err := d.Uint64()
		if err != nil {
			return
		}
		b, err := d.BytesField(1 << 16)
		if err != nil {
			return
		}
		i, err := d.Int64()
		if err != nil {
			return
		}
		if err := d.Finish(); err != nil {
			return
		}
		out := NewEncoder()
		out.Header(1, 1)
		out.Uint64(u)
		out.BytesField(b)
		out.Int64(i)
		if !bytes.Equal(out.Bytes(), data) {
			t.Fatalf("accepted non-canonical record")
		}
	})
}
