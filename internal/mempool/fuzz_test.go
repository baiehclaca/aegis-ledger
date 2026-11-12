package mempool

import "testing"

func FuzzUnmarshalIDs(f *testing.F) {
	f.Add([]byte{0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		t.Helper()
		_, _ = UnmarshalIDs(b)
	})
}

func FuzzUnmarshalBody(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		t.Helper()
		_, _, _ = UnmarshalBody(b)
	})
}
