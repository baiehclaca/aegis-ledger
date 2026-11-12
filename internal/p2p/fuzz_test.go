package p2p

import (
	"bytes"
	"testing"
)

func FuzzFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, KindPing})
	f.Fuzz(func(t *testing.T, b []byte) {
		t.Helper()
		_, _, _ = ReadFrame(bytes.NewReader(b))
	})
}
