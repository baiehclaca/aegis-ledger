package p2p

import (
	"bytes"
	"testing"
	"time"
)

func TestLimiterBurstAndBan(t *testing.T) {
	lim := NewLimiter()
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < BurstVote; i++ {
		if !lim.Allow(now, KindVote) {
			t.Fatalf("token %d refused", i)
		}
	}
	if lim.Allow(now, KindVote) {
		t.Fatal("burst exceeded")
	}
	for i := 0; i < MaxStrikes-1; i++ {
		if lim.Strike(now) {
			t.Fatalf("banned at strike %d", i+1)
		}
	}
	if !lim.Strike(now) {
		t.Fatal("eighth strike did not ban")
	}
	if !lim.Banned(now.Add(time.Second)) {
		t.Fatal("ban did not stick")
	}
	if lim.Allow(now.Add(time.Second), KindVote) {
		t.Fatal("banned peer was allowed")
	}
	if lim.Banned(now.Add(BanFor + time.Second)) {
		t.Fatal("ban outlived its window")
	}
}

func TestLimiterCredit(t *testing.T) {
	lim := NewLimiter()
	now := time.Unix(1_700_000_000, 0)
	for range MaxStrikes - 1 {
		if lim.Strike(now) {
			t.Fatal("banned early")
		}
	}
	lim.Credit()
	if lim.Strike(now) {
		t.Fatal("credit did not drop a strike")
	}
}

func TestFrameRejects(t *testing.T) {
	var buf bytes.Buffer
	payload := bytes.Repeat([]byte{1}, limitVote+1)
	if err := WriteFrame(&buf, KindVote, payload); err == nil {
		t.Fatal("oversize vote accepted")
	}
	if err := WriteFrame(&buf, 0x7f, []byte{1}); err == nil {
		t.Fatal("unknown kind accepted")
	}
	var hdr [5]byte
	hdr[3] = 2
	hdr[4] = 0x7f
	hdrBuf := append([]byte(nil), hdr[:]...)
	hdrBuf = append(hdrBuf, 9)
	if _, _, err := ReadFrame(bytes.NewReader(hdrBuf)); err == nil {
		t.Fatal("unknown kind read")
	}
}
