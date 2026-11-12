package api

import (
	"strconv"
	"testing"
	"time"
)

func TestGateSharesHost(t *testing.T) {
	g := newGate()
	now := time.Now()
	for i := range ReadBurst {
		if !g.allow(now, "10.0.0.1:"+strconv.Itoa(i+1), false) {
			t.Fatalf("read %d rejected inside the burst", i)
		}
	}
	if g.allow(now, "10.0.0.1:40000", false) {
		t.Fatal("a new port on the same host was given a fresh burst")
	}
}

func TestGateDropsOldestHost(t *testing.T) {
	g := newGate()
	now := time.Now()
	for g.allow(now, "10.1.0.0:9", false) {
	}
	for i := 1; i < maxRateKeys; i++ {
		if !g.allow(now, "10.1.0."+strconv.Itoa(i)+":9", false) {
			t.Fatalf("host %d rejected", i)
		}
	}
	if !g.allow(now, "10.2.0.1:9", false) {
		t.Fatal("a new host was rejected instead of dropping the oldest")
	}
	if !g.allow(now, "10.1.0.0:9", false) {
		t.Fatal("the evicted host was not admitted with a new bucket")
	}
}
