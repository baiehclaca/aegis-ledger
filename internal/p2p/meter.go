package p2p

import (
	"net"
	"sync/atomic"
)

// Meter counts ciphertext bytes on the wire, including the handshake.
// A nil meter counts nothing. It is optional so production nodes do not
// keep a counter they never read.
type Meter struct {
	sent atomic.Uint64
	recv atomic.Uint64
}

// Reset zeroes both directions.
func (m *Meter) Reset() {
	if m == nil {
		return
	}
	m.sent.Store(0)
	m.recv.Store(0)
}

// Snapshot returns sent and received bytes.
func (m *Meter) Snapshot() (sent, recv uint64) {
	if m == nil {
		return 0, 0
	}
	return m.sent.Load(), m.recv.Load()
}

// Count wraps conn so reads and writes update m.
func Count(conn net.Conn, m *Meter) net.Conn {
	if m == nil {
		return conn
	}
	return &countingConn{Conn: conn, meter: m}
}

type countingConn struct {
	net.Conn
	meter *Meter
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.meter.recv.Add(uint64(n))
	}
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.meter.sent.Add(uint64(n))
	}
	return n, err
}
