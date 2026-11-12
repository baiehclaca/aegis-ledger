// Package node runs one validator. Consensus and gossip use mutually
// authenticated TLS. The replica stays the pure state machine from the
// consensus package; this package owns the clock, the disk, and the sockets.
package node
