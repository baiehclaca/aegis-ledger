// Package state is the membership, role, nonce, and policy machine.
//
// A ledger value is a pure function of genesis and the block that was
// applied. The state root is a Merkle commitment to that value. Consensus
// votes only for a block whose header carries the root this package
// computes. The package does not read a clock, a disk, or the network.
package state
