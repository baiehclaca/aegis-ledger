// Package store is the crash-safe storage behind the consensus Store
// interface. Blocks live in an append-only log. The safety snapshot
// lives in its own atomically replaced file. Current membership, nonces,
// and indexes live in Pebble and can be rebuilt by replaying committed
// blocks.
//
// Snapshots for state sync are a later milestone. This package only
// keeps what a restarted process on the same disk needs.
package store
