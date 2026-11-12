package store

import "errors"

// ErrCorrupt means a safety file is present and does not checksum.
// The store refuses to open it. Replacing it with an empty snapshot
// would let a replica sign a view it may already have signed.
var ErrCorrupt = errors.New("store: corrupt safety file")

// Injected faults. They exist so tests can tear a write without a
// second implementation of the log.
const (
	faultNone faultKind = iota
	faultTornBlock
	faultSkipBlockSync
	faultTornSafety
	faultSkipSafetyRename
	faultKillBlock
	faultKillSafety
)

type faultKind uint8

var (
	errInjectedTorn   = errors.New("store: injected torn write")
	errInjectedSync   = errors.New("store: injected sync failure")
	errInjectedRename = errors.New("store: injected rename failure")
)
