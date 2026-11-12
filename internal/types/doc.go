// Package types is the ledger data model: events, blocks, quorum
// certificates, votes, timeouts, genesis, and inclusion proofs.
//
// Unmarshal checks that the bytes are the canonical encoding and that
// each field is inside its limit. Validate checks the hash links inside
// one value (a justify certificate really is the parent, an events root
// really is the events). Verify checks signatures. Those are separate
// because a canonical block can still be unsigned, and a fuzzer has to
// be able to tell the two apart.
package types
