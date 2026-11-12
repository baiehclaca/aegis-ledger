// Package verify checks inclusion proofs and document hashes offline.
//
// A successful proof means a quorum of the supplied validator set
// certified the block that contains the event. That is certification.
// HotStuff-2 finality is the two-chain rule; it needs the following
// block's certificate as well, which this milestone does not claim.
//
// The caller supplies the validator set and the writer key. Walking
// the membership history from genesis is a later milestone. This
// package trusts the set it is given and checks everything else.
package verify
