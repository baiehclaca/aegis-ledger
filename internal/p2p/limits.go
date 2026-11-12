package p2p

import "time"

// Frame kinds. Snapshot chunks and a separate NewView are not in this
// set: state sync is a later milestone, and a timeout certificate is
// how a replica announces a view change.
const (
	KindProposal      byte = 1
	KindVote          byte = 2
	KindTimeout       byte = 3
	KindTC            byte = 4
	KindEvidence      byte = 5
	KindTxAnnounce    byte = 6
	KindTxRequest     byte = 7
	KindTxBody        byte = 8
	KindBlockRequest  byte = 9
	KindBlockResponse byte = 10
	KindPing          byte = 11
	// KindGov carries a whole governance transaction. They are rare, so
	// the body is pushed rather than announced by hash.
	KindGov byte = 12
)

// AbsoluteMax is the largest frame this process will allocate. A frame
// bigger than the limit for its kind is still rejected after the kind
// byte is known.
const AbsoluteMax = 8 << 20

// Per-kind payload caps. A vote is one ML-DSA-65 signature. A timeout
// carries one QC, and a timeout certificate carries one timeout per
// quorum member, so those caps follow the 31-validator maximum. A
// block response has to fit a full block. Announce and request carry
// at most 64 event ids.
const (
	limitProposal = 8 << 20
	limitVote     = 8 << 10
	limitTimeout  = 256 << 10
	limitTC       = 4 << 20
	limitEvidence = 32 << 10
	limitAnnounce = 4 << 10
	limitBody     = 32 << 10
	limitRequest  = 16
	limitPing     = 8
	// A governance transaction may carry one ML-DSA-65 signature per
	// founder, up to the 31-validator bitmap. 256 KiB covers that plus
	// the action bytes and stays under AbsoluteMax.
	limitGov = 256 << 10
)

// DoS budgets. Rates are tokens per second. Bursts cover one honest
// burst: a quorum of votes, or one parent-chain reply of 256 blocks
// plus its end marker. Eight rejected frames ban the peer for 30s.
const (
	RateProposal       = 10
	BurstProposal      = 8
	RateVote           = 100
	BurstVote          = 64
	RateTimeout        = 20
	BurstTimeout       = 16
	RateTC             = 10
	BurstTC            = 8
	RateEvidence       = 5
	BurstEvidence      = 8
	RateAnnounce       = 50
	BurstAnnounce      = 100
	RateBody           = 50
	BurstBody          = 64
	RateBlockRequest   = 10
	BurstBlockRequest  = 20
	RateBlockResponse  = 64
	BurstBlockResponse = 280
	RatePing           = 4
	BurstPing          = 8

	MaxStrikes = 8
	BanFor     = 30 * time.Second
)

// Class is the rate-limit bucket of a frame.
type Class uint8

const (
	// ClassConsensus is the bucket for proposals, votes, timeouts, and evidence.
	ClassConsensus Class = iota
	// ClassGossip is the bucket for event announcements and bodies.
	ClassGossip
	// ClassSync is the bucket for parent-block fetch.
	ClassSync
	// ClassPing is the bucket for a ping frame.
	ClassPing
)

// PayloadLimit is the largest payload accepted for kind.
func PayloadLimit(kind byte) (int, bool) {
	switch kind {
	case KindProposal:
		return limitProposal, true
	case KindVote:
		return limitVote, true
	case KindTimeout:
		return limitTimeout, true
	case KindTC:
		return limitTC, true
	case KindEvidence:
		return limitEvidence, true
	case KindTxAnnounce, KindTxRequest:
		return limitAnnounce, true
	case KindTxBody:
		return limitBody, true
	case KindBlockRequest:
		return limitRequest, true
	case KindBlockResponse:
		return limitProposal, true
	case KindPing:
		return limitPing, true
	case KindGov:
		return limitGov, true
	default:
		return 0, false
	}
}

// ClassOf reports the bucket for a known kind.
func ClassOf(kind byte) (Class, bool) {
	switch kind {
	case KindProposal, KindVote, KindTimeout, KindTC, KindEvidence:
		return ClassConsensus, true
	case KindTxAnnounce, KindTxRequest, KindTxBody, KindGov:
		return ClassGossip, true
	case KindBlockRequest, KindBlockResponse:
		return ClassSync, true
	case KindPing:
		return ClassPing, true
	default:
		return 0, false
	}
}

func bucketFor(kind byte) (rate, burst int, ok bool) {
	switch kind {
	case KindProposal:
		return RateProposal, BurstProposal, true
	case KindVote:
		return RateVote, BurstVote, true
	case KindTimeout:
		return RateTimeout, BurstTimeout, true
	case KindTC:
		return RateTC, BurstTC, true
	case KindEvidence:
		return RateEvidence, BurstEvidence, true
	case KindTxAnnounce, KindTxRequest:
		return RateAnnounce, BurstAnnounce, true
	case KindTxBody, KindGov:
		return RateBody, BurstBody, true
	case KindBlockRequest:
		return RateBlockRequest, BurstBlockRequest, true
	case KindBlockResponse:
		return RateBlockResponse, BurstBlockResponse, true
	case KindPing:
		return RatePing, BurstPing, true
	default:
		return 0, 0, false
	}
}
