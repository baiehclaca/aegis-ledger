package crypto

// Hash domains are prefixes of SHA3-256. They are not prefixes of each
// other, so a digest of one object cannot be substituted for another.
// DomainGovernance is the prefix of a governance transaction id and of
// the rotate preimage. It is not a prefix of any other domain.
const (
	DomainEvent      = "silvergrey/event"
	DomainBlock      = "silvergrey/block"
	DomainVote       = "silvergrey/vote"
	DomainKey        = "silvergrey/key"
	DomainTimeout    = "silvergrey/timeout"
	DomainGenesis    = "silvergrey/genesis"
	DomainGovernance = "silvergrey/governance"
)

// Context strings are the FIPS 204/205 context parameter, not a prefix
// of the hashed message. SignDigest accepts only the contexts whose
// preimage is defined.
const (
	ContextEvent      = "silvergrey/v1/event"
	ContextProposal   = "silvergrey/v1/proposal"
	ContextVote       = "silvergrey/v1/vote"
	ContextTimeout    = "silvergrey/v1/timeout"
	ContextGenesis    = "silvergrey/v1/genesis"
	ContextGovernance = "silvergrey/v1/governance"
)

// DigestSize is the SHA3-256 output size. Signatures cover a digest of
// this size and never a raw payload.
const DigestSize = 32

// maxContextLen is the FIPS 204 and FIPS 205 limit on the context string.
const maxContextLen = 255

func knownSignContext(context string) bool {
	switch context {
	case ContextEvent, ContextProposal, ContextVote, ContextTimeout, ContextGenesis, ContextGovernance:
		return true
	default:
		return false
	}
}

func checkContextBytes(context string) error {
	if len(context) > maxContextLen {
		return ErrContext
	}
	return nil
}
