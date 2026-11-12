package types

import (
	"fmt"

	"github.com/silvergreyhound/silver-grey-ledger/internal/merkle"
)

const (
	// Version is the encoding version of every M0 value. Decoders reject
	// every other version so a later format cannot be mistaken for this one.
	Version uint16 = 1
	// GenesisVersion is the genesis record that carries SLH-DSA founding
	// signatures. Version 1 was the M1 record signed by validator keys.
	GenesisVersion uint16 = 2
	// BlockVersion is the block that carries a governance-transaction list.
	// The header version stays Version. There is no deployed version-1 chain.
	BlockVersion uint16 = 2
	// GovVersion is the governance transaction encoding.
	GovVersion uint16 = 1
)

// Wire type identifiers. They stay fixed for version 1.
const (
	TypeEvent          uint16 = 1
	TypeBlockHeader    uint16 = 2
	TypeQC             uint16 = 3
	TypeBlock          uint16 = 4
	TypeInclusionProof uint16 = 5
	TypeValidatorSet   uint16 = 6
	TypePublicKey      uint16 = 7
	TypeVote           uint16 = 8
	TypeTimeout        uint16 = 9
	TypeTC             uint16 = 10
	TypeProposal       uint16 = 11
	TypeEquivocation   uint16 = 12
	TypeGenesis        uint16 = 13
	TypeGovernance     uint16 = 14
)

const (

	// MaxSubjectID is the longest opaque subject identifier.
	MaxSubjectID = 64
	// MaxDocHashes is the most document hashes one event may carry.
	MaxDocHashes = 16
	// MaxValidators is the largest set the 31-bit signer bitmap can name.
	// 31 is also 3*10+1, so it is a legal BFT size.
	MaxValidators = 31
	// MinValidators is the smallest set we deploy: n = 4, f = 1.
	MinValidators = 4

	// MaxEventsPerBlock is the decided v1 cap. It matches the Merkle tree
	// cap so a block and a proof agree on the largest batch.
	MaxEventsPerBlock = merkle.MaxLeaves
	// MaxMerkleSiblings is the longest inclusion path the decoder accepts.
	MaxMerkleSiblings = merkle.MaxSiblings

	// MinFounders is the fewest founding organisations a chain may have.
	// One organisation would be able to meet a ceil(2/3) threshold alone.
	MinFounders = 2
	// MaxFounders is the most founding organisations a genesis may name.
	MaxFounders = 31
	// MaxGrants is the most identities a genesis may name.
	MaxGrants = 64
	// MaxRegistry is the most event types a registry may name.
	MaxRegistry = 64
	// MaxOrgLen is the longest organisation identifier.
	MaxOrgLen = 64
	// MaxAddressLen is the longest validator network address stored in genesis.
	MaxAddressLen = 128
	// MaxRegName is the longest event-type name.
	MaxRegName = 32
	// MaxGrantTypes is the most event types one role grant may list.
	MaxGrantTypes = 32
	// MaxGovActions is the most actions one governance transaction may carry.
	MaxGovActions = 4
	// MaxGovPerBlock is the most governance transactions one block may carry.
	MaxGovPerBlock = 16
	// MaxAdminSigs is the most admin signatures on one governance transaction.
	MaxAdminSigs = 31
	// MinEpochDelay is the smallest height gap before a governance effect.
	MinEpochDelay uint64 = 1
	// MaxEpochDelay is the largest height gap before a governance effect.
	MaxEpochDelay uint64 = 256
)

// Role bits. A grant may combine them. Unknown bits are rejected.
const (
	RoleValidator uint16 = 1 << iota
	RoleWriter
	RoleReader
	RoleAuditor
	RoleAdmin
)

// RoleKnown is every role bit this version understands.
const RoleKnown = RoleValidator | RoleWriter | RoleReader | RoleAuditor | RoleAdmin

// Governance action kinds.
const (
	GovAddValidator    uint8 = 1
	GovRemoveValidator uint8 = 2
	GovGrantRole       uint8 = 3
	GovRevokeKey       uint8 = 4
	GovRotate          uint8 = 5
	GovExtendRegistry  uint8 = 6
)

// DefaultThreshold is ceil(2/3 of the founding organisations).
// Two founders yield 2. Fewer than two is rejected.
func DefaultThreshold(founders int) (uint16, error) {
	if founders < MinFounders || founders > MaxFounders {
		return 0, fmt.Errorf("types: founder count: %w", ErrInvalid)
	}
	return uint16((2*founders + 2) / 3), nil
}

// AlgSHA3_256 is the only document-hash algorithm in v1. The byte is
// stored next to the digest so a later algorithm cannot be read as
// SHA3-256.
const (
	AlgSHA3_256 uint8 = 1
)

// Event type numbers from the design. Zero is rejected: it would be an
// unset type. Any other non-zero value is accepted so the genesis
// registry can grow without a codec change.
const (
	EventShipmentDispatched uint16 = 1
	EventClearanceGranted   uint16 = 2
	EventAccessLogin        uint16 = 3
)

// Read-policy tags from the design. Zero is rejected so an event cannot
// omit a policy. Unknown non-zero tags are accepted; enforcement is an
// API concern, not a codec concern.
const (
	ReadAllMembers uint16 = 1
	ReadOrgOnly    uint16 = 2
	ReadAuditors   uint16 = 3
)

// maxSignerBits is bits 0..30 of the signer bitmap. Bit 31 is rejected
// so a bitmap cannot name a validator past MaxValidators.
const maxSignerBits uint32 = 1<<31 - 1
