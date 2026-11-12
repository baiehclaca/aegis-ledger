package types

import (
	"fmt"

	"github.com/silvergreyhound/silver-grey-ledger/internal/codec"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/merkle"
)

// BlockHeader is the signed prefix of a block. Justify certifies the
// parent. EventsRoot is the Merkle root of the block's event ids.
// StateRoot commits to membership and nonce state after the block.
type BlockHeader struct {
	ChainID      [crypto.DigestSize]byte
	Height       uint64
	View         uint64
	ParentHash   [crypto.DigestSize]byte
	Justify      QC
	EventsRoot   [crypto.DigestSize]byte
	StateRoot    [crypto.DigestSize]byte
	ProposerID   [crypto.DigestSize]byte
	ProposerTime int64
}

// Hash is SHA3-256("silvergrey/block" || canonical header).
func (h BlockHeader) Hash() ([crypto.DigestSize]byte, error) {
	raw, err := h.MarshalBinary()
	if err != nil {
		return [crypto.DigestSize]byte{}, err
	}
	return crypto.DomainSum(crypto.DomainBlock, raw), nil
}

// Validate checks the parent link. It does not check signatures or the
// events root; the root needs the block body.
func (h BlockHeader) Validate() error {
	if zero32(h.ChainID) {
		return fmt.Errorf("types: chain id is zero: %w", ErrInvalid)
	}
	if zero32(h.ProposerID) {
		return fmt.Errorf("types: proposer id is zero: %w", ErrInvalid)
	}
	if h.Height == 0 {
		if !zero32(h.ParentHash) || !h.Justify.IsEmpty() {
			return fmt.Errorf("types: genesis header needs a zero parent and an empty justify QC: %w", ErrInvalid)
		}
		return nil
	}
	if zero32(h.ParentHash) || h.Justify.IsEmpty() {
		return fmt.Errorf("types: non-genesis header needs a parent certificate: %w", ErrInvalid)
	}
	if h.Justify.BlockHash != h.ParentHash {
		return fmt.Errorf("types: justify QC does not certify the parent: %w", ErrInvalid)
	}
	if h.View <= h.Justify.View {
		return fmt.Errorf("types: block view must be higher than its justify view: %w", ErrInvalid)
	}
	return nil
}

// MarshalBinary encodes the header.
func (h BlockHeader) MarshalBinary() ([]byte, error) {
	if err := h.checkFields(); err != nil {
		return nil, err
	}
	e := codec.NewEncoder()
	if err := encodeHeader(e, h); err != nil {
		return nil, err
	}
	return e.Bytes(), nil
}

// UnmarshalBlockHeader decodes a header.
func UnmarshalBlockHeader(b []byte) (BlockHeader, error) {
	d := codec.NewDecoder(b)
	h, err := decodeHeader(d)
	if err != nil {
		return BlockHeader{}, err
	}
	if err := d.Finish(); err != nil {
		return BlockHeader{}, err
	}
	return h, nil
}

func encodeHeader(e *codec.Encoder, h BlockHeader) error {
	e.Header(TypeBlockHeader, Version)
	e.Fixed(h.ChainID[:])
	e.Uint64(h.Height)
	e.Uint64(h.View)
	e.Fixed(h.ParentHash[:])
	if err := encodeQC(e, h.Justify); err != nil {
		return err
	}
	e.Fixed(h.EventsRoot[:])
	e.Fixed(h.StateRoot[:])
	e.Fixed(h.ProposerID[:])
	e.Int64(h.ProposerTime)
	return nil
}

func decodeHeader(d *codec.Decoder) (BlockHeader, error) {
	if err := d.ExpectHeader(TypeBlockHeader, Version); err != nil {
		return BlockHeader{}, err
	}
	var h BlockHeader
	var err error
	if h.ChainID, err = d.Hash(); err != nil {
		return BlockHeader{}, err
	}
	if h.Height, err = d.Uint64(); err != nil {
		return BlockHeader{}, err
	}
	if h.View, err = d.Uint64(); err != nil {
		return BlockHeader{}, err
	}
	if h.ParentHash, err = d.Hash(); err != nil {
		return BlockHeader{}, err
	}
	if h.Justify, err = decodeQC(d); err != nil {
		return BlockHeader{}, err
	}
	if h.EventsRoot, err = d.Hash(); err != nil {
		return BlockHeader{}, err
	}
	if h.StateRoot, err = d.Hash(); err != nil {
		return BlockHeader{}, err
	}
	if h.ProposerID, err = d.Hash(); err != nil {
		return BlockHeader{}, err
	}
	if h.ProposerTime, err = d.Int64(); err != nil {
		return BlockHeader{}, err
	}
	if err := h.checkFields(); err != nil {
		return BlockHeader{}, err
	}
	return h, nil
}

func (h BlockHeader) checkFields() error {
	if zero32(h.ChainID) || zero32(h.ProposerID) {
		return fmt.Errorf("types: header identity is zero: %w", ErrInvalid)
	}
	return h.Justify.check()
}

// Block is a header, its events, its governance transactions, and the
// proposer's signature over the header hash with context silvergrey/v1/proposal.
// Governance transactions are bound by state_root, which commits to their ids.
type Block struct {
	Header      BlockHeader
	Events      []Event
	Gov         []GovTx
	ProposerSig []byte
}

// Validate checks the header link and that EventsRoot is the Merkle
// root of the event ids. It does not check signatures.
func (b Block) Validate() error {
	if err := b.Header.Validate(); err != nil {
		return err
	}
	if len(b.Events) > MaxEventsPerBlock {
		return fmt.Errorf("types: too many events: %w", ErrInvalid)
	}
	ids := make([][crypto.DigestSize]byte, len(b.Events))
	for i, ev := range b.Events {
		if ev.ChainID != b.Header.ChainID {
			return fmt.Errorf("types: event %d chain id: %w", i, ErrInvalid)
		}
		id, err := ev.ID()
		if err != nil {
			return err
		}
		ids[i] = id
	}
	root, err := merkle.Root(ids)
	if err != nil {
		return err
	}
	if root != b.Header.EventsRoot {
		return fmt.Errorf("types: events root: %w", ErrInvalid)
	}
	return nil
}

// Sign sets ProposerSig. The key's id must already be ProposerID, and
// Validate must pass.
func (b *Block) Sign(priv crypto.PrivateKey) error {
	if err := b.Validate(); err != nil {
		return err
	}
	pub, err := priv.Public()
	if err != nil {
		return err
	}
	if pub.Algorithm() != crypto.AlgMLDSA65 {
		return fmt.Errorf("types: proposer key must be ML-DSA-65: %w", ErrSignature)
	}
	id, err := pub.ID()
	if err != nil {
		return err
	}
	if id != b.Header.ProposerID {
		return fmt.Errorf("types: proposer id does not match key: %w", ErrSignature)
	}
	hash, err := b.Header.Hash()
	if err != nil {
		return err
	}
	sig, err := priv.SignDigest(hash, crypto.ContextProposal)
	if err != nil {
		return err
	}
	b.ProposerSig = sig
	return nil
}

// VerifyProposer checks Validate and the proposer signature.
func (b Block) VerifyProposer(pub crypto.PublicKey) error {
	if err := b.Validate(); err != nil {
		return err
	}
	if pub.Algorithm() != crypto.AlgMLDSA65 {
		return fmt.Errorf("types: proposer key must be ML-DSA-65: %w", ErrSignature)
	}
	id, err := pub.ID()
	if err != nil {
		return err
	}
	if id != b.Header.ProposerID {
		return fmt.Errorf("types: proposer id does not match key: %w", ErrSignature)
	}
	hash, err := b.Header.Hash()
	if err != nil {
		return err
	}
	if err := crypto.VerifyDigest(pub, hash, b.ProposerSig, crypto.ContextProposal); err != nil {
		return fmt.Errorf("types: proposer signature: %w", ErrSignature)
	}
	return nil
}

// MarshalBinary encodes a block whose proposer signature has the right length.
func (b Block) MarshalBinary() ([]byte, error) {
	if err := b.Header.checkFields(); err != nil {
		return nil, err
	}
	if len(b.ProposerSig) != crypto.MLDSASignatureSize() {
		return nil, fmt.Errorf("types: proposer signature length: %w", ErrInvalid)
	}
	if len(b.Events) > MaxEventsPerBlock {
		return nil, fmt.Errorf("types: too many events: %w", ErrInvalid)
	}
	if len(b.Gov) > MaxGovPerBlock {
		return nil, fmt.Errorf("types: too many governance transactions: %w", ErrInvalid)
	}
	e := codec.NewEncoder()
	e.Header(TypeBlock, BlockVersion)
	if err := encodeHeader(e, b.Header); err != nil {
		return nil, err
	}
	e.Length(len(b.Events))
	for _, ev := range b.Events {
		raw, err := ev.MarshalBinary()
		if err != nil {
			return nil, err
		}
		// The event encoding already contains its own header. Write it
		// as raw bytes so it is not length-prefixed a second time.
		e.Fixed(raw)
	}
	e.Length(len(b.Gov))
	for _, tx := range b.Gov {
		raw, err := tx.MarshalBinary()
		if err != nil {
			return nil, err
		}
		e.Fixed(raw)
	}
	e.Fixed(b.ProposerSig)
	return e.Bytes(), nil
}

// UnmarshalBlock decodes a block. Call Validate before trusting the root.
func UnmarshalBlock(b []byte) (Block, error) {
	d := codec.NewDecoder(b)
	blk, err := decodeBlock(d)
	if err != nil {
		return Block{}, err
	}
	if err := d.Finish(); err != nil {
		return Block{}, err
	}
	return blk, nil
}

func decodeBlock(d *codec.Decoder) (Block, error) {
	if err := d.ExpectHeader(TypeBlock, BlockVersion); err != nil {
		return Block{}, err
	}
	h, err := decodeHeader(d)
	if err != nil {
		return Block{}, err
	}
	n, err := d.Length(MaxEventsPerBlock)
	if err != nil {
		return Block{}, err
	}
	events := make([]Event, n)
	for i := range events {
		events[i], err = decodeEvent(d)
		if err != nil {
			return Block{}, err
		}
	}
	ng, err := d.Length(MaxGovPerBlock)
	if err != nil {
		return Block{}, err
	}
	gov := make([]GovTx, ng)
	for i := range gov {
		gov[i], err = decodeGov(d)
		if err != nil {
			return Block{}, err
		}
	}
	sig, err := d.Fixed(crypto.MLDSASignatureSize())
	if err != nil {
		return Block{}, err
	}
	return Block{Header: h, Events: events, Gov: gov, ProposerSig: sig}, nil
}
