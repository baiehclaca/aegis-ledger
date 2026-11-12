package consensus

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/merkle"
	"github.com/silvergreyhound/silver-grey-ledger/internal/state"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

// Extra is an identity added beside the validator seats.
type Extra struct {
	Key        crypto.PrivateKey
	Org        string
	Roles      uint16
	EventTypes []uint16
}

// GenesisWith is the input to BuildGenesisWith. A zero EpochDelay
// becomes 2. A zero Threshold becomes ceil(2/3 of the founders).
// An empty Founders list generates two SLH-DSA founding keys.
// One founding organisation is rejected.
type GenesisWith struct {
	Created    int64
	EpochDelay uint64
	Threshold  uint16
	Validators []crypto.PrivateKey
	Founders   []crypto.PrivateKey
	Extra      []Extra
}

// BuildGenesis signs a two-founder genesis, the height-0 block, and a
// view-0 quorum certificate. Each validator receives every role,
// including writer, so existing tests can submit. The threshold is
// ceil(2/3) of the founders, so one organisation cannot pass alone.
func BuildGenesis(created int64, keys []crypto.PrivateKey) (types.Genesis, types.Block, types.QC, error) {
	return BuildGenesisWith(GenesisWith{Created: created, Validators: keys})
}

// BuildGenesisWith signs the genesis described by in.
func BuildGenesisWith(in GenesisWith) (types.Genesis, types.Block, types.QC, error) {
	if _, err := types.Quorum(len(in.Validators)); err != nil {
		return types.Genesis{}, types.Block{}, types.QC{}, err
	}
	founders := in.Founders
	if len(founders) == 0 {
		founders = make([]crypto.PrivateKey, types.MinFounders)
		for i := range founders {
			key, err := crypto.GenerateSLHDSA(nil)
			if err != nil {
				return types.Genesis{}, types.Block{}, types.QC{}, err
			}
			founders[i] = key
		}
	}
	delay := in.EpochDelay
	if delay == 0 {
		delay = 2
	}
	threshold := in.Threshold
	if threshold == 0 {
		got, err := types.DefaultThreshold(len(founders))
		if err != nil {
			return types.Genesis{}, types.Block{}, types.QC{}, err
		}
		threshold = got
	}
	g, err := assembleGenesis(in.Created, delay, threshold, founders, in.Validators, in.Extra)
	if err != nil {
		return types.Genesis{}, types.Block{}, types.QC{}, err
	}
	if err := g.Sign(founders); err != nil {
		return types.Genesis{}, types.Block{}, types.QC{}, err
	}
	chain, err := g.ChainID()
	if err != nil {
		return types.Genesis{}, types.Block{}, types.QC{}, err
	}
	block, err := genesisBlock(g, chain, in.Validators[0])
	if err != nil {
		return types.Genesis{}, types.Block{}, types.QC{}, err
	}
	hash, err := block.Header.Hash()
	if err != nil {
		return types.Genesis{}, types.Block{}, types.QC{}, err
	}
	signers := make([]int, len(in.Validators))
	for i := range signers {
		signers[i] = i
	}
	qc, err := types.AssembleQC(chain, 0, hash, in.Validators, signers)
	if err != nil {
		return types.Genesis{}, types.Block{}, types.QC{}, err
	}
	return g, block, qc, nil
}

func assembleGenesis(created int64, delay uint64, threshold uint16, founders, validators []crypto.PrivateKey, extra []Extra) (types.Genesis, error) {
	fs := make([]types.Founder, len(founders))
	for i, key := range founders {
		if key.Algorithm() != crypto.AlgSLHDSAShake128s {
			return types.Genesis{}, fmt.Errorf("consensus: founding key: %w", ErrState)
		}
		pub, err := key.Public()
		if err != nil {
			return types.Genesis{}, err
		}
		org := "founding"
		if len(founders) > 1 {
			org = fmt.Sprintf("founding-%d", i)
		}
		fs[i] = types.Founder{Org: org, Key: pub}
	}
	seatOrg := fs[0].Org
	seats := make([]types.Seat, len(validators))
	grants := make([]types.Grant, 0, len(validators)+len(extra))
	allTypes := []uint16{types.EventShipmentDispatched, types.EventClearanceGranted, types.EventAccessLogin}
	for i, key := range validators {
		if key.Algorithm() != crypto.AlgMLDSA65 {
			return types.Genesis{}, fmt.Errorf("consensus: validator key: %w", ErrState)
		}
		pub, err := key.Public()
		if err != nil {
			return types.Genesis{}, err
		}
		org := seatOrg
		if len(founders) > 1 {
			org = fs[i%len(fs)].Org
		}
		seats[i] = types.Seat{Key: pub, Org: org, Address: "local"}
		grants = append(grants, types.Grant{
			Key:        pub,
			Org:        org,
			Roles:      types.RoleKnown,
			EventTypes: append([]uint16(nil), allTypes...),
		})
	}
	for _, ex := range extra {
		pub, err := ex.Key.Public()
		if err != nil {
			return types.Genesis{}, err
		}
		if pub.Algorithm() != crypto.AlgMLDSA65 {
			return types.Genesis{}, fmt.Errorf("consensus: extra key: %w", ErrState)
		}
		org := ex.Org
		if org == "" {
			org = seatOrg
		}
		roles := ex.Roles
		if roles == 0 {
			roles = types.RoleWriter | types.RoleReader
		}
		ts := ex.EventTypes
		if roles&types.RoleWriter != 0 && len(ts) == 0 {
			ts = allTypes
		}
		grants = append(grants, types.Grant{
			Key:        pub,
			Org:        org,
			Roles:      roles,
			EventTypes: append([]uint16(nil), ts...),
		})
	}
	slices.SortFunc(grants, func(a, b types.Grant) int {
		aid, _ := a.Key.ID()
		bid, _ := b.Key.ID()
		return bytes.Compare(aid[:], bid[:])
	})
	return types.Genesis{
		Created:    created,
		EpochDelay: delay,
		Threshold:  threshold,
		Founders:   fs,
		Seats:      seats,
		Grants:     grants,
		Registry: []types.RegEntry{
			{Type: types.EventShipmentDispatched, Name: "shipment"},
			{Type: types.EventClearanceGranted, Name: "clearance"},
			{Type: types.EventAccessLogin, Name: "access"},
		},
	}, nil
}

func genesisBlock(g types.Genesis, chain [crypto.DigestSize]byte, proposer crypto.PrivateKey) (types.Block, error) {
	led, err := state.FromGenesis(g)
	if err != nil {
		return types.Block{}, err
	}
	root, err := merkle.Root(nil)
	if err != nil {
		return types.Block{}, err
	}
	id, err := g.Validators().Keys[0].ID()
	if err != nil {
		return types.Block{}, err
	}
	block := types.Block{Header: types.BlockHeader{
		ChainID:      chain,
		Height:       0,
		View:         0,
		EventsRoot:   root,
		StateRoot:    led.Root(),
		ProposerID:   id,
		ProposerTime: g.Created,
	}}
	if err := block.Sign(proposer); err != nil {
		return types.Block{}, err
	}
	return block, nil
}
