package state

import (
	"fmt"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

// ChainView is the validator set at every committed height, derived from
// genesis and from quorum-certified state roots. Voters[h] signed block h.
type ChainView struct {
	Tip    *Ledger
	Voters [][]crypto.PublicKey
}

// Authenticate checks that headers and witnesses are the chain of g.
// commitQC certifies the last header. It is ignored when the chain is
// still the genesis block; genesisQC is the view-0 certificate then.
// peer must be a validator in the tip set.
func Authenticate(g types.Genesis, genesis types.Block, genesisQC types.QC, headers []types.BlockHeader, witnesses [][]byte, commitQC types.QC, peer crypto.PublicKey) (ChainView, error) {
	var zero ChainView
	if err := g.Verify(); err != nil {
		return zero, err
	}
	if len(headers) == 0 || len(headers) != len(witnesses) || len(headers) > 4096 {
		return zero, fmt.Errorf("%w: membership history", ErrTransition)
	}
	chain, err := g.ChainID()
	if err != nil {
		return zero, err
	}
	led, err := FromGenesis(g)
	if err != nil {
		return zero, err
	}
	if led.Root() != genesis.Header.StateRoot || genesis.Header.ChainID != chain || genesis.Header.Height != 0 {
		return zero, fmt.Errorf("%w: genesis block", ErrTransition)
	}
	genesisHash, err := genesis.Header.Hash()
	if err != nil {
		return zero, err
	}
	if err := genesisQC.Verify(chain, g.Validators().Keys); err != nil || genesisQC.BlockHash != genesisHash {
		return zero, fmt.Errorf("%w: genesis certificate", ErrTransition)
	}
	headHash, err := headers[0].Hash()
	if err != nil || headHash != genesisHash || headers[0].StateRoot != led.Root() {
		return zero, fmt.Errorf("%w: genesis header", ErrTransition)
	}
	opened, err := RestoreWitness(witnesses[0])
	if err != nil || opened.Root() != headers[0].StateRoot {
		return zero, fmt.Errorf("%w: genesis witness", ErrTransition)
	}
	voters := make([][]crypto.PublicKey, len(headers))
	keys, err := led.ValidatorKeys()
	if err != nil {
		return zero, err
	}
	voters[0] = keys
	prevHash := genesisHash
	for h := 1; h < len(headers); h++ {
		hdr := headers[h]
		hash, err := hdr.Hash()
		if err != nil {
			return zero, err
		}
		if hdr.Height != uint64(h) || hdr.ChainID != chain || hdr.ParentHash != prevHash {
			return zero, fmt.Errorf("%w: header link", ErrTransition)
		}
		parentKeys, err := led.ValidatorKeys()
		if err != nil {
			return zero, err
		}
		if err := hdr.Justify.Verify(chain, parentKeys); err != nil || hdr.Justify.BlockHash != prevHash {
			return zero, fmt.Errorf("%w: justify", ErrTransition)
		}
		var qc types.QC
		if h == len(headers)-1 {
			qc = commitQC
		} else {
			qc = headers[h+1].Justify
		}
		signers, err := led.VotersForChild(hdr.Height)
		if err != nil {
			return zero, err
		}
		if err := qc.Verify(chain, signers); err != nil || qc.BlockHash != hash || qc.View != hdr.View {
			return zero, fmt.Errorf("%w: commit certificate", ErrTransition)
		}
		next, err := RestoreWitness(witnesses[h])
		if err != nil || next.Root() != hdr.StateRoot || next.chain != chain {
			return zero, fmt.Errorf("%w: state witness", ErrTransition)
		}
		seat, err := next.ValidatorKeys()
		if err != nil {
			return zero, err
		}
		voters[h] = seat
		led = next
		prevHash = hash
	}
	tip, err := led.ValidatorKeys()
	if err != nil {
		return zero, err
	}
	found := false
	for _, key := range tip {
		if key.Equal(peer) {
			found = true
			break
		}
	}
	if !found {
		return zero, fmt.Errorf("%w: server is not a current validator", ErrTransition)
	}
	return ChainView{Tip: led, Voters: voters}, nil
}
