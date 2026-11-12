package node

import (
	"bytes"

	"github.com/silvergreyhound/silver-grey-ledger/internal/consensus"
	"github.com/silvergreyhound/silver-grey-ledger/internal/p2p"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

func frameKind(kind byte, payload []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := p2p.WriteFrame(&buf, kind, payload); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeConsensus(kind byte, payload []byte) (consensus.Input, error) {
	switch kind {
	case p2p.KindProposal:
		p, err := types.UnmarshalProposal(payload)
		if err != nil {
			return consensus.Input{}, err
		}
		return consensus.Input{Proposal: &p}, nil
	case p2p.KindVote:
		v, err := types.UnmarshalVote(payload)
		if err != nil {
			return consensus.Input{}, err
		}
		return consensus.Input{Vote: &v}, nil
	case p2p.KindTimeout:
		tm, err := types.UnmarshalTimeout(payload)
		if err != nil {
			return consensus.Input{}, err
		}
		return consensus.Input{TimeoutMsg: &tm}, nil
	case p2p.KindTC:
		tc, err := types.UnmarshalTC(payload)
		if err != nil {
			return consensus.Input{}, err
		}
		return consensus.Input{TC: &tc}, nil
	case p2p.KindEvidence:
		ev, err := types.UnmarshalEquivocation(payload)
		if err != nil {
			return consensus.Input{}, err
		}
		return consensus.Input{Evidence: &ev}, nil
	default:
		return consensus.Input{}, p2p.ErrFrame
	}
}

func encodeOutbound(m consensus.Outbound) ([]byte, error) {
	switch {
	case m.Proposal != nil:
		raw, err := m.Proposal.MarshalBinary()
		if err != nil {
			return nil, err
		}
		return frameKind(p2p.KindProposal, raw)
	case m.Vote != nil:
		raw, err := m.Vote.MarshalBinary()
		if err != nil {
			return nil, err
		}
		return frameKind(p2p.KindVote, raw)
	case m.Timeout != nil:
		raw, err := m.Timeout.MarshalBinary()
		if err != nil {
			return nil, err
		}
		return frameKind(p2p.KindTimeout, raw)
	case m.TC != nil:
		raw, err := m.TC.MarshalBinary()
		if err != nil {
			return nil, err
		}
		return frameKind(p2p.KindTC, raw)
	case m.Evidence != nil:
		raw, err := m.Evidence.MarshalBinary()
		if err != nil {
			return nil, err
		}
		return frameKind(p2p.KindEvidence, raw)
	default:
		return nil, p2p.ErrFrame
	}
}
