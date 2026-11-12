package sim

import (
	"math"

	"github.com/silvergreyhound/silver-grey-ledger/internal/consensus"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

func cloneOutbound(m consensus.Outbound) consensus.Outbound {
	switch {
	case m.Proposal != nil:
		p := cloneProposal(*m.Proposal)
		m.Proposal = &p
	case m.Vote != nil:
		v := *m.Vote
		v.Signature = append([]byte(nil), v.Signature...)
		m.Vote = &v
	case m.Timeout != nil:
		t := *m.Timeout
		t.Signature = append([]byte(nil), t.Signature...)
		m.Timeout = &t
	case m.TC != nil:
		tc := *m.TC
		tc.Timeouts = append([]types.Timeout(nil), tc.Timeouts...)
		for i := range tc.Timeouts {
			tc.Timeouts[i].Signature = append([]byte(nil), tc.Timeouts[i].Signature...)
		}
		m.TC = &tc
	case m.Evidence != nil:
		e := *m.Evidence
		e.First = append([]byte(nil), e.First...)
		e.Second = append([]byte(nil), e.Second...)
		m.Evidence = &e
	}
	return m
}

func cloneProposal(p types.Proposal) types.Proposal {
	p.Block.ProposerSig = append([]byte(nil), p.Block.ProposerSig...)
	p.Block.Events = append([]types.Event(nil), p.Block.Events...)
	p.Block.Gov = append([]types.GovTx(nil), p.Block.Gov...)
	p.TC.Timeouts = append([]types.Timeout(nil), p.TC.Timeouts...)
	for i := range p.TC.Timeouts {
		p.TC.Timeouts[i].Signature = append([]byte(nil), p.TC.Timeouts[i].Signature...)
	}
	return p
}

func corrupt(m consensus.Outbound) consensus.Outbound {
	switch {
	case m.Proposal != nil && len(m.Proposal.Block.ProposerSig) > 0:
		m.Proposal.Block.ProposerSig[len(m.Proposal.Block.ProposerSig)-1] ^= 1
	case m.Vote != nil && len(m.Vote.Signature) > 0:
		m.Vote.Signature[len(m.Vote.Signature)-1] ^= 1
	case m.Timeout != nil && len(m.Timeout.Signature) > 0:
		m.Timeout.Signature[len(m.Timeout.Signature)-1] ^= 1
	case m.TC != nil && len(m.TC.Timeouts) > 0 && len(m.TC.Timeouts[0].Signature) > 0:
		sig := m.TC.Timeouts[0].Signature
		sig[len(sig)-1] ^= 1
	case m.Evidence != nil && len(m.Evidence.First) > 0:
		m.Evidence.First[len(m.Evidence.First)-1] ^= 1
	}
	return m
}

func equivocateProposal(p types.Proposal, key crypto.PrivateKey) (types.Proposal, error) {
	q := cloneProposal(p)
	if q.Block.Header.ProposerTime < math.MaxInt64 {
		q.Block.Header.ProposerTime++
	} else {
		q.Block.Header.ProposerTime--
	}
	if err := q.Block.Sign(key); err != nil {
		return types.Proposal{}, err
	}
	return q, nil
}
