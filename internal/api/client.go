package api

import (
	"context"
	"encoding/hex"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/silvergreyhound/silver-grey-ledger/internal/api/pb"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/p2p"
	"github.com/silvergreyhound/silver-grey-ledger/internal/state"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

// Client calls one node's API over mTLS. The key is the caller's
// identity. pubs is the validator set the server certificate must match.
type Client struct {
	conn *grpc.ClientConn
	rpc  pb.LedgerClient
}

// Dial starts a lazy connection. The handshake runs on the first call.
func Dial(addr string, key crypto.PrivateKey, pubs []crypto.PublicKey) (*Client, error) {
	cert, err := p2p.Certificate(key)
	if err != nil {
		return nil, err
	}
	cfg := p2p.APIClientConfig(cert, pubs)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn, rpc: pb.NewLedgerClient(conn)}, nil
}

// Close releases the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Session is a client that learned the validator set from the chain.
// Voters(h) is the set that signed the committed block at height h.
type Session struct {
	*Client
	mu     sync.Mutex
	peer   crypto.PublicKey
	voters [][]crypto.PublicKey
}

// DialChain connects to addr and accepts the server only when its
// certificate is in the validator set committed by genesis. The set is
// recomputed from certified headers and state witnesses, so a rotation
// does not require a new local file.
func DialChain(ctx context.Context, addr string, key crypto.PrivateKey, g types.Genesis, genesis types.Block, genesisQC types.QC) (*Session, error) {
	cert, err := p2p.Certificate(key)
	if err != nil {
		return nil, err
	}
	s := &Session{}
	cfg := p2p.APIClientObserve(cert, func(peer crypto.PublicKey) {
		s.mu.Lock()
		s.peer = peer
		s.mu.Unlock()
	})
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(credentials.NewTLS(cfg)),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(MaxSend)),
	)
	if err != nil {
		return nil, err
	}
	s.Client = &Client{conn: conn, rpc: pb.NewLedgerClient(conn)}
	res, err := s.rpc.Membership(ctx, &pb.MembershipRequest{})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if len(res.GetHeaders()) != len(res.GetWitnesses()) || len(res.GetHeaders()) == 0 {
		_ = conn.Close()
		return nil, ErrRejected
	}
	headers := make([]types.BlockHeader, len(res.GetHeaders()))
	for i, raw := range res.GetHeaders() {
		headers[i], err = types.UnmarshalBlockHeader(raw)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	var commit types.QC
	if len(headers) > 1 {
		commit, err = types.UnmarshalQC(res.GetCommitQc())
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	s.mu.Lock()
	peer := s.peer
	s.mu.Unlock()
	view, err := state.Authenticate(g, genesis, genesisQC, headers, res.GetWitnesses(), commit, peer)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	s.voters = view.Voters
	return s, nil
}

// Voters is the validator set that signed the block at height.
func (s *Session) Voters(height uint64) ([]crypto.PublicKey, bool) {
	if height >= uint64(len(s.voters)) {
		return nil, false
	}
	return s.voters[height], true
}

// Status returns the node's commit point.
func (c *Client) Status(ctx context.Context) (Status, error) {
	res, err := c.rpc.Status(ctx, &pb.StatusRequest{})
	if err != nil {
		return Status{}, err
	}
	if len(res.GetChain()) != crypto.DigestSize || len(res.GetCommitHash()) != crypto.DigestSize {
		return Status{}, ErrRejected
	}
	var st Status
	copy(st.Chain[:], res.GetChain())
	copy(st.Hash[:], res.GetCommitHash())
	st.Height = res.GetHeight()
	st.View = res.GetView()
	return st, nil
}

// Submit sends a signed event. The client certificate must be pub.
func (c *Client) Submit(ctx context.Context, pub crypto.PublicKey, ev types.Event) ([crypto.DigestSize]byte, string, error) {
	kb, err := types.MarshalPublicKey(pub)
	if err != nil {
		return [crypto.DigestSize]byte{}, "", err
	}
	eb, err := ev.MarshalBinary()
	if err != nil {
		return [crypto.DigestSize]byte{}, "", err
	}
	res, err := c.rpc.SubmitEvent(ctx, &pb.SubmitEventRequest{Writer: kb, Event: eb})
	if err != nil {
		return [crypto.DigestSize]byte{}, "", err
	}
	if len(res.GetEventId()) != crypto.DigestSize {
		return [crypto.DigestSize]byte{}, "", ErrRejected
	}
	var id [crypto.DigestSize]byte
	copy(id[:], res.GetEventId())
	return id, res.GetStatus(), nil
}

// Proof fetches the inclusion proof of a committed event.
func (c *Client) Proof(ctx context.Context, id [crypto.DigestSize]byte) (types.InclusionProof, error) {
	res, err := c.rpc.GetProof(ctx, &pb.GetProofRequest{EventId: hex.EncodeToString(id[:])})
	if err != nil {
		return types.InclusionProof{}, err
	}
	return types.UnmarshalInclusionProof(res.GetProof())
}

// Event fetches a committed or pending event.
func (c *Client) Event(ctx context.Context, id [crypto.DigestSize]byte) (types.Event, uint64, string, error) {
	res, err := c.rpc.GetEvent(ctx, &pb.GetEventRequest{EventId: hex.EncodeToString(id[:])})
	if err != nil {
		return types.Event{}, 0, "", err
	}
	ev, err := types.UnmarshalEvent(res.GetEvent())
	if err != nil {
		return types.Event{}, 0, "", err
	}
	return ev, res.GetHeight(), res.GetFinality(), nil
}

// Verify asks the node for a committed document hash and returns the
// proof bytes so the caller can check them offline.
func (c *Client) Verify(ctx context.Context, sum [crypto.DigestSize]byte, writer crypto.PublicKey) (DocMatch, error) {
	kb, err := types.MarshalPublicKey(writer)
	if err != nil {
		return DocMatch{}, err
	}
	res, err := c.rpc.VerifyDocument(ctx, &pb.VerifyDocumentRequest{DocHash: sum[:], Writer: kb})
	if err != nil {
		return DocMatch{}, err
	}
	if !res.GetMatch() || len(res.GetEventId()) != crypto.DigestSize {
		return DocMatch{}, ErrNotFound
	}
	var id [crypto.DigestSize]byte
	copy(id[:], res.GetEventId())
	return DocMatch{
		Height:  res.GetHeight(),
		View:    res.GetView(),
		Claimed: res.GetClaimedTime(),
		EventID: id,
		Proof:   append([]byte(nil), res.GetProof()...),
	}, nil
}

// ProposeGov stores a governance transaction. When enough admin
// signatures are already present, the node submits it for inclusion.
func (c *Client) ProposeGov(ctx context.Context, raw []byte) ([crypto.DigestSize]byte, int, bool, error) {
	res, err := c.rpc.ProposeGovernance(ctx, &pb.ProposeGovernanceRequest{Tx: raw})
	if err != nil {
		return [crypto.DigestSize]byte{}, 0, false, err
	}
	if len(res.GetId()) != crypto.DigestSize {
		return [crypto.DigestSize]byte{}, 0, false, ErrRejected
	}
	var id [crypto.DigestSize]byte
	copy(id[:], res.GetId())
	return id, int(res.GetSignatures()), res.GetSubmitted(), nil
}

// SignGov adds this client's signature to a stored proposal.
func (c *Client) SignGov(ctx context.Context, id [crypto.DigestSize]byte, sig []byte) (int, bool, error) {
	res, err := c.rpc.SignGovernance(ctx, &pb.SignGovernanceRequest{
		Id:        hex.EncodeToString(id[:]),
		Signature: sig,
	})
	if err != nil {
		return 0, false, err
	}
	return int(res.GetSignatures()), res.GetSubmitted(), nil
}

// ListGov returns proposal ids this client is allowed to see.
func (c *Client) ListGov(ctx context.Context) ([][crypto.DigestSize]byte, error) {
	res, err := c.rpc.ListGovernance(ctx, &pb.ListGovernanceRequest{})
	if err != nil {
		return nil, err
	}
	out := make([][crypto.DigestSize]byte, 0, len(res.GetIds()))
	for _, s := range res.GetIds() {
		raw, err := hex.DecodeString(s)
		if err != nil || len(raw) != crypto.DigestSize {
			return nil, ErrRejected
		}
		var id [crypto.DigestSize]byte
		copy(id[:], raw)
		out = append(out, id)
	}
	return out, nil
}
