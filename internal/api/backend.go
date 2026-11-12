package api

import (
	"context"
	"errors"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

const (
	// MaxConns is the most simultaneous API connections.
	MaxConns = 32
	// MaxRecv is the largest request a client may send.
	MaxRecv = 1 << 20
	// MaxSend is the largest block this server will return.
	MaxSend = 8 << 20
	// SubmitRate is the sustained write limit per remote address, per second.
	SubmitRate = 20
	// SubmitBurst is how many writes may arrive at once.
	SubmitBurst = 40
	// ReadRate is the sustained read limit per remote address, per second.
	ReadRate = 100
	// ReadBurst is how many reads may arrive at once.
	ReadBurst = 200
)

var (
	// ErrNotFound means the event, block, or document is not committed.
	ErrNotFound = errors.New("api: not found")
	// ErrRejected means the request failed a cheap check: signature,
	// nonce, certificate, or a full mempool.
	ErrRejected = errors.New("api: rejected")
	// ErrDenied means the caller's ledger role does not allow the request.
	ErrDenied = errors.New("api: denied")
	// ErrUnavailable means the node is stopping.
	ErrUnavailable = errors.New("api: unavailable")
)

// Status is a node's commit point.
type Status struct {
	Chain  [crypto.DigestSize]byte
	Height uint64
	Hash   [crypto.DigestSize]byte
	View   uint64
}

// Notice is one committed event.
type Notice struct {
	ID     [crypto.DigestSize]byte
	Height uint64
}

// DocMatch is a committed event that carries a document hash.
type DocMatch struct {
	Height  uint64
	View    uint64
	Claimed int64
	EventID [crypto.DigestSize]byte
	Proof   []byte
}

// Backend is the node behind the API. Implementations must be safe to
// call from the server's goroutines; the node serialises them onto the
// replica loop.
type Backend interface {
	Submit(ctx context.Context, pub crypto.PublicKey, ev types.Event) ([crypto.DigestSize]byte, string, error)
	Event(ctx context.Context, caller crypto.PublicKey, id [crypto.DigestSize]byte) (types.Event, uint64, string, error)
	Proof(ctx context.Context, caller crypto.PublicKey, id [crypto.DigestSize]byte) (types.InclusionProof, error)
	History(ctx context.Context, caller crypto.PublicKey, subject []byte) ([][crypto.DigestSize]byte, error)
	LookupDoc(ctx context.Context, caller crypto.PublicKey, sum [crypto.DigestSize]byte, writer crypto.PublicKey) (DocMatch, error)
	Block(ctx context.Context, caller crypto.PublicKey, height uint64) (types.Block, error)
	Latest(ctx context.Context, caller crypto.PublicKey) (types.Block, error)
	Members(ctx context.Context, caller crypto.PublicKey) ([]byte, error)
	Membership(ctx context.Context, caller crypto.PublicKey) (commitQC []byte, headers [][]byte, witnesses [][]byte, err error)
	Status(ctx context.Context, caller crypto.PublicKey) (Status, error)
	Subscribe() (<-chan Notice, func(), error)
	Visible(ctx context.Context, caller crypto.PublicKey, id [crypto.DigestSize]byte) (string, bool, error)
	ProposeGov(ctx context.Context, caller crypto.PublicKey, raw []byte) ([crypto.DigestSize]byte, int, bool, error)
	SignGov(ctx context.Context, caller crypto.PublicKey, id [crypto.DigestSize]byte, sig []byte) (int, bool, error)
	ListGov(ctx context.Context, caller crypto.PublicKey) ([][crypto.DigestSize]byte, error)
}
