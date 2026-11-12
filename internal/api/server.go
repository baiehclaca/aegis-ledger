package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/silvergreyhound/silver-grey-ledger/internal/api/pb"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/p2p"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
	"github.com/silvergreyhound/silver-grey-ledger/pkg/verify"
)

type certKey struct{}
type remoteKey struct{}

// Serve accepts mTLS connections until ctx is cancelled or ln closes.
// gRPC and JSON share the port. The JSON routes are the gateway of the
// same service.
func Serve(ctx context.Context, ln net.Listener, cfg *tls.Config, back Backend) error {
	srv := &ledgerServer{back: back, gate: newGate(), gateMu: sync.Mutex{}}
	grpcSrv := grpc.NewServer(
		grpc.MaxRecvMsgSize(MaxRecv),
		grpc.MaxSendMsgSize(MaxSend),
		grpc.MaxConcurrentStreams(8),
	)
	pb.RegisterLedgerServer(grpcSrv, srv)
	mux := http.NewServeMux()
	gw := runtime.NewServeMux()
	if err := pb.RegisterLedgerHandlerServer(ctx, gw, srv); err != nil {
		return err
	}
	mux.Handle("/", gw)
	httpSrv := &http.Server{
		Handler:           route(grpcSrv, mux),
		TLSConfig:         cfg,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
	capped := &capListener{Listener: ln, sem: make(chan struct{}, MaxConns)}
	tlsLn := tls.NewListener(capped, cfg)
	errCh := make(chan error, 1)
	go func() {
		err := httpSrv.Serve(tlsLn)
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			err = nil
		}
		errCh <- err
	}()
	select {
	case <-ctx.Done():
		shut, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shut)
		grpcSrv.GracefulStop()
		return nil
	case err := <-errCh:
		return err
	}
}

func route(grpcSrv *grpc.Server, gw http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), remoteKey{}, r.RemoteAddr)
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			ctx = context.WithValue(ctx, certKey{}, r.TLS.PeerCertificates[0])
		}
		r = r.WithContext(ctx)
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			grpcSrv.ServeHTTP(w, r)
			return
		}
		gw.ServeHTTP(w, r)
	})
}

type ledgerServer struct {
	pb.UnimplementedLedgerServer
	back   Backend
	gate   *gate
	gateMu sync.Mutex
}

func (s *ledgerServer) SubmitEvent(ctx context.Context, req *pb.SubmitEventRequest) (*pb.SubmitEventResponse, error) {
	if err := s.admit(ctx, true); err != nil {
		return nil, err
	}
	client, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	writer, err := types.UnmarshalPublicKey(req.GetWriter())
	if err != nil || !client.Equal(writer) {
		return nil, status.Error(codes.PermissionDenied, "client certificate is not the writer")
	}
	ev, err := types.UnmarshalEvent(req.GetEvent())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "event")
	}
	id, finality, err := s.back.Submit(ctx, writer, ev)
	if err != nil {
		return nil, mapErr(err)
	}
	return &pb.SubmitEventResponse{EventId: id[:], Status: finality}, nil
}

func (s *ledgerServer) GetEvent(ctx context.Context, req *pb.GetEventRequest) (*pb.GetEventResponse, error) {
	if err := s.admit(ctx, false); err != nil {
		return nil, err
	}
	id, err := parseHexID(req.GetEventId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "event id")
	}
	client, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	ev, height, finality, err := s.back.Event(ctx, client, id)
	if err != nil {
		return nil, mapErr(err)
	}
	raw, err := ev.MarshalBinary()
	if err != nil {
		return nil, mapErr(err)
	}
	return &pb.GetEventResponse{Event: raw, Height: height, Finality: finality}, nil
}

func (s *ledgerServer) GetProof(ctx context.Context, req *pb.GetProofRequest) (*pb.GetProofResponse, error) {
	if err := s.admit(ctx, false); err != nil {
		return nil, err
	}
	client, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	id, err := parseHexID(req.GetEventId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "event id")
	}
	proof, err := s.back.Proof(ctx, client, id)
	if err != nil {
		return nil, mapErr(err)
	}
	raw, err := proof.MarshalBinary()
	if err != nil {
		return nil, mapErr(err)
	}
	return &pb.GetProofResponse{Proof: raw}, nil
}

func (s *ledgerServer) SubjectHistory(ctx context.Context, req *pb.SubjectHistoryRequest) (*pb.SubjectHistoryResponse, error) {
	if err := s.admit(ctx, false); err != nil {
		return nil, err
	}
	client, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	subject, err := hex.DecodeString(req.GetSubjectHex())
	if err != nil || len(subject) == 0 || len(subject) > types.MaxSubjectID {
		return nil, status.Error(codes.InvalidArgument, "subject")
	}
	ids, err := s.back.History(ctx, client, subject)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = hex.EncodeToString(id[:])
	}
	return &pb.SubjectHistoryResponse{EventIds: out}, nil
}

func (s *ledgerServer) VerifyDocument(ctx context.Context, req *pb.VerifyDocumentRequest) (*pb.VerifyDocumentResponse, error) {
	if err := s.admit(ctx, false); err != nil {
		return nil, err
	}
	client, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if len(req.GetDocHash()) != crypto.DigestSize {
		return nil, status.Error(codes.InvalidArgument, "document hash")
	}
	var sum [crypto.DigestSize]byte
	copy(sum[:], req.GetDocHash())
	if len(req.GetProof()) > 0 {
		return s.verifyProof(req, sum)
	}
	writer, err := types.UnmarshalPublicKey(req.GetWriter())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "writer")
	}
	match, err := s.back.LookupDoc(ctx, client, sum, writer)
	if err != nil {
		return nil, mapErr(err)
	}
	return &pb.VerifyDocumentResponse{
		Match:       true,
		Height:      match.Height,
		View:        match.View,
		ClaimedTime: match.Claimed,
		EventId:     match.EventID[:],
		Proof:       match.Proof,
	}, nil
}

func (s *ledgerServer) verifyProof(req *pb.VerifyDocumentRequest, sum [crypto.DigestSize]byte) (*pb.VerifyDocumentResponse, error) {
	proof, err := types.UnmarshalInclusionProof(req.GetProof())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "proof")
	}
	set, err := types.UnmarshalValidatorSet(req.GetValidators())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "validators")
	}
	writer, err := types.UnmarshalPublicKey(req.GetWriter())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "writer")
	}
	res, err := verify.Inclusion(proof, set, writer)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "proof rejected")
	}
	if err := verify.CheckDocument(proof.Event, types.SHA3Doc(sum)); err != nil {
		return nil, status.Error(codes.InvalidArgument, "document hash")
	}
	raw, err := proof.MarshalBinary()
	if err != nil {
		return nil, mapErr(err)
	}
	return &pb.VerifyDocumentResponse{
		Match:       true,
		Height:      res.Height,
		View:        res.View,
		ClaimedTime: proof.Event.ClaimedTime,
		EventId:     res.EventID[:],
		Proof:       raw,
	}, nil
}

func (s *ledgerServer) GetBlock(ctx context.Context, req *pb.GetBlockRequest) (*pb.BlockResponse, error) {
	return s.block(ctx, false, req.GetHeight())
}

func (s *ledgerServer) LatestBlock(ctx context.Context, _ *pb.LatestBlockRequest) (*pb.BlockResponse, error) {
	return s.block(ctx, true, 0)
}

func (s *ledgerServer) block(ctx context.Context, latest bool, height uint64) (*pb.BlockResponse, error) {
	if err := s.admit(ctx, false); err != nil {
		return nil, err
	}
	client, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	var block types.Block
	if latest {
		block, err = s.back.Latest(ctx, client)
	} else {
		block, err = s.back.Block(ctx, client, height)
	}
	if err != nil {
		return nil, mapErr(err)
	}
	raw, err := block.MarshalBinary()
	if err != nil {
		return nil, mapErr(err)
	}
	return &pb.BlockResponse{Height: block.Header.Height, Block: raw}, nil
}

func (s *ledgerServer) Members(ctx context.Context, _ *pb.MembersRequest) (*pb.MembersResponse, error) {
	if err := s.admit(ctx, false); err != nil {
		return nil, err
	}
	client, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	raw, err := s.back.Members(ctx, client)
	if err != nil {
		return nil, mapErr(err)
	}
	return &pb.MembersResponse{ValidatorSet: raw}, nil
}

func (s *ledgerServer) Membership(ctx context.Context, _ *pb.MembershipRequest) (*pb.MembershipResponse, error) {
	if err := s.admit(ctx, false); err != nil {
		return nil, err
	}
	client, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	qc, headers, witnesses, err := s.back.Membership(ctx, client)
	if err != nil {
		return nil, mapErr(err)
	}
	return &pb.MembershipResponse{CommitQc: qc, Headers: headers, Witnesses: witnesses}, nil
}

func (s *ledgerServer) Status(ctx context.Context, _ *pb.StatusRequest) (*pb.StatusResponse, error) {
	if err := s.admit(ctx, false); err != nil {
		return nil, err
	}
	client, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	st, err := s.back.Status(ctx, client)
	if err != nil {
		return nil, mapErr(err)
	}
	return &pb.StatusResponse{Chain: st.Chain[:], Height: st.Height, CommitHash: st.Hash[:], View: st.View}, nil
}

func (s *ledgerServer) StreamEvents(_ *pb.StreamEventsRequest, stream grpc.ServerStreamingServer[pb.EventNotice]) error {
	ctx := stream.Context()
	if err := s.admit(ctx, false); err != nil {
		return err
	}
	client, err := caller(ctx)
	if err != nil {
		return err
	}
	ch, cancel, err := s.back.Subscribe()
	if err != nil {
		return mapErr(err)
	}
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return nil
		case note := <-ch:
			finality, ok, err := s.back.Visible(ctx, client, note.ID)
			if err != nil {
				return mapErr(err)
			}
			if !ok {
				continue
			}
			msg := &pb.EventNotice{EventId: note.ID[:], Height: note.Height, Finality: finality}
			if err := stream.Send(msg); err != nil {
				return err
			}
		}
	}
}

func (s *ledgerServer) ProposeGovernance(ctx context.Context, req *pb.ProposeGovernanceRequest) (*pb.ProposeGovernanceResponse, error) {
	if err := s.admit(ctx, true); err != nil {
		return nil, err
	}
	client, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	id, n, submitted, err := s.back.ProposeGov(ctx, client, req.GetTx())
	if err != nil {
		return nil, mapErr(err)
	}
	return &pb.ProposeGovernanceResponse{Id: id[:], Signatures: uint32(n), Submitted: submitted}, nil
}

func (s *ledgerServer) SignGovernance(ctx context.Context, req *pb.SignGovernanceRequest) (*pb.SignGovernanceResponse, error) {
	if err := s.admit(ctx, true); err != nil {
		return nil, err
	}
	client, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	id, err := parseHexID(req.GetId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "proposal id")
	}
	n, submitted, err := s.back.SignGov(ctx, client, id, req.GetSignature())
	if err != nil {
		return nil, mapErr(err)
	}
	return &pb.SignGovernanceResponse{Signatures: uint32(n), Submitted: submitted}, nil
}

func (s *ledgerServer) ListGovernance(ctx context.Context, _ *pb.ListGovernanceRequest) (*pb.ListGovernanceResponse, error) {
	if err := s.admit(ctx, false); err != nil {
		return nil, err
	}
	client, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	ids, err := s.back.ListGov(ctx, client)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = hex.EncodeToString(id[:])
	}
	return &pb.ListGovernanceResponse{Ids: out}, nil
}

func (s *ledgerServer) admit(ctx context.Context, submit bool) error {
	s.gateMu.Lock()
	ok := s.gate.allow(time.Now(), remoteOf(ctx), submit)
	s.gateMu.Unlock()
	if !ok {
		return status.Error(codes.ResourceExhausted, "rate")
	}
	return nil
}

func caller(ctx context.Context) (crypto.PublicKey, error) {
	cert := certOf(ctx)
	if cert == nil {
		return crypto.PublicKey{}, status.Error(codes.Unauthenticated, "client certificate")
	}
	key, err := p2p.PublicFromCert(cert)
	if err != nil {
		return crypto.PublicKey{}, status.Error(codes.Unauthenticated, "client certificate")
	}
	return key, nil
}

func certOf(ctx context.Context) *x509.Certificate {
	if c, ok := ctx.Value(certKey{}).(*x509.Certificate); ok {
		return c
	}
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.PeerCertificates) == 0 {
		return nil
	}
	return info.State.PeerCertificates[0]
}

func remoteOf(ctx context.Context) string {
	if s, ok := ctx.Value(remoteKey{}).(string); ok {
		return s
	}
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}
	return p.Addr.String()
}

func parseHexID(s string) ([crypto.DigestSize]byte, error) {
	var id [crypto.DigestSize]byte
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != len(id) {
		return id, errors.New("api: event id")
	}
	copy(id[:], raw)
	return id, nil
}

func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrNotFound):
		return status.Error(codes.NotFound, "not found")
	case errors.Is(err, ErrRejected):
		return status.Error(codes.InvalidArgument, "rejected")
	case errors.Is(err, ErrDenied):
		return status.Error(codes.PermissionDenied, "denied")
	case errors.Is(err, ErrUnavailable), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.Unavailable, "unavailable")
	default:
		return status.Error(codes.Internal, "internal")
	}
}

type capListener struct {
	net.Listener
	sem chan struct{}
}

func (l *capListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.sem <- struct{}{}:
			return &releaseConn{Conn: conn, sem: l.sem}, nil
		default:
			_ = conn.Close()
			time.Sleep(5 * time.Millisecond)
		}
	}
}

type releaseConn struct {
	net.Conn
	sem  chan struct{}
	once sync.Once
}

func (c *releaseConn) Close() error {
	c.once.Do(func() { <-c.sem })
	return c.Conn.Close()
}
