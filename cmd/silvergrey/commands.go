package main

import (
	"context"
	hexenc "encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/silvergreyhound/silver-grey-ledger/internal/api"
	"github.com/silvergreyhound/silver-grey-ledger/internal/consensus"
	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/keyfile"
	"github.com/silvergreyhound/silver-grey-ledger/internal/node"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
	"github.com/silvergreyhound/silver-grey-ledger/pkg/verify"
)

const testKeyWarning = "test-network key file; forbidden in production\n"

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	alg := fs.String("alg", "", "")
	out := fs.String("out", "", "")
	pub := fs.String("pub", "", "")
	pass := fs.String("passphrase-file", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return usageError{msg: usageText()}
	}
	if *out == "" || *pub == "" || *pass == "" {
		return usageError{msg: usageText()}
	}
	phrase, err := readPassphrase(*pass)
	if err != nil {
		return err
	}
	var key crypto.PrivateKey
	switch *alg {
	case "ml-dsa-65":
		key, err = crypto.GenerateMLDSA65()
	case "slh-dsa-shake-128s":
		key, err = crypto.GenerateSLHDSA(nil)
	default:
		return usageError{msg: usageText()}
	}
	if err != nil {
		return err
	}
	if err := keyfile.Write(*out, key, phrase); err != nil {
		return err
	}
	pk, err := key.Public()
	if err != nil {
		return err
	}
	raw, err := types.MarshalPublicKey(pk)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*pub, raw, 0o644); err != nil {
		return err
	}
	_, err = io.WriteString(os.Stderr, "silvergrey: "+testKeyWarning)
	return err
}

func cmdNode(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return usageError{msg: usageText()}
	}
	switch args[0] {
	case "genesis":
		return cmdGenesis(args[1:], stdout)
	case "init":
		return cmdInit(args[1:])
	case "start":
		return cmdStart(args[1:], stdout)
	default:
		return usageError{msg: usageText()}
	}
}

func cmdGenesis(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("genesis", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	out := fs.String("out", "", "")
	vals := fs.String("validators-out", "", "")
	keys := fs.String("keys", "", "")
	founders := fs.String("founders", "", "")
	writers := fs.String("writers", "", "")
	pass := fs.String("passphrase-file", "", "")
	created := fs.Int64("time", time.Now().Unix(), "")
	delay := fs.Uint64("epoch-delay", 2, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return usageError{msg: usageText()}
	}
	if *out == "" || *vals == "" || *keys == "" || *founders == "" || *pass == "" {
		return usageError{msg: usageText()}
	}
	phrase, err := readPassphrase(*pass)
	if err != nil {
		return err
	}
	founderKeys, err := openKeys(splitComma(*founders), phrase, crypto.AlgSLHDSAShake128s)
	if err != nil {
		return err
	}
	if len(founderKeys) < types.MinFounders {
		return fmt.Errorf("at least two founding organisations are required")
	}
	privs, err := openKeys(splitComma(*keys), phrase, crypto.AlgMLDSA65)
	if err != nil {
		return err
	}
	var extra []consensus.Extra
	if *writers != "" {
		wkeys, err := openKeys(splitComma(*writers), phrase, crypto.AlgMLDSA65)
		if err != nil {
			return err
		}
		for _, key := range wkeys {
			extra = append(extra, consensus.Extra{Key: key, Roles: types.RoleWriter | types.RoleReader})
		}
	}
	g, block, qc, err := consensus.BuildGenesisWith(consensus.GenesisWith{
		Created:    *created,
		EpochDelay: *delay,
		Founders:   founderKeys,
		Validators: privs,
		Extra:      extra,
	})
	if err != nil {
		return err
	}
	if err := node.WriteGenesis(*out, g, block, qc); err != nil {
		return err
	}
	raw, err := g.Validators().MarshalBinary()
	if err != nil {
		return err
	}
	if err := os.WriteFile(*vals, raw, 0o644); err != nil {
		return err
	}
	chain, err := g.ChainID()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "chain %x\nvalidators %d\n", chain[:], len(privs))
	return err
}

func openKeys(paths []string, phrase string, alg crypto.Algorithm) ([]crypto.PrivateKey, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("no key files")
	}
	out := make([]crypto.PrivateKey, len(paths))
	for i, path := range paths {
		key, err := keyfile.Open(path, phrase)
		if err != nil {
			return nil, err
		}
		if key.Algorithm() != alg {
			return nil, fmt.Errorf("key algorithm")
		}
		out[i] = key
	}
	return out, nil
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", "", "")
	index := fs.Int("index", -1, "")
	listen := fs.String("listen", "", "")
	client := fs.String("client", "", "")
	peers := fs.String("peers", "", "")
	genesis := fs.String("genesis", "", "")
	keyfilePath := fs.String("keyfile", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return usageError{msg: usageText()}
	}
	cfg := node.Config{
		Dir:         *dir,
		Listen:      *listen,
		Client:      *client,
		Peers:       splitComma(*peers),
		Index:       *index,
		GenesisPath: *genesis,
		KeyPath:     *keyfilePath,
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	return cfg.WriteFile(filepath.Join(*dir, "node.conf"))
}

func cmdStart(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", "", "")
	pass := fs.String("passphrase-file", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return usageError{msg: usageText()}
	}
	if *dir == "" || *pass == "" {
		return usageError{msg: usageText()}
	}
	body, err := os.ReadFile(filepath.Join(*dir, "node.conf"))
	if err != nil {
		return err
	}
	cfg, err := node.ParseConfig(string(body))
	if err != nil {
		return err
	}
	cfg.Passphrase, err = readPassphrase(*pass)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(os.Stderr, "silvergrey: "+testKeyWarning); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return node.Run(ctx, cfg, stdout)
}

func cmdGov(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return usageError{msg: usageText()}
	}
	switch args[0] {
	case "propose":
		return cmdGovPropose(args[1:], stdout)
	case "sign":
		return cmdGovSign(args[1:], stdout)
	case "list":
		return cmdGovList(args[1:], stdout)
	default:
		return usageError{msg: usageText()}
	}
}

func cmdGovPropose(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("propose", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addr := fs.String("node", "", "")
	keyPath := fs.String("key", "", "")
	pass := fs.String("passphrase-file", "", "")
	genesis := fs.String("genesis", "", "")
	txPath := fs.String("tx", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return usageError{msg: usageText()}
	}
	if *addr == "" || *keyPath == "" || *pass == "" || *genesis == "" || *txPath == "" {
		return usageError{msg: usageText()}
	}
	raw, err := os.ReadFile(*txPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := dialLedger(ctx, *addr, *keyPath, *pass, *genesis)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	id, n, submitted, err := client.ProposeGov(ctx, raw)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "%x\nsignatures %d\nsubmitted %t\n", id[:], n, submitted)
	return err
}

func cmdGovSign(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addr := fs.String("node", "", "")
	keyPath := fs.String("key", "", "")
	pass := fs.String("passphrase-file", "", "")
	genesis := fs.String("genesis", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		return usageError{msg: usageText()}
	}
	if *addr == "" || *keyPath == "" || *pass == "" || *genesis == "" {
		return usageError{msg: usageText()}
	}
	id, err := parseID(fs.Arg(0))
	if err != nil {
		return err
	}
	phrase, err := readPassphrase(*pass)
	if err != nil {
		return err
	}
	key, err := keyfile.Open(*keyPath, phrase)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := dialLedger(ctx, *addr, *keyPath, *pass, *genesis)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	// The signature is over the proposal id. The id is the governance
	// digest, which is what admins sign.
	sig, err := key.SignDigest(id, crypto.ContextGovernance)
	if err != nil {
		return err
	}
	n, submitted, err := client.SignGov(ctx, id, sig)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "signatures %d\nsubmitted %t\n", n, submitted)
	return err
}

func cmdGovList(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addr := fs.String("node", "", "")
	keyPath := fs.String("key", "", "")
	pass := fs.String("passphrase-file", "", "")
	genesis := fs.String("genesis", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return usageError{msg: usageText()}
	}
	if *addr == "" || *keyPath == "" || *pass == "" || *genesis == "" {
		return usageError{msg: usageText()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := dialLedger(ctx, *addr, *keyPath, *pass, *genesis)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	ids, err := client.ListGov(ctx)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := fmt.Fprintf(stdout, "%x\n", id[:]); err != nil {
			return err
		}
	}
	return nil
}

func cmdEvent(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return usageError{msg: usageText()}
	}
	switch args[0] {
	case "submit":
		return cmdSubmit(args[1:], stdout)
	case "proof":
		return cmdProof(args[1:])
	case "get":
		return cmdGet(args[1:], stdout)
	default:
		return usageError{msg: usageText()}
	}
}

func cmdSubmit(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("submit", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addr := fs.String("node", "", "")
	keyPath := fs.String("key", "", "")
	pass := fs.String("passphrase-file", "", "")
	genesis := fs.String("genesis", "", "")
	kind := fs.String("type", "", "")
	subject := fs.String("subject", "", "")
	doc := fs.String("doc", "", "")
	nonce := fs.Uint64("nonce", 0, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return usageError{msg: usageText()}
	}
	if *addr == "" || *keyPath == "" || *pass == "" || *genesis == "" || *subject == "" || *doc == "" || *nonce == 0 {
		return usageError{msg: usageText()}
	}
	eventType, err := eventTypeOf(*kind)
	if err != nil {
		return err
	}
	phrase, err := readPassphrase(*pass)
	if err != nil {
		return err
	}
	key, err := keyfile.Open(*keyPath, phrase)
	if err != nil {
		return err
	}
	pub, err := key.Public()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := dialLedger(ctx, *addr, *keyPath, *pass, *genesis)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	st, err := client.Status(ctx)
	if err != nil {
		return err
	}
	wid, err := pub.ID()
	if err != nil {
		return err
	}
	f, err := os.Open(*doc)
	if err != nil {
		return err
	}
	sum, err := verify.HashDocument(f)
	cerr := f.Close()
	if err != nil {
		return err
	}
	if cerr != nil {
		return cerr
	}
	ev := types.Event{
		ChainID:     st.Chain,
		EventType:   eventType,
		Subject:     []byte(*subject),
		Status:      1,
		DocHashes:   []types.DocHash{sum},
		ClaimedTime: time.Now().Unix(),
		WriterID:    wid,
		Nonce:       *nonce,
		ReadPolicy:  types.ReadAllMembers,
	}
	if err := ev.Sign(key); err != nil {
		return err
	}
	id, _, err := client.Submit(ctx, pub, ev)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "%x\n", id[:])
	return err
}

func cmdProof(args []string) error {
	fs := flag.NewFlagSet("proof", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addr := fs.String("node", "", "")
	out := fs.String("out", "", "")
	keyPath := fs.String("key", "", "")
	pass := fs.String("passphrase-file", "", "")
	genesis := fs.String("genesis", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		return usageError{msg: usageText()}
	}
	if *addr == "" || *out == "" || *keyPath == "" || *pass == "" || *genesis == "" {
		return usageError{msg: usageText()}
	}
	id, err := parseID(fs.Arg(0))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := dialLedger(ctx, *addr, *keyPath, *pass, *genesis)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	proof, err := client.Proof(ctx, id)
	if err != nil {
		return err
	}
	raw, err := proof.MarshalBinary()
	if err != nil {
		return err
	}
	return os.WriteFile(*out, raw, 0o644)
}

func cmdGet(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addr := fs.String("node", "", "")
	keyPath := fs.String("key", "", "")
	pass := fs.String("passphrase-file", "", "")
	genesis := fs.String("genesis", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		return usageError{msg: usageText()}
	}
	if *addr == "" || *keyPath == "" || *pass == "" || *genesis == "" {
		return usageError{msg: usageText()}
	}
	id, err := parseID(fs.Arg(0))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := dialLedger(ctx, *addr, *keyPath, *pass, *genesis)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	ev, height, _, err := client.Event(ctx, id)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "height %d\nsubject %s\ntype %d\nnonce %d\n", height, ev.Subject, ev.EventType, ev.Nonce)
	return err
}

func eventTypeOf(name string) (uint16, error) {
	switch name {
	case "shipment":
		return types.EventShipmentDispatched, nil
	case "clearance":
		return types.EventClearanceGranted, nil
	case "access":
		return types.EventAccessLogin, nil
	default:
		return 0, usageError{msg: usageText()}
	}
}

func parseID(s string) ([32]byte, error) {
	var id [32]byte
	raw, err := hexenc.DecodeString(s)
	if err != nil || len(raw) != len(id) {
		return id, fmt.Errorf("event id")
	}
	copy(id[:], raw)
	return id, nil
}

func readPassphrase(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(b) > 1024 {
		return "", fmt.Errorf("passphrase file is too large")
	}
	s := strings.TrimRight(string(b), "\r\n")
	if len(s) < keyfile.MinPassphrase {
		return "", fmt.Errorf("passphrase is too short")
	}
	return s, nil
}

func dialLedger(ctx context.Context, addr, keyPath, passPath, genesisPath string) (*api.Session, error) {
	phrase, err := readPassphrase(passPath)
	if err != nil {
		return nil, err
	}
	key, err := keyfile.Open(keyPath, phrase)
	if err != nil {
		return nil, err
	}
	g, block, qc, err := node.ReadGenesis(genesisPath)
	if err != nil {
		return nil, err
	}
	return api.DialChain(ctx, addr, key, g, block, qc)
}

func loadValidators(path string) (types.ValidatorSet, error) {
	raw, err := readLimited(path, maxKeyBytes)
	if err != nil {
		return types.ValidatorSet{}, err
	}
	return types.UnmarshalValidatorSet(raw)
}

// cmdVerifyRemote hashes the file locally, asks the node for a proof,
// and checks that proof offline. A lying node cannot make this succeed.
func cmdVerifyRemote(file, addr, keyPath, passPath, genesisPath, writerPath string, stdout io.Writer) error {
	doc, err := os.Open(file)
	if err != nil {
		return err
	}
	sum, err := verify.HashDocument(doc)
	cerr := doc.Close()
	if err != nil {
		return err
	}
	if cerr != nil {
		return cerr
	}
	writerBytes, err := readLimited(writerPath, maxKeyBytes)
	if err != nil {
		return err
	}
	writer, err := types.UnmarshalPublicKey(writerBytes)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := dialLedger(ctx, addr, keyPath, passPath, genesisPath)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	match, err := client.Verify(ctx, sum.Sum, writer)
	if err != nil {
		return err
	}
	proof, err := types.UnmarshalInclusionProof(match.Proof)
	if err != nil {
		return err
	}
	keys, ok := client.Voters(proof.Header.Height)
	if !ok {
		return fmt.Errorf("proof height is not in the certified chain")
	}
	res, err := verify.Inclusion(proof, types.ValidatorSet{Keys: keys}, writer)
	if err != nil {
		return err
	}
	if err := verify.CheckDocument(proof.Event, sum); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "certified height %d view %d\nevent %x\ndocument hash matches\n", res.Height, res.View, res.EventID[:])
	return err
}

func splitComma(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
