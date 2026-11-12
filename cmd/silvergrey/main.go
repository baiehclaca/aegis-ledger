// Command silvergrey hashes a document, checks an inclusion proof offline,
// and, on a test network, runs a local node.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
	"github.com/silvergreyhound/silver-grey-ledger/pkg/verify"
)

const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2

	// Proofs carry signatures, so the cap is far above an honest proof
	// and still small enough that a hostile file cannot exhaust memory.
	maxProofBytes = 16 << 20
	maxKeyBytes   = 1 << 20
)

func main() {
	code := exitOK
	if err := run(os.Args[1:], os.Stdout); err != nil {
		code = exitFail
		var u usageError
		if errors.As(err, &u) {
			code = exitUsage
		}
		// A failed write to stderr cannot be reported anywhere else.
		// The exit status is then the generic failure.
		if _, werr := fmt.Fprintf(os.Stderr, "silvergrey: %s\n", err); werr != nil {
			code = exitFail
		}
	}
	os.Exit(code)
}

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func run(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return usageError{msg: usageText()}
	}
	switch args[0] {
	case "hash":
		return cmdHash(args[1:], stdout)
	case "verify":
		return cmdVerify(args[1:], stdout)
	case "keygen":
		return cmdKeygen(args[1:])
	case "node":
		return cmdNode(args[1:], stdout)
	case "event":
		return cmdEvent(args[1:], stdout)
	case "gov":
		return cmdGov(args[1:], stdout)
	case "-h", "--help", "help":
		if _, err := fmt.Fprint(stdout, usageText()); err != nil {
			return err
		}
		return nil
	default:
		return usageError{msg: usageText()}
	}
}

func usageText() string {
	return `silvergrey hash <file>
silvergrey verify document <file> --proof <proof> --validators <set> --writer <key>
silvergrey verify document <file> --node <addr> --key <file> --passphrase-file <file> --genesis <file> --writer <key>
silvergrey keygen --alg ml-dsa-65|slh-dsa-shake-128s --out <file> --pub <file> --passphrase-file <file>
silvergrey node genesis --out <file> --validators-out <file> --founders <slh,...> --keys <k0,k1,...> [--writers <w,...>] [--epoch-delay <k>] --passphrase-file <file>
silvergrey node init --dir <dir> --index <n> --listen <addr> --client <addr> --peers <a,b,...> --genesis <file> --keyfile <file>
silvergrey node start --dir <dir> --passphrase-file <file>
silvergrey event submit --node <addr> --key <file> --passphrase-file <file> --genesis <file> --type shipment|clearance|access --subject <id> --doc <file> --nonce <n>
silvergrey event proof --node <addr> --key <file> --passphrase-file <file> --genesis <file> --out <file> <event-id>
silvergrey event get --node <addr> --key <file> --passphrase-file <file> --genesis <file> <event-id>
silvergrey gov propose --node <addr> --key <file> --passphrase-file <file> --genesis <file> --tx <file>
silvergrey gov sign --node <addr> --key <file> --passphrase-file <file> --genesis <file> <proposal-id>
silvergrey gov list --node <addr> --key <file> --passphrase-file <file> --genesis <file>

hash prints the SHA3-256 digest of a file. The file is not uploaded.
verify checks an inclusion proof offline. With --node and no --proof,
the file is hashed locally and the returned proof is checked offline.
The key file is test-network only and is forbidden in production.
keygen writes a test-network encrypted key file. That file is forbidden
in production; production keys stay in an HSM, which this binary does
not speak to. A founding key is SLH-DSA-SHAKE-128s. A validator or
writer key is ML-DSA-65. The same file format holds either, and neither
file is accepted as a production key.
`
}

func cmdHash(args []string, stdout io.Writer) error {
	if len(args) != 1 {
		return usageError{msg: usageText()}
	}
	f, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	sum, err := verify.HashDocument(f)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "%x\n", sum.Sum[:])
	return err
}

func cmdVerify(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "document" {
		return usageError{msg: usageText()}
	}
	fs, err := parseVerifyFlags(args[1:])
	if err != nil {
		return err
	}
	if fs.proof == "" {
		return cmdVerifyRemote(fs.file, fs.node, fs.key, fs.pass, fs.genesis, fs.writer, stdout)
	}
	doc, err := os.Open(fs.file)
	if err != nil {
		return err
	}
	defer func() { _ = doc.Close() }()
	proofBytes, err := readLimited(fs.proof, maxProofBytes)
	if err != nil {
		return err
	}
	proof, err := types.UnmarshalInclusionProof(proofBytes)
	if err != nil {
		return err
	}
	set, err := loadValidators(fs.validators)
	if err != nil {
		return err
	}
	keyBytes, err := readLimited(fs.writer, maxKeyBytes)
	if err != nil {
		return err
	}
	writer, err := types.UnmarshalPublicKey(keyBytes)
	if err != nil {
		return err
	}
	res, err := verify.Inclusion(proof, set, writer)
	if err != nil {
		return err
	}
	sum, err := verify.HashDocument(doc)
	if err != nil {
		return err
	}
	if err := verify.CheckDocument(proof.Event, sum); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "certified height %d view %d\nevent %x\ndocument hash matches\n", res.Height, res.View, res.EventID[:])
	return err
}

type verifyFlags struct {
	file       string
	proof      string
	validators string
	genesis    string
	writer     string
	node       string
	key        string
	pass       string
}

func parseVerifyFlags(args []string) (verifyFlags, error) {
	var f verifyFlags
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--proof", "--validators", "--genesis", "--writer", "--node", "--key", "--passphrase-file":
			if i+1 >= len(args) {
				return verifyFlags{}, usageError{msg: usageText()}
			}
			val := args[i+1]
			i++
			switch args[i-1] {
			case "--proof":
				f.proof = val
			case "--validators":
				f.validators = val
			case "--genesis":
				f.genesis = val
			case "--writer":
				f.writer = val
			case "--node":
				f.node = val
			case "--key":
				f.key = val
			case "--passphrase-file":
				f.pass = val
			}
		default:
			if len(args[i]) > 0 && args[i][0] == '-' {
				return verifyFlags{}, usageError{msg: usageText()}
			}
			if f.file != "" {
				return verifyFlags{}, usageError{msg: usageText()}
			}
			f.file = args[i]
		}
	}
	if f.file == "" || f.writer == "" {
		return verifyFlags{}, usageError{msg: usageText()}
	}
	if f.proof != "" {
		if f.validators == "" {
			return verifyFlags{}, usageError{msg: usageText()}
		}
		return f, nil
	}
	if f.node == "" || f.key == "" || f.pass == "" || f.genesis == "" {
		return verifyFlags{}, usageError{msg: usageText()}
	}
	return f, nil
}

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	var tmp bytes.Buffer
	if _, err := io.Copy(&tmp, io.LimitReader(f, limit+1)); err != nil {
		return nil, err
	}
	if int64(tmp.Len()) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	return tmp.Bytes(), nil
}
