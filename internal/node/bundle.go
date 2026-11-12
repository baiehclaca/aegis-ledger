package node

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

const bundleMagic = "AGB1"

// WriteGenesis writes the genesis record, the height-0 block, and the
// view-0 certificate. A torn file is rejected by ReadGenesis.
func WriteGenesis(path string, g types.Genesis, block types.Block, qc types.QC) error {
	parts := make([][]byte, 3)
	var err error
	if parts[0], err = g.MarshalBinary(); err != nil {
		return err
	}
	if parts[1], err = block.MarshalBinary(); err != nil {
		return err
	}
	if parts[2], err = qc.MarshalBinary(); err != nil {
		return err
	}
	buf := make([]byte, 0, 64)
	buf = append(buf, bundleMagic...)
	for _, p := range parts {
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(p)))
		buf = append(buf, p...)
	}
	tmp := path + ".next"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(buf)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	if cerr != nil {
		return cerr
	}
	if serr != nil {
		return serr
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return nil
}

// ReadGenesis reads a file written by WriteGenesis.
func ReadGenesis(path string) (types.Genesis, types.Block, types.QC, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return types.Genesis{}, types.Block{}, types.QC{}, err
	}
	if len(raw) < 4 || string(raw[:4]) != bundleMagic || len(raw) > 32<<20 {
		return types.Genesis{}, types.Block{}, types.QC{}, fmt.Errorf("node: genesis bundle")
	}
	rest := raw[4:]
	take := func() ([]byte, error) {
		if len(rest) < 4 {
			return nil, fmt.Errorf("node: genesis bundle")
		}
		n := binary.BigEndian.Uint32(rest[:4])
		rest = rest[4:]
		if uint32(len(rest)) < n {
			return nil, fmt.Errorf("node: genesis bundle")
		}
		out := rest[:n]
		rest = rest[n:]
		return out, nil
	}
	gb, err := take()
	if err != nil {
		return types.Genesis{}, types.Block{}, types.QC{}, err
	}
	bb, err := take()
	if err != nil {
		return types.Genesis{}, types.Block{}, types.QC{}, err
	}
	qb, err := take()
	if err != nil {
		return types.Genesis{}, types.Block{}, types.QC{}, err
	}
	if len(rest) != 0 {
		return types.Genesis{}, types.Block{}, types.QC{}, fmt.Errorf("node: genesis bundle trailing bytes")
	}
	g, err := types.UnmarshalGenesis(gb)
	if err != nil {
		return types.Genesis{}, types.Block{}, types.QC{}, err
	}
	block, err := types.UnmarshalBlock(bb)
	if err != nil {
		return types.Genesis{}, types.Block{}, types.QC{}, err
	}
	qc, err := types.UnmarshalQC(qb)
	if err != nil {
		return types.Genesis{}, types.Block{}, types.QC{}, err
	}
	return g, block, qc, nil
}
