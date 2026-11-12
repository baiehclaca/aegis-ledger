package consensus

import "github.com/silvergreyhound/silver-grey-ledger/internal/types"

// Leader is the validator index that proposes in view. Index 0 proposes
// in views 0, n, 2n, ... View 0 is the genesis block, which that same
// validator signs.
func Leader(view uint64, n int) (int, error) {
	if _, err := types.Quorum(n); err != nil {
		return 0, err
	}
	return int(view % uint64(n)), nil
}
