#!/usr/bin/env bash
# Run each decoder fuzzer for a short, fixed time. A finding exits non-zero.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

fuzztime=${FUZZTIME:-5s}

targets=(
	"internal/codec FuzzLength"
	"internal/codec FuzzBytesField"
	"internal/codec FuzzRecord"
	"internal/merkle FuzzVerify"
	"internal/merkle FuzzProveVerify"
	"internal/types FuzzEvent"
	"internal/types FuzzBlockHeader"
	"internal/types FuzzQC"
	"internal/types FuzzBlock"
	"internal/types FuzzInclusionProof"
	"internal/types FuzzPublicKey"
	"internal/types FuzzValidatorSet"
	"internal/types FuzzVote"
	"internal/types FuzzTimeout"
	"internal/types FuzzTC"
	"internal/types FuzzProposal"
	"internal/types FuzzEquivocation"
	"internal/types FuzzGenesis"
	"internal/types FuzzGovTx"
	"internal/store FuzzSafety"
	"internal/store FuzzBlockLog"
	"internal/keyfile FuzzOpen"
	"internal/mempool FuzzUnmarshalIDs"
	"internal/mempool FuzzUnmarshalBody"
	"internal/p2p FuzzFrame"
)

for spec in "${targets[@]}"; do
	pkg=${spec%% *}
	name=${spec##* }
	echo "fuzz ${pkg} ${name} (${fuzztime})"
	go test -run='^$' -fuzz="^${name}$" -fuzztime="$fuzztime" "./${pkg}"
done
