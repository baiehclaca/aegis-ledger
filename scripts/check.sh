#!/usr/bin/env bash
# Format, build, vet, lint, race tests, and fuzz smoke.
# The race tests include the short simulator campaign.
# TLC is scripts/tlc.sh: it needs a JRE and is a separate CI job.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

# A shell that already measured or ran the large campaign must not
# change this script. The benchmark is scripts/bench.sh. The large
# simulator budget is scripts/sim-budget.sh.
unset SILVERGREY_BENCH
unset SILVERGREY_SIM_BUDGET

if ! command -v go >/dev/null 2>&1; then
	echo "go is not on PATH" >&2
	exit 1
fi
if ! command -v golangci-lint >/dev/null 2>&1; then
	echo "golangci-lint is not on PATH" >&2
	exit 1
fi

unformatted=$(gofmt -l .)
if [[ -n "$unformatted" ]]; then
	echo "gofmt required:" >&2
	echo "$unformatted" >&2
	exit 1
fi

go build ./...
go vet ./...
golangci-lint run ./...
go test -race ./...
"$root/scripts/fuzz-smoke.sh"
