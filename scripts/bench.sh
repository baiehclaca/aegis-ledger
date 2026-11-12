#!/usr/bin/env bash
# Measure the M3 figures. The numbers are written by the test log.
# This script is not part of CI and it does not publish anything.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

export SILVERGREY_BENCH=1
go test -count=1 -timeout 10m -v ./internal/node/ -run '^TestBenchmarkM3$'
