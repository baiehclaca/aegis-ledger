#!/usr/bin/env bash
# The large seeded simulator budget. The default go test runs a shorter
# campaign so CI stays small. This script is the acceptance run:
# safety seeds 1–120 at n=4 and 1001–1060 at n=7, liveness seeds
# 2001–2048 at n=4 and 3001–3024 at n=7 (252 runs).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

export SILVERGREY_SIM_BUDGET=large
go test -count=1 -timeout 60m ./sim/ -run 'TestSafetyCampaign|TestLivenessCampaign' -v
