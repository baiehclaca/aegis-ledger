#!/usr/bin/env bash
# Model-check spec/tla/HotStuff2.tla and spec/tla/Epoch.tla. The jar is
# downloaded on first use and is not committed. TLC checks safety only;
# liveness is the simulator. Epoch.tla is a separate finite abstraction
# (one batch, n=4, K=1 MaxH=3 and K=2 MaxH=4). HotStuff2 stays a fixed set.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
dir="$root/spec/tla"
ver=1.7.4
jar="$dir/tla2tools.jar"
# SHA-256 of the v1.7.4 release asset from github.com/tlaplus/tlaplus.
sum=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88

if ! command -v java >/dev/null 2>&1; then
	echo "java is not on PATH" >&2
	exit 1
fi

have=""
if [[ -f "$jar" ]]; then
	have=$(sha256sum "$jar" | awk '{print $1}')
fi
if [[ "$have" != "$sum" ]]; then
	tmp=$(mktemp)
	curl -fsSL -o "$tmp" "https://github.com/tlaplus/tlaplus/releases/download/v${ver}/tla2tools.jar"
	got=$(sha256sum "$tmp" | awk '{print $1}')
	if [[ "$got" != "$sum" ]]; then
		echo "tla2tools.jar sha256 is $got" >&2
		echo "expected $sum" >&2
		rm -f "$tmp"
		exit 1
	fi
	mv "$tmp" "$jar"
fi

cd "$dir"
workers=${TLC_WORKERS:-2}
for cfg in MC4.cfg MC7.cfg; do
	echo "tlc $cfg"
	java -XX:+UseParallelGC -Xmx2g -jar "$jar" -deadlock -workers "$workers" -config "$cfg" HotStuff2.tla
done
for cfg in EpochK1.cfg EpochK2.cfg; do
	echo "tlc $cfg"
	java -XX:+UseParallelGC -Xmx2g -jar "$jar" -deadlock -workers "$workers" -config "$cfg" Epoch.tla
done
