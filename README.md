# Silver Grey Ledger

*None Swifter Than These.*

Silver Grey Ledger is a permissioned Byzantine-fault-tolerant ledger for critical records: supply-chain steps, clearance changes, and system access. Several organisations hold one append-only history. Documents stay in each organisation's own store; the ledger keeps identifiers and SHA3-256 hashes.

**Status: M4.** This tree has the M0 encoding and offline verifier, the M1 HotStuff-2 core, the M2 crash-safe store, the M3 network (TLS 1.3 with X25519MLKEM768 and ML-DSA-65 certificates, a gossiped mempool, and an mTLS API), and M4 governance. Founding signatures are SLH-DSA-SHAKE-128s. Roles and read policy are enforced. Membership changes, rotation, and revocation take effect at an epoch after a governance threshold. M5 is on hold and is not started.

Measurements from one run on the build VM are in [docs/benchmarks.md](docs/benchmarks.md), with the machine and the method. They describe that run. They are not a claim about any other machine.

The design is [docs/design.md](docs/design.md). Section 12 is the M0 encoding. Section 13 is the consensus behaviour. Section 14 is the storage and the crash rules. Section 15 is the transport, the mempool, and the API. Section 16 is governance.


- Whitepaper: [silver-grey-ledger-whitepaper.pdf](silver-grey-ledger-whitepaper.pdf)
- Site: https://silvergreyhound.github.io/silver-grey-ledger/ (source in `website/`, deployed by GitHub Pages)

The name comes from the silver greyhound, the emblem of the British King's Messengers. Motto: *None Swifter Than These.* Silver Grey Ledger is not affiliated with or endorsed by the UK or U.S. governments or their courier services.

Repository: https://github.com/silvergreyhound/silver-grey-ledger

## Module path

The Go module path is `github.com/silvergreyhound/silver-grey-ledger`. The command is `silvergrey`.

## Requirements

Go 1.27.3. ML-DSA comes from the standard library `crypto/mldsa`, which that release provides. Do not build with the FIPS 140-3 Go cryptographic module v1.0.0: that module disables `crypto/mldsa`.

SLH-DSA-SHAKE-128s comes from `github.com/cloudflare/circl` v1.6.5. The state index is `github.com/cockroachdb/pebble/v2` v2.1.7. The test-network key file uses `golang.org/x/crypto` v0.58.0 for scrypt. The API is `google.golang.org/grpc` v1.85.0 and `github.com/grpc-ecosystem/grpc-gateway/v2` v2.33.0, with `google.golang.org/protobuf` v1.36.12.

Production keys belong in an HSM. That driver is not implemented. `silvergrey keygen` writes an encrypted key file for a test network only. The file is `silvergrey-test-key-v1`, scrypt `N=32768`, `r=8`, `p=1`, and AES-256-GCM around the raw private key. An ML-DSA-65 key is a 32-byte seed. An SLH-DSA-SHAKE-128s founding key is the 64-byte circl private encoding. The passphrase is not stored. Using that file in production is forbidden, and the command says so. `silvergrey node genesis` takes at least two `--founders` files (SLH-DSA) and `--keys` for the ML-DSA-65 validators. One founding organisation is rejected.

## Build and test

```sh
go build ./...
go vet ./...
golangci-lint run ./...
go test -race ./...
```

`scripts/check.sh` runs those, plus a `gofmt` check and a short fuzz smoke pass. `FUZZTIME` defaults to `5s` per fuzzer. The race tests include the short simulator campaign (safety seeds 1–6 at n=4 and 101–103 at n=7; liveness seeds 201–204 and 301–302) and the crash tests, including `SIGKILL` of a child process mid-write and mid-vote. They also include the namespace tests when `sudo -n` works. Without sudo those tests skip.

```sh
./scripts/check.sh
```

`scripts/sim-budget.sh` is the large campaign (`SILVERGREY_SIM_BUDGET=large`): safety seeds 1–120 at n=4 and 1001–1060 at n=7, liveness seeds 2001–2048 at n=4 and 3001–3024 at n=7 (252 runs). It is not part of CI. It was re-run after genesis began requiring two founding organisations and revocation began removing the seat. The timing is in [docs/design.md](docs/design.md) §16.6.

`scripts/bench.sh` runs the M3 measurements. It is not part of CI. The method and the figures are in [docs/benchmarks.md](docs/benchmarks.md).

`scripts/tlc.sh` downloads TLA+ tools v1.7.4 (the jar is not committed) and model-checks `spec/tla/HotStuff2.tla` for n=4 and n=7, then `spec/tla/Epoch.tla` at K=1 (heights 0..3) and K=2 (heights 0..4). It needs a Java 21 runtime. TLC checks safety only. The simulator checks liveness. HotStuff-2 stays a fixed validator set. The epoch spec is one batch on four seats: membership change, rotation, revocation, and effect height = inclusion + K. It is not a model of votes, and it is not checked at n=7. Those cases are the Go tests.

The namespace test needs `sudo -n`, `ip`, `iptables-legacy`, and `ethtool`. This kernel has no `sch_netem` qdisc. The test forwards frames itself and applies a 20 ms ± 5 ms delay, 1% loss, and 5% reorder, then isolates the last f nodes with iptables.

## Command line

`silvergrey hash <file>` prints the SHA3-256 digest of a file, which is the document hash an event stores.

`silvergrey verify document <file> --proof <proof> --validators <set> --writer <key>` checks an inclusion proof offline. Exit 0 means a quorum certified the block that contains the event, and the file matches a document hash on that event. That is certification of the block. It is not HotStuff-2 finality. Exit 1 is a failed check. Exit 2 is a usage error.

`silvergrey verify document <file> --node <addr> --key <file> --passphrase-file <file> --genesis <file> --writer <key>` hashes the file locally, fetches the proof over mTLS, and checks it against the validator set committed at that block. `--genesis` is the bundle written by `silvergrey node genesis`: the genesis record, the height-0 block, and the view-0 certificate. The client learns the current validator set from the chain. It does not take a `--validators` file for a remote command.

`silvergrey keygen` writes a test-network key file. `silvergrey node genesis` builds the founding record from at least two SLH-DSA keys and the ML-DSA-65 validators. `silvergrey node init` writes a line-oriented config (`node.conf`) for one node. `client` is the mTLS API address. `silvergrey node start` runs that node. `silvergrey event submit` signs one event and sends it to `--node`. The document is hashed on the client and is not uploaded. `silvergrey event proof` writes the inclusion proof. `silvergrey event get` prints a committed event. Every remote command takes `--key`, `--passphrase-file`, and `--genesis`.

## Licence

Apache-2.0. Copyright 2026 Teodor Walter Vido. See [LICENSE](LICENSE).
