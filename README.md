# Arxia

[![CI](https://github.com/ArxiaNetwork/Arxia/actions/workflows/ci.yml/badge.svg)](https://github.com/ArxiaNetwork/Arxia/actions/workflows/ci.yml)

The offline settlement network. Value that moves without internet.

Arxia is an offline settlement layer: transactions are created, signed and
propagated over long range radio with no internet, and the result anchors to
an existing chain when a connection returns. It is built for people with no
bank and no connection.

This repository holds the protocol core, written in Rust. The settlement
layer is a direction we have committed to, not code that exists today. We
will show it when it runs.

Website: https://arxia.network

## How it works

- **Radio first.** The protocol is designed for long range LoRa radio, with
  Bluetooth, SMS and satellite as planned transports. In this repository the
  transport layer is an interface with a simulated implementation; no radio
  driver is written yet (see [Status](#status)).
- **One radio packet per transaction.** Every block serializes to 193 bytes,
  so a transaction fits in a single LoRa packet.
- **One chain per account.** The ledger is a block lattice: each account has
  its own chain, and each block carries a sequence number (nonce). Blocks are
  signed with Ed25519 over Blake3 hashes.
- **A double spend cannot survive.** A node that already holds a block for an
  account's sequence number rejects a second, different block for the same
  number. When groups that were cut off from each other meet again,
  reconciliation keeps exactly one block per account sequence number, chosen
  the same way on every node, rejects receives with no matching send and
  refuses any negative balance. Today that choice is made by block hash; the
  stake-weighted resolver in `arxia-consensus` is not yet called by
  reconciliation. Until two such groups meet, each can confirm its own side
  of a conflict: the Local tier with a single nearby node, the Mesh tier with
  the nodes in reach. That is why Local is capped at 10 ARX in code.
- **Finality has tiers.** The four public tiers are Local, Mesh, Batch and
  Anchored. Local: a payment of at most 10 ARX, confirmed by one signed
  confirmation from a registered node. Mesh: the node's nonce registry
  matches a neighbour's on every account sequence number. The code also
  has full consensus inside the radio network: signed votes from registered
  validators holding at least 67% of registered stake, with no internet
  involved. The code's internal identifiers for these tiers, and their
  mapping, are in [docs/architecture/FINALITY.md](docs/architecture/FINALITY.md).
  Value caps above Local are set per pilot and documented in the pilot
  agreement. Batch and Anchored belong to the settlement layer and have no
  code yet.

## Status

### Built and tested in this repository

These pieces are implemented and tested as libraries. No running node ties
them together yet.

- Block lattice with one chain per account, 193-byte compact block
  serialization, Ed25519 signatures over Blake3 hashes, and a ledger that
  derives every balance from chain history and accepts a receive only against
  a matching unspent send.
- Gossip logic: block intake that rejects a second block for the same account
  sequence number, nonce registry merge and sync, signed and size-capped
  messages.
- CRDT reconciliation when partitions rejoin.
- Stake-weighted representative voting (ORV): signed votes, a representative
  threshold of 0.1% of supply, quorum checks and conflict resolution.
- Finality assessment from signed confirmations and signed votes, with the
  Local tier capped at 10 ARX.
- Signed relay receipts and relay reputation scoring.
- A flash storage layer that survives power loss by design, proven by a
  fault injection suite that cuts power at every write boundary
  (`arxia-storage-flash`), and a persistent redb backend for hosts
  (`arxia-storage-redb`).
- The portable core compiles for bare metal embedded targets, checked in CI
  on every push and pull request to `main`. The T-Beam power-loss bench
  firmware (`targets/esp32-bench`) builds with the Xtensa toolchain.
- 800+ workspace tests, run in CI together with formatting, Clippy and
  documentation checks on every push and pull request to `main`.

### Shown on hardware

- 18 April 2026: first transaction between two T-Beam boards over LoRa radio
  with no internet in the loop. It ran through a bridge, not through the node
  binary in this repository.

### Not built yet

- `arxia-node` is a stub binary: it logs a startup banner and exits.
- Radio drivers (LoRa, Bluetooth, SMS, satellite). `arxia-transport`
  provides the interface, signed messages, fragment reassembly and a
  simulated link used in tests.
- No network loop connects gossip to a transport yet.
- Consensus is not yet wired to finality: the finality check takes a
  validator set supplied by the caller.
- The storage backends are not wired to the ledger yet; the ledger runs in
  memory.
- ChaCha20-Poly1305 encryption and SLIP39 seed backup are stubs that return
  `Unimplemented`.
- `arxia-wasm` and `arxia-inspector` are placeholders. `arxia-cli` generates
  keys and `did:arxia` identifiers only.

### Direction

There is no anchoring, bridge or sequencer code in this repository yet. The
v1 scope is a single settlement asset.

The next step is the field test: real boards, real distance, a transaction
settling with no internet in the loop, filmed and published.

## Quick Start

Requirements: Git, and Rust 1.89.0 (pinned in `rust-toolchain.toml`)
installed with `rustup`, so that the toolchain is on `PATH`. A dependency's
build script invokes `rustc` from `PATH`; see
[docs/dependency-risks.md](docs/dependency-risks.md).

```bash
git clone https://github.com/ArxiaNetwork/Arxia.git
cd Arxia

# Build
cargo build --workspace

# Test
cargo test --workspace

# Run examples (each example is its own workspace member binary,
# not a Cargo `[[example]]` target, so invoke it with `-p`).
cargo run -p offline_payment
cargo run -p did_issuance
cargo run -p mesh_relay
cargo run -p partition_reconciliation
```

> The first build of `arxia-proto` emits
> `warning: arxia-proto@0.1.0: protoc not found, using stub
> protobuf module (LOW-008: cfg=arxia_proto_stub set)` when the
> `protoc` binary is not on `PATH`. This is expected on hosts
> without a Protobuf toolchain; the workspace falls back to a
> stub module gated by `cfg=arxia_proto_stub`.

## Architecture

```
Transport (LoRa first; Bluetooth, SMS, satellite planned; simulated in tests today)
  -> Gossip (nonce registry, sync)
    -> Block lattice (one chain per account)
      -> CRDT reconciliation (PN-Counter, OR-Set, vector clocks)
        -> ORV consensus (stake-weighted representative voting)
          -> Finality (Local, Mesh and full consensus in code)
            -> Batch and Anchored: settlement direction, no code yet
```

See [docs/architecture/OVERVIEW.md](docs/architecture/OVERVIEW.md) for details.

## Workspace

| Crate | Description |
|---|---|
| `arxia-core` | Shared types, constants and errors |
| `arxia-crypto` | Ed25519 signatures, Blake3 hashing; ChaCha20-Poly1305 and SLIP39 are stubs |
| `arxia-lattice` | Block types, per-account chains, ledger, 193-byte compact serialization |
| `arxia-crdt` | PN-Counter, OR-Set, vector clocks, partition reconciliation |
| `arxia-consensus` | ORV votes, delegation, quorum, conflict resolution (not wired to finality yet) |
| `arxia-gossip` | Nonce registry, signed gossip messages, sync |
| `arxia-finality` | Finality assessment from signed confirmations and votes |
| `arxia-transport` | Transport interface, fragment reassembly, simulated transport |
| `arxia-relay` | Relay receipts, relay scoring, signed penalty proofs |
| `arxia-did` | `did:arxia` identifiers derived from Ed25519 keys |
| `arxia-storage` | Storage interface, in-memory backends, shared conformance suite |
| `arxia-storage-redb` | Persistent storage backend on redb (not wired to the ledger yet) |
| `arxia-storage-flash` | Flash storage backend for embedded targets, power-loss safe |
| `arxia-flash-bench` | Power-loss bench protocol for the flash backend, as a `no_std` library |
| `arxia-proto` | Protobuf wire definitions and frame validation |
| `arxia-wasm` | WebAssembly bindings (placeholder, not implemented) |
| `arxia-bench` | Criterion benchmarks |

Other members of the workspace:

- `bin/arxia-node`: node binary (stub).
- `tools/arxia-cli`: key and DID generation. `tools/arxia-inspector`: stub.
- `examples/`: four example programs (`offline_payment`, `did_issuance`,
  `mesh_relay`, `partition_reconciliation`).
- `contracts/`: two example contract crates (`escrow`, `token-lock`). There
  is no contract runtime.
- `targets/esp32`: ESP32 target crate (`no_std`, radio driver not written
  yet).

Outside the workspace: `targets/esp32-bench`, the T-Beam power-loss bench
firmware, a standalone Cargo project built with the Xtensa toolchain.

## Hardware

The reference board is a T-Beam class device: an ESP32 with an SX1276 LoRa
radio and GPS. It costs tens of dollars, around 30 to 40 USD.
See [docs/guides/HARDWARE_SETUP.md](docs/guides/HARDWARE_SETUP.md).

## Security and audit

ERC-20 token contract audited by SolidProof, zero findings. The protocol,
bridge, wallet and embedded code have not been audited yet.

The token contract exists on a test network only. No token is live. ARX
amounts in this code are protocol units with 6 decimals.

The `CRIT-`, `HIGH-`, `MED-` and `LOW-` identifiers in code comments refer to
an internal security review, not an external audit; see
[docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md). To report a
vulnerability, see [SECURITY.md](SECURITY.md).

## Documentation

- [Architecture overview](docs/architecture/OVERVIEW.md)
- [Finality model](docs/protocol/FINALITY_MODEL.md)
- [Block serialization](docs/protocol/SERIALIZATION.md)
- [Power-loss protocol for flash storage](docs/architecture/POWER_LOSS_PROTOCOL.md)
- [Getting started](docs/guides/GETTING_STARTED.md)
- [Hardware setup](docs/guides/HARDWARE_SETUP.md)
- [Dependency risks](docs/dependency-risks.md)
- [Arxia Improvement Proposals](docs/aips/)

## Disclaimer

Arxia is not affiliated with or endorsed by the Meshtastic project. No
Meshtastic code is in this repository, and the protocol does not depend on
any one radio firmware.

## Repository History

This repository was consolidated from a private workspace in March 2026.
Commits from that point onward represent live, in-the-open development.

## Contact

- Website: https://arxia.network
- Email: arxia.network@proton.me
- X: https://x.com/ArxiaNetwork
- Telegram: https://t.me/Arxialayerone

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
