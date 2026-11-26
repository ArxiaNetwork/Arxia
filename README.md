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
- **A payment is settled by the nodes in radio reach.** A receiver checks
  alone that a payment is authentic and funded, by replaying the payer's
  blocks. What it cannot see alone is whether the payer signed something else
  elsewhere. Witnesses close that gap: nodes in reach that each keep a ledger
  and confirm a block only when their own ledger accepts it, so a witness
  never confirms two blocks for the same account sequence number. A payment
  is final when the witnesses that confirmed it hold more than two thirds of
  the weight of the roster the receiver recognises. Two conflicting payments
  cannot both reach that threshold while witnesses holding more than one
  third of the weight follow the rules.
- **A double signature is evidence.** Two blocks signed for one account
  sequence number form a proof that anyone can verify from the two blocks
  alone. A ledger that holds it accepts nothing further from that account at
  that sequence number or after, except a block the witnesses already
  settled, and the proof travels with later payments.
- **With no witness in reach, a reserve bounds the exposure.** While
  witnesses are reachable, an account can move an amount to a reserve account
  and have it confirmed. A receiver with nobody to ask then accepts payments
  from that reserve, up to the certified amount, by checking the certificate
  alone. It cannot know whether the same reserve was also spent elsewhere:
  the reserve bounds what is at stake, and a reserve spent twice yields the
  proof above and freezes the owner's account in the ledgers that hold it.
- **Value enters by certificate.** Under an issuance policy, an account opens
  with a balance only when enough of the configured issuer keys signed a
  certificate for that account and that amount.
- **Finality has tiers.** The four public tiers are Local, Mesh, Batch and
  Anchored. Local: a payment from a certified reserve, accepted with no
  witness in reach. Mesh: a payment confirmed by witnesses in radio reach,
  above two thirds of the roster weight. Batch and Anchored belong to the
  settlement layer and have no code yet. The earlier finality identifiers
  that remain in the code are described in
  [docs/architecture/FINALITY.md](docs/architecture/FINALITY.md).

## Status

### Built and tested in this repository

These pieces are implemented and tested as libraries. The node binary does
not tie them together yet; an example program runs them between separate
processes.

- Block lattice with one chain per account, 193-byte compact block
  serialization, Ed25519 signatures over Blake3 hashes, and a ledger that
  derives every balance from chain history and accepts a receive only against
  a matching unspent send.
- A wallet that owns an account and the ledger that validates it: every block
  from another device enters under the full ledger rules, and a payment is
  credited only when its funding can be replayed.
- Persistence: a signed block is on storage before it is handed out, and the
  wallet is rebuilt from storage alone, replaying every stored block under
  the ledger rules. It runs on the redb backend and fits the limits of the
  flash backend.
- Issuance certificates signed by a threshold of issuer keys.
- Witness confirmations, settlement above two thirds of the roster weight,
  and equivocation proofs with the account freeze.
- Certified reserves for payments with no witness in reach.
- Bundles: the frame format one device hands to another, each frame small
  enough for one LoRa packet, and signed fragments that carry a bundle
  across a link in packets of at most one MTU.
- `examples/offline_settlement`: two payments in a row settled between
  separate processes that exchange only files of frames, with witnesses, and
  a reserve paying a receiver with no witness in reach.
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
- A radio link in use. `arxia-radio` is a LoRa driver for the SX1276
  family, tested against a register-level model of the chip; it has not
  been run on hardware and the firmware does not use it yet. There is no
  driver for Bluetooth, SMS or satellite. `arxia-transport` provides the
  interface, signed messages, fragment splitting and reassembly, and a
  simulated link used in tests.
- The node firmware is a first stage (`targets/esp32-node`): the wallet and
  the ledger build for the board and run a check at boot. It has not been
  run on a board yet, and it does not use the radio.
- The witness roster and the issuer keys are configuration. There is no
  on-ledger bond, no penalty for a witness, and no way yet to update a roster
  from the network.
- A payment carries the payer's whole history. Starting from a settled
  point is not implemented yet.
- There is no retransmission protocol for lost packets.
- ChaCha20-Poly1305 encryption and SLIP39 seed backup are stubs that return
  `Unimplemented`. Keys are stored unencrypted.
- `arxia-wasm` and `arxia-inspector` are placeholders. `arxia-cli` generates
  keys and `did:arxia` identifiers only.

### Earlier design, kept for reference

The repository still contains the consensus design that preceded witness
settlement: stake-weighted representative voting (`arxia-consensus`),
partition reconciliation by block hash (`arxia-crdt`), the gossip nonce
registry (`arxia-gossip`) and the earlier finality assessment in
`arxia-finality`. None of it is on the settlement path described above. It
stays until the documentation that refers to it is rewritten, then it is
removed.

### Direction

There is no anchoring, bridge or sequencer code in this repository yet. The
v1 scope is a single settlement asset.

The next step is the field test: real boards, real distance, a transaction
settling with no internet in the loop, filmed and published.

## Quick Start

Requirements: Git, and Rust 1.90.0 (pinned in `rust-toolchain.toml`)
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
cargo test -p offline_settlement   # payments settled between separate processes
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
  -> Signed fragments (one MTU each) -> bundles of frames
    -> Wallet and ledger (one chain per account, issuance certificates)
      -> Witness confirmations (settlement above two thirds of the roster weight)
        -> Equivocation proofs and certified reserves
          -> Batch and Anchored: settlement direction, no code yet
```

See [docs/architecture/OVERVIEW.md](docs/architecture/OVERVIEW.md) for details.

## Workspace

| Crate | Description |
|---|---|
| `arxia-core` | Shared types, constants and errors |
| `arxia-crypto` | Ed25519 signatures, Blake3 hashing; ChaCha20-Poly1305 and SLIP39 are stubs |
| `arxia-lattice` | Blocks, ledger, wallet, persistence, issuance, witness counting, equivocation proofs, reserves, bundles |
| `arxia-crdt` | PN-Counter, OR-Set, vector clocks; partition reconciliation (earlier design) |
| `arxia-consensus` | ORV votes, delegation, quorum, conflict resolution (earlier design) |
| `arxia-gossip` | Nonce registry, signed gossip messages, sync (earlier design) |
| `arxia-finality` | Witness node and settlement by confirmed weight; the earlier finality assessment |
| `arxia-transport` | Transport interface, fragment splitting and reassembly, simulated transport |
| `arxia-radio` | Blocking LoRa driver for the SX1276 family, generic over `embedded-hal` (not yet run on hardware) |
| `arxia-relay` | Relay receipts, relay scoring, signed penalty proofs |
| `arxia-did` | `did:arxia` identifiers derived from Ed25519 keys |
| `arxia-storage` | Storage interface, in-memory backends, shared conformance suite |
| `arxia-storage-redb` | Persistent storage backend on redb |
| `arxia-storage-flash` | Flash storage backend for embedded targets, power-loss safe |
| `arxia-flash-bench` | Power-loss bench protocol for the flash backend, as a `no_std` library |
| `arxia-proto` | Protobuf wire definitions and frame validation |
| `arxia-wasm` | WebAssembly bindings (placeholder, not implemented) |
| `arxia-bench` | Criterion benchmarks |

Other members of the workspace:

- `bin/arxia-node`: node binary (stub).
- `tools/arxia-cli`: key and DID generation. `tools/arxia-inspector`: stub.
- `examples/`: five example programs (`offline_payment`, `offline_settlement`,
  `did_issuance`, `mesh_relay`, `partition_reconciliation`).
  `offline_settlement` settles payments between separate processes that
  exchange only files of frames.
- `contracts/`: two example contract crates (`escrow`, `token-lock`). There
  is no contract runtime.
- `targets/esp32`: ESP32 target crate (`no_std`, radio driver not written
  yet).

Outside the workspace, two standalone Cargo projects built with the Xtensa
toolchain: `targets/esp32-bench`, the T-Beam power-loss bench firmware, and
`targets/esp32-node`, the first stage of the node firmware: the wallet and
the ledger on the board's own flash, checked at every boot over the serial
line. It builds; it has not been run on a board yet, and it has no radio.

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
- [Settlement](docs/architecture/SETTLEMENT.md)
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
