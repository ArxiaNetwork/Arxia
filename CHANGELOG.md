# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Documentation

- New `docs/architecture/SETTLEMENT.md` describes settlement as the code performs it. The architecture overview is rewritten around it, `FINALITY.md` leads with the current meaning of the tiers, and the pages and modules of the earlier consensus design (ORV, reconciliation by hash, gossip nonce registry, earlier finality assessment) carry a notice that they are kept for reference and will be removed.
- The README describes settlement as the code performs it: witnesses in radio reach, equivocation proofs, certified reserves and issuance certificates. The status lists are brought up to date, and the earlier consensus design is identified as kept for reference and due for removal.
- Documentation and workspace metadata now describe Arxia as an offline settlement layer. Links point to https://github.com/ArxiaNetwork/Arxia and https://arxia.network, and the security contact is arxia.network@proton.me. No code behaviour or identifier changed.

### Security

- **Dependency advisories**: `rustix` 1.1.4 to 1.1.6 (RUSTSEC-2026-0486). The nine `heapless` 0.8.0 advisories (RUSTSEC-2026-0574 to 0582) are ignored with a written rationale in `docs/dependency-risks.md`: the crate is resolved only for the host-side mock flash and none of the affected types is used. Routine updates: `rand` 0.10.4, `prost` and `prost-build` 0.14.6.
- **Authentication at the receiving boundary**: `AccountChain::receive` authenticates the SEND itself (hash recomputed from content, strict signature check under the sending account) before any state changes, in addition to the ledger checks. Funding remains a ledger decision.
- **Reconciliation authenticates its inputs**: `reconcile_partitions` verifies every block of both partitions before merging, where it previously required callers to pass authenticated blocks. A block that fails verification has no effect on the merge and is listed in the new `ReconciliationReport::rejected_blocks`.
- **Bug 1: Double-receive prevention** ([#17](https://github.com/ArxiaNetwork/Arxia/pull/17)): track consumed SEND hashes per account to prevent a receiver from applying the same SEND block twice.
- **Bug 2: Ed25519 signature verification in `add_block`** ([#12](https://github.com/ArxiaNetwork/Arxia/pull/12)): verify Ed25519 signatures on every insertion path, including gossip ingress, closing a missing check that allowed forged blocks to be accepted.
- **Bug 3: Idempotent `AccountChain::open`** ([#13](https://github.com/ArxiaNetwork/Arxia/pull/13)): make `open` idempotent so that replaying an `OPEN` block on an already-opened chain is rejected cleanly instead of silently mutating state.
- **Bug 4: NonceRegistry rekeyed from hash to `(account, nonce)`** ([#18](https://github.com/ArxiaNetwork/Arxia/pull/18)): the registry was keyed by block hash, which meant two signed blocks reusing the same nonce with different payloads were not flagged as a double-spend. Rekeying to `(account, nonce)` now returns `ArxiaError::DoubleSpend` at merge time.
- **Bug 5: Timestamp-in-hash determinism** ([#19](https://github.com/ArxiaNetwork/Arxia/pull/19)): pin regression tests that assert the timestamp is included in the Blake3 preimage, preventing accidental removal that would make block hashes malleable.
- **Bug 6: Per-account supply cap on `OPEN`** ([#14](https://github.com/ArxiaNetwork/Arxia/pull/14)): enforce the protocol supply cap at `open` time so a newly-created account cannot declare a genesis balance above `MAX_SUPPLY_PER_ACCOUNT`.
- **Bug 7: CRDT conflict + non-negative balance invariant** ([#20](https://github.com/ArxiaNetwork/Arxia/pull/20)): `reconcile` now detects `(account, nonce)` conflicts and enforces `balance >= 0` post-merge, preventing partition reconciliation from producing negative balances.
- **RUSTSEC-2026-0097** ([#25](https://github.com/ArxiaNetwork/Arxia/pull/25)): bump `rand` from `0.8.5` to `0.8.6`. Arxia uses `OsRng` (not `ThreadRng`), so the project is not believed to be affected in practice, but the patched release is taken for a clean audit baseline.

### Added

- `arxia-radio`: a blocking LoRa driver for the Semtech SX1276 family, generic over `embedded-hal` 1.0 and `no_std`. It resets and identifies the chip, applies a configuration that has no default frequency, transmits one packet with a bounded wait, and receives with checksum filtering. It is tested against a register-level model of the chip, including a signed fragment crossing two modelled radios, and joins the bare-metal gate in CI. It has not been run on hardware.
- `targets/esp32-node`: first stage of the node firmware for the T-Beam. The wallet and the ledger run on the board, on its own flash: the signing seed is drawn from the true random number generator, the wallet is rebuilt from flash at every boot, a payment is signed, verified and credited by a second wallet, and each step is reported on the serial line. It builds with the Xtensa toolchain and is built in CI; it has no radio and has not been run on a board yet.
- The durable wallet is tested on the flash backend over its fault-injecting mock: power cycles, witness-settled payments between flash-backed devices, power cut at every write boundary of a payment and of a receive, a reserve and an equivocation proof on flash, and a full flash.
- Settled starting points: a block the witnesses settled can be the first block a ledger holds for an account, or carry its chain forward over blocks it never saw. A receiver with an empty ledger credits a payment from the payment block and its confirmations alone, and `DurableWallet::delta_bundle` shows the witnesses only what a payer did since its own last settled block, so bundle size follows recent activity instead of the age of the account.
- The witness node and the transport layer build without the standard library. `Witness` and `receive_final` now live in `arxia_lattice::witness` (still re-exported from `arxia_finality::witness`), and `arxia-transport` gains a default `std` feature that holds only the simulated link. Both crates join the bare-metal gate in CI.
- `arxia-lattice` builds without the standard library (`--no-default-features`, `no_std` with `alloc`) and joins the bare-metal gate in CI. Key generation from OS entropy and the wall clock sit behind the default `std` feature; a device uses `AccountChain::from_seed`, `Wallet::from_seed`, `DurableWallet::open_with_entropy` and `set_clock`. Maps and sets are ordered on every target, which changes the type of `Ledger::chains` and `AccountChain::consumed_sources`.
- Transport: `arxia_transport::fragment` splits a message into signed fragments that each fit one MTU, and `Fragment::to_bytes` / `from_bytes` define their wire encoding, completing the sending side of the existing reassembly. A bundle of any size now crosses a link as packets of at most one MTU; tests settle a payment across the simulated radio link with reordered, repeated and lost packets.

- Reserve certificates and equivocation proofs travel in bundles (frame tags 5 and 6). A payment carries the backing of its funds and every proof its sender knows of, and `ingest_bundle` applies items in a fixed order: issuance, reserves, history, proofs. The process-level example gains `request`, `reserve` and `receive --mode isolated`, and its tests cover a reserve paying a receiver with no witness in reach.

- Convergence on settled blocks: a ledger that took in the block of an equivocating pair that did not become final now follows the witnesses. `Ledger::replace_with_settled` removes the held block and what the account built on it, where nothing settled or already received depends on them, and takes in the settled block; `Wallet::ingest` does it automatically and `DurableWallet` mirrors it on storage in one batch. Block sequence numbers on storage are no longer reused.

- Settled blocks: `Ledger::add_settlement` records a block as final under the witness roster and keeps the confirmations. A settled block is exempt from the freeze that follows an equivocation, so the party that was paid, and whoever it pays next, are not affected by what the payer signs afterwards. `receive_final` keeps the confirmations of what it credits, bundles carry them, and `DurableWallet` stores them.

- Bundles (`arxia_lattice::bundle`): the frame format one device hands to another. A payment travels as issuance certificates, history blocks and the payment block, each frame at most 238 bytes so that it fits one LoRa packet. `DurableWallet::payment_bundle` builds a bundle, `ingest_bundle` replays one under the ledger rules, and `history` returns the stored blocks in acceptance order.
- `examples/offline_settlement`: the settlement rules end to end between separate operating-system processes. Each run is one device doing one thing (signing, witnessing, receiving) on its own redb database; devices exchange only files of frames. Its tests settle two payments in a row and show that a restored copy of a wallet cannot pay a second time. It is a demonstration, not the node.

- Certified reserves (`arxia_lattice::reserve`): an owner moves an amount to a reserve account and has the witnesses confirm it; the resulting `ReserveCertificate` lets a receiver with no witness in reach, and without the funding history, accept payments from that reserve up to the certified amount. A reserve spent twice yields an equivocation proof as for any account, and a ledger holding the proof and the certificate also freezes the owner account after the funding block. `WalletConfig` groups the issuance policy and the witness roster; `DurableWallet::open_with_config` stores and re-verifies reserve certificates. The confirmation-counting types now live in `arxia_lattice::witness` and stay re-exported from `arxia_finality::witness`.

- Equivocation proofs (`arxia_lattice::equivocation`): two authentic blocks for one account position form an `EquivocationProof` that any node can verify and pass on. A wallet that sees both blocks keeps the proof automatically. A ledger holding a proof freezes the account from that position: nothing new is accepted from it there or after, and its unsettled SENDs in that range can no longer be received, while its earlier blocks stay acceptable. `DurableWallet` stores proofs.

- Witnesses (`arxia_finality::witness`): a `Witness` confirms a block only when its own durable ledger accepts it, so it never confirms two blocks for the same account position, including across a restart. A receiver counts confirmations with `assess` under a `WitnessRoster`; a payment is final when the confirming weight is more than two thirds of the roster total, and `receive_final` credits only final payments. The decision takes nothing from the caller but the roster.

- Issuance policy (`arxia_lattice::issuance`): a ledger built with `Ledger::with_issuance` accepts a non-zero opening balance only for an account and an amount covered by an `IssuanceCertificate` signed by enough of the policy issuer keys. Certificates are self-contained, travel with payments, and fit the flash value limit. `Wallet` and `DurableWallet` gain the matching constructors, `open_certified` and `ingest_issuance`. `Ledger::new` keeps its behaviour for simulations and tests.

- `arxia_lattice::DurableWallet`: a wallet persisted through any `StorageBackend`. A signed block is returned only after storage has accepted it, so a device that loses power cannot come back having released a signature it no longer remembers. Opening replays every stored block through the ledger rules. `Wallet::restore` and `Wallet::seed` support it; `StorageFault` gains `RecordUndecodable` and `ReopenRequired`.

- `arxia_lattice::Wallet`: an account together with the ledger that validates it. Blocks from another device enter through `Wallet::ingest` under the full ledger rules, and `Wallet::receive` credits a payment only when the receiver has replayed its funding. Every operation updates account and ledger together or leaves both untouched.

- CI badge, Meshtastic disclaimer, and repository history note in `README.md` ([#22](https://github.com/ArxiaNetwork/Arxia/pull/22)).
- First transaction between two T-Beam boards over LoRa radio with no internet in the loop (`2026-04-18`). It ran through a bridge, not through the node binary in this repository.

### Changed

- MSRV raised from `1.89.0` to `1.90.0`, required by `redb` 4.2.0 and later. The toolchain file, the manifests, `clippy.toml`, the CI workflows and the LOW-014 pin test move together.
- Bump `redb` from `4.1.0` to `4.4.0`. `4.2.0` fixed the two crash windows around file growth that `4.1.0` carried. The kill-nine test no longer pre-grows the file and gains a large-value test, and a database written by `4.1.0` opens under `4.4.0` with every key intact.
- Bump `criterion` from `0.5.1` to `0.7.0` via workspace dependency ([#24](https://github.com/ArxiaNetwork/Arxia/pull/24)). Held at `0.7` because `0.8.x` requires Rust `1.86` while the workspace MSRV is pinned to `1.85.0`.
- `arxia-bench` now consumes `criterion` through `[workspace.dependencies]` instead of an inline version.

### Fixed

- `.gitignore` was silently excluding the `docs/` tree on case-insensitive filesystems; restored tracking and re-synced `docs/architecture/GOSSIP.md` and `docs/aips/AIP-0001-gossip-protocol.md` with the post-#18 API ([#21](https://github.com/ArxiaNetwork/Arxia/pull/21)).

### CI

- `Security Audit` workflow rewritten ([#23](https://github.com/ArxiaNetwork/Arxia/pull/23)): explicit `permissions:` block (`checks: write`, `issues: write`), toolchain pinned to `1.85.0`, `rustsec/audit-check@v2` replaced with a direct `cargo install --locked cargo-audit && cargo audit --deny warnings` invocation, and a `pull_request` trigger scoped to `Cargo.toml` / `Cargo.lock` / the workflow file itself.

## [0.1.0] - 2025-01-15

### Added

- Block lattice with per-account chains (SEND/RECEIVE/OPEN/REVOKE)
- Ed25519 signatures over raw Blake3 hash bytes
- Open Representative Voting (ORV) consensus
- 3-tier conflict resolution cascade (stake > vector_clock > hash_tiebreaker)
- CRDT reconciliation (PN-Counter, OR-Set, Vector Clocks)
- Gossip protocol with nonce registry and double-spend detection
- 4-level finality assessment: not yet confirmed, Local, Mesh and full consensus (`FinalityLevel::Pending`, `L0`, `L1`, `L2` in code)
- Multi-modal transport abstraction (LoRa, BLE, SMS, Satellite)
- SimulatedTransport with deterministic xorshift64 PRNG
- Relay scoring and slashing system
- W3C Decentralized Identifiers (did:arxia: method)
- 193-byte compact block serialization
- ChaCha20-Poly1305 local encryption interface (stub, not implemented)
- Pluggable storage backend
- Protobuf message definitions
- Criterion benchmark harness
- ESP32 target (no_std stub)
- 4 example programs
- 2 example contracts (escrow, token-lock)
- CLI tools (keygen, DID generation)
