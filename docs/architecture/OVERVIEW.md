# Arxia Architecture Overview

Arxia is an offline settlement layer: transactions are created, signed and propagated over long range radio with no internet, and the result anchors to an existing chain when a connection returns. Long range LoRa radio is the first target transport; Bluetooth, SMS and satellite are planned behind the same transport trait. No radio driver exists in this repository yet: tests and examples run over a simulated link.

This repository holds the protocol core: a block lattice with one chain per account, a ledger and a wallet that validate every block a device takes in, issuance certificates, witness settlement, equivocation proofs and certified reserves. Every block fits in one 193-byte radio packet. These pieces are implemented and tested as libraries, and they build without the standard library. An example program settles payments between separate processes; the node binary is a stub, and the device firmware is a first stage with no radio. [SETTLEMENT.md](SETTLEMENT.md) describes how a payment is settled.

The settlement layer is a direction we have committed to, not code that exists today. We will show it when it runs.

## Layer Diagram

```
+------------------------------------------------------------------+
|      Batch and Anchored (settlement direction, no code yet)      |
+------------------------------------------------------------------+
|   Local: certified reserves   |   Mesh: witness confirmations    |
+------------------------------------------------------------------+
|     Equivocation proofs, account freeze, settled starting points |
+------------------------------------------------------------------+
|      Wallet and ledger (one chain per account, issuance)         |
+------------------------------------------------------------------+
|      Storage (in-memory, redb, flash for embedded targets)       |
+------------------------------------------------------------------+
|            Cryptographic Primitives (Ed25519, Blake3)            |
+------------------------------------------------------------------+
|        Bundles of frames, signed fragments of one MTU each       |
+------------------------------------------------------------------+
|   Transport trait (LoRa first; BLE, SMS, satellite; simulated)   |
+------------------------------------------------------------------+
```

## Crate Dependency Graph (simplified)

```
arxia-core (types, errors, constants)
  +-- arxia-crypto (Ed25519, Blake3: shipped;
                    ChaCha20, SLIP39: stub, Err(Unimplemented), see
                    docs/protocol/CRYPTOGRAPHY.md)
       +-- arxia-storage (storage trait, in-memory backends)
       |    +-- arxia-storage-redb (redb persistent backend)
       |    +-- arxia-storage-flash (flash backend for embedded targets)
       |         +-- arxia-flash-bench (power-loss bench protocol)
       +-- arxia-lattice (blocks, ledger, wallet, persistence, issuance,
       |    |             witnesses, equivocation proofs, reserves, bundles)
       |    +-- arxia-finality (re-exports the witness types; the earlier
       |    |                   finality assessment)
       |    +-- arxia-crdt (PNCounter, ORSet; reconciliation: earlier design)
       |    +-- arxia-consensus (ORV votes, quorum: earlier design)
       |    +-- arxia-gossip (nonce registry, sync: earlier design)
       +-- arxia-transport (transport trait, signed messages, fragment
       |                    splitting and reassembly, simulated link;
       |                    no radio driver yet)
       +-- arxia-did (did:arxia derivation and parsing)
       +-- arxia-relay (relay receipts, scoring, signed penalty proofs)
  +-- arxia-wasm (placeholder, not implemented; see WASM.md)
  +-- arxia-proto (protobuf definitions)
bin/arxia-node (stub; gated by docs/SECURITY_INTERFACES.md)
targets/esp32-node (device firmware, first stage, no radio)
```

`arxia-core`, `arxia-crypto`, `arxia-storage`, `arxia-storage-flash`, `arxia-flash-bench`, `arxia-lattice` and `arxia-transport` build for a bare-metal target with no default features; CI checks this on every push and pull request to `main`.

## Design Principles

1. **Offline-first**: the protocol core is designed so that no operation needs the internet. Nodes in radio reach of each other are meant to settle their own transactions with no connection. A connection is needed only to anchor to an existing chain, which is a direction, not code that exists today.

2. **Deterministic**: ordered maps on every target, so a host and a device iterate in the same order, and an xorshift64 PRNG for reproducible transport simulation.

3. **Minimal trust**: no oracles and no central arbiter. A device checks on its own everything that can be decided from the blocks it holds. What it cannot see alone, whether a payer signed something else elsewhere, is settled by the witnesses in reach, above two thirds of the roster weight. In the settlement direction, the sequencer orders and anchors; it never arbitrates.

4. **Constrained-device friendly**: 193-byte compact blocks fit the 256-byte LoRa MTU used in this code. Ed25519 and Blake3 are efficient on ESP32.

5. **Partition tolerant**: a group of devices cut off from the rest settles its own payments with the witnesses it can reach. With no witness in reach, a certified reserve bounds what a receiver risks. Two blocks signed for one account position are a proof that travels with later payments and freezes the account in every ledger that holds it.
