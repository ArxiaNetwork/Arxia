# Arxia Architecture Overview

Arxia is an offline settlement layer: transactions are created, signed and propagated over long range radio with no internet, and the result anchors to an existing chain when a connection returns. Long range LoRa radio is the first target transport; Bluetooth, SMS and satellite are planned behind the same transport trait. No radio driver exists in this repository yet: tests and examples run over a simulated link.

This repository holds the protocol core: a block lattice with one chain per account, stake-weighted representative voting (ORV), CRDT reconciliation when partitions rejoin, and finality assessment. Every transaction fits in one 193-byte radio packet. These pieces are implemented and tested as libraries; no running node ties them together yet.

The settlement layer is a direction we have committed to, not code that exists today. We will show it when it runs.

## Layer Diagram

```
+------------------------------------------------------------------+
|      Batch and Anchored (settlement direction, no code yet)      |
+------------------------------------------------------------------+
|           Finality tiers (Local, Mesh, full consensus)           |
+------------------------------------------------------------------+
|    Gossip Protocol  |  ORV Consensus  |  Conflict Resolution     |
+------------------------------------------------------------------+
|             CRDT Reconciliation (PN-Counter, OR-Set)             |
+------------------------------------------------------------------+
|   Block Lattice (per-account chains)  |  did:arxia identifiers   |
+------------------------------------------------------------------+
|      Storage (in-memory, redb, flash for embedded targets)       |
+------------------------------------------------------------------+
|            Cryptographic Primitives (Ed25519, Blake3)            |
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
       +-- arxia-lattice (Block, AccountChain, VectorClock)
       |    +-- arxia-crdt (PNCounter, ORSet, reconciliation)
       |    +-- arxia-consensus (ORV votes, conflict resolution, quorum)
       |    +-- arxia-gossip (nonce registry, sync protocol)
       +-- arxia-did (did:arxia derivation and parsing)
       +-- arxia-transport (transport trait, signed messages, fragment
       |                    reassembly, simulated link; no radio driver yet)
       +-- arxia-relay (relay receipts, scoring, signed penalty proofs)
       +-- arxia-storage (storage trait, in-memory backends)
            +-- arxia-storage-redb (redb persistent backend)
            +-- arxia-storage-flash (flash backend for embedded targets)
                 +-- arxia-flash-bench (power-loss bench protocol)
  +-- arxia-finality (tier assessment, monotonic latch)
  +-- arxia-wasm (placeholder, not implemented; see WASM.md)
  +-- arxia-proto (protobuf definitions)
bin/arxia-node (stub; gated by docs/SECURITY_INTERFACES.md)
```

## Design Principles

1. **Offline-first**: the protocol core is designed so that no operation needs the internet. Nodes in radio reach of each other are meant to settle their own transactions with no connection. A connection is needed only to anchor to an existing chain, which is a direction, not code that exists today.

2. **Deterministic**: BTreeMap for ordered iteration, xorshift64 PRNG for reproducible transport simulation, stable hash ordering for conflict resolution.

3. **Minimal trust**: no oracles and no central arbiter. Conflicts are designed to be settled by the nodes themselves, through stake-weighted voting and CRDT convergence. Today partition reconciliation picks the surviving block by hash and does not yet call the stake-weighted resolver. In the settlement direction, the sequencer orders and anchors; it never arbitrates.

4. **Constrained-device friendly**: 193-byte compact blocks fit the 256-byte LoRa MTU used in this code. Ed25519 and Blake3 are efficient on ESP32.

5. **Partition tolerant**: CRDTs guarantee eventual consistency after network partitions heal. No liveness dependency on quorum for local transactions.
