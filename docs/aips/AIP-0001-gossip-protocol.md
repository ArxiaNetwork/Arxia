# AIP-0001: Gossip Protocol

| Field       | Value                          |
|-------------|--------------------------------|
| **AIP**     | 0001                           |
| **Title**   | Gossip Protocol Specification  |
| **Status**  | Implemented as a library (`arxia-gossip`) |
| **Created** | 2025-01-15                     |

This AIP records the original proposal. The message set, merge behaviour and test coverage have since changed; docs/architecture/GOSSIP.md is the current specification.

## Motivation

Arxia nodes, linked over long range radio and other low bandwidth links, need a protocol to propagate blocks and
detect double-spend attempts. Given intermittent connectivity, the protocol
must be efficient (minimal bandwidth), convergent (CRDT-based), and
resilient to partitions.

## Specification

### Nonce Registry

Each node maintains a nonce registry:

```rust
pub type NonceKey = ([u8; 32], u64);        // (account pubkey, nonce)
pub type NonceEntry = [u8; 32];             // block hash
pub type NonceRegistry = BTreeMap<NonceKey, NonceEntry>;
```

Key: `(account public key, nonce)` tuple.
Value: hash of the block that claimed this `(account, nonce)`.

Keying on `(account, nonce)` — rather than on the block hash itself —
is what allows the registry to detect double-spends at the same nonce:
two blocks with the same `(account, nonce)` but different destinations
produce different hashes and would collide on the registry key,
surfacing the conflict. BTreeMap is mandatory for deterministic
iteration order.

### Messages

```rust
enum GossipMessage {
    BlockAnnounce {
        block_hash: [u8; 32],
        account: [u8; 32],
        nonce: u64,
    },
    SyncRequest {
        registry_subset: Vec<([u8; 32], u64)>,
    },
    SyncResponse {
        updates: Vec<([u8; 32], u64, [u8; 32])>,
    },
}
```

### Sync Protocol

1. Node A sends `SyncRequest` with its registry entries
2. Node B compares with local registry
3. Node B sends `SyncResponse` with entries where B has higher nonces
4. Node A merges response into local registry
5. If any entry has same nonce but different hash: conflict detected

### Merge Algorithm

```
for each ((account, nonce), remote_hash) in response:
    match local.get((account, nonce)):
        Some(local_hash) if local_hash == remote_hash:
            no-op (identical)
        Some(local_hash):
            push NonceConflict { key: (account, nonce),
                                 local_hash, remote_hash }
        None:
            local.insert((account, nonce), remote_hash)
```

Merge never silently overwrites. Conflicts are returned as a
`Vec<NonceConflict>` for the caller to resolve (the stake-weighted
resolver in `arxia-consensus::conflict` exists as a library and is not
yet called).

### SyncResult

```rust
enum SyncResult {
    Success,           // All entries consistent
    Mismatch(usize),   // N conflicts detected
    NoNeighbors,       // No peers to sync with
}
```

Mesh finality (code `FinalityLevel::L1`) requires `SyncResult::Success`.

## Rationale

- BTreeMap over HashMap: Deterministic ordering is critical for reproducible
  conflict detection and testing.
- Nonce-based: Compact representation (~40 bytes per account) fits LoRa MTU.
- Merge semantics: Higher nonce always wins (monotonically increasing).

## Test Results

The nonce registry, registry merge, conflict reporting and message validation are covered by unit tests in `crates/arxia-gossip` (`node.rs`, `nonce_registry.rs`, `message.rs`, `signed_message.rs`). A multi-node convergence suite over linear, star and fully connected topologies does not exist in this repository yet.

## Implementation

- Crate: `arxia-gossip`
- Entry point: `sync_nonces_before_l1()`
- Tests: unit tests in `crates/arxia-gossip` (see Test Results above)
