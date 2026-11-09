# Contracts

> **Status:** there is no contract runtime in Arxia today. `crates/arxia-wasm` is a placeholder crate (`WASM_VERSION = "0.1.0-stub"`) with no runtime, no host functions and no tests. The block format has four kinds (OPEN, SEND, RECEIVE, REVOKE; see [SERIALIZATION.md](../protocol/SERIALIZATION.md)) and no deploy block.

## What exists

The `contracts/` directory holds two native Rust library crates that prototype contract logic. They are built and tested as ordinary workspace members, not as WebAssembly:

| Crate        | Path                              | What it models |
|--------------|-----------------------------------|----------------|
| `escrow`     | `contracts/escrow/src/lib.rs`     | Funds released on a signed authorization, or refunded after a timeout |
| `token-lock` | `contracts/token-lock/src/lib.rs` | Deadline locks and cliff plus linear release schedules |

```bash
cargo test -p escrow -p token-lock
```

## Design notes (not implemented)

An earlier design sketched WebAssembly contracts compiled from Rust, run offline in a sandbox with a small host interface (balance query, transfer, block hash lookup, credential verification, logging), with no cross-contract calls, no floating point and no network access. The use case closest to the mission is releasing funds only to wallets that hold a verifiable credential issued by a trusted organisation. None of this is implemented, and it is not a commitment. The full design sketch is in [docs/architecture/WASM.md](../architecture/WASM.md).
