# Finality Tiers

## Overview

A payment in Arxia does not wait for one global ordering. Each block is assessed against tiers of increasing confidence: a small payment between neighbours confirms as soon as the nodes around it see it, and a larger one waits until more of the network has seen it. The full specification is in [`docs/protocol/FINALITY_MODEL.md`](../protocol/FINALITY_MODEL.md).

## Tiers

The public names of the tiers are Local, Mesh, Batch and Anchored. The code in this repository implements Local, Mesh and full consensus. The enum variants in `arxia-finality::FinalityLevel` carry the internal identifiers `Pending`, `L0`, `L1` and `L2`; renaming them is a separate engineering task.

| Tier (code identifier) | Condition |
|---|---|
| Not yet confirmed (`Pending`) | None of the conditions below is met |
| Local (`L0`) | Amount at or below 10 ARX and at least one signed confirmation over this block hash from a key in the validator registry |
| Mesh (`L1`) | The caller reports `SyncResult::Success`: the local nonce registry matches a neighbour's on every account sequence number |
| Full consensus (`L2`) | Signed votes over this block hash from registered validators holding at least 67% of registered stake |

Batch and Anchored belong to the settlement layer. The settlement layer is a direction we have committed to, not code that exists today. We will show it when it runs.

## Assessment

`assess_finality(amount_micro_arx, block_hash, confirmations, sync_result, votes, registry)` returns `Result<FinalityLevel, FinalityError>` and checks the tiers from the top down: full consensus first, then Mesh, then Local, otherwise Pending. Confirmations and votes carry Ed25519 signatures bound to the block hash, and only keys in the validator registry count. Two inputs are not yet authenticated by this crate: the `SyncResult` that grants Mesh is supplied by the caller, and the validator registry is populated by the caller. Consensus is not yet wired to finality. `FinalityLatch` keeps finality monotonic: once a block reaches a tier, later assessments through the latch never return a lower one.

## Local cap

`L0_CAP_MICRO_ARX = 10_000_000` (10 ARX at 6 decimals). A payment above this amount cannot reach the Local tier and waits for Mesh or full consensus.

The cap exists because a group cut off from the rest of the network can confirm a payment before the whole network has seen it. Two groups that cannot see each other can each confirm their own side of a conflicting pair: at the Local tier with a single nearby node, at the Mesh tier with the nodes in reach. When they meet, reconciliation keeps exactly one block per account sequence number, chosen the same way on every node, and the other is dropped and reported as a conflict. Today that choice is made by block hash; the stake-weighted resolver in `arxia-consensus` is not yet called by reconciliation.

Value caps for the other tiers are set per pilot and documented in the pilot agreement. No value cap above Local is enforced in code today: the constant `L1_CAP_USD` in `crates/arxia-core/src/constants.rs` is declared but not used by the assessment.

## Mesh gossip requirement

Mesh finality depends on `SyncResult::Success` from the gossip nonce sync. If the sync returns `Mismatch` or `NoNeighbors`, the block falls back to Local (if the amount qualifies and a signed confirmation exists) or stays Pending, unless full consensus is already reached.
