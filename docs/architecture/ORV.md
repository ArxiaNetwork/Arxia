# Open Representative Voting (ORV) Specification

## Overview

ORV is Arxia's consensus mechanism, adapted from Nano's design with
modifications for offline operation. Representatives vote on blocks
weighted by delegated stake.

## Vote Structure

```rust
pub struct VoteORV {
    pub block_hash: [u8; 32],
    pub voter_pubkey: [u8; 32],
    pub delegated_stake: u64,
    pub nonce: u64,
    pub signature: [u8; 64],
}
```

## Vote Hash Computation

The vote hash is computed over an 80-byte input:
- bytes 0..32: block_hash
- bytes 32..64: voter_pubkey
- bytes 64..72: delegated_stake (little-endian)
- bytes 72..80: nonce (little-endian; monotonic, prevents vote replay)

This is then Blake3-hashed and Ed25519-signed. See `compute_vote_hash` in `crates/arxia-consensus/src/vote.rs`.

## 3-Tier Conflict Resolution Cascade

When two blocks conflict (same account, same nonce):

1. **Stake-weighted**: Sum the delegated stake of the votes for each candidate. If the gap
   exceeds 5% of the two candidates' combined stake, the higher-stake candidate wins.
2. **Vector clock**: (Reserved for future implementation.) Compare causal
   ordering via vector clocks.
3. **Hash tiebreaker**: Lexicographically smaller block hash wins.
   Deterministic and requires no additional communication.

## Quorum Requirements

- At least 2/3 of known representatives must have voted
- At least 20% of total stake must be represented
- Both conditions must be met simultaneously

## Minimum Delegation

A vote is only counted if the representative's delegated stake is at least 0.1% of total supply (`total_supply / 1000`, integer division; see `crates/arxia-consensus/src/orv.rs`). This prevents Sybil attacks via many low-stake voters.

## Delegation

In the design, a representative's voting power is the sum of the stake
delegated to it plus its own. Today the stake is passed into the vote
directly; delegation is not yet reconstructed from the ledger.
