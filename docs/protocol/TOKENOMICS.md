# ARX token

> **Status:** the ARX token contract exists on a test network only. No token is live. There are no holders and no market.

Earlier versions of this page are superseded. None of their figures, schedules or plans apply.

## What the protocol code fixes

- **6 decimals.** Ledger balances are `u64` values in micro-ARX: `1 ARX = 1_000_000` micro-ARX (`ONE_ARX` in `crates/arxia-core/src/constants.rs`).
- **Local cap: 10 ARX.** A payment confirmed at the Local tier (code identifier `L0`) is capped at 10 ARX (`L0_CAP_MICRO_ARX`). See [FINALITY_MODEL.md](FINALITY_MODEL.md).
- **Representative threshold: 0.1% of supply.** Votes whose delegated stake is below 0.1% of total supply are filtered out by `collect_votes` (`MIN_REPRESENTATIVE_STAKE_DENOM` in `crates/arxia-consensus/src/orv.rs`).

No fee, staking reward or emission is implemented in the protocol code.

## Settlement

Arxia is an offline settlement layer: transactions are created, signed and propagated over long range radio with no internet, and the result anchors to an existing chain when a connection returns. The settlement layer is a direction we have committed to, not code that exists today. We will show it when it runs. Scope: a single settlement asset in v1.

## Audit scope

ERC-20 token contract audited by SolidProof, zero findings. The protocol, bridge, wallet and embedded code have not been audited yet.

## Contact

arxia.network@proton.me
