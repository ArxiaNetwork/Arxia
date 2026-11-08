# Threat Model

Scope: the protocol core in this repository (block lattice, ORV consensus, gossip, relay scoring, finality). The settlement layer is a direction we have committed to, not code that exists today. We will show it when it runs. Anchoring and withdrawal threats are therefore not modelled here yet.

ERC-20 token contract audited by SolidProof, zero findings. The protocol, bridge, wallet and embedded code have not been audited yet.

## 1. Sybil Attacks

**Threat**: Attacker creates many identities to influence consensus.

**Mitigation**: ORV is stake-weighted. Creating identities without stake
provides no voting power. A representative's vote counts only if its stake is at least 0.1% of total supply, which prevents dust-stake attacks.

## 2. Double-Spend Attacks

**Threat**: User creates two conflicting Send blocks with the same nonce.

**Detection**: Gossip protocol detects nonce collisions with different
block hashes. Nonce registry stores (account, nonce, block_hash) tuples.

**Resolution**: a node that already holds a block for an account's sequence number rejects a second, different one. When partitions rejoin, reconciliation keeps exactly one block per account sequence number, chosen the same way on every node, and the other is dropped and reported as a conflict. Today reconciliation chooses by block hash. The stake-weighted ORV cascade in `arxia-consensus` (stake first, then block hash; the vector clock tier is reserved) is implemented as a library but is not yet called by reconciliation. A payment can never end up counted twice in the ledger.

**Exposure before groups meet**: two groups that cannot see each other can each confirm their own side of a conflicting pair, at the Local tier with a single nearby node and at the Mesh tier with the nodes in reach. That is why Local is capped at 10 ARX in code, and why value caps above Local are set per pilot and documented in the pilot agreement.

## 3. Eclipse Attacks

**Threat**: Attacker surrounds a target node, controlling all its peers.

**Mitigation** (design; the radio, BLE and satellite drivers are not implemented yet): multi-transport redundancy. Even if LoRa peers are controlled, BLE proximity with the counterparty would provide an independent channel, and satellite broadcast is planned as another independent data source.

## 4. Relay Gaming

**Threat**: Relay operators selectively forward or withhold transactions.

**Mitigation**:
- Relay scoring tracks success/failure ratio
- A relay counts as trusted while its cumulative score is at or above a configurable threshold (default: a positive score); a separate rolling-window score is available to callers
- Signed penalty proofs (`SlashingProof`) lower a relay's reputation score; no stake is taken
- Cryptographic relay receipts provide evidence of forwarding

## 5. Partition Manipulation

**Threat**: Attacker deliberately partitions the network to exploit
inconsistency.

**Mitigation**: CRDTs guarantee eventual consistency. After partition heals,
state converges deterministically. Finality tiers (Local, Mesh, full consensus) communicate the confidence level to users. A payment above the 10 ARX Local cap needs at least Mesh, and an application that wants more confidence waits for full consensus (code tier `L2`): signed votes from registered validators holding at least 67% of registered stake.

## 6. Long-Range Attacks

**Threat**: Attacker uses old keys to create alternative history.

**Mitigation**: Block lattice structure makes long-range attacks difficult
because each account chain is independent. Rewriting one chain does not
affect others. Nonce monotonicity prevents replaying old blocks.

## 7. Transaction Censorship

**Threat**: Validators refuse to vote on certain transactions.

**Mitigation**: ORV does not require specific validators. Any representative
with sufficient stake can vote. Multiple transports are designed to give a transaction alternative propagation paths; production transports are in progress, and only the simulated transport is implemented in this repository today.

## 8. Key Compromise

**Threat**: An attacker obtains a user's private key.

**Mitigation**:
- ChaCha20-Poly1305 encryption for local key storage *(planned;
  `arxia_crypto::chacha20` currently returns `Err(Unimplemented)`
  post-CRIT-002 / PR #41 — no on-disk encryption is active until the
  real implementation lands)*
- SLIP39 seed backup for recovery *(planned; `arxia_crypto::slip39`
  also returns `Err(Unimplemented)` post-CRIT-003 / PR #41)*
- Users should rotate keys periodically
- REVOKE blocks are designed to invalidate compromised DID credentials (credential handling is not implemented yet)

## 9. Carrington Event (Solar Storm)

**Threat**: A severe solar storm destroys electronic infrastructure over a wide area.

**Mitigation** (design intent): nodes are T-Beam class boards costing tens of dollars, so spares are cheap to keep. Battery-operated nodes with solar panels can survive grid failures. Nodes in radio reach of each other are designed to keep settling their own transactions with no internet. Satellite state snapshots for recovering nodes are planned, not implemented.

## 10. Denial of Service

**Threat**: Attacker floods the network with transactions.

**Mitigation**: no transaction fee is implemented yet, so flooding is not priced today. LoRa duty cycle limits (1% EU) naturally rate-limit individual nodes. The simulated transport bounds its queues and reassembly caps in-flight messages per peer; production transports must keep the same bounds and can enforce per-peer rate limits.
