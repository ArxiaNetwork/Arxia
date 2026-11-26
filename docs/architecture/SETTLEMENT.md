# Settlement

This page describes how a payment is settled in this repository today: what a device checks on its own, what witnesses add, what happens when an account signs two blocks for one position, and how a payment is made where no witness is in reach. It follows the code in `arxia-lattice`.

Nothing here needs the internet. Anchoring to an existing chain is a direction, not code that exists today.

## The parts

| Part | Where | Role |
|---|---|---|
| Block, account chain | `arxia_lattice::block`, `chain` | One chain per account. Each block carries a sequence number, the hash of the previous block and an Ed25519 signature over its Blake3 hash. A block serializes to 193 bytes. |
| Ledger | `arxia_lattice::ledger` | Decides whether a block is acceptable given everything held so far: authentic, in sequence, funded, received once. |
| Wallet | `arxia_lattice::wallet` | An account together with the ledger that validates it. Every block from another device enters through it. |
| Durable wallet | `arxia_lattice::durable` | The wallet on a storage backend. A signed block is on storage before it is handed out. |
| Issuance | `arxia_lattice::issuance` | Who may bring value into a ledger. |
| Witnesses | `arxia_lattice::witness` | Nodes that confirm a block only when their own ledger accepts it, and the count that makes a block final. |
| Equivocation | `arxia_lattice::equivocation` | Two signed blocks for one account position, as a proof. |
| Reserves | `arxia_lattice::reserve` | Paying where no witness is in reach. |
| Bundles | `arxia_lattice::bundle` | What one device hands to another, as frames of at most one radio packet. |
| Fragments | `arxia_transport::reassembly` | A bundle split into signed packets of at most one MTU, and put back together. |

All of them build without the standard library.

## What a receiver checks alone

A receiver replays the blocks it is handed under the ledger rules:

- the hash of each block matches its content and its signature verifies under the account it names;
- each block follows the previous one of its account, by sequence number and by hash;
- every balance is derived from the chain, never taken from what a block states about itself;
- a SEND never exceeds the balance before it;
- a RECEIVE is accepted only against a matching SEND addressed to that account, and a SEND funds one RECEIVE.

Under an issuance policy, an account opens with a balance only when enough of the configured issuer keys signed a certificate for that account and that exact amount. The certificate travels with the blocks.

What a receiver cannot check alone is whether the payer signed something else, elsewhere, for the same position.

## Witnesses

A witness is a node that keeps a ledger and signs a confirmation for a block only when its own ledger accepts it. The block is on the witness's storage before the confirmation is signed, so a witness never confirms two different blocks for the same account position, including after a restart.

A receiver recognises a roster of witnesses, each with a weight. A block is final when the witnesses that confirmed exactly that block hold more than two thirds of the roster weight. Two quorums of more than two thirds share more than one third of the weight, so two conflicting blocks cannot both become final while witnesses holding more than one third of the weight follow the rules.

A confirmation counts only if it names the block, comes from a roster witness other than the block's own account, verifies, and is the first from that witness. Anything else is ignored rather than fatal.

The roster and the issuer keys are configuration today. There is no on-ledger bond and no penalty for a witness.

## Two signatures for one position

Two different blocks at one account position, both carrying the account's signature, can only come from the holder of the account key. Together they are an equivocation proof that anyone can verify from the two blocks alone.

A ledger that holds a proof freezes the account from that position: nothing new is accepted from it there or after, and a SEND it holds in that range can no longer be received. Blocks before that position are untouched.

A block the witnesses settled is exempt. It stays acceptable and, if it is a SEND, receivable: the party that was paid, and whoever that party pays next, are not affected by what the payer signs afterwards. A ledger that had taken in the block of the pair that did not become final replaces it with the settled one, where nothing settled or already received depends on what it removes.

Proofs travel with payments, so news of an equivocation spreads along the same paths as value.

## Starting from a settled block

A settled block can be the first block a ledger holds for an account, or carry its chain forward over blocks the ledger never saw. The witnesses replayed what precedes it; the balance the block states is the starting balance, and the ordinary rules apply to every later block.

This keeps payments small:

- a receiver with an empty ledger credits a payment from the payment block and its confirmations, under 600 bytes with three confirmations;
- a payer shows the witnesses its own blocks since the last one they settled, together with the settled SENDs it received in that span.

A block that is not settled cannot start a chain.

## No witness in reach

While witnesses are reachable, an account can move an amount to a second account it also controls, the reserve account, and have the witnesses confirm it. The funding SEND, the reserve account's empty opening block, its RECEIVE and the confirmations form a reserve certificate.

A receiver with nobody to ask verifies the certificate against the roster it carries and accepts payments from that reserve, up to the certified amount.

It cannot know whether the same reserve was also spent towards someone else. A reserve bounds that exposure to an amount chosen in advance, and two spends of one reserve position are an equivocation proof as for any account; a ledger holding the proof and the certificate also freezes the owner's account after the funding block.

## Tiers

The public tiers are Local, Mesh, Batch and Anchored.

| Tier | In this repository |
|---|---|
| Local | A payment from a certified reserve, accepted with no witness in reach. |
| Mesh | A payment confirmed by witnesses in radio reach, above two thirds of the roster weight. |
| Batch | Settlement direction, no code yet. |
| Anchored | Settlement direction, no code yet. |

## Persistence and power loss

A signed block is returned to the caller only after the storage backend has accepted it. A device that loses power comes back either without the block and with the account position still free, or with the block on storage and the position taken. Opening replays every stored block under the ledger rules.

The wallet runs on the in-memory, redb and flash backends. On the flash backend it is tested with power cut at every write boundary of a payment and of a receive. See [POWER_LOSS_PROTOCOL.md](POWER_LOSS_PROTOCOL.md) for the flash backend itself.

## On the wire

A bundle is a sequence of frames, `[tag][length][payload]`, each at most 238 bytes: issuance certificates, history blocks, the payment block, witness confirmations, the blocks of a reserve certificate, the blocks of an equivocation proof. Decoding checks shape only; every item is verified when it is ingested.

`arxia_transport::fragment` splits a bundle into signed fragments that each fit one MTU, and `Reassembler` puts them back together in any order, ignoring repetitions. The header is 116 bytes, leaving 140 payload bytes per 256-byte packet.

## What is not built

- A radio link in use. `arxia-radio` drives the SX1276 family and is tested against a model of the chip, not yet on hardware; the firmware does not use it yet.
- A node. `bin/arxia-node` is a stub, and the device firmware in `targets/esp32-node` is a first stage with no radio that has not been run on a board yet.
- Bonds, penalties for a witness, and a way to update a roster from the network.
- A retransmission protocol for lost packets.
- Dropping blocks a ledger no longer needs.
- Encryption of keys at rest.
- Batch and Anchored.

## Earlier design

The repository still contains the design that preceded witness settlement: stake-weighted representative voting ([ORV.md](ORV.md)), partition reconciliation by block hash ([CRDT.md](CRDT.md)), the gossip nonce registry ([GOSSIP.md](GOSSIP.md)) and the earlier finality assessment ([FINALITY.md](FINALITY.md), [FINALITY_MODEL.md](../protocol/FINALITY_MODEL.md)). None of it is on the settlement path described here. It is kept for reference and will be removed.
