# Running an Arxia Node

> **Status:** there is no running Arxia node yet, and no public network to join. The `arxia-node` binary in `bin/arxia-node` is a stub: it logs a version line, a `STUB BINARY` warning and two status lines, then exits. It reads no arguments and opens no port. Its production implementation is gated by [`docs/SECURITY_INTERFACES.md`](../SECURITY_INTERFACES.md) (HIGH-027).

## What you can run today

```bash
git clone https://github.com/ArxiaNetwork/Arxia.git
cd Arxia
cargo build --workspace
cargo test --workspace
cargo run --bin arxia-node            # logs the stub banner and exits
cargo run --bin arxia-cli -- keygen   # writes an Ed25519 keypair file (arxia_keypair.json)
cargo run --bin arxia-cli -- did      # prints a did:arxia identifier for a fresh key
```

The programs under `examples/` exercise the protocol core in one process: an offline payment, DID issuance, signed relay receipts and partition reconciliation. See [GETTING_STARTED.md](GETTING_STARTED.md).

## What a node will do

A node will keep the ledger (one chain per account), exchange blocks with nearby nodes over long range LoRa radio, and assess finality through the tiers described in [FINALITY_MODEL.md](../protocol/FINALITY_MODEL.md). Every transaction fits in one 193-byte radio packet ([SERIALIZATION.md](../protocol/SERIALIZATION.md)). Bluetooth, SMS and satellite are planned as additional transports. Only a simulated transport (`SimulatedTransport` in `crates/arxia-transport`) exists in this repository today.

## Storage

`arxia-storage` defines the `StorageBackend` trait, with ordered prefix scans and atomic batches. Two persistent backends implement it:

- `arxia-storage-redb`, for nodes with a filesystem. A test kills a writer process mid-stream and checks that every batch is either entirely present or entirely absent.
- `arxia-storage-flash`, for embedded targets. The flash storage layer survives power loss by design, proven by a fault injection suite that cuts power at every write boundary. See [POWER_LOSS_PROTOCOL.md](../architecture/POWER_LOSS_PROTOCOL.md).

Neither backend is wired to a node yet; the ledger still runs in memory.

## Hardware

The reference board is a T-Beam class ESP32 with a LoRa radio, costing tens of dollars. See [HARDWARE_SETUP.md](HARDWARE_SETUP.md). The firmware built today is the power-loss bench in `targets/esp32-bench`. Node firmware is not built yet.

## Stake and rewards

No stake locking, reward or fee mechanism is implemented. Stake appears in the code only as an input to representative voting: votes whose delegated stake is below 0.1% of total supply are filtered out by `collect_votes` (`MIN_REPRESENTATIVE_STAKE_DENOM` in `crates/arxia-consensus/src/orv.rs`).

## Next

The field test is next: real boards, real distance, a transaction settling with no internet in the loop, filmed and published. The settlement layer is a direction we have committed to, not code that exists today. We will show it when it runs.
