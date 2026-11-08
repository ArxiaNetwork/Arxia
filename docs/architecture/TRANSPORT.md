# Multi-Modal Transport Layer

## Overview

Arxia is designed to run over several physical transports, with long range LoRa radio first. The transport layer abstracts the underlying medium behind a common trait. Today the code provides that trait, signed transport messages, receive-side reassembly of signed fragments, and a simulated transport for tests and examples. No LoRa, Bluetooth, SMS or satellite driver exists in this repository yet.

## TransportTrait

```rust
pub trait TransportTrait {
    fn send(&mut self, msg: TransportMessage) -> Result<(), TransportError>;
    fn try_recv(&mut self) -> Option<TransportMessage>;
    fn mtu(&self) -> usize;
}
```

`TransportError` carries structured error variants
(`PayloadTooLarge`, `Disconnected`, `MessageLost`, `BackPressure`,
`Other`) so the caller can implement explicit retry / backoff /
abort policies. See
[`arxia-transport::traits`](../../crates/arxia-transport/src/traits.rs)
for the canonical definitions.

`latency_ms` is NOT part of the trait — it is a property of specific
implementations (e.g.
[`SimulatedTransport::latency_ms()`](../../crates/arxia-transport/src/sim/simulated.rs)).

## Target transports

### LoRa (primary)

Arxia is designed for raw LoRa, not LoRaWAN. Every transaction fits in one 193-byte radio packet, so two nodes in radio reach can exchange it directly with nothing in between. LoRaWAN can serve only as an optional short range on-ramp: under regional payload limits a 193-byte block fits only at SF7 and SF8 in Europe and at SF7 in North America, and LoRaWAN has no standard uplink fragmentation. No Meshtastic code is in this repository; Arxia is not affiliated with the Meshtastic project.

- **Frequency**: EU 868 MHz (1% duty cycle), US 915 MHz
- **Spreading factors**: SF7 (short range, fast) to SF12 (long range, slow)
- **MTU**: 256 bytes (Arxia compact block = 193 bytes fits)
- **Range**: long range; depends on spreading factor, antenna and terrain. Not measured for Arxia yet.
- **Hardware**: SX1276/SX1278 radios; the reference node is a T-Beam class board (ESP32 with LoRa) costing tens of dollars

### BLE (short range)

- **Range**: short range
- **Use case**: Point-of-sale, face-to-face transactions
- **Finality**: assessed the same way as on any transport (see FINALITY.md); the transport does not set the tier
- **MTU**: 512 bytes (simulated)

### SMS (fallback)

- **Encoding**: Base64 compact block split across several SMS messages
- **Use case**: Areas with cellular but no internet

### Satellite DVB-S2 (Reception-only)

- **Mode**: Broadcast reception only (no uplink)
- **Use case**: Periodic state snapshots for remote nodes
- **Data**: Compressed block batches, validator set updates

## Simulated Transport

For testing,
[`SimulatedTransport`](../../crates/arxia-transport/src/sim/simulated.rs)
uses:

- Configurable MTU and latency
- xorshift64 PRNG for deterministic packet loss simulation
- In-memory `VecDeque` inbox + `Vec` outbox
- Configurable loss rate (0.0-1.0)

### Bounded queues (CRIT-012)

Both queues are bounded to defend against denial-of-service via
unbounded growth (internal security review finding **CRIT-012**, see `../SECURITY_REVIEW.md`; closed by PR #44).
Defaults are `DEFAULT_INBOX_CAPACITY = 1024` and
`DEFAULT_OUTBOX_CAPACITY = 1024` (≈ 256 KB per direction at LoRa
MTU). For custom limits use
`SimulatedTransport::with_capacity(latency_ms, loss_rate, mtu,
inbox_cap, outbox_cap)`.

| Queue   | Overflow policy              | Observability |
|---------|------------------------------|---------------|
| Inbox   | drop-oldest (silent)         | `inbox_dropped() -> u64` cumulative counter, saturating at `u64::MAX` |
| Outbox  | back-pressure (return `Err(BackPressure { capacity })`) | `outbox_len() -> usize`, configured `outbox_capacity()` |

The asymmetry is deliberate:

- **Inbox is adversary-influenced** (a flooding peer controls
  injection rate). Drop-oldest preserves recency under flood; the
  observable counter is the back-pressure signal for the receive
  side. Refusing injection would let a malicious peer DoS the
  legitimate one.
- **Outbox is caller-controlled** (we control the send rate).
  Back-pressure forces the caller to slow down with an explicit
  `Err`, preserving test-side determinism (drop-oldest on outbox
  would silently rewrite the record of "what was emitted").

Production transports (LoRa, BLE, SMS, satellite) MUST inherit
the same bounded discipline once their inbox/outbox
representations land. The simulated layer establishes the
contract first so adversarial tests can assert against it.
