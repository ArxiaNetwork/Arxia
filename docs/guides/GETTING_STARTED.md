# Getting Started

## Prerequisites

- Rust 1.89.0 or later
- Git

## Clone and Build

```bash
git clone https://github.com/ArxiaNetwork/Arxia.git
cd Arxia
cargo build --workspace
```

> The first build of `arxia-proto` emits
> `warning: arxia-proto@0.1.0: protoc not found, using stub
> protobuf module (LOW-008: cfg=arxia_proto_stub set)` when the
> `protoc` binary is not on `PATH`. This is expected on hosts
> without a Protobuf toolchain ; the workspace falls back to a
> stub module gated by `cfg=arxia_proto_stub`.

## Run Tests

```bash
cargo test --workspace
```

## Run Examples

Each example under `examples/` is its own workspace member binary
(not a Cargo `[[example]]` target). Invoke with `-p`:

```bash
# Offline payment flow
cargo run -p offline_payment

# DID issuance
cargo run -p did_issuance

# Mesh relay simulation
cargo run -p mesh_relay

# Partition reconciliation
cargo run -p partition_reconciliation
```

## Run the Node (Development)

```bash
cargo run --bin arxia-node
```

The node binary is a stub: it logs a version line and a `STUB BINARY` warning that points to [`docs/SECURITY_INTERFACES.md`](../SECURITY_INTERFACES.md), then exits. There is no running node yet.

## CLI Tools

```bash
# Generate a keypair (writes JSON {public_key, private_key} to a file).
# Default output path is ./arxia_keypair.json in the current directory.
# The private key is NEVER printed on stdout — only the public key and the
# output path are shown. The file is created with create_new (refuses to
# overwrite an existing keyfile) and on Unix is mode 0600.
cargo run --bin arxia-cli -- keygen

# Choose an explicit output path:
cargo run --bin arxia-cli -- keygen --out=/path/to/keypair.json
# (or:  cargo run --bin arxia-cli -- keygen --out /path/to/keypair.json)

# Generate a DID
cargo run --bin arxia-cli -- did
```

> **Backup the keypair file offline.** It contains the only copy of the
> Ed25519 secret seed. Never share it or commit it to version control.

## Embedded Builds

The portable core compiles for bare metal embedded targets. CI checks it on `riscv32imc-unknown-none-elf`:

```bash
rustup target add riscv32imc-unknown-none-elf
cargo build -p arxia-core -p arxia-crypto -p arxia-storage -p arxia-storage-flash -p arxia-flash-bench --no-default-features --target riscv32imc-unknown-none-elf
```

The T-Beam firmware built today is the power-loss bench in `targets/esp32-bench`, a standalone Cargo project (not a workspace member) with its own Xtensa toolchain. Build and flashing steps are in [`targets/esp32-bench/README.md`](../../targets/esp32-bench/README.md). `targets/esp32` is a placeholder crate; node firmware is not built yet.

## Project Structure

```
Arxia/
  crates/          # Library crates (includes arxia-proto for
                   #   Protobuf definitions)
  bin/             # Binary targets
  tools/           # CLI tools
  examples/        # Example programs (each is its own workspace
                   #   member binary; invoke with `cargo run -p`)
  contracts/       # Example state machines in plain Rust (escrow,
                   #   time lock); no runtime executes them
  targets/         # Hardware targets (ESP32)
  docs/            # Documentation
```
