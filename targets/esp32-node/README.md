# arxia-esp32-node

Node firmware for the LilyGO T-Beam (ESP32), first stage.

This stage has no radio. It puts the wallet and the ledger on the
device, on its own flash, and checks at every boot that they do there
what they do on a host. It is the same `arxia-lattice` code the
workspace tests on hosts, built without the standard library.

This is a standalone Cargo project, not a workspace member: it builds
with the Espressif Rust fork (the `esp` toolchain), which
`rust-toolchain.toml` selects automatically.

## What a boot does

1. Draws the signing seed from the true random number generator, once,
   and keeps it on flash. Later boots reuse it.
2. Rebuilds the wallet from flash alone, replaying every stored block
   under the ledger rules.
3. Signs one payment. The block is on flash before it is reported.
4. Verifies the payment, then has a second wallet, held in RAM and
   handed nothing but blocks, replay the chain and credit it.

Cut the power at any moment and boot again: `blocks` in the `NODE`
line counts every payment that was reported, and no other.

## Toolchain

```sh
cargo install espup --locked
espup install --targets esp32
```

On Unix, source `$HOME/export-esp.sh` before building; on Windows the
installer sets the environment variables (a copy lives in
`%USERPROFILE%\export-esp.ps1`).

## Build, commission, run

```sh
cargo build --release
```

The image is about 310 KiB. The wallet owns the last mebibyte of the
4 MiB part (`0x300000..0x400000`), addressed absolutely; the
application image at `0x10000` never reaches it.

First flash of a board (commissioning): erase the whole chip, so the
wallet region starts from erased flash. This removes whatever firmware
the board carried.

```sh
espflash erase-flash
```

Flash and watch the serial protocol:

```sh
espflash flash --monitor --chip esp32 target/xtensa-esp32-none-elf/release/arxia-esp32-node
```

## Serial protocol

One line each, parseable off-device.

- `ARXIA-NODE boot region=…`: first line of every boot.
- `NODE id=… blocks=N balance=B`: the wallet is open. `id` is the
  account's public key and is the same at every boot.
- `PAY nonce=N hash=… sign_us=…`: a payment was signed and is on
  flash. `sign_us` covers signing and the flash write.
- `VERIFY ok us=…`: hash and signature of that payment check.
- `RECEIVE ok balance=… replayed=… us=…`: the second wallet replayed
  the chain and credited the payment.
- `HEAP free=… used=…`: allocator state at the end of the boot.
- `DONE blocks=N balance=B`: the boot's work is finished.
- `HALT <reason>`: a step failed; the flash is left as it is.

## What this stage is not

- No radio: nothing leaves the board.
- No issuance policy and no witness roster: the account opens with a
  fixed balance so that there is something to pay with.
- The signing seed is stored unencrypted.
- Every boot adds one block, so the wallet region fills after a few
  thousand boots; erase the chip to start again.
- It has been built, not yet run on a board.
