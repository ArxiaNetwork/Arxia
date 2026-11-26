//! Node firmware for the LilyGO T-Beam (ESP32), first stage.
//!
//! This stage has no radio. It puts the wallet and the ledger on the
//! device and checks, at every boot, that they do there what they do
//! on a host:
//!
//! 1. The signing seed is drawn once from the true random number
//!    generator and kept on flash. Later boots reuse it.
//! 2. The wallet is rebuilt from flash alone, every stored block
//!    replayed under the ledger rules.
//! 3. One payment is signed. It is on flash before it is reported.
//! 4. The payment is verified, then credited by a second wallet that
//!    lives in RAM and is handed nothing but blocks.
//!
//! Cut the power at any moment and boot again: `blocks` in the `NODE`
//! line counts every payment that was reported, and no other.
//!
//! Serial protocol, one line each, parseable off-device:
//! `NODE id=… blocks=N balance=B` once the wallet is open;
//! `PAY nonce=N hash=… sign_us=… ` after the payment is durable;
//! `VERIFY ok us=…` and `RECEIVE ok balance=…` for the two checks;
//! `HEAP free=… used=…`; `DONE` when the boot's work is finished;
//! `HALT <reason>` if a step fails, leaving the evidence on flash.

#![no_std]
#![no_main]

extern crate alloc;

use arxia_lattice::{verify_block, DurableWallet, WalletConfig};
use arxia_storage::MemoryStorage;
use arxia_storage_flash::FlashStorage;
use embassy_embedded_hal::adapter::BlockingAsync;
use esp_backtrace as _;
use esp_hal::clock::CpuClock;
use esp_hal::main;
use esp_hal::rng::{Trng, TrngSource};
use esp_hal::time::Instant;
use esp_println::println;

// The app-descriptor the esp-idf second-stage bootloader expects.
esp_bootloader_esp_idf::esp_app_desc!();

/// The flash region the wallet owns: the last mebibyte of the
/// T-Beam's 4 MiB part, addressed absolutely. The application image
/// lives at 0x10000 and never reaches it. Commissioning erases the
/// whole chip (`espflash erase-flash`), so the first mount sees erased
/// flash.
const RANGE: core::ops::Range<u32> = 0x30_0000..0x40_0000;

/// Balance the account opens with on a fresh device, in micro-ARX.
/// This stage runs without an issuance policy: the figure exists so
/// that there is something to pay with, and stands for nothing.
const OPENING_BALANCE: u64 = 1_000_000_000;

/// Amount of the payment signed at every boot, in micro-ARX.
const PAYMENT: u64 = 1;

/// The boot's work has ended. The last serial lines said how.
fn park() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// Report a failed step and stop, leaving the flash as it is.
macro_rules! halt {
    ($($arg:tt)*) => {{
        println!("HALT {}", format_args!($($arg)*));
        park()
    }};
}

#[main]
fn main() -> ! {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);
    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 98768);
    esp_alloc::heap_allocator!(size: 64 * 1024);

    println!(
        "ARXIA-NODE boot region={:#x}..{:#x}",
        RANGE.start, RANGE.end
    );

    // True randomness needs an entropy source switched on. Without it
    // the generator is only pseudo-random, and no key is drawn.
    let _entropy_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let trng = match Trng::try_new() {
        Ok(trng) => trng,
        Err(_) => halt!("no true random source"),
    };

    let flash = BlockingAsync::new(esp_storage::FlashStorage::new(peripherals.FLASH));
    let store = match FlashStorage::<_>::mount(flash, RANGE) {
        Ok(store) => store,
        Err(failure) => halt!("unmountable error={}", failure.error),
    };

    let mut wallet = match DurableWallet::open_with_entropy(store, WalletConfig::default(), || {
        let mut seed = [0u8; 32];
        trng.read(&mut seed);
        seed
    }) {
        Ok(wallet) => wallet,
        Err(error) => halt!("wallet error={}", error),
    };
    if wallet.chain().is_empty() {
        if let Err(error) = wallet.open_account(OPENING_BALANCE) {
            halt!("open error={}", error);
        }
    }
    println!(
        "NODE id={} blocks={} balance={}",
        wallet.id(),
        wallet.chain().len(),
        wallet.balance()
    );

    // A second party, in RAM, with its own key from the same source.
    let mut peer = match DurableWallet::open_with_entropy(
        MemoryStorage::default(),
        WalletConfig::default(),
        || {
            let mut seed = [0u8; 32];
            trng.read(&mut seed);
            seed
        },
    ) {
        Ok(peer) => peer,
        Err(error) => halt!("peer error={}", error),
    };
    if let Err(error) = peer.open_account(0) {
        halt!("peer open error={}", error);
    }

    // Sign one payment. `send` returns only after the block is on
    // flash, so this line is never printed for a block that a power
    // cut could take back.
    let started = Instant::now();
    let payment = match wallet.send(peer.id(), PAYMENT) {
        Ok(payment) => payment,
        Err(error) => halt!("pay error={}", error),
    };
    println!(
        "PAY nonce={} hash={} sign_us={}",
        payment.nonce,
        payment.hash,
        started.elapsed().as_micros()
    );

    let started = Instant::now();
    if let Err(error) = verify_block(&payment) {
        halt!("verify error={}", error);
    }
    println!("VERIFY ok us={}", started.elapsed().as_micros());

    // The peer is handed blocks and nothing else: it replays the
    // payer's chain under the ledger rules, then credits the payment.
    let started = Instant::now();
    let history = &wallet.chain()[..wallet.chain().len() - 1];
    if let Err(error) = peer.ingest_all(history) {
        halt!("replay error={}", error);
    }
    if let Err(error) = peer.receive(&payment) {
        halt!("receive error={}", error);
    }
    println!(
        "RECEIVE ok balance={} replayed={} us={}",
        peer.balance(),
        history.len(),
        started.elapsed().as_micros()
    );

    println!(
        "HEAP free={} used={}",
        esp_alloc::HEAP.free(),
        esp_alloc::HEAP.used()
    );
    println!(
        "DONE blocks={} balance={}",
        wallet.chain().len(),
        wallet.balance()
    );
    park()
}
