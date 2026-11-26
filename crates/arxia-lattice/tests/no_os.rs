//! The constructors a device without an operating system uses: a
//! signing seed from the caller's entropy, and a clock the caller
//! installs. They are exercised here on the host; the build for a
//! bare-metal target is checked separately in CI.

use arxia_lattice::chain::{AccountChain, VectorClock};
use arxia_lattice::{verify_block, DurableWallet, Wallet, WalletConfig};
use arxia_storage::MemoryStorage;

const ARX: u64 = 1_000_000;

fn fixed_clock() -> u64 {
    1_700_000_000_000
}

#[test]
fn an_account_is_determined_by_its_seed() {
    let first = AccountChain::from_seed(&[7; 32]);
    let again = AccountChain::from_seed(&[7; 32]);
    let other = AccountChain::from_seed(&[8; 32]);
    assert_eq!(first.id(), again.id());
    assert_ne!(first.id(), other.id());
}

#[test]
fn blocks_signed_from_a_seed_verify() {
    let mut vclock = VectorClock::new();
    let mut account = AccountChain::from_seed(&[7; 32]);
    let receiver = AccountChain::from_seed(&[8; 32]);
    let open = account.open(10 * ARX, &mut vclock).unwrap();
    let send = account.send(receiver.id(), 4 * ARX, &mut vclock).unwrap();
    assert!(verify_block(&open).is_ok());
    assert!(verify_block(&send).is_ok());
}

#[test]
fn an_installed_clock_stamps_the_blocks() {
    let mut vclock = VectorClock::new();
    let mut account = AccountChain::from_seed(&[7; 32]);
    account.set_clock(fixed_clock);
    let open = account.open(0, &mut vclock).unwrap();
    assert_eq!(open.timestamp, fixed_clock());
    assert!(verify_block(&open).is_ok());
}

#[test]
fn a_wallet_from_a_seed_pays_and_is_paid() {
    let mut alice = Wallet::from_seed(&[1; 32], WalletConfig::default());
    let mut bob = Wallet::from_seed(&[2; 32], WalletConfig::default());
    alice.set_clock(fixed_clock);
    alice.open(100 * ARX).unwrap();
    bob.open(0).unwrap();
    let payment = alice.send(bob.id(), 30 * ARX).unwrap();
    assert_eq!(payment.timestamp, fixed_clock());
    bob.ingest_all(alice.chain()).unwrap();
    bob.receive(&payment).unwrap();
    assert_eq!(bob.balance(), 30 * ARX);
}

#[test]
fn entropy_is_asked_for_once_and_the_seed_is_kept() {
    let mut calls = 0;
    let wallet =
        DurableWallet::open_with_entropy(MemoryStorage::default(), WalletConfig::default(), || {
            calls += 1;
            [9; 32]
        })
        .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(wallet.id(), AccountChain::from_seed(&[9; 32]).id());

    // On the next start the stored seed is used; the entropy source is
    // not consulted, whatever it would return.
    let reopened =
        DurableWallet::open_with_entropy(wallet.into_storage(), WalletConfig::default(), || {
            panic!("entropy must not be drawn for an existing wallet")
        })
        .unwrap();
    assert_eq!(reopened.id(), AccountChain::from_seed(&[9; 32]).id());
}
