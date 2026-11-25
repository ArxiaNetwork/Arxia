//! Reconciliation must authenticate every block it merges.
//!
//! A partition handed over by a peer is untrusted input. A block whose
//! hash does not match its content, or whose signature does not verify
//! under the account it names, must have no effect on the merged
//! state: it cannot credit, debit, win a conflict, hide a genuine
//! block, or abort the merge.

use arxia_crdt::reconciliation::reconcile_partitions;
use arxia_lattice::block::{Block, BlockType};
use arxia_lattice::chain::{AccountChain, VectorClock};

/// A block with the given content, a made-up hash and no signature.
fn unsigned(account: &str, block_type: BlockType, nonce: u64, hash: &str) -> Block {
    Block {
        account: account.to_string(),
        previous: String::new(),
        block_type,
        balance: 0,
        nonce,
        timestamp: 0,
        hash: hash.to_string(),
        signature: Vec::new(),
    }
}

#[test]
fn unsigned_open_does_not_create_a_balance() {
    let mallory = AccountChain::new();
    let forged = unsigned(
        mallory.id(),
        BlockType::Open {
            initial_balance: 5_000_000,
        },
        1,
        "aa",
    );
    let report = reconcile_partitions(&[forged], &[]).unwrap();
    assert!(
        !report.balances.contains_key(mallory.id()),
        "an unsigned Open must not create a balance"
    );
    assert_eq!(report.rejected_blocks.len(), 1);
    assert_eq!(report.rejected_blocks[0].block_hash, "aa");
}

#[test]
fn unsigned_send_does_not_debit_the_named_account() {
    // Mallory does not hold Alice's key. She names Alice's account in
    // a SEND to herself.
    let mut vc = VectorClock::new();
    let mut alice = AccountChain::new();
    let mallory = AccountChain::new();
    alice.open(1_000_000, &mut vc).unwrap();
    let theft = unsigned(
        alice.id(),
        BlockType::Send {
            destination: mallory.id().to_string(),
            amount: 900_000,
        },
        2,
        "bb",
    );
    let report = reconcile_partitions(&alice.chain, &[theft]).unwrap();
    assert_eq!(report.balances[alice.id()], 1_000_000);
    assert_eq!(report.rejected_blocks.len(), 1);
}

#[test]
fn unsigned_block_does_not_win_a_conflict() {
    // The forged block claims the same (account, nonce) as Alice's
    // genuine SEND, with a hash that sorts first.
    let mut vc = VectorClock::new();
    let mut alice = AccountChain::new();
    let bob = AccountChain::new();
    let mallory = AccountChain::new();
    alice.open(1_000_000, &mut vc).unwrap();
    let genuine = alice.send(bob.id(), 100, &mut vc).unwrap();
    let forged = unsigned(
        alice.id(),
        BlockType::Send {
            destination: mallory.id().to_string(),
            amount: 1_000_000,
        },
        genuine.nonce,
        "00",
    );
    let report = reconcile_partitions(&alice.chain, &[forged]).unwrap();
    assert!(
        report.conflicts.is_empty(),
        "a block that fails verification is not a competing spend"
    );
    assert_eq!(report.balances[alice.id()], 999_900);
}

#[test]
fn forged_block_reusing_a_genuine_hash_does_not_hide_the_genuine_block() {
    // Deduplication is by hash. A forged block that copies the hash
    // string of Alice's Open and arrives first must not shadow it.
    let mut vc = VectorClock::new();
    let mut alice = AccountChain::new();
    alice.open(1_000_000, &mut vc).unwrap();
    let shadow = unsigned(
        alice.id(),
        BlockType::Open { initial_balance: 0 },
        1,
        &alice.chain[0].hash,
    );
    let report = reconcile_partitions(&[shadow], &alice.chain).unwrap();
    assert_eq!(report.balances[alice.id()], 1_000_000);
    assert_eq!(report.rejected_blocks.len(), 1);
}

#[test]
fn malformed_account_does_not_abort_the_merge() {
    // A block whose account string is not a key at all is set aside
    // like any other unauthenticated block; the merge completes.
    let mut vc = VectorClock::new();
    let mut alice = AccountChain::new();
    alice.open(1_000_000, &mut vc).unwrap();
    let junk = unsigned("abc", BlockType::Open { initial_balance: 1 }, 1, "cc");
    let report = reconcile_partitions(&alice.chain, &[junk]).unwrap();
    assert_eq!(report.balances[alice.id()], 1_000_000);
    assert_eq!(report.rejected_blocks.len(), 1);
}

#[test]
fn genuine_blocks_are_not_reported_as_rejected() {
    let mut vc = VectorClock::new();
    let mut alice = AccountChain::new();
    let mut bob = AccountChain::new();
    alice.open(1_000_000, &mut vc).unwrap();
    bob.open(0, &mut vc).unwrap();
    let send = alice.send(bob.id(), 250, &mut vc).unwrap();
    bob.receive(&send, &mut vc).unwrap();
    let report = reconcile_partitions(&alice.chain, &bob.chain).unwrap();
    assert!(report.rejected_blocks.is_empty());
    assert_eq!(report.balances[alice.id()], 999_750);
    assert_eq!(report.balances[bob.id()], 250);
}
