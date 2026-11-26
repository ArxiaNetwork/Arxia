//! Two signed blocks for one account position: the proof, and what a
//! ledger does once it holds it.

use arxia_core::{ArxiaError, EquivocationFault};
use arxia_lattice::chain::{AccountChain, VectorClock};
use arxia_lattice::{Block, DurableWallet, EquivocationProof, Wallet};
use arxia_storage::MemoryStorage;

const ARX: u64 = 1_000_000;

/// An account whose key is used outside any wallet, so that two blocks
/// can be signed for the same position.
struct Payer {
    account: AccountChain,
    vclock: VectorClock,
}

impl Payer {
    fn new(balance: u64) -> Self {
        let mut account = AccountChain::new();
        let mut vclock = VectorClock::new();
        account.open(balance, &mut vclock).unwrap();
        Self { account, vclock }
    }

    fn send(&mut self, destination: &str, amount: u64) -> Block {
        self.account
            .send(destination, amount, &mut self.vclock)
            .unwrap()
    }

    /// Sign a second block for the position of the last one.
    fn send_again(&mut self, destination: &str, amount: u64) -> Block {
        let replaced = self.account.chain.pop().unwrap();
        self.account.balance = self.account.chain.last().unwrap().balance;
        self.account.nonce = replaced.nonce - 1;
        self.send(destination, amount)
    }
}

fn frozen_from<T: std::fmt::Debug>(result: Result<T, ArxiaError>) -> u64 {
    match result {
        Err(ArxiaError::Equivocation {
            fault: EquivocationFault::AccountFrozen { from_nonce },
        }) => from_nonce,
        other => panic!("expected AccountFrozen, got {other:?}"),
    }
}

#[test]
fn two_blocks_for_one_position_make_a_proof() {
    let mut payer = Payer::new(100 * ARX);
    let bob = Wallet::new();
    let dave = Wallet::new();
    let to_bob = payer.send(bob.id(), 60 * ARX);
    let to_dave = payer.send_again(dave.id(), 60 * ARX);

    let proof = EquivocationProof::new(to_bob.clone(), to_dave.clone()).unwrap();
    assert_eq!(proof.account(), payer.account.id());
    assert_eq!(proof.nonce(), 2);
    // The order in which the blocks are presented does not matter.
    assert_eq!(proof, EquivocationProof::new(to_dave, to_bob).unwrap());
}

#[test]
fn blocks_that_do_not_conflict_are_not_a_proof() {
    let mut payer = Payer::new(100 * ARX);
    let mut other = Payer::new(100 * ARX);
    let bob = Wallet::new();
    let first = payer.send(bob.id(), 10 * ARX);
    let next = payer.send(bob.id(), 10 * ARX);
    let foreign = other.send(bob.id(), 10 * ARX);

    let not_a_conflict = |a: &Block, b: &Block| {
        matches!(
            EquivocationProof::new(a.clone(), b.clone()),
            Err(ArxiaError::Equivocation {
                fault: EquivocationFault::NotAConflict
            })
        )
    };
    assert!(not_a_conflict(&first, &first), "the same block twice");
    assert!(not_a_conflict(&first, &next), "two positions");
    assert!(not_a_conflict(&first, &foreign), "two accounts");
}

#[test]
fn a_proof_cannot_be_made_against_someone_else() {
    // The second block names the payer's account at the same position
    // but is not signed by the payer.
    let mut payer = Payer::new(100 * ARX);
    let bob = Wallet::new();
    let genuine = payer.send(bob.id(), 10 * ARX);
    let mut forged = genuine.clone();
    forged.timestamp += 1;
    forged.hash = Block::compute_hash(
        &forged.account,
        &forged.previous,
        &forged.block_type,
        forged.balance,
        forged.nonce,
        forged.timestamp,
    )
    .unwrap();
    assert!(matches!(
        EquivocationProof::new(genuine, forged),
        Err(ArxiaError::SignatureInvalid { .. })
    ));
}

#[test]
fn a_wallet_that_sees_both_blocks_keeps_the_proof_and_freezes_the_account() {
    let mut payer = Payer::new(100 * ARX);
    let mut bob = Wallet::new();
    let dave = Wallet::new();
    bob.open(0).unwrap();
    let to_bob = payer.send(bob.id(), 60 * ARX);
    let to_dave = payer.send_again(dave.id(), 60 * ARX);

    bob.ingest(&payer.account.chain[0]).unwrap();
    bob.ingest(&to_bob).unwrap();
    assert!(matches!(
        bob.ingest(&to_dave),
        Err(ArxiaError::NonceConflict { .. })
    ));

    let proof = bob
        .ledger()
        .equivocation_for(payer.account.id())
        .expect("the proof is kept");
    assert_eq!(proof.nonce(), 2);

    // The payment that was not yet received can no longer be credited.
    assert_eq!(frozen_from(bob.receive(&to_bob)), 2);
    assert_eq!(bob.balance(), 0);

    // Nothing more is accepted from the account.
    let later = payer.send(dave.id(), 5 * ARX);
    assert_eq!(frozen_from(bob.ingest(&later)), 2);
}

#[test]
fn a_payment_already_received_keeps_its_receive() {
    let mut payer = Payer::new(100 * ARX);
    let mut bob = Wallet::new();
    let dave = Wallet::new();
    bob.open(0).unwrap();
    let to_bob = payer.send(bob.id(), 60 * ARX);
    let to_dave = payer.send_again(dave.id(), 60 * ARX);

    bob.ingest(&payer.account.chain[0]).unwrap();
    bob.receive(&to_bob).unwrap();
    assert!(bob.ingest(&to_dave).is_err());
    assert_eq!(bob.balance(), 60 * ARX);
    assert!(bob.ledger().equivocation_for(payer.account.id()).is_some());
}

#[test]
fn the_proof_travels_to_a_node_that_saw_neither_block_conflict() {
    let mut payer = Payer::new(100 * ARX);
    let mut bob = Wallet::new();
    let mut carol = Wallet::new();
    let dave = Wallet::new();
    bob.open(0).unwrap();
    carol.open(0).unwrap();

    // An honest payment first, at position 2.
    let to_carol = payer.send(carol.id(), 10 * ARX);
    let history = payer.account.chain.clone();
    // Then two blocks for position 3.
    let to_bob = payer.send(bob.id(), 60 * ARX);
    let to_dave = payer.send_again(dave.id(), 60 * ARX);

    bob.ingest_all(&history).unwrap();
    bob.ingest(&to_bob).unwrap();
    assert!(bob.ingest(&to_dave).is_err());
    let proof = bob
        .ledger()
        .equivocations()
        .next()
        .expect("bob holds a proof")
        .clone();

    // Carol receives the proof before any block of the account.
    carol.ingest_equivocation(&proof).unwrap();

    // The part of the chain before the conflict is still accepted, so
    // the earlier payment is credited.
    carol.ingest_all(&history).unwrap();
    carol.receive(&to_carol).unwrap();
    assert_eq!(carol.balance(), 10 * ARX);

    // The conflicting position and everything after it is refused,
    // whichever of the two blocks is presented.
    assert_eq!(frozen_from(carol.ingest(&to_bob)), 3);
    assert_eq!(frozen_from(carol.ingest(&to_dave)), 3);
}

#[test]
fn an_earlier_conflict_replaces_a_later_one() {
    let mut payer = Payer::new(100 * ARX);
    let bob = Wallet::new();
    let dave = Wallet::new();
    let mut carol = Wallet::new();

    let early_a = payer.send(bob.id(), ARX);
    let early_b = payer.send_again(dave.id(), ARX);
    let late_a = payer.send(bob.id(), 2 * ARX);
    let late_b = payer.send_again(dave.id(), 2 * ARX);
    let early = EquivocationProof::new(early_a, early_b).unwrap();
    let late = EquivocationProof::new(late_a, late_b).unwrap();
    assert_eq!((early.nonce(), late.nonce()), (2, 3));

    carol.ingest_equivocation(&late).unwrap();
    carol.ingest_equivocation(&early).unwrap();
    carol.ingest_equivocation(&late).unwrap();
    let held = carol.ledger().equivocation_for(payer.account.id()).unwrap();
    assert_eq!(held.nonce(), 2);
}

#[test]
fn proof_encoding_round_trips_and_is_verified_on_decode() {
    let mut payer = Payer::new(100 * ARX);
    let bob = Wallet::new();
    let dave = Wallet::new();
    let to_bob = payer.send(bob.id(), 60 * ARX);
    let to_dave = payer.send_again(dave.id(), 60 * ARX);
    let proof = EquivocationProof::new(to_bob, to_dave).unwrap();

    let bytes = proof.to_bytes().unwrap();
    assert_eq!(bytes.len(), 386);
    assert_eq!(EquivocationProof::from_bytes(&bytes).unwrap(), proof);

    // Byte 70 lies in the balance field of the first block.
    let mut altered = bytes.clone();
    altered[70] ^= 0x01;
    assert!(EquivocationProof::from_bytes(&altered).is_err());
    assert!(EquivocationProof::from_bytes(&bytes[..385]).is_err());
}

#[test]
fn the_freeze_survives_a_restart() {
    let mut payer = Payer::new(100 * ARX);
    let mut bob = DurableWallet::open(MemoryStorage::default()).unwrap();
    let dave = Wallet::new();
    bob.open_account(0).unwrap();
    let to_bob = payer.send(bob.id(), 60 * ARX);
    let to_dave = payer.send_again(dave.id(), 60 * ARX);

    bob.ingest(&payer.account.chain[0]).unwrap();
    bob.ingest(&to_bob).unwrap();
    assert!(matches!(
        bob.ingest(&to_dave),
        Err(ArxiaError::NonceConflict { .. })
    ));

    let mut bob = DurableWallet::open(bob.into_storage()).unwrap();
    assert!(bob
        .wallet()
        .ledger()
        .equivocation_for(payer.account.id())
        .is_some());
    assert_eq!(frozen_from(bob.receive(&to_bob)), 2);
    assert_eq!(bob.balance(), 0);
}

#[test]
fn a_proof_received_from_another_node_survives_a_restart() {
    let mut payer = Payer::new(100 * ARX);
    let bob = Wallet::new();
    let dave = Wallet::new();
    let to_bob = payer.send(bob.id(), 60 * ARX);
    let to_dave = payer.send_again(dave.id(), 60 * ARX);
    let proof = EquivocationProof::new(to_bob.clone(), to_dave).unwrap();

    let mut carol = DurableWallet::open(MemoryStorage::default()).unwrap();
    carol.ingest_equivocation(&proof).unwrap();
    let mut carol = DurableWallet::open(carol.into_storage()).unwrap();
    carol.ingest(&payer.account.chain[0]).unwrap();
    assert_eq!(frozen_from(carol.ingest(&to_bob)), 2);
}
