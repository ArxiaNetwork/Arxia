//! Two payments in a row with no network: Alice pays Bob, then Bob
//! pays Carol with what he just received. Each party holds its own
//! [`Wallet`]; blocks travel between them as plain values, the way
//! they would over a radio link.

use arxia_core::ArxiaError;
use arxia_lattice::chain::{AccountChain, VectorClock};
use arxia_lattice::Wallet;

const ARX: u64 = 1_000_000;

#[test]
fn alice_pays_bob_then_bob_pays_carol() {
    let mut alice = Wallet::new();
    let mut bob = Wallet::new();
    let mut carol = Wallet::new();
    alice.open(100 * ARX).unwrap();
    bob.open(0).unwrap();
    carol.open(0).unwrap();

    // Alice -> Bob. Alice hands over her chain; the last block is the
    // payment.
    let pay_bob = alice.send(bob.id(), 30 * ARX).unwrap();
    bob.ingest_all(alice.chain()).unwrap();
    bob.receive(&pay_bob).unwrap();
    assert_eq!(alice.balance(), 70 * ARX);
    assert_eq!(bob.balance(), 30 * ARX);

    // Bob -> Carol, spending what he just received. Carol replays the
    // funding: Alice's chain, then Bob's.
    let pay_carol = bob.send(carol.id(), 20 * ARX).unwrap();
    carol.ingest_all(alice.chain()).unwrap();
    carol.ingest_all(bob.chain()).unwrap();
    carol.receive(&pay_carol).unwrap();
    assert_eq!(bob.balance(), 10 * ARX);
    assert_eq!(carol.balance(), 20 * ARX);

    // Nothing was created or lost on the way.
    assert_eq!(alice.balance() + bob.balance() + carol.balance(), 100 * ARX);
}

#[test]
fn handing_over_the_same_blocks_twice_changes_nothing() {
    let mut alice = Wallet::new();
    let mut bob = Wallet::new();
    alice.open(10 * ARX).unwrap();
    bob.open(0).unwrap();
    let pay = alice.send(bob.id(), 4 * ARX).unwrap();
    bob.ingest_all(alice.chain()).unwrap();
    bob.ingest_all(alice.chain()).unwrap();
    bob.receive(&pay).unwrap();
    assert_eq!(bob.balance(), 4 * ARX);
    assert!(matches!(
        bob.receive(&pay),
        Err(ArxiaError::DuplicateReceive { .. })
    ));
    assert_eq!(bob.balance(), 4 * ARX);
}

#[test]
fn payment_whose_funding_is_not_shown_is_not_credited() {
    // The SEND is authentic, but Bob has not been given the chain that
    // funds it.
    let mut alice = Wallet::new();
    let mut bob = Wallet::new();
    alice.open(10 * ARX).unwrap();
    bob.open(0).unwrap();
    let pay = alice.send(bob.id(), 4 * ARX).unwrap();
    assert!(bob.receive(&pay).is_err());
    assert_eq!(bob.balance(), 0);
    assert_eq!(bob.chain().len(), 1);
}

#[test]
fn payment_above_the_sender_balance_is_not_credited() {
    // The sender signs a SEND for more than the account holds, with a
    // correct hash and signature.
    let mut vc = VectorClock::new();
    let mut sender = AccountChain::new();
    let mut bob = Wallet::new();
    bob.open(0).unwrap();
    sender.open(10 * ARX, &mut vc).unwrap();
    sender.balance = 1_000 * ARX;
    let pay = sender.send(bob.id(), 500 * ARX, &mut vc).unwrap();

    bob.ingest(&sender.chain[0]).unwrap();
    assert!(matches!(
        bob.receive(&pay),
        Err(ArxiaError::InsufficientBalance { .. })
    ));
    assert_eq!(bob.balance(), 0);
}

#[test]
fn second_spend_of_the_same_position_is_reported_as_a_conflict() {
    // Two SENDs signed for the same account position. Bob accepted
    // the first; the second reaches him afterwards.
    let mut vc = VectorClock::new();
    let mut sender = AccountChain::new();
    let mut bob = Wallet::new();
    let dave = Wallet::new();
    bob.open(0).unwrap();
    sender.open(10 * ARX, &mut vc).unwrap();
    let to_bob = sender.send(bob.id(), 10 * ARX, &mut vc).unwrap();
    sender.chain.pop();
    sender.balance = 10 * ARX;
    sender.nonce -= 1;
    let to_dave = sender.send(dave.id(), 10 * ARX, &mut vc).unwrap();

    bob.ingest(&sender.chain[0]).unwrap();
    bob.receive(&to_bob).unwrap();
    assert!(matches!(
        bob.ingest(&to_dave),
        Err(ArxiaError::NonceConflict {
            nonce: 2,
            count: 2,
            ..
        })
    ));
    assert_eq!(bob.balance(), 10 * ARX);
}

#[test]
fn forwarded_funds_are_checked_back_to_their_origin() {
    // Carol is shown Bob's chain but not Alice's. Bob's RECEIVE cites
    // a SEND Carol's ledger does not hold, so his balance is not
    // established and his payment is not credited.
    let mut alice = Wallet::new();
    let mut bob = Wallet::new();
    let mut carol = Wallet::new();
    alice.open(100 * ARX).unwrap();
    bob.open(0).unwrap();
    carol.open(0).unwrap();
    let pay_bob = alice.send(bob.id(), 30 * ARX).unwrap();
    bob.ingest_all(alice.chain()).unwrap();
    bob.receive(&pay_bob).unwrap();
    let pay_carol = bob.send(carol.id(), 20 * ARX).unwrap();

    assert!(matches!(
        carol.ingest_all(bob.chain()),
        Err(ArxiaError::UnknownSourceSend { .. })
    ));
    assert!(carol.receive(&pay_carol).is_err());
    assert_eq!(carol.balance(), 0);
}

#[test]
fn refused_operations_leave_the_wallet_untouched() {
    let mut alice = Wallet::new();
    let bob = Wallet::new();
    alice.open(5 * ARX).unwrap();
    let chain_len = alice.chain().len();
    assert!(alice.send(bob.id(), 6 * ARX).is_err());
    assert!(alice.open(1).is_err());
    assert_eq!(alice.balance(), 5 * ARX);
    assert_eq!(alice.chain().len(), chain_len);
    // The wallet still works afterwards.
    alice.send(bob.id(), 5 * ARX).unwrap();
    assert_eq!(alice.balance(), 0);
}
