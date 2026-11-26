//! Frames and bundles: encoding, decoding, and what a wallet does with
//! a bundle.

use arxia_core::{ArxiaError, BundleFault};
use arxia_crypto::generate_keypair;
use arxia_lattice::bundle::{decode, encode, Frame, MAX_FRAME_LEN};
use arxia_lattice::witness::WitnessConfirmation;
use arxia_lattice::{DurableWallet, IssuanceCertificate, IssuancePolicy};
use arxia_storage::MemoryStorage;
use ed25519_dalek::SigningKey;

const ARX: u64 = 1_000_000;

struct Authority {
    keys: Vec<SigningKey>,
    policy: IssuancePolicy,
}

fn authority() -> Authority {
    let keys: Vec<SigningKey> = (0..3).map(|_| generate_keypair().0).collect();
    let public = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
    Authority {
        policy: IssuancePolicy::new(public, 2).unwrap(),
        keys,
    }
}

impl Authority {
    fn node(&self) -> DurableWallet<MemoryStorage> {
        DurableWallet::open_with_issuance(MemoryStorage::default(), self.policy.clone()).unwrap()
    }

    fn certify(&self, account: &str, amount: u64, signers: usize) -> IssuanceCertificate {
        let mut certificate = IssuanceCertificate::new(account, amount).unwrap();
        for key in &self.keys[..signers] {
            certificate.sign(&self.policy, key).unwrap();
        }
        certificate
    }
}

fn bundle_fault<T: std::fmt::Debug>(result: Result<T, ArxiaError>) -> BundleFault {
    match result {
        Err(ArxiaError::Bundle { fault }) => fault,
        other => panic!("expected a bundle fault, got {other:?}"),
    }
}

#[test]
fn every_frame_fits_one_radio_packet() {
    let authority = authority();
    let mut alice = authority.node();
    let certificate = authority.certify(alice.id(), 100 * ARX, 3);
    let open = alice.open_certified(&certificate).unwrap();
    let confirmation = WitnessConfirmation::sign(&authority.keys[0], &open).unwrap();

    let frames = [
        Frame::Issuance(certificate),
        Frame::Block(open.clone()),
        Frame::Payment(open),
        Frame::Confirmation(confirmation),
    ];
    let lengths: Vec<usize> = frames
        .iter()
        .map(|frame| frame.to_bytes().unwrap().len())
        .collect();
    assert_eq!(lengths, [238, 195, 195, 130]);
    assert!(lengths.iter().all(|&length| length <= MAX_FRAME_LEN));
}

#[test]
fn a_bundle_round_trips() {
    let authority = authority();
    let mut alice = authority.node();
    let bob = authority.node();
    alice
        .open_certified(&authority.certify(alice.id(), 100 * ARX, 2))
        .unwrap();
    let payment = alice.send(bob.id(), 30 * ARX).unwrap();
    let frames = alice.payment_bundle(&payment).unwrap();

    let bytes = encode(&frames).unwrap();
    let decoded = decode(&bytes).unwrap();
    assert_eq!(decoded.len(), frames.len());
    assert_eq!(encode(&decoded).unwrap(), bytes);
    assert!(matches!(decoded.last(), Some(Frame::Payment(block)) if block.hash == payment.hash));
}

#[test]
fn damaged_bundles_are_refused() {
    let authority = authority();
    let mut alice = authority.node();
    let bob = authority.node();
    alice
        .open_certified(&authority.certify(alice.id(), 100 * ARX, 2))
        .unwrap();
    let payment = alice.send(bob.id(), 30 * ARX).unwrap();
    let bytes = encode(&alice.payment_bundle(&payment).unwrap()).unwrap();

    assert_eq!(
        bundle_fault(decode(&bytes[..bytes.len() - 1])),
        BundleFault::Truncated
    );
    assert_eq!(bundle_fault(decode(&bytes[..1])), BundleFault::Truncated);

    let mut unknown = bytes.clone();
    unknown[0] = 99;
    assert_eq!(bundle_fault(decode(&unknown)), BundleFault::UnknownTag);

    // A block frame whose stated length is not a block's length.
    let block_frame = Frame::Block(payment).to_bytes().unwrap();
    let mut short = block_frame[..block_frame.len() - 1].to_vec();
    short[1] -= 1;
    assert_eq!(bundle_fault(decode(&short)), BundleFault::Payload);

    assert!(decode(&[]).unwrap().is_empty());
}

#[test]
fn a_receiver_replays_a_bundle_and_is_handed_the_payment() {
    let authority = authority();
    let mut alice = authority.node();
    let mut bob = authority.node();
    alice
        .open_certified(&authority.certify(alice.id(), 100 * ARX, 2))
        .unwrap();
    bob.open_account(0).unwrap();
    let payment = alice.send(bob.id(), 30 * ARX).unwrap();
    let frames = decode(&encode(&alice.payment_bundle(&payment).unwrap()).unwrap()).unwrap();

    let (handed, confirmations) = bob.ingest_bundle(&frames).unwrap();
    assert_eq!(handed.hash, payment.hash);
    assert!(confirmations.is_empty());
    // Taking a bundle in does not credit anything by itself.
    assert_eq!(bob.balance(), 0);
    bob.receive(&handed).unwrap();
    assert_eq!(bob.balance(), 30 * ARX);
}

#[test]
fn a_bundle_carries_the_whole_chain_of_custody() {
    // Bob's bundle to Carol contains what Carol needs about Alice,
    // although Carol never dealt with Alice.
    let authority = authority();
    let mut alice = authority.node();
    let mut bob = authority.node();
    let mut carol = authority.node();
    alice
        .open_certified(&authority.certify(alice.id(), 100 * ARX, 2))
        .unwrap();
    bob.open_account(0).unwrap();
    carol.open_account(0).unwrap();

    let to_bob = alice.send(bob.id(), 30 * ARX).unwrap();
    let (handed, _) = bob
        .ingest_bundle(&alice.payment_bundle(&to_bob).unwrap())
        .unwrap();
    bob.receive(&handed).unwrap();

    let to_carol = bob.send(carol.id(), 20 * ARX).unwrap();
    let (handed, _) = carol
        .ingest_bundle(&bob.payment_bundle(&to_carol).unwrap())
        .unwrap();
    carol.receive(&handed).unwrap();
    assert_eq!(carol.balance(), 20 * ARX);
}

#[test]
fn a_bundle_must_carry_exactly_one_payment() {
    let authority = authority();
    let mut alice = authority.node();
    let mut bob = authority.node();
    alice
        .open_certified(&authority.certify(alice.id(), 100 * ARX, 2))
        .unwrap();
    let payment = alice.send(bob.id(), 30 * ARX).unwrap();
    let mut frames = alice.payment_bundle(&payment).unwrap();

    frames.push(Frame::Payment(payment));
    assert_eq!(
        bundle_fault(bob.ingest_bundle(&frames)),
        BundleFault::PaymentCount
    );
    frames.truncate(frames.len() - 2);
    assert_eq!(
        bundle_fault(bob.ingest_bundle(&frames)),
        BundleFault::PaymentCount
    );
}

#[test]
fn a_bundle_with_an_unfunded_history_is_refused_on_ingest() {
    // The bundle is well formed, but its history opens an account
    // with a balance no issuer certified.
    let authority = authority();
    let mut outsider = DurableWallet::open(MemoryStorage::default()).unwrap();
    let mut bob = authority.node();
    outsider.open_account(1_000 * ARX).unwrap();
    let payment = outsider.send(bob.id(), 500 * ARX).unwrap();
    let frames = outsider.payment_bundle(&payment).unwrap();
    assert!(matches!(
        bob.ingest_bundle(&frames),
        Err(ArxiaError::Issuance { .. })
    ));
}
