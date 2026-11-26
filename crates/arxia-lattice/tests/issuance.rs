//! Issuance under a two-of-three policy: a balance exists only when
//! the issuers certified it, and a receiver with no network can check
//! that from the certificate alone.

use arxia_core::{ArxiaError, IssuanceFault};
use arxia_crypto::generate_keypair;
use arxia_lattice::chain::{AccountChain, VectorClock};
use arxia_lattice::{DurableWallet, IssuanceCertificate, IssuancePolicy, Ledger, Wallet};
use arxia_storage::MemoryStorage;
use ed25519_dalek::SigningKey;

const ARX: u64 = 1_000_000;

struct Issuers {
    keys: Vec<SigningKey>,
    policy: IssuancePolicy,
}

fn issuers() -> Issuers {
    let keys: Vec<SigningKey> = (0..3).map(|_| generate_keypair().0).collect();
    let public = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
    Issuers {
        policy: IssuancePolicy::new(public, 2).unwrap(),
        keys,
    }
}

impl Issuers {
    /// A certificate signed by the issuers at `signers`.
    fn certify(&self, account: &str, amount: u64, signers: &[usize]) -> IssuanceCertificate {
        let mut certificate = IssuanceCertificate::new(account, amount).unwrap();
        for &signer in signers {
            certificate.sign(&self.policy, &self.keys[signer]).unwrap();
        }
        certificate
    }
}

fn issuance_fault<T: std::fmt::Debug>(result: Result<T, ArxiaError>) -> IssuanceFault {
    match result {
        Err(ArxiaError::Issuance { fault }) => fault,
        other => panic!("expected an issuance fault, got {other:?}"),
    }
}

#[test]
fn a_balance_needs_a_certificate() {
    let authority = issuers();
    let mut wallet = Wallet::with_issuance(authority.policy.clone());
    assert_eq!(
        issuance_fault(wallet.open(100 * ARX)),
        IssuanceFault::MissingCertificate
    );
    assert_eq!(wallet.balance(), 0);
    assert!(wallet.chain().is_empty());
}

#[test]
fn an_account_can_always_open_empty() {
    let authority = issuers();
    let mut wallet = Wallet::with_issuance(authority.policy.clone());
    wallet.open(0).unwrap();
    assert_eq!(wallet.balance(), 0);
}

#[test]
fn two_issuers_out_of_three_certify_a_balance() {
    let authority = issuers();
    let mut wallet = Wallet::with_issuance(authority.policy.clone());
    let certificate = authority.certify(wallet.id(), 100 * ARX, &[0, 2]);
    wallet.open_certified(&certificate).unwrap();
    assert_eq!(wallet.balance(), 100 * ARX);
    assert_eq!(wallet.issuance(), Some(&certificate));
}

#[test]
fn one_issuer_is_not_enough() {
    let authority = issuers();
    let mut wallet = Wallet::with_issuance(authority.policy.clone());
    let certificate = authority.certify(wallet.id(), 100 * ARX, &[1]);
    assert_eq!(
        issuance_fault(wallet.open_certified(&certificate)),
        IssuanceFault::InsufficientSignatures {
            valid: 1,
            required: 2
        }
    );
    assert_eq!(wallet.balance(), 0);
}

#[test]
fn the_same_issuer_signing_twice_counts_once() {
    let authority = issuers();
    let mut wallet = Wallet::with_issuance(authority.policy.clone());
    let certificate = authority.certify(wallet.id(), 100 * ARX, &[1, 1]);
    assert_eq!(
        issuance_fault(wallet.open_certified(&certificate)),
        IssuanceFault::InsufficientSignatures {
            valid: 1,
            required: 2
        }
    );
}

#[test]
fn a_key_outside_the_policy_cannot_sign() {
    let authority = issuers();
    let outsider = generate_keypair().0;
    let wallet = Wallet::with_issuance(authority.policy.clone());
    let mut certificate = IssuanceCertificate::new(wallet.id(), 100 * ARX).unwrap();
    assert_eq!(
        issuance_fault(certificate.sign(&authority.policy, &outsider)),
        IssuanceFault::UnknownIssuer
    );
}

#[test]
fn signatures_made_by_other_keys_under_issuer_indices_do_not_count() {
    // The holder writes a certificate for itself, signs with keys it
    // generated, and labels the signatures with issuer indices.
    let authority = issuers();
    let own_keys: Vec<SigningKey> = (0..3).map(|_| generate_keypair().0).collect();
    let own_public = own_keys.iter().map(|k| k.verifying_key().to_bytes());
    let own_policy = IssuancePolicy::new(own_public.collect(), 2).unwrap();

    let mut wallet = Wallet::with_issuance(authority.policy.clone());
    let mut certificate = IssuanceCertificate::new(wallet.id(), 100 * ARX).unwrap();
    certificate.sign(&own_policy, &own_keys[0]).unwrap();
    certificate.sign(&own_policy, &own_keys[1]).unwrap();
    assert_eq!(
        issuance_fault(wallet.open_certified(&certificate)),
        IssuanceFault::InsufficientSignatures {
            valid: 0,
            required: 2
        }
    );
}

#[test]
fn the_opening_balance_must_equal_the_certified_amount() {
    let authority = issuers();
    let mut wallet = Wallet::with_issuance(authority.policy.clone());
    let certificate = authority.certify(wallet.id(), 100 * ARX, &[0, 1]);
    wallet.ingest_issuance(&certificate).unwrap();
    assert_eq!(
        issuance_fault(wallet.open(500 * ARX)),
        IssuanceFault::AmountMismatch {
            certified: 100 * ARX,
            opened: 500 * ARX
        }
    );
    wallet.open(100 * ARX).unwrap();
}

#[test]
fn a_certificate_covers_one_account_only() {
    let authority = issuers();
    let alice = Wallet::with_issuance(authority.policy.clone());
    let mut mallory = Wallet::with_issuance(authority.policy.clone());
    let for_alice = authority.certify(alice.id(), 100 * ARX, &[0, 1]);
    mallory.ingest_issuance(&for_alice).unwrap();
    assert_eq!(
        issuance_fault(mallory.open(100 * ARX)),
        IssuanceFault::MissingCertificate
    );
}

#[test]
fn a_second_certificate_with_another_amount_is_refused() {
    let authority = issuers();
    let mut wallet = Wallet::with_issuance(authority.policy.clone());
    wallet
        .ingest_issuance(&authority.certify(wallet.id(), 100 * ARX, &[0, 1]))
        .unwrap();
    let larger = authority.certify(wallet.id(), 900 * ARX, &[1, 2]);
    assert_eq!(
        issuance_fault(wallet.ingest_issuance(&larger)),
        IssuanceFault::ConflictingCertificate
    );
}

#[test]
fn an_invalid_extra_signature_does_not_spoil_a_valid_certificate() {
    let authority = issuers();
    let mut wallet = Wallet::with_issuance(authority.policy.clone());
    let certificate = authority.certify(wallet.id(), 100 * ARX, &[0, 1]);

    // Append an entry under issuer index 2 with a signature that does
    // not verify, and one under an index outside the policy.
    let mut bytes = certificate.to_bytes();
    bytes[40] += 2;
    bytes.push(2);
    bytes.extend_from_slice(&[7u8; 64]);
    bytes.push(200);
    bytes.extend_from_slice(&[9u8; 64]);
    let noisy = IssuanceCertificate::from_bytes(&bytes).unwrap();

    wallet.open_certified(&noisy).unwrap();
    assert_eq!(wallet.balance(), 100 * ARX);
}

#[test]
fn certificate_encoding_round_trips_and_fits_the_flash_value_limit() {
    let authority = issuers();
    let account = Wallet::new();
    let certificate = authority.certify(account.id(), 100 * ARX, &[0, 1, 2]);
    let bytes = certificate.to_bytes();
    assert_eq!(bytes.len(), 236);
    assert!(bytes.len() <= 256);
    assert_eq!(
        IssuanceCertificate::from_bytes(&bytes).unwrap(),
        certificate
    );

    assert!(IssuanceCertificate::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(IssuanceCertificate::from_bytes(&longer).is_err());
    assert!(IssuanceCertificate::from_bytes(&[]).is_err());
}

#[test]
fn malformed_policies_are_refused() {
    let keys: Vec<[u8; 32]> = (0..3).map(|_| generate_keypair().1.to_bytes()).collect();
    assert!(IssuancePolicy::new(keys.clone(), 0).is_err());
    assert!(IssuancePolicy::new(keys.clone(), 4).is_err());
    assert!(IssuancePolicy::new(vec![keys[0], keys[0], keys[1]], 2).is_err());
    assert!(IssuancePolicy::new(vec![], 1).is_err());
    assert!(IssuancePolicy::new(keys, 2).is_ok());
}

#[test]
fn two_offline_payments_under_an_issuance_policy() {
    let authority = issuers();
    let mut alice = Wallet::with_issuance(authority.policy.clone());
    let mut bob = Wallet::with_issuance(authority.policy.clone());
    let mut carol = Wallet::with_issuance(authority.policy.clone());
    alice
        .open_certified(&authority.certify(alice.id(), 100 * ARX, &[0, 1]))
        .unwrap();
    bob.open(0).unwrap();
    carol.open(0).unwrap();

    // Alice -> Bob: certificate, chain, payment.
    let pay_bob = alice.send(bob.id(), 30 * ARX).unwrap();
    bob.ingest_issuance(alice.issuance().unwrap()).unwrap();
    bob.ingest_all(alice.chain()).unwrap();
    bob.receive(&pay_bob).unwrap();

    // Bob -> Carol: Bob forwards Alice's certificate, which his ledger
    // holds, together with both chains.
    let pay_carol = bob.send(carol.id(), 20 * ARX).unwrap();
    carol
        .ingest_issuance(bob.ledger().issuance_for(alice.id()).unwrap())
        .unwrap();
    carol.ingest_all(alice.chain()).unwrap();
    carol.ingest_all(bob.chain()).unwrap();
    carol.receive(&pay_carol).unwrap();

    assert_eq!(alice.balance(), 70 * ARX);
    assert_eq!(bob.balance(), 10 * ARX);
    assert_eq!(carol.balance(), 20 * ARX);
}

#[test]
fn a_payment_from_an_uncertified_balance_is_not_credited() {
    // The sender opens an account with a balance on its own device,
    // outside any policy, and signs a valid SEND from it.
    let authority = issuers();
    let mut vc = VectorClock::new();
    let mut sender = AccountChain::new();
    let mut bob = Wallet::with_issuance(authority.policy.clone());
    bob.open(0).unwrap();
    sender.open(1_000 * ARX, &mut vc).unwrap();
    let pay = sender.send(bob.id(), 500 * ARX, &mut vc).unwrap();

    assert_eq!(
        issuance_fault(bob.ingest_all(&sender.chain)),
        IssuanceFault::MissingCertificate
    );
    assert!(bob.receive(&pay).is_err());
    assert_eq!(bob.balance(), 0);
}

#[test]
fn forwarded_funds_need_the_certificate_of_their_origin() {
    let authority = issuers();
    let mut alice = Wallet::with_issuance(authority.policy.clone());
    let mut bob = Wallet::with_issuance(authority.policy.clone());
    let mut carol = Wallet::with_issuance(authority.policy.clone());
    alice
        .open_certified(&authority.certify(alice.id(), 100 * ARX, &[0, 1]))
        .unwrap();
    bob.open(0).unwrap();
    carol.open(0).unwrap();
    let pay_bob = alice.send(bob.id(), 30 * ARX).unwrap();
    bob.ingest_issuance(alice.issuance().unwrap()).unwrap();
    bob.ingest_all(alice.chain()).unwrap();
    bob.receive(&pay_bob).unwrap();
    let pay_carol = bob.send(carol.id(), 20 * ARX).unwrap();

    // Carol is given the chains but not Alice's certificate.
    assert_eq!(
        issuance_fault(carol.ingest_all(alice.chain())),
        IssuanceFault::MissingCertificate
    );
    assert!(carol.receive(&pay_carol).is_err());
    assert_eq!(carol.balance(), 0);
}

#[test]
fn a_ledger_without_a_policy_keeps_its_behaviour() {
    let mut vc = VectorClock::new();
    let mut account = AccountChain::new();
    let open = account.open(5 * ARX, &mut vc).unwrap();
    let mut ledger = Ledger::new();
    ledger.add_block(open).unwrap();
    assert!(ledger.issuance_policy().is_none());
}

#[test]
fn certificates_survive_a_restart() {
    let authority = issuers();
    let mut alice = Wallet::with_issuance(authority.policy.clone());
    alice
        .open_certified(&authority.certify(alice.id(), 100 * ARX, &[0, 1]))
        .unwrap();

    let mut bob =
        DurableWallet::open_with_issuance(MemoryStorage::default(), authority.policy.clone())
            .unwrap();
    let certificate = authority.certify(bob.id(), 40 * ARX, &[1, 2]);
    bob.open_certified(&certificate).unwrap();
    let pay_bob = alice.send(bob.id(), 30 * ARX).unwrap();
    bob.ingest_issuance(alice.issuance().unwrap()).unwrap();
    bob.ingest_all(alice.chain()).unwrap();
    bob.receive(&pay_bob).unwrap();

    let storage = bob.into_storage();
    let bob = DurableWallet::open_with_issuance(storage, authority.policy.clone()).unwrap();
    assert_eq!(bob.balance(), 70 * ARX);
    assert_eq!(bob.wallet().issuance(), Some(&certificate));
    assert!(bob.wallet().ledger().issuance_for(alice.id()).is_some());
}

#[test]
fn stored_state_is_refused_under_a_different_policy() {
    // The storage medium is opened with other issuer keys than the
    // ones that certified its contents.
    let authority = issuers();
    let other = issuers();
    let mut bob =
        DurableWallet::open_with_issuance(MemoryStorage::default(), authority.policy.clone())
            .unwrap();
    bob.open_certified(&authority.certify(bob.id(), 40 * ARX, &[0, 1]))
        .unwrap();
    let storage = bob.into_storage();
    assert!(DurableWallet::open_with_issuance(storage, other.policy.clone()).is_err());
}
