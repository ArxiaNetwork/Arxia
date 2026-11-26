//! What travels with a payment: reserve certificates and equivocation
//! proofs ride in the same bundle as the blocks.

use arxia_core::{ArxiaError, BundleFault, EquivocationFault};
use arxia_crypto::generate_keypair;
use arxia_finality::witness::{receive_final, Witness, WitnessConfirmation, WitnessRoster};
use arxia_lattice::bundle::{decode, encode, Frame, MAX_FRAME_LEN};
use arxia_lattice::chain::{AccountChain, VectorClock};
use arxia_lattice::{
    Block, DurableWallet, IssuanceCertificate, IssuancePolicy, ReserveCertificate, Wallet,
    WalletConfig,
};
use arxia_storage::MemoryStorage;
use ed25519_dalek::SigningKey;

const ARX: u64 = 1_000_000;

type Node = DurableWallet<MemoryStorage>;

struct World {
    issuer_keys: Vec<SigningKey>,
    policy: IssuancePolicy,
    witnesses: Vec<Witness<MemoryStorage>>,
    roster: WitnessRoster,
}

impl World {
    fn new() -> Self {
        let issuer_keys: Vec<SigningKey> = (0..3).map(|_| generate_keypair().0).collect();
        let public = issuer_keys
            .iter()
            .map(|k| k.verifying_key().to_bytes())
            .collect();
        let policy = IssuancePolicy::new(public, 2).unwrap();
        let witnesses: Vec<_> = (0..3)
            .map(|_| {
                Witness::new(
                    DurableWallet::open_with_issuance(MemoryStorage::default(), policy.clone())
                        .unwrap(),
                )
            })
            .collect();
        let roster =
            WitnessRoster::new(witnesses.iter().map(|w| (w.public_key(), 10)).collect()).unwrap();
        Self {
            issuer_keys,
            policy,
            witnesses,
            roster,
        }
    }

    fn node(&self) -> Node {
        let config = WalletConfig {
            issuance: Some(self.policy.clone()),
            witnesses: Some(self.roster.clone()),
        };
        let mut node = DurableWallet::open_with_config(MemoryStorage::default(), config).unwrap();
        node.open_account(0).unwrap();
        node
    }

    fn certify(&self, account: &str, amount: u64) -> IssuanceCertificate {
        let mut certificate = IssuanceCertificate::new(account, amount).unwrap();
        certificate
            .sign(&self.policy, &self.issuer_keys[0])
            .unwrap();
        certificate
            .sign(&self.policy, &self.issuer_keys[1])
            .unwrap();
        certificate
    }

    /// Hand every witness a certificate and some blocks, then ask for
    /// a confirmation of `block`.
    fn confirm(
        &mut self,
        certificate: &IssuanceCertificate,
        history: &[Block],
        block: &Block,
    ) -> Vec<WitnessConfirmation> {
        self.witnesses
            .iter_mut()
            .map(|witness| {
                witness.ingest_issuance(certificate).unwrap();
                witness.ingest_all(history).unwrap();
                witness.confirm(block).unwrap()
            })
            .collect()
    }
}

/// An account with a certified balance whose key is used directly.
struct Raw {
    account: AccountChain,
    vclock: VectorClock,
    certificate: IssuanceCertificate,
}

impl Raw {
    fn new(world: &World, balance: u64) -> Self {
        let mut account = AccountChain::new();
        let mut vclock = VectorClock::new();
        let certificate = world.certify(account.id(), balance);
        account.open(balance, &mut vclock).unwrap();
        Self {
            account,
            vclock,
            certificate,
        }
    }

    fn send(&mut self, destination: &str, amount: u64) -> Block {
        self.account
            .send(destination, amount, &mut self.vclock)
            .unwrap()
    }

    /// Sign another block for the position of the last one.
    fn send_again(&mut self, destination: &str, amount: u64) -> Block {
        let replaced = self.account.chain.pop().unwrap();
        self.account.balance = self.account.chain.last().unwrap().balance;
        self.account.nonce = replaced.nonce - 1;
        self.send(destination, amount)
    }
}

/// Bob, paid with finality by a payer who also signed for someone
/// else, and who has seen both blocks.
fn bob_holding_a_proof(world: &mut World) -> (Node, Raw, Block) {
    let mut bob = world.node();
    let dave = world.node();
    let mut payer = Raw::new(world, 100 * ARX);
    let history = payer.account.chain.clone();
    let to_bob = payer.send(bob.id(), 60 * ARX);
    let confirmations = world.confirm(&payer.certificate, &history, &to_bob);
    bob.ingest_issuance(&payer.certificate).unwrap();
    bob.ingest_all(&history).unwrap();
    receive_final(&mut bob, &to_bob, &confirmations, &world.roster).unwrap();
    let to_dave = payer.send_again(dave.id(), 60 * ARX);
    assert!(bob.ingest(&to_dave).is_err());
    (bob, payer, to_dave)
}

#[test]
fn an_equivocation_proof_spreads_with_the_next_payment() {
    let mut world = World::new();
    let (mut bob, mut payer, to_dave) = bob_holding_a_proof(&mut world);
    let mut carol = world.node();

    let to_carol = bob.send(carol.id(), 25 * ARX).unwrap();
    let bundle = decode(&encode(&bob.payment_bundle(&to_carol).unwrap()).unwrap()).unwrap();
    assert_eq!(
        bundle
            .iter()
            .filter(|frame| matches!(frame, Frame::EquivocationBlock(_)))
            .count(),
        2
    );
    let (payment, _) = carol.ingest_bundle(&bundle).unwrap();
    carol.receive(&payment).unwrap();
    assert_eq!(carol.balance(), 25 * ARX);

    // Carol never saw the two blocks arrive; she now holds the proof
    // and refuses what the payer signs next.
    assert!(carol
        .wallet()
        .ledger()
        .equivocation_for(payer.account.id())
        .is_some());
    let later = payer.send(carol.id(), ARX);
    for block in [&to_dave, &later] {
        assert!(matches!(
            carol.ingest(block),
            Err(ArxiaError::Equivocation {
                fault: EquivocationFault::AccountFrozen { .. }
            }) | Err(ArxiaError::NonceConflict { .. })
        ));
    }
}

/// A reserve of `amount`, certified, and a receiver paid from it with
/// no witness in reach.
fn bob_paid_from_a_reserve(world: &mut World, amount: u64) -> (Node, ReserveCertificate) {
    let mut main = Wallet::with_issuance(world.policy.clone());
    let certificate = world.certify(main.id(), 100 * ARX);
    main.open_certified(&certificate).unwrap();
    let mut reserve = AccountChain::new();
    let mut vclock = VectorClock::new();
    reserve.open(0, &mut vclock).unwrap();
    let funding = main.send(reserve.id(), amount).unwrap();
    reserve.receive(&funding, &mut vclock).unwrap();

    let mut history = main.chain().to_vec();
    history.push(reserve.chain[0].clone());
    let confirmations = world.confirm(&certificate, &history, &reserve.chain[1]);
    let reserve_certificate = ReserveCertificate::new(
        funding,
        reserve.chain[0].clone(),
        reserve.chain[1].clone(),
        confirmations,
    )
    .unwrap();

    let mut bob = world.node();
    reserve.send(bob.id(), amount, &mut vclock).unwrap();
    bob.receive_from_reserve(&reserve_certificate, &reserve.chain[2..])
        .unwrap();
    (bob, reserve_certificate)
}

#[test]
fn a_reserve_certificate_travels_with_the_funds_it_backs() {
    let mut world = World::new();
    let (mut bob, reserve_certificate) = bob_paid_from_a_reserve(&mut world, 20 * ARX);
    let mut carol = world.node();

    // Bob pays Carol. Nothing is handed over besides the bundle.
    let to_carol = bob.send(carol.id(), 12 * ARX).unwrap();
    let bundle = decode(&encode(&bob.payment_bundle(&to_carol).unwrap()).unwrap()).unwrap();
    let (payment, _) = carol.ingest_bundle(&bundle).unwrap();
    carol.receive(&payment).unwrap();

    assert_eq!(carol.balance(), 12 * ARX);
    assert_eq!(
        carol
            .wallet()
            .ledger()
            .reserve_for(reserve_certificate.account())
            .map(ReserveCertificate::amount),
        Some(20 * ARX)
    );
}

#[test]
fn a_device_without_a_roster_refuses_funds_that_rest_on_a_reserve() {
    let mut world = World::new();
    let (mut bob, _) = bob_paid_from_a_reserve(&mut world, 20 * ARX);
    let mut plain =
        DurableWallet::open_with_issuance(MemoryStorage::default(), world.policy.clone()).unwrap();
    plain.open_account(0).unwrap();
    let payment = bob.send(plain.id(), 12 * ARX).unwrap();
    assert!(matches!(
        plain.ingest_bundle(&bob.payment_bundle(&payment).unwrap()),
        Err(ArxiaError::UnknownSourceSend { .. })
    ));
    assert_eq!(plain.balance(), 0);
}

#[test]
fn incomplete_groups_are_refused() {
    let mut world = World::new();
    let (mut bob, _) = bob_paid_from_a_reserve(&mut world, 20 * ARX);
    let mut carol = world.node();
    let payment = bob.send(carol.id(), 12 * ARX).unwrap();
    let bundle = bob.payment_bundle(&payment).unwrap();

    let drop_first = |wanted: fn(&Frame) -> bool| -> Vec<Frame> {
        let mut dropped = false;
        bundle
            .iter()
            .filter(|frame| {
                if !dropped && wanted(frame) {
                    dropped = true;
                    return false;
                }
                true
            })
            .cloned()
            .collect()
    };
    let two_of_three = drop_first(|frame| matches!(frame, Frame::ReserveBlock(_)));
    assert!(matches!(
        carol.ingest_bundle(&two_of_three),
        Err(ArxiaError::Bundle {
            fault: BundleFault::IncompleteGroup
        })
    ));

    let mut one_of_two = bundle.clone();
    one_of_two.insert(0, Frame::EquivocationBlock(payment));
    assert!(matches!(
        carol.ingest_bundle(&one_of_two),
        Err(ArxiaError::Bundle {
            fault: BundleFault::IncompleteGroup
        })
    ));
    assert_eq!(carol.balance(), 0);
}

#[test]
fn the_new_frames_fit_one_radio_packet() {
    let mut world = World::new();
    let (mut bob, _) = bob_paid_from_a_reserve(&mut world, 20 * ARX);
    let carol = world.node();
    let payment = bob.send(carol.id(), 12 * ARX).unwrap();
    for frame in bob.payment_bundle(&payment).unwrap() {
        assert!(frame.to_bytes().unwrap().len() <= MAX_FRAME_LEN);
    }
}
