//! Payments that do not carry their history.
//!
//! A block the witnesses settled is taken as a starting point: a
//! device that holds its confirmations needs nothing older. A payment
//! then travels as the payment block and its confirmations, and what a
//! payer shows the witnesses is what it did since its own last settled
//! block.

use arxia_core::{ArxiaError, WitnessFault};
use arxia_crypto::generate_keypair;
use arxia_finality::witness::{receive_final, Witness, WitnessConfirmation, WitnessRoster};
use arxia_lattice::bundle::{encode, Frame};
use arxia_lattice::chain::{AccountChain, VectorClock};
use arxia_lattice::{Block, DurableWallet, IssuanceCertificate, IssuancePolicy, WalletConfig};
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
        // The roster is fixed first, from three keys; the witnesses are
        // then opened with a configuration that includes it, so that
        // they too can start from settled blocks.
        let seeds: Vec<[u8; 32]> = (0..3).map(|i| [i as u8 + 1; 32]).collect();
        let roster = WitnessRoster::new(
            seeds
                .iter()
                .map(|seed| (SigningKey::from_bytes(seed).verifying_key().to_bytes(), 10))
                .collect(),
        )
        .unwrap();
        let config = WalletConfig {
            issuance: Some(policy.clone()),
            witnesses: Some(roster.clone()),
        };
        let witnesses = seeds
            .iter()
            .map(|seed| {
                let wallet = DurableWallet::open_with_entropy(
                    MemoryStorage::default(),
                    config.clone(),
                    || *seed,
                )
                .unwrap();
                Witness::new(wallet)
            })
            .collect();
        Self {
            issuer_keys,
            policy,
            witnesses,
            roster,
        }
    }

    fn config(&self) -> WalletConfig {
        WalletConfig {
            issuance: Some(self.policy.clone()),
            witnesses: Some(self.roster.clone()),
        }
    }

    fn node(&self) -> Node {
        let mut node =
            DurableWallet::open_with_config(MemoryStorage::default(), self.config()).unwrap();
        node.open_account(0).unwrap();
        node
    }

    /// A node whose account opens with a certified balance.
    fn funded(&self, amount: u64) -> Node {
        let mut node =
            DurableWallet::open_with_config(MemoryStorage::default(), self.config()).unwrap();
        let mut certificate = IssuanceCertificate::new(node.id(), amount).unwrap();
        certificate
            .sign(&self.policy, &self.issuer_keys[0])
            .unwrap();
        certificate
            .sign(&self.policy, &self.issuer_keys[1])
            .unwrap();
        node.open_certified(&certificate).unwrap();
        node
    }

    /// The witnesses take in a bundle and confirm its payment.
    fn confirm(&mut self, bundle: &[Frame]) -> Vec<WitnessConfirmation> {
        self.witnesses
            .iter_mut()
            .map(|witness| confirm_with(witness, bundle).unwrap())
            .collect()
    }
}

/// Hand `bundle` to one witness and ask it to confirm the payment.
fn confirm_with(
    witness: &mut Witness<MemoryStorage>,
    bundle: &[Frame],
) -> Result<WitnessConfirmation, ArxiaError> {
    let (payment, _) = witness.ingest_bundle(bundle)?;
    witness.confirm(&payment)
}

/// `payer` pays `receiver` through the witnesses: a short bundle to
/// the witnesses, then the payment and its confirmations to the
/// receiver. Returns what the receiver was handed.
fn pay(world: &mut World, payer: &mut Node, receiver: &mut Node, amount: u64) -> Vec<Frame> {
    let payment = payer.send(receiver.id(), amount).unwrap();
    let confirmations = world.confirm(&payer.delta_bundle(&payment));
    // The payer keeps the confirmations of its own payment: this is
    // its next starting point.
    payer.ingest_settlement(&payment, &confirmations).unwrap();
    receive_final(receiver, &payment, &confirmations, &world.roster).unwrap();
    let mut handed: Vec<Frame> = confirmations.into_iter().map(Frame::Confirmation).collect();
    handed.push(Frame::Payment(payment));
    handed
}

#[test]
fn a_receiver_that_knows_nothing_credits_a_settled_payment() {
    let mut world = World::new();
    let mut alice = world.funded(100 * ARX);
    let mut bob = world.node();

    let handed = pay(&mut world, &mut alice, &mut bob, 30 * ARX);

    // Bob was handed the payment and three confirmations, nothing
    // else: not Alice's opening block, not her issuance certificate.
    assert_eq!(handed.len(), 4);
    assert!(encode(&handed).unwrap().len() < 600);
    assert_eq!(bob.balance(), 30 * ARX);
    assert!(bob.wallet().ledger().issuance_for(alice.id()).is_none());
}

#[test]
fn funds_are_paid_on_without_their_history() {
    let mut world = World::new();
    let mut alice = world.funded(100 * ARX);
    let mut bob = world.node();
    let mut carol = world.node();

    pay(&mut world, &mut alice, &mut bob, 30 * ARX);
    pay(&mut world, &mut bob, &mut carol, 20 * ARX);

    assert_eq!(alice.balance(), 70 * ARX);
    assert_eq!(bob.balance(), 10 * ARX);
    assert_eq!(carol.balance(), 20 * ARX);
    // Carol never held a block of Alice's account.
    assert!(carol.wallet().ledger().get_chain(alice.id()).is_none());
}

#[test]
fn a_witness_that_was_not_there_confirms_from_the_short_bundle() {
    // A fourth witness joins after Alice paid Bob. It has seen nothing.
    let mut world = World::new();
    let mut alice = world.funded(100 * ARX);
    let mut bob = world.node();
    let carol = world.node();
    pay(&mut world, &mut alice, &mut bob, 30 * ARX);

    let mut newcomer = Witness::new(
        DurableWallet::open_with_config(MemoryStorage::default(), world.config()).unwrap(),
    );
    let payment = bob.send(carol.id(), 20 * ARX).unwrap();
    let confirmation = confirm_with(&mut newcomer, &bob.delta_bundle(&payment)).unwrap();
    assert!(confirmation.verifies());
}

#[test]
fn the_short_bundle_does_not_grow_with_the_age_of_the_account() {
    let mut world = World::new();
    let mut alice = world.funded(1_000 * ARX);
    let mut bob = world.node();
    pay(&mut world, &mut alice, &mut bob, 100 * ARX);

    // Twenty payments back and forth.
    let mut short = Vec::new();
    let mut full = Vec::new();
    for round in 0..20 {
        let (payer, receiver) = if round % 2 == 0 {
            (&mut bob, &mut alice)
        } else {
            (&mut alice, &mut bob)
        };
        let payment = payer.send(receiver.id(), ARX).unwrap();
        short.push(payer.delta_bundle(&payment).len());
        full.push(payer.payment_bundle(&payment).unwrap().len());
        let confirmations = world.confirm(&payer.delta_bundle(&payment));
        payer.ingest_settlement(&payment, &confirmations).unwrap();
        receive_final(receiver, &payment, &confirmations, &world.roster).unwrap();
    }

    let (first, last) = (short[1], short[19]);
    assert_eq!(first, last, "the short bundle has a steady size: {short:?}");
    assert!(last <= 12, "{short:?}");
    assert!(full[19] > 4 * last, "full {full:?} against short {short:?}");
}

#[test]
fn a_block_that_is_not_settled_cannot_start_a_chain() {
    let world = World::new();
    let mut alice = world.funded(100 * ARX);
    let mut carol = world.node();
    let payment = alice.send(carol.id(), 30 * ARX).unwrap();

    // Carol is shown the payment alone, with no confirmation.
    assert!(matches!(
        receive_final(&mut carol, &payment, &[], &world.roster),
        Err(ArxiaError::Witness {
            fault: WitnessFault::NotFinal { .. }
        })
    ));
    assert!(matches!(
        carol.ingest(&payment),
        Err(ArxiaError::NonceGap { .. })
    ));
    assert_eq!(carol.balance(), 0);
}

#[test]
fn two_of_three_confirmations_do_not_make_a_starting_point() {
    let mut world = World::new();
    let mut alice = world.funded(100 * ARX);
    let mut carol = world.node();
    let payment = alice.send(carol.id(), 30 * ARX).unwrap();
    let mut confirmations = world.confirm(&alice.delta_bundle(&payment));
    confirmations.truncate(2);

    assert!(receive_final(&mut carol, &payment, &confirmations, &world.roster).is_err());
    assert!(carol.ingest_settlement(&payment, &confirmations).is_err());
    assert!(carol.ingest(&payment).is_err());
    assert_eq!(carol.balance(), 0);
}

#[test]
fn the_ordinary_rules_apply_after_a_starting_point() {
    // Carol starts Alice's chain at a settled payment. What Alice
    // signs next is checked against the balance that block states.
    let mut world = World::new();
    let mut vclock = VectorClock::new();
    let mut payer = AccountChain::from_seed(&[42; 32]);
    let mut certificate = IssuanceCertificate::new(payer.id(), 100 * ARX).unwrap();
    certificate
        .sign(&world.policy, &world.issuer_keys[0])
        .unwrap();
    certificate
        .sign(&world.policy, &world.issuer_keys[1])
        .unwrap();
    let mut carol = world.node();
    let open = payer.open(100 * ARX, &mut vclock).unwrap();
    let payment = payer.send(carol.id(), 30 * ARX, &mut vclock).unwrap();
    let confirmations: Vec<_> = world
        .witnesses
        .iter_mut()
        .map(|witness| {
            witness.ingest_issuance(&certificate).unwrap();
            witness.ingest_all(std::slice::from_ref(&open)).unwrap();
            witness.confirm(&payment).unwrap()
        })
        .collect();
    receive_final(&mut carol, &payment, &confirmations, &world.roster).unwrap();

    // Alice has 70 left. She signs a payment of 500.
    payer.balance = 10_000 * ARX;
    let overdraft: Block = payer.send(carol.id(), 500 * ARX, &mut vclock).unwrap();
    assert!(matches!(
        carol.ingest(&overdraft),
        Err(ArxiaError::InsufficientBalance { .. })
    ));
    // The opening block, older than the starting point, is superseded:
    // offered again it changes nothing.
    carol.ingest(&open).unwrap();
    assert_eq!(
        carol.wallet().ledger().get_chain(payer.id()).map(Vec::len),
        Some(1)
    );
}

#[test]
fn a_starting_point_survives_a_restart() {
    let mut world = World::new();
    let mut alice = world.funded(100 * ARX);
    let mut bob = world.node();
    let mut carol = world.node();
    pay(&mut world, &mut alice, &mut bob, 30 * ARX);
    pay(&mut world, &mut bob, &mut carol, 20 * ARX);

    let mut bob = DurableWallet::open_with_config(bob.into_storage(), world.config()).unwrap();
    let mut carol = DurableWallet::open_with_config(carol.into_storage(), world.config()).unwrap();
    assert_eq!(bob.balance(), 10 * ARX);
    assert_eq!(carol.balance(), 20 * ARX);

    // Both keep paying after the restart.
    pay(&mut world, &mut carol, &mut bob, 5 * ARX);
    assert_eq!(bob.balance(), 15 * ARX);
    assert_eq!(carol.balance(), 15 * ARX);
}

#[test]
fn a_later_settled_block_carries_a_chain_forward() {
    // Carol holds Alice's chain as of an earlier payment. Alice then
    // pays others; Carol sees none of it. A later settled payment to
    // Carol is accepted over the gap.
    let mut world = World::new();
    let mut alice = world.funded(100 * ARX);
    let mut bob = world.node();
    let mut carol = world.node();
    pay(&mut world, &mut alice, &mut carol, 10 * ARX);
    pay(&mut world, &mut alice, &mut bob, 10 * ARX);
    pay(&mut world, &mut alice, &mut bob, 10 * ARX);
    pay(&mut world, &mut alice, &mut carol, 10 * ARX);
    assert_eq!(carol.balance(), 20 * ARX);
    assert_eq!(alice.balance(), 60 * ARX);
}
