//! A node that took in the block the witnesses did not settle follows
//! them to the one they did.
//!
//! The payer signs two blocks for one position. The witnesses settle
//! the one paid to Bob. Carol happened to see the other one first.

use arxia_core::{ArxiaError, EquivocationFault};
use arxia_crypto::generate_keypair;
use arxia_finality::witness::{receive_final, Witness, WitnessConfirmation, WitnessRoster};
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

    fn confirm(&mut self, payer: &Payer, block: &Block) -> Vec<WitnessConfirmation> {
        self.witnesses
            .iter_mut()
            .map(|witness| {
                witness.ingest_issuance(&payer.certificate).unwrap();
                witness.ingest_all(&payer.history()).unwrap();
                witness.confirm(block).unwrap()
            })
            .collect()
    }
}

/// A payer whose key signs two payments for position 2, and one more
/// on top of the second.
struct Payer {
    account: AccountChain,
    certificate: IssuanceCertificate,
    to_bob: Block,
    to_dave: Block,
    after_dave: Block,
}

impl Payer {
    fn new(world: &World, bob: &str, dave: &str) -> Self {
        let mut account = AccountChain::new();
        let mut vclock = VectorClock::new();
        let certificate = world.certify(account.id(), 100 * ARX);
        account.open(100 * ARX, &mut vclock).unwrap();
        let to_bob = account.send(bob, 60 * ARX, &mut vclock).unwrap();
        account.chain.pop();
        account.balance = 100 * ARX;
        account.nonce -= 1;
        let to_dave = account.send(dave, 60 * ARX, &mut vclock).unwrap();
        let after_dave = account.send(dave, 5 * ARX, &mut vclock).unwrap();
        Self {
            account,
            certificate,
            to_bob,
            to_dave,
            after_dave,
        }
    }

    fn history(&self) -> Vec<Block> {
        self.account.chain[..1].to_vec()
    }
}

/// The payer, Bob paid with finality, and Dave who was signed the
/// other block.
fn setup(world: &mut World) -> (Payer, Node, Node) {
    let mut bob = world.node();
    let dave = world.node();
    let payer = Payer::new(world, bob.id(), dave.id());
    let confirmations = world.confirm(&payer, &payer.to_bob);
    bob.ingest_issuance(&payer.certificate).unwrap();
    bob.ingest_all(&payer.history()).unwrap();
    receive_final(&mut bob, &payer.to_bob, &confirmations, &world.roster).unwrap();
    (payer, bob, dave)
}

/// Hand `node` the payer's certificate, history and the block that the
/// witnesses did not settle.
fn sees_the_other_block(node: &mut Node, payer: &Payer) {
    node.ingest_issuance(&payer.certificate).unwrap();
    node.ingest_all(&payer.history()).unwrap();
    node.ingest(&payer.to_dave).unwrap();
}

fn held_at(node: &Node, payer: &Payer, position: usize) -> Option<String> {
    node.wallet()
        .ledger()
        .get_chain(payer.account.id())
        .and_then(|chain| chain.get(position - 1))
        .map(|block| block.hash.clone())
}

#[test]
fn a_node_holding_the_other_block_follows_the_witnesses() {
    let mut world = World::new();
    let (payer, mut bob, _dave) = setup(&mut world);
    let mut carol = world.node();
    sees_the_other_block(&mut carol, &payer);
    assert_eq!(held_at(&carol, &payer, 2), Some(payer.to_dave.hash.clone()));

    // Bob pays Carol. His bundle carries the settled block and its
    // confirmations.
    let to_carol = bob.send(carol.id(), 25 * ARX).unwrap();
    let (payment, _) = carol
        .ingest_bundle(&bob.payment_bundle(&to_carol).unwrap())
        .unwrap();
    carol.receive(&payment).unwrap();

    assert_eq!(carol.balance(), 25 * ARX);
    assert_eq!(held_at(&carol, &payer, 2), Some(payer.to_bob.hash.clone()));
    // The two signatures are kept as a proof all the same.
    assert!(carol
        .wallet()
        .ledger()
        .equivocation_for(payer.account.id())
        .is_some());
}

#[test]
fn what_the_payer_built_on_the_other_block_goes_with_it() {
    let mut world = World::new();
    let (payer, mut bob, _dave) = setup(&mut world);
    let mut carol = world.node();
    sees_the_other_block(&mut carol, &payer);
    carol.ingest(&payer.after_dave).unwrap();
    assert_eq!(
        held_at(&carol, &payer, 3),
        Some(payer.after_dave.hash.clone())
    );

    let to_carol = bob.send(carol.id(), 25 * ARX).unwrap();
    carol
        .ingest_bundle(&bob.payment_bundle(&to_carol).unwrap())
        .unwrap();
    assert_eq!(held_at(&carol, &payer, 2), Some(payer.to_bob.hash.clone()));
    assert_eq!(held_at(&carol, &payer, 3), None);
}

#[test]
fn following_the_witnesses_survives_a_restart() {
    let mut world = World::new();
    let (payer, mut bob, _dave) = setup(&mut world);
    let mut carol = world.node();
    sees_the_other_block(&mut carol, &payer);
    carol.ingest(&payer.after_dave).unwrap();

    let first = bob.send(carol.id(), 25 * ARX).unwrap();
    let (payment, _) = carol
        .ingest_bundle(&bob.payment_bundle(&first).unwrap())
        .unwrap();
    carol.receive(&payment).unwrap();

    let mut carol = DurableWallet::open_with_config(carol.into_storage(), world.config()).unwrap();
    assert_eq!(carol.balance(), 25 * ARX);
    assert_eq!(held_at(&carol, &payer, 2), Some(payer.to_bob.hash.clone()));
    assert_eq!(held_at(&carol, &payer, 3), None);

    // The device keeps working: what it stores next reopens cleanly.
    let second = bob.send(carol.id(), 10 * ARX).unwrap();
    let (payment, _) = carol
        .ingest_bundle(&bob.payment_bundle(&second).unwrap())
        .unwrap();
    carol.receive(&payment).unwrap();
    let carol = DurableWallet::open_with_config(carol.into_storage(), world.config()).unwrap();
    assert_eq!(carol.balance(), 35 * ARX);
}

#[test]
fn a_block_that_was_already_received_is_not_replaced() {
    // Dave credited the block signed for him without waiting for the
    // witnesses. His ledger cannot give that block up: his own chain
    // rests on it.
    let mut world = World::new();
    let (payer, mut bob, mut dave) = setup(&mut world);
    sees_the_other_block(&mut dave, &payer);
    dave.receive(&payer.to_dave).unwrap();
    assert_eq!(dave.balance(), 60 * ARX);

    let to_dave = bob.send(dave.id(), 25 * ARX).unwrap();
    assert!(matches!(
        dave.ingest_bundle(&bob.payment_bundle(&to_dave).unwrap()),
        Err(ArxiaError::NonceConflict { .. })
    ));
    assert_eq!(held_at(&dave, &payer, 2), Some(payer.to_dave.hash.clone()));
    assert_eq!(dave.balance(), 60 * ARX);
}

#[test]
fn the_settled_block_is_not_displaced_by_the_other_one() {
    let mut world = World::new();
    let (payer, mut bob, _dave) = setup(&mut world);
    assert!(matches!(
        bob.ingest(&payer.to_dave),
        Err(ArxiaError::NonceConflict { .. })
    ));
    assert_eq!(held_at(&bob, &payer, 2), Some(payer.to_bob.hash.clone()));
    assert_eq!(bob.balance(), 60 * ARX);
}

#[test]
fn replacement_needs_a_settlement() {
    // Without confirmations the incoming block is just the second
    // block of a pair.
    let mut world = World::new();
    let (payer, _bob, _dave) = setup(&mut world);
    let mut carol = world.node();
    sees_the_other_block(&mut carol, &payer);
    assert!(matches!(
        carol.ingest(&payer.to_bob),
        Err(ArxiaError::NonceConflict { .. })
    ));
    assert_eq!(held_at(&carol, &payer, 2), Some(payer.to_dave.hash.clone()));

    let mut ledger = carol.wallet().ledger().clone();
    assert!(matches!(
        ledger.replace_with_settled(&payer.to_bob),
        Err(ArxiaError::Equivocation {
            fault: EquivocationFault::NotAConflict
        })
    ));
}
