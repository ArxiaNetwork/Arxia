//! A payment the witnesses settled stays good for the party that was
//! paid, whatever the payer signs afterwards.
//!
//! The payer signs two blocks for one account position. One of them
//! is confirmed by the witnesses and received by Bob. The other
//! surfaces later, the account is frozen, and the proof spreads. Bob
//! and whoever Bob pays must not be affected.

use arxia_core::{ArxiaError, EquivocationFault, WitnessFault};
use arxia_crypto::generate_keypair;
use arxia_finality::witness::{receive_final, Witness, WitnessConfirmation, WitnessRoster};
use arxia_lattice::bundle::Frame;
use arxia_lattice::chain::{AccountChain, VectorClock};
use arxia_lattice::{
    Block, DurableWallet, EquivocationProof, IssuanceCertificate, IssuancePolicy, WalletConfig,
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

    /// Ask the first `count` witnesses to confirm `block`, after
    /// handing them the certificate and the history.
    fn confirm(
        &mut self,
        certificate: &IssuanceCertificate,
        history: &[Block],
        block: &Block,
        count: usize,
    ) -> Vec<WitnessConfirmation> {
        self.witnesses
            .iter_mut()
            .take(count)
            .map(|witness| {
                witness.ingest_issuance(certificate).unwrap();
                witness.ingest_all(history).unwrap();
                witness.confirm(block).unwrap()
            })
            .collect()
    }
}

/// A payer whose key signs two payments for one position.
struct Payer {
    account: AccountChain,
    certificate: IssuanceCertificate,
    to_bob: Block,
    to_dave: Block,
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
        Self {
            account,
            certificate,
            to_bob,
            to_dave,
        }
    }

    fn history(&self) -> Vec<Block> {
        self.account.chain[..1].to_vec()
    }

    fn proof(&self) -> EquivocationProof {
        EquivocationProof::new(self.to_bob.clone(), self.to_dave.clone()).unwrap()
    }
}

fn frozen<T: std::fmt::Debug>(result: Result<T, ArxiaError>) -> bool {
    matches!(
        result,
        Err(ArxiaError::Equivocation {
            fault: EquivocationFault::AccountFrozen { .. }
        })
    )
}

/// Bob is paid, with finality, by a payer who also signed for Dave.
fn bob_is_paid(world: &mut World) -> (Node, Payer, Vec<WitnessConfirmation>) {
    let mut bob = world.node();
    let dave = world.node();
    let payer = Payer::new(world, bob.id(), dave.id());
    let confirmations = world.confirm(&payer.certificate, &payer.history(), &payer.to_bob, 3);
    bob.ingest_issuance(&payer.certificate).unwrap();
    bob.ingest_all(&payer.history()).unwrap();
    receive_final(&mut bob, &payer.to_bob, &confirmations, &world.roster).unwrap();
    assert_eq!(bob.balance(), 60 * ARX);
    (bob, payer, confirmations)
}

#[test]
fn a_receiver_keeps_the_confirmations_of_what_it_was_paid() {
    let mut world = World::new();
    let (bob, payer, confirmations) = bob_is_paid(&mut world);
    let kept = bob
        .wallet()
        .ledger()
        .settlement_for(&payer.to_bob.hash)
        .expect("the payment is recorded as settled");
    assert_eq!(kept.len(), 3);
    assert!(kept.iter().all(|c| confirmations.contains(c)));
}

#[test]
fn a_settled_payment_can_still_be_received_after_the_freeze() {
    // Bob holds the payment and its confirmations but has not yet
    // signed his RECEIVE when the other block reaches him.
    let mut world = World::new();
    let mut bob = world.node();
    let dave = world.node();
    let payer = Payer::new(&world, bob.id(), dave.id());
    let confirmations = world.confirm(&payer.certificate, &payer.history(), &payer.to_bob, 3);
    bob.ingest_issuance(&payer.certificate).unwrap();
    bob.ingest_all(&payer.history()).unwrap();
    bob.ingest(&payer.to_bob).unwrap();
    bob.ingest_settlement(&payer.to_bob, &confirmations)
        .unwrap();

    assert!(matches!(
        bob.ingest(&payer.to_dave),
        Err(ArxiaError::NonceConflict { .. })
    ));
    bob.receive(&payer.to_bob).unwrap();
    assert_eq!(bob.balance(), 60 * ARX);
}

#[test]
fn an_unsettled_payment_is_still_stopped_by_the_freeze() {
    let world = World::new();
    let mut bob = world.node();
    let dave = world.node();
    let payer = Payer::new(&world, bob.id(), dave.id());
    bob.ingest_issuance(&payer.certificate).unwrap();
    bob.ingest_all(&payer.history()).unwrap();
    bob.ingest(&payer.to_bob).unwrap();
    assert!(bob.ingest(&payer.to_dave).is_err());
    assert!(frozen(bob.receive(&payer.to_bob)));
    assert_eq!(bob.balance(), 0);
}

#[test]
fn someone_who_learned_of_the_proof_first_still_accepts_settled_funds() {
    // Carol hears about the payer's two signatures before she ever
    // deals with Bob. Bob then pays her with the funds he received.
    let mut world = World::new();
    let (mut bob, payer, _) = bob_is_paid(&mut world);
    let mut carol = world.node();
    carol.ingest_equivocation(&payer.proof()).unwrap();

    let to_carol = bob.send(carol.id(), 25 * ARX).unwrap();
    let bundle = bob.payment_bundle(&to_carol).unwrap();
    let (payment, _) = carol.ingest_bundle(&bundle).unwrap();
    carol.receive(&payment).unwrap();
    assert_eq!(carol.balance(), 25 * ARX);
}

#[test]
fn without_the_confirmations_the_frozen_block_is_refused() {
    // The same bundle with its confirmation frames removed: Carol has
    // no evidence that the block at the frozen position was settled.
    let mut world = World::new();
    let (mut bob, payer, _) = bob_is_paid(&mut world);
    let mut carol = world.node();
    carol.ingest_equivocation(&payer.proof()).unwrap();

    let to_carol = bob.send(carol.id(), 25 * ARX).unwrap();
    let stripped: Vec<Frame> = bob
        .payment_bundle(&to_carol)
        .unwrap()
        .into_iter()
        .filter(|frame| !matches!(frame, Frame::Confirmation(_)))
        .collect();
    assert!(frozen(carol.ingest_bundle(&stripped)));
    assert_eq!(carol.balance(), 0);
}

#[test]
fn the_other_block_cannot_be_passed_off_as_settled() {
    // The confirmations are for the block paid to Bob. Attached to
    // the block signed for Dave they settle nothing.
    let mut world = World::new();
    let (_bob, payer, confirmations) = bob_is_paid(&mut world);
    let mut carol = world.node();
    assert!(matches!(
        carol.ingest_settlement(&payer.to_dave, &confirmations),
        Err(ArxiaError::Witness {
            fault: WitnessFault::NotFinal {
                confirmed: 0,
                total: 30
            }
        })
    ));
    carol.ingest_equivocation(&payer.proof()).unwrap();
    carol.ingest_issuance(&payer.certificate).unwrap();
    carol.ingest_all(&payer.history()).unwrap();
    assert!(frozen(carol.ingest(&payer.to_dave)));
}

#[test]
fn two_of_three_confirmations_do_not_settle_a_block() {
    let mut world = World::new();
    let mut bob = world.node();
    let dave = world.node();
    let payer = Payer::new(&world, bob.id(), dave.id());
    let two = world.confirm(&payer.certificate, &payer.history(), &payer.to_bob, 2);
    assert!(matches!(
        bob.ingest_settlement(&payer.to_bob, &two),
        Err(ArxiaError::Witness {
            fault: WitnessFault::NotFinal { .. }
        })
    ));
    assert!(bob
        .wallet()
        .ledger()
        .settlement_for(&payer.to_bob.hash)
        .is_none());
}

#[test]
fn a_ledger_without_a_roster_records_no_settlement() {
    let mut world = World::new();
    let dave = world.node();
    let mut plain =
        DurableWallet::open_with_issuance(MemoryStorage::default(), world.policy.clone()).unwrap();
    plain.open_account(0).unwrap();
    let payer = Payer::new(&world, plain.id(), dave.id());
    let confirmations = world.confirm(&payer.certificate, &payer.history(), &payer.to_bob, 3);
    assert!(matches!(
        plain.ingest_settlement(&payer.to_bob, &confirmations),
        Err(ArxiaError::Witness {
            fault: WitnessFault::NoRoster
        })
    ));
}

#[test]
fn settlements_survive_a_restart() {
    let mut world = World::new();
    let (bob, payer, _) = bob_is_paid(&mut world);
    let mut bob = DurableWallet::open_with_config(bob.into_storage(), world.config()).unwrap();
    assert_eq!(
        bob.wallet()
            .ledger()
            .settlement_for(&payer.to_bob.hash)
            .map(<[_]>::len),
        Some(3)
    );

    // The proof arrives after the restart; Bob's funds stay usable by
    // a receiver who already holds the proof.
    assert!(bob.ingest(&payer.to_dave).is_err());
    let mut carol = world.node();
    carol.ingest_equivocation(&payer.proof()).unwrap();
    let to_carol = bob.send(carol.id(), 25 * ARX).unwrap();
    let (payment, _) = carol
        .ingest_bundle(&bob.payment_bundle(&to_carol).unwrap())
        .unwrap();
    carol.receive(&payment).unwrap();
    assert_eq!(carol.balance(), 25 * ARX);
}
