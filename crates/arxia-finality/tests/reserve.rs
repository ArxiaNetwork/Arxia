//! Certified reserves: paying where no witness is in reach.
//!
//! The owner prepares a reserve while witnesses are reachable. Later,
//! receivers who have never seen the owner's history, and have nobody
//! to ask, check the certificate against the roster they carry.

use arxia_core::{ArxiaError, EquivocationFault, ReserveFault, WitnessFault};
use arxia_crypto::generate_keypair;
use arxia_finality::witness::{Witness, WitnessConfirmation, WitnessRoster};
use arxia_lattice::chain::{AccountChain, VectorClock};
use arxia_lattice::{
    Block, DurableWallet, IssuanceCertificate, IssuancePolicy, ReserveCertificate, Wallet,
    WalletConfig,
};
use arxia_storage::MemoryStorage;
use ed25519_dalek::SigningKey;

const ARX: u64 = 1_000_000;

type Node = DurableWallet<MemoryStorage>;

/// Issuers, three witnesses, and the configuration every node carries.
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

    /// A receiver that has seen nothing yet.
    fn receiver(&self) -> Node {
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
}

/// An owner with a main account and a reserve account. The reserve key
/// is used directly, so that tests can also sign what an honest wallet
/// would refuse to sign.
struct Owner {
    main: Wallet,
    reserve: AccountChain,
    vclock: VectorClock,
    funding: Block,
}

impl Owner {
    /// Certified `balance` on the main account, `amount` moved to the
    /// reserve account and received there.
    fn new(world: &World, balance: u64, amount: u64) -> Self {
        let mut main = Wallet::with_issuance(world.policy.clone());
        main.open_certified(&world.certify(main.id(), balance))
            .unwrap();
        let mut reserve = AccountChain::new();
        let mut vclock = VectorClock::new();
        reserve.open(0, &mut vclock).unwrap();
        let funding = main.send(reserve.id(), amount).unwrap();
        reserve.receive(&funding, &mut vclock).unwrap();
        Self {
            main,
            reserve,
            vclock,
            funding,
        }
    }

    /// Ask the first `count` witnesses to confirm the reserve block.
    fn confirmations(&self, world: &mut World, count: usize) -> Vec<WitnessConfirmation> {
        world
            .witnesses
            .iter_mut()
            .take(count)
            .map(|witness| {
                witness
                    .ingest_issuance(self.main.issuance().unwrap())
                    .unwrap();
                witness.ingest_all(self.main.chain()).unwrap();
                witness.ingest_all(&self.reserve.chain[..1]).unwrap();
                witness.confirm(&self.reserve.chain[1]).unwrap()
            })
            .collect()
    }

    fn certificate(&self, world: &mut World) -> ReserveCertificate {
        let confirmations = self.confirmations(world, 3);
        ReserveCertificate::new(
            self.funding.clone(),
            self.reserve.chain[0].clone(),
            self.reserve.chain[1].clone(),
            confirmations,
        )
        .unwrap()
    }

    fn pay(&mut self, destination: &str, amount: u64) -> Block {
        self.reserve
            .send(destination, amount, &mut self.vclock)
            .unwrap()
    }

    /// The reserve account's blocks after the certified one.
    fn spends(&self) -> &[Block] {
        &self.reserve.chain[2..]
    }
}

#[test]
fn a_receiver_with_no_one_to_ask_accepts_a_payment_from_a_reserve() {
    let mut world = World::new();
    let mut owner = Owner::new(&world, 100 * ARX, 20 * ARX);
    let certificate = owner.certificate(&mut world);
    assert_eq!(certificate.amount(), 20 * ARX);
    assert_eq!(certificate.owner(), owner.main.id());

    // Bob has never seen the owner's chain or its issuance
    // certificate. He carries the roster, and that is all he needs.
    let mut bob = world.receiver();
    owner.pay(bob.id(), 5 * ARX);
    bob.receive_from_reserve(&certificate, owner.spends())
        .unwrap();
    assert_eq!(bob.balance(), 5 * ARX);
}

#[test]
fn one_ledger_never_credits_more_than_the_reserve() {
    let mut world = World::new();
    let mut owner = Owner::new(&world, 100 * ARX, 20 * ARX);
    let certificate = owner.certificate(&mut world);
    let mut bob = world.receiver();

    owner.pay(bob.id(), 15 * ARX);
    bob.receive_from_reserve(&certificate, owner.spends())
        .unwrap();

    // The owner signs a second payment for more than what is left.
    owner.reserve.balance = 1_000 * ARX;
    let overdraft = owner.pay(bob.id(), 500 * ARX);
    assert!(matches!(
        bob.receive(&overdraft),
        Err(ArxiaError::InsufficientBalance { .. })
    ));
    assert_eq!(bob.balance(), 15 * ARX);
}

#[test]
fn a_certificate_below_finality_is_refused() {
    let mut world = World::new();
    let mut owner = Owner::new(&world, 100 * ARX, 20 * ARX);
    let two_of_three = owner.confirmations(&mut world, 2);
    let certificate = ReserveCertificate::new(
        owner.funding.clone(),
        owner.reserve.chain[0].clone(),
        owner.reserve.chain[1].clone(),
        two_of_three,
    )
    .unwrap();

    let mut bob = world.receiver();
    owner.pay(bob.id(), 5 * ARX);
    assert!(matches!(
        bob.receive_from_reserve(&certificate, owner.spends()),
        Err(ArxiaError::Witness {
            fault: WitnessFault::NotFinal {
                confirmed: 20,
                total: 30
            }
        })
    ));
    assert_eq!(bob.balance(), 0);
}

#[test]
fn a_reserve_nobody_confirmed_is_refused() {
    // The owner builds the three blocks alone and presents them
    // without any confirmation.
    let world = World::new();
    let mut owner = Owner::new(&world, 100 * ARX, 20 * ARX);
    let certificate = ReserveCertificate::new(
        owner.funding.clone(),
        owner.reserve.chain[0].clone(),
        owner.reserve.chain[1].clone(),
        Vec::new(),
    )
    .unwrap();
    let mut bob = world.receiver();
    owner.pay(bob.id(), 5 * ARX);
    assert!(bob
        .receive_from_reserve(&certificate, owner.spends())
        .is_err());
    assert_eq!(bob.balance(), 0);
}

#[test]
fn confirmations_of_another_block_do_not_certify_a_reserve() {
    // Genuine confirmations, but of the funding block, attached to
    // the reserve.
    let mut world = World::new();
    let mut owner = Owner::new(&world, 100 * ARX, 20 * ARX);
    owner.confirmations(&mut world, 3);
    let of_funding: Vec<_> = world
        .witnesses
        .iter_mut()
        .map(|w| w.confirm(&owner.funding).unwrap())
        .collect();
    let certificate = ReserveCertificate::new(
        owner.funding.clone(),
        owner.reserve.chain[0].clone(),
        owner.reserve.chain[1].clone(),
        of_funding,
    )
    .unwrap();
    let mut bob = world.receiver();
    owner.pay(bob.id(), 5 * ARX);
    assert!(bob
        .receive_from_reserve(&certificate, owner.spends())
        .is_err());
}

#[test]
fn blocks_that_do_not_form_a_reserve_are_refused() {
    let world = World::new();
    let owner = Owner::new(&world, 100 * ARX, 20 * ARX);
    let other = Owner::new(&world, 100 * ARX, 20 * ARX);
    let malformed = |funding: &Block, opening: &Block, reserve: &Block| {
        matches!(
            ReserveCertificate::new(funding.clone(), opening.clone(), reserve.clone(), vec![]),
            Err(ArxiaError::Reserve {
                fault: ReserveFault::Malformed
            })
        )
    };
    let (opening, reserve) = (&owner.reserve.chain[0], &owner.reserve.chain[1]);

    // A funding block addressed to another reserve.
    assert!(malformed(&other.funding, opening, reserve));
    // The opening block of another account.
    assert!(malformed(&owner.funding, &other.reserve.chain[0], reserve));
    // The blocks in the wrong roles.
    assert!(malformed(&owner.funding, reserve, opening));
    assert!(malformed(opening, opening, reserve));
}

#[test]
fn a_ledger_without_a_roster_does_not_accept_reserves() {
    let mut world = World::new();
    let mut owner = Owner::new(&world, 100 * ARX, 20 * ARX);
    let certificate = owner.certificate(&mut world);
    let mut bob = Wallet::with_issuance(world.policy.clone());
    bob.open(0).unwrap();
    owner.pay(bob.id(), 5 * ARX);
    assert!(matches!(
        bob.receive_from_reserve(&certificate, owner.spends()),
        Err(ArxiaError::Reserve {
            fault: ReserveFault::NoRoster
        })
    ));
}

#[test]
fn funds_received_from_a_reserve_can_be_paid_on() {
    let mut world = World::new();
    let mut owner = Owner::new(&world, 100 * ARX, 20 * ARX);
    let certificate = owner.certificate(&mut world);
    let mut bob = world.receiver();
    let mut carol = world.receiver();
    owner.pay(bob.id(), 12 * ARX);
    bob.receive_from_reserve(&certificate, owner.spends())
        .unwrap();

    // Bob pays Carol. He forwards the certificate his ledger holds,
    // the reserve's spends, and his own chain.
    let pay_carol = bob.send(carol.id(), 7 * ARX).unwrap();
    let forwarded = bob
        .wallet()
        .ledger()
        .reserve_for(certificate.account())
        .unwrap()
        .clone();
    carol.ingest_reserve(&forwarded).unwrap();
    carol.ingest_all(owner.spends()).unwrap();
    carol.ingest_all(bob.chain()).unwrap();
    carol.receive(&pay_carol).unwrap();
    assert_eq!(carol.balance(), 7 * ARX);
    assert_eq!(bob.balance(), 5 * ARX);
}

#[test]
fn a_reserve_and_what_it_paid_survive_a_restart() {
    let mut world = World::new();
    let mut owner = Owner::new(&world, 100 * ARX, 20 * ARX);
    let certificate = owner.certificate(&mut world);
    let mut bob = world.receiver();
    owner.pay(bob.id(), 5 * ARX);
    bob.receive_from_reserve(&certificate, owner.spends())
        .unwrap();

    let mut bob = DurableWallet::open_with_config(bob.into_storage(), world.config()).unwrap();
    assert_eq!(bob.balance(), 5 * ARX);
    assert_eq!(
        bob.wallet().ledger().reserve_for(certificate.account()),
        Some(&certificate)
    );
    // A later payment from the same reserve is still accepted.
    let second = owner.pay(bob.id(), 3 * ARX);
    bob.receive(&second).unwrap();
    assert_eq!(bob.balance(), 8 * ARX);
}

#[test]
fn stored_reserves_are_refused_under_another_roster() {
    let mut world = World::new();
    let other = World::new();
    let mut owner = Owner::new(&world, 100 * ARX, 20 * ARX);
    let certificate = owner.certificate(&mut world);
    let mut bob = world.receiver();
    owner.pay(bob.id(), 5 * ARX);
    bob.receive_from_reserve(&certificate, owner.spends())
        .unwrap();

    let foreign = WalletConfig {
        issuance: Some(world.policy.clone()),
        witnesses: Some(other.roster.clone()),
    };
    assert!(DurableWallet::open_with_config(bob.into_storage(), foreign).is_err());
}

#[test]
fn a_reserve_spent_twice_is_proven_and_freezes_its_owner() {
    // Two receivers, each alone with the owner, are each paid the
    // whole reserve. Neither can know about the other at that moment:
    // what each of them risks is the reserve, not more.
    let mut world = World::new();
    let mut owner = Owner::new(&world, 100 * ARX, 20 * ARX);
    let certificate = owner.certificate(&mut world);
    let mut bob = world.receiver();
    let mut dave = world.receiver();

    let to_bob = owner.pay(bob.id(), 20 * ARX);
    bob.receive_from_reserve(&certificate, std::slice::from_ref(&to_bob))
        .unwrap();
    owner.reserve.chain.pop();
    owner.reserve.balance = 20 * ARX;
    owner.reserve.nonce -= 1;
    let to_dave = owner.pay(dave.id(), 20 * ARX);
    dave.receive_from_reserve(&certificate, std::slice::from_ref(&to_dave))
        .unwrap();

    // The two meet, or a witness relays one block to the other side.
    assert!(matches!(
        bob.ingest(&to_dave),
        Err(ArxiaError::NonceConflict { .. })
    ));
    let proof = bob
        .wallet()
        .ledger()
        .equivocation_for(certificate.account())
        .expect("the two signatures are kept as a proof")
        .clone();
    assert_eq!(proof.nonce(), 3);

    // Bob's ledger now refuses the owner's main account after the
    // funding block, although that account itself never forked.
    let later = owner.main.send(bob.id(), 50 * ARX).unwrap();
    bob.ingest_issuance(owner.main.issuance().unwrap()).unwrap();
    let frozen = bob.ingest_all(owner.main.chain());
    assert!(matches!(
        frozen,
        Err(ArxiaError::Equivocation {
            fault: EquivocationFault::AccountFrozen { from_nonce }
        }) if from_nonce == owner.funding.nonce + 1
    ));
    assert!(bob.receive(&later).is_err());

    // The proof travels: a node that holds the certificate and
    // receives the proof freezes the owner too.
    let mut carol = world.receiver();
    carol.ingest_reserve(&certificate).unwrap();
    carol.ingest_equivocation(&proof).unwrap();
    carol
        .ingest_issuance(owner.main.issuance().unwrap())
        .unwrap();
    assert!(carol.ingest_all(owner.main.chain()).is_err());
    assert!(carol.receive(&later).is_err());
}

#[test]
fn certificate_records_round_trip_and_fit_the_flash_value_limit() {
    let mut world = World::new();
    let owner = Owner::new(&world, 100 * ARX, 20 * ARX);
    let certificate = owner.certificate(&mut world);
    let records = certificate.to_records().unwrap();
    assert_eq!(records.len(), 6);
    assert!(records.iter().all(|record| record.len() <= 256));
    assert_eq!(
        ReserveCertificate::from_records(&records).unwrap(),
        certificate
    );
    assert!(ReserveCertificate::from_records(&records[..2]).is_err());
}
