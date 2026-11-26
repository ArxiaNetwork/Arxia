//! The wallet on the flash backend, the storage a T-Beam class device
//! has. The medium is the fault-injecting mock the flash backend is
//! itself tested with: sixteen 4 KiB pages, with power cuts armed at
//! chosen write boundaries.
//!
//! "Power cycle" here means what it means on a board: the software
//! state is dropped, the same flash is mounted again, and the wallet
//! is rebuilt from it.

use arxia_core::ArxiaError;
use arxia_lattice::chain::{AccountChain, VectorClock};
use arxia_lattice::witness::{receive_final, Witness, WitnessConfirmation, WitnessRoster};
use arxia_lattice::{
    DurableWallet, IssuanceCertificate, IssuancePolicy, ReserveCertificate, WalletConfig,
};
use arxia_storage_flash::testing::{FaultyFlash, RANGE};
use arxia_storage_flash::FlashStorage;
use ed25519_dalek::SigningKey;

const ARX: u64 = 1_000_000;

type Store = FlashStorage<FaultyFlash>;
type Node = DurableWallet<Store>;

fn mount(flash: &FaultyFlash) -> Store {
    FlashStorage::mount(flash.clone(), RANGE).expect("the flash mounts")
}

/// Open the wallet on `flash`. The seed is used only if the flash
/// holds no wallet yet.
fn open(flash: &FaultyFlash, config: &WalletConfig, seed: u8) -> Node {
    DurableWallet::open_with_entropy(mount(flash), config.clone(), || [seed; 32])
        .expect("the wallet opens")
}

/// Drop the software state and come back from the same flash.
fn power_cycle(node: Node, flash: &FaultyFlash, config: &WalletConfig) -> Node {
    drop(node);
    DurableWallet::open_with_entropy(mount(flash), config.clone(), || {
        panic!("a wallet already on flash must not draw entropy")
    })
    .expect("the wallet reopens")
}

/// Issuers, a roster of three witnesses, and the devices' flashes.
struct World {
    issuer_keys: Vec<SigningKey>,
    config: WalletConfig,
    roster: WitnessRoster,
    witnesses: Vec<Witness<Store>>,
}

impl World {
    fn new() -> Self {
        let issuer_keys: Vec<SigningKey> = (0..3)
            .map(|i| SigningKey::from_bytes(&[200 + i; 32]))
            .collect();
        let policy = IssuancePolicy::new(
            issuer_keys
                .iter()
                .map(|key| key.verifying_key().to_bytes())
                .collect(),
            2,
        )
        .unwrap();
        let witness_seeds = [101u8, 102, 103];
        let roster = WitnessRoster::new(
            witness_seeds
                .iter()
                .map(|seed| {
                    let key = SigningKey::from_bytes(&[*seed; 32]);
                    (key.verifying_key().to_bytes(), 10)
                })
                .collect(),
        )
        .unwrap();
        let config = WalletConfig {
            issuance: Some(policy),
            witnesses: Some(roster.clone()),
        };
        let witnesses = witness_seeds
            .iter()
            .map(|seed| Witness::new(open(&FaultyFlash::healthy(), &config, *seed)))
            .collect();
        Self {
            issuer_keys,
            config,
            roster,
            witnesses,
        }
    }

    fn certify(&self, account: &str, amount: u64) -> IssuanceCertificate {
        let policy = self.config.issuance.as_ref().unwrap();
        let mut certificate = IssuanceCertificate::new(account, amount).unwrap();
        certificate.sign(policy, &self.issuer_keys[0]).unwrap();
        certificate.sign(policy, &self.issuer_keys[1]).unwrap();
        certificate
    }

    /// A device on its own flash, with an empty account.
    fn device(&self, seed: u8) -> (Node, FaultyFlash) {
        let flash = FaultyFlash::healthy();
        let mut node = open(&flash, &self.config, seed);
        node.open_account(0).unwrap();
        (node, flash)
    }

    /// A device on its own flash, with a certified balance.
    fn funded(&self, seed: u8, amount: u64) -> (Node, FaultyFlash) {
        let flash = FaultyFlash::healthy();
        let mut node = open(&flash, &self.config, seed);
        let certificate = self.certify(node.id(), amount);
        node.open_certified(&certificate).unwrap();
        (node, flash)
    }

    /// `payer` pays `receiver` through the witnesses.
    fn pay(&mut self, payer: &mut Node, receiver: &mut Node, amount: u64) {
        let payment = payer.send(receiver.id(), amount).unwrap();
        let bundle = payer.delta_bundle(&payment);
        let confirmations: Vec<WitnessConfirmation> = self
            .witnesses
            .iter_mut()
            .map(|witness| {
                let (heard, _) = witness.ingest_bundle(&bundle).unwrap();
                witness.confirm(&heard).unwrap()
            })
            .collect();
        payer.ingest_settlement(&payment, &confirmations).unwrap();
        receive_final(receiver, &payment, &confirmations, &self.roster).unwrap();
    }
}

#[test]
fn a_wallet_on_flash_comes_back_after_a_power_cycle() {
    let config = WalletConfig::default();
    let flash = FaultyFlash::healthy();
    let mut alice = open(&flash, &config, 1);
    alice.open_account(100 * ARX).unwrap();
    let payment = alice
        .send(AccountChain::from_seed(&[2; 32]).id(), 30 * ARX)
        .unwrap();
    let id = alice.id().to_string();

    let alice = power_cycle(alice, &flash, &config);
    assert_eq!(alice.id(), id);
    assert_eq!(alice.balance(), 70 * ARX);
    assert_eq!(alice.chain().last().unwrap().hash, payment.hash);
}

#[test]
fn two_payments_settle_between_devices_on_flash() {
    // Payer, receivers and witnesses each keep everything on flash:
    // blocks, the issuance certificate, settlements.
    let mut world = World::new();
    let (mut alice, alice_flash) = world.funded(1, 100 * ARX);
    let (mut bob, bob_flash) = world.device(2);
    let (mut carol, carol_flash) = world.device(3);

    world.pay(&mut alice, &mut bob, 30 * ARX);
    world.pay(&mut bob, &mut carol, 20 * ARX);

    let config = world.config.clone();
    let alice = power_cycle(alice, &alice_flash, &config);
    let bob = power_cycle(bob, &bob_flash, &config);
    let carol = power_cycle(carol, &carol_flash, &config);
    assert_eq!(alice.balance(), 70 * ARX);
    assert_eq!(bob.balance(), 10 * ARX);
    assert_eq!(carol.balance(), 20 * ARX);
}

#[test]
fn a_payment_signed_as_power_is_cut_is_never_handed_out_and_lost() {
    // Power is cut after `cut` flash writes, at every boundary a
    // payment can cross. Whatever the boundary:
    // - if the payment was handed out, it is on flash afterwards;
    // - the device comes back with a valid wallet and keeps working.
    let config = WalletConfig::default();
    let receiver = AccountChain::from_seed(&[2; 32]);
    let (mut refused, mut handed_out) = (0, 0);

    for cut in 0..24 {
        let flash = FaultyFlash::healthy();
        let mut alice = open(&flash, &config, 1);
        alice.open_account(100 * ARX).unwrap();

        flash.arm_cut(cut);
        let outcome = alice.send(receiver.id(), 30 * ARX);
        flash.heal();

        let mut alice = power_cycle(alice, &flash, &config);
        match &outcome {
            Ok(payment) => {
                handed_out += 1;
                assert_eq!(
                    alice.chain().last().unwrap().hash,
                    payment.hash,
                    "cut {cut}: a payment that was handed out must be on flash"
                );
                assert_eq!(alice.balance(), 70 * ARX);
            }
            Err(_) => {
                refused += 1;
                // Nothing was handed out. The position is either still
                // free or taken by that same payment; never anything
                // else.
                match alice.chain().len() {
                    1 => assert_eq!(alice.balance(), 100 * ARX, "cut {cut}"),
                    2 => assert_eq!(alice.balance(), 70 * ARX, "cut {cut}"),
                    other => panic!("cut {cut}: unexpected chain length {other}"),
                }
            }
        }
        // The device keeps working: the next payment extends the chain.
        let before = alice.chain().len();
        let next = alice.send(receiver.id(), ARX).unwrap();
        assert_eq!(next.nonce as usize, before + 1, "cut {cut}");
    }
    assert!(refused > 0, "the sweep never hit the payment");
    assert!(handed_out > 0, "the sweep never let a payment through");
}

#[test]
fn a_receive_interrupted_by_a_power_cut_is_not_credited_twice() {
    let config = WalletConfig::default();
    for cut in 0..24 {
        let alice_flash = FaultyFlash::healthy();
        let mut alice = open(&alice_flash, &config, 1);
        alice.open_account(100 * ARX).unwrap();
        let bob_flash = FaultyFlash::healthy();
        let mut bob = open(&bob_flash, &config, 2);
        bob.open_account(0).unwrap();
        let payment = alice.send(bob.id(), 30 * ARX).unwrap();
        bob.ingest_all(&alice.chain()[..1]).unwrap();

        bob_flash.arm_cut(cut);
        let _ = bob.receive(&payment);
        bob_flash.heal();

        // After the power cycle Bob tries again, as a device would.
        let mut bob = power_cycle(bob, &bob_flash, &config);
        match bob.receive(&payment) {
            Ok(_) => {}
            Err(ArxiaError::DuplicateReceive { .. }) => {}
            Err(other) => panic!("cut {cut}: unexpected {other:?}"),
        }
        assert_eq!(bob.balance(), 30 * ARX, "cut {cut}");
        let bob = power_cycle(bob, &bob_flash, &config);
        assert_eq!(bob.balance(), 30 * ARX, "cut {cut}");
    }
}

#[test]
fn a_reserve_and_an_equivocation_proof_fit_on_flash() {
    let mut world = World::new();
    let (mut alice, _alice_flash) = world.funded(1, 100 * ARX);

    // A reserve account, funded by a settled payment and confirmed.
    let mut vclock = VectorClock::new();
    let mut reserve = AccountChain::from_seed(&[9; 32]);
    reserve.open(0, &mut vclock).unwrap();
    let funding = alice.send(reserve.id(), 20 * ARX).unwrap();
    reserve.receive(&funding, &mut vclock).unwrap();
    let bundle = alice.delta_bundle(&funding);
    let confirmations: Vec<_> = world
        .witnesses
        .iter_mut()
        .map(|witness| {
            let (heard, _) = witness.ingest_bundle(&bundle).unwrap();
            witness.confirm(&heard).unwrap();
            witness
                .ingest_all(std::slice::from_ref(&reserve.chain[0]))
                .unwrap();
            witness.confirm(&reserve.chain[1]).unwrap()
        })
        .collect();
    let certificate = ReserveCertificate::new(
        funding,
        reserve.chain[0].clone(),
        reserve.chain[1].clone(),
        confirmations,
    )
    .unwrap();

    // Bob is paid from the reserve with no witness in reach.
    let (mut bob, bob_flash) = world.device(2);
    let to_bob = reserve.send(bob.id(), 20 * ARX, &mut vclock).unwrap();
    bob.receive_from_reserve(&certificate, std::slice::from_ref(&to_bob))
        .unwrap();

    // The reserve is spent a second time; Bob later sees that block.
    reserve.chain.pop();
    reserve.balance = 20 * ARX;
    reserve.nonce -= 1;
    let elsewhere = reserve
        .send(
            AccountChain::from_seed(&[3; 32]).id(),
            20 * ARX,
            &mut vclock,
        )
        .unwrap();
    assert!(matches!(
        bob.ingest(&elsewhere),
        Err(ArxiaError::NonceConflict { .. })
    ));

    // Certificate, proof and balance are all back after a power cycle.
    let config = world.config.clone();
    let bob = power_cycle(bob, &bob_flash, &config);
    let ledger = bob.wallet().ledger();
    assert_eq!(bob.balance(), 20 * ARX);
    assert_eq!(ledger.reserve_for(reserve.id()), Some(&certificate));
    assert!(ledger.equivocation_for(reserve.id()).is_some());
}

#[test]
fn a_full_flash_is_reported_and_the_wallet_reopens() {
    let config = WalletConfig::default();
    let flash = FaultyFlash::healthy();
    let mut alice = open(&flash, &config, 1);
    alice.open_account(100 * ARX).unwrap();
    let receiver = AccountChain::from_seed(&[2; 32]);

    let mut stored = 0u64;
    let failure = loop {
        match alice.send(receiver.id(), 1) {
            Ok(_) => stored += 1,
            Err(error) => break error,
        }
        assert!(stored < 5_000, "sixteen pages cannot hold this many blocks");
    };
    assert!(
        matches!(failure, ArxiaError::Storage { .. }),
        "a full flash is a storage error, got {failure:?}"
    );
    assert!(stored > 50, "only {stored} blocks fitted");

    // Every payment that was handed out is still there.
    let alice = power_cycle(alice, &flash, &config);
    assert!(alice.chain().len() as u64 > stored);
    assert_eq!(
        alice.balance(),
        100 * ARX - (alice.chain().len() as u64 - 1)
    );
}
