//! Settlement by witnesses, with no internet.
//!
//! The setting: an issuance policy, a roster of witnesses within radio
//! reach, a payer who signs two different payments for the same
//! account position, and two receivers who each see only one of them.

use arxia_core::{ArxiaError, WitnessFault};
use arxia_crypto::generate_keypair;
use arxia_finality::witness::{
    assess, receive_final, Witness, WitnessConfirmation, WitnessRoster, CONFIRMATION_LEN,
};
use arxia_lattice::chain::{AccountChain, VectorClock};
use arxia_lattice::{Block, DurableWallet, IssuanceCertificate, IssuancePolicy, Wallet};
use arxia_storage::MemoryStorage;
use ed25519_dalek::SigningKey;

const ARX: u64 = 1_000_000;

type Node = DurableWallet<MemoryStorage>;

struct World {
    issuer_keys: Vec<SigningKey>,
    policy: IssuancePolicy,
}

impl World {
    fn new() -> Self {
        let issuer_keys: Vec<SigningKey> = (0..3).map(|_| generate_keypair().0).collect();
        let public = issuer_keys
            .iter()
            .map(|k| k.verifying_key().to_bytes())
            .collect();
        Self {
            policy: IssuancePolicy::new(public, 2).unwrap(),
            issuer_keys,
        }
    }

    fn node(&self) -> Node {
        DurableWallet::open_with_issuance(MemoryStorage::default(), self.policy.clone()).unwrap()
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

    fn witnesses(&self, count: usize) -> (Vec<Witness<MemoryStorage>>, WitnessRoster) {
        let witnesses: Vec<_> = (0..count).map(|_| Witness::new(self.node())).collect();
        let roster =
            WitnessRoster::new(witnesses.iter().map(|w| (w.public_key(), 10)).collect()).unwrap();
        (witnesses, roster)
    }
}

/// A payer who keeps the signing key outside any wallet, so that two
/// payments can be signed for the same account position.
struct Payer {
    account: AccountChain,
    vclock: VectorClock,
    certificate: IssuanceCertificate,
}

impl Payer {
    fn new(world: &World, amount: u64) -> Self {
        let mut account = AccountChain::new();
        let mut vclock = VectorClock::new();
        let certificate = world.certify(account.id(), amount);
        account.open(amount, &mut vclock).unwrap();
        Self {
            account,
            vclock,
            certificate,
        }
    }

    fn history(&self) -> Vec<Block> {
        self.account.chain[..1].to_vec()
    }

    /// Two payments of `amount` for the same position, to two
    /// receivers.
    fn pay_twice(&mut self, first: &str, second: &str, amount: u64) -> (Block, Block) {
        let to_first = self.account.send(first, amount, &mut self.vclock).unwrap();
        self.account.chain.pop();
        self.account.balance += amount;
        self.account.nonce -= 1;
        let to_second = self.account.send(second, amount, &mut self.vclock).unwrap();
        (to_first, to_second)
    }
}

/// Hand a witness everything it needs and ask for a confirmation.
fn ask(
    witness: &mut Witness<MemoryStorage>,
    payer: &Payer,
    payment: &Block,
) -> Result<WitnessConfirmation, ArxiaError> {
    witness.ingest_issuance(&payer.certificate)?;
    witness.ingest_all(&payer.history())?;
    witness.confirm(payment)
}

fn prepare(receiver: &mut Node, payer: &Payer) {
    receiver.open_account(0).unwrap();
    receiver.ingest_issuance(&payer.certificate).unwrap();
    receiver.ingest_all(&payer.history()).unwrap();
}

#[test]
fn a_payment_confirmed_by_the_witnesses_is_final() {
    let world = World::new();
    let (mut witnesses, roster) = world.witnesses(3);
    let mut payer = Payer::new(&world, 100 * ARX);
    let mut bob = world.node();
    let dave = world.node();
    prepare(&mut bob, &payer);
    let (to_bob, _) = payer.pay_twice(bob.id(), dave.id(), 60 * ARX);

    let confirmations: Vec<_> = witnesses
        .iter_mut()
        .map(|w| ask(w, &payer, &to_bob).unwrap())
        .collect();
    let settlement = assess(&to_bob, &confirmations, &roster).unwrap();
    assert_eq!(settlement.witnesses, 3);
    assert!(settlement.is_final());

    receive_final(&mut bob, &to_bob, &confirmations, &roster).unwrap();
    assert_eq!(bob.balance(), 60 * ARX);
}

#[test]
fn the_second_payment_of_the_same_position_cannot_become_final() {
    // The payer gives one payment to Bob and a conflicting one to
    // Dave. Bob and Dave never talk to each other; both talk to the
    // witnesses in range.
    let world = World::new();
    let (mut witnesses, roster) = world.witnesses(3);
    let mut payer = Payer::new(&world, 100 * ARX);
    let mut bob = world.node();
    let mut dave = world.node();
    prepare(&mut bob, &payer);
    prepare(&mut dave, &payer);
    let (to_bob, to_dave) = payer.pay_twice(bob.id(), dave.id(), 60 * ARX);

    let for_bob: Vec<_> = witnesses
        .iter_mut()
        .map(|w| ask(w, &payer, &to_bob).unwrap())
        .collect();

    // Every witness refuses the conflicting payment.
    for witness in &mut witnesses {
        assert!(matches!(
            ask(witness, &payer, &to_dave),
            Err(ArxiaError::NonceConflict { .. })
        ));
    }

    receive_final(&mut bob, &to_bob, &for_bob, &roster).unwrap();
    assert!(matches!(
        receive_final(&mut dave, &to_dave, &[], &roster),
        Err(ArxiaError::Witness {
            fault: WitnessFault::NotFinal {
                confirmed: 0,
                total: 30
            }
        })
    ));
    assert_eq!(bob.balance(), 60 * ARX);
    assert_eq!(dave.balance(), 0);
}

#[test]
fn splitting_the_witnesses_makes_neither_payment_final_twice() {
    // The payer shows one payment to some witnesses and the other to
    // the rest, in every possible split of four witnesses. At most one
    // of the two payments is ever final.
    let world = World::new();
    for split in 0u8..16 {
        let (mut witnesses, roster) = world.witnesses(4);
        let mut payer = Payer::new(&world, 100 * ARX);
        let bob = Wallet::new();
        let dave = Wallet::new();
        let (to_bob, to_dave) = payer.pay_twice(bob.id(), dave.id(), 60 * ARX);

        let mut for_bob = Vec::new();
        let mut for_dave = Vec::new();
        for (index, witness) in witnesses.iter_mut().enumerate() {
            let (first, second) = if split >> index & 1 == 0 {
                (&to_bob, &to_dave)
            } else {
                (&to_dave, &to_bob)
            };
            let confirmation = ask(witness, &payer, first).unwrap();
            if std::ptr::eq(first, &to_bob) {
                for_bob.push(confirmation);
            } else {
                for_dave.push(confirmation);
            }
            // The payer then tries the other payment on the same witness.
            assert!(ask(witness, &payer, second).is_err());
        }

        let bob_final = assess(&to_bob, &for_bob, &roster).unwrap().is_final();
        let dave_final = assess(&to_dave, &for_dave, &roster).unwrap().is_final();
        assert!(
            !(bob_final && dave_final),
            "split {split:04b}: both payments final"
        );
    }
}

#[test]
fn a_witness_still_refuses_after_a_restart() {
    let world = World::new();
    let (mut witnesses, _roster) = world.witnesses(1);
    let mut payer = Payer::new(&world, 100 * ARX);
    let bob = Wallet::new();
    let dave = Wallet::new();
    let (to_bob, to_dave) = payer.pay_twice(bob.id(), dave.id(), 60 * ARX);

    let mut witness = witnesses.pop().unwrap();
    let key = witness.public_key();
    ask(&mut witness, &payer, &to_bob).unwrap();

    // Power cycle: the witness is rebuilt from its storage alone.
    let storage = witness.into_wallet().into_storage();
    let mut witness =
        Witness::new(DurableWallet::open_with_issuance(storage, world.policy.clone()).unwrap());
    assert_eq!(witness.public_key(), key);
    assert!(matches!(
        witness.confirm(&to_dave),
        Err(ArxiaError::NonceConflict { .. })
    ));
    // The payment it already accepted is confirmed again, identically.
    let again = witness.confirm(&to_bob).unwrap();
    assert!(again.verifies());
}

#[test]
fn witnesses_do_not_confirm_a_payment_that_is_not_funded() {
    // The payer signs a payment above the certified balance.
    let world = World::new();
    let (mut witnesses, _roster) = world.witnesses(1);
    let mut payer = Payer::new(&world, 100 * ARX);
    let bob = Wallet::new();
    payer.account.balance = 10_000 * ARX;
    let overdraft = payer
        .account
        .send(bob.id(), 5_000 * ARX, &mut payer.vclock)
        .unwrap();
    assert!(matches!(
        ask(&mut witnesses[0], &payer, &overdraft),
        Err(ArxiaError::InsufficientBalance { .. })
    ));
}

#[test]
fn witnesses_do_not_confirm_a_balance_without_a_certificate() {
    let world = World::new();
    let (mut witnesses, _roster) = world.witnesses(1);
    let mut vclock = VectorClock::new();
    let mut account = AccountChain::new();
    let bob = Wallet::new();
    account.open(1_000 * ARX, &mut vclock).unwrap();
    let payment = account.send(bob.id(), 500 * ARX, &mut vclock).unwrap();

    assert!(witnesses[0].ingest_all(&account.chain[..1]).is_err());
    assert!(witnesses[0].confirm(&payment).is_err());
}

#[test]
fn two_thirds_exactly_is_not_enough() {
    let world = World::new();
    let (mut witnesses, roster) = world.witnesses(3);
    let mut payer = Payer::new(&world, 100 * ARX);
    let mut bob = world.node();
    let dave = world.node();
    prepare(&mut bob, &payer);
    let (to_bob, _) = payer.pay_twice(bob.id(), dave.id(), 60 * ARX);

    let two: Vec<_> = witnesses
        .iter_mut()
        .take(2)
        .map(|w| ask(w, &payer, &to_bob).unwrap())
        .collect();
    let settlement = assess(&to_bob, &two, &roster).unwrap();
    assert_eq!(settlement.confirmed_weight, 20);
    assert_eq!(settlement.total_weight, 30);
    assert!(!settlement.is_final());
    assert!(receive_final(&mut bob, &to_bob, &two, &roster).is_err());
    assert_eq!(bob.balance(), 0);
}

#[test]
fn confirmations_that_do_not_count_are_ignored() {
    let world = World::new();
    let (mut witnesses, roster) = world.witnesses(3);
    let mut payer = Payer::new(&world, 100 * ARX);
    let bob = Wallet::new();
    let dave = Wallet::new();
    let (to_bob, _) = payer.pay_twice(bob.id(), dave.id(), 60 * ARX);
    let genuine = ask(&mut witnesses[0], &payer, &to_bob).unwrap();

    // The same witness, repeated.
    let repeated = genuine.clone();

    // A node outside the roster.
    let mut outsider = Witness::new(world.node());
    let from_outsider = ask(&mut outsider, &payer, &to_bob).unwrap();

    // A roster witness's key with a signature that does not verify.
    let mut bytes = [0u8; CONFIRMATION_LEN];
    bytes[..32].copy_from_slice(&witnesses[1].public_key());
    bytes[32..64].copy_from_slice(genuine.block_hash());
    let forged = WitnessConfirmation::from_bytes(&bytes).unwrap();

    // A valid confirmation of another block.
    let other_block = ask(&mut witnesses[2], &payer, &payer.history()[0]).unwrap();

    let settlement = assess(
        &to_bob,
        &[genuine, repeated, from_outsider, forged, other_block],
        &roster,
    )
    .unwrap();
    assert_eq!(settlement.witnesses, 1);
    assert_eq!(settlement.confirmed_weight, 10);
    assert!(!settlement.is_final());
}

#[test]
fn a_payer_cannot_witness_its_own_payment() {
    // The paying account is itself a roster witness with most of the
    // weight. Its confirmation of its own payment does not count.
    let world = World::new();
    let mut payer_node = world.node();
    let certificate = world.certify(payer_node.id(), 100 * ARX);
    payer_node.open_certified(&certificate).unwrap();
    let bob = Wallet::new();
    let payment = payer_node.send(bob.id(), 60 * ARX).unwrap();

    let mut payer_as_witness = Witness::new(payer_node);
    let other = Witness::new(world.node());
    let roster = WitnessRoster::new(vec![
        (payer_as_witness.public_key(), 90),
        (other.public_key(), 10),
    ])
    .unwrap();
    let own = payer_as_witness.confirm(&payment).unwrap();
    assert!(own.verifies());

    let settlement = assess(&payment, &[own], &roster).unwrap();
    assert_eq!(settlement.confirmed_weight, 0);
    assert!(!settlement.is_final());
}

#[test]
fn weight_decides_not_head_count() {
    let world = World::new();
    let mut heavy = Witness::new(world.node());
    let mut light: Vec<_> = (0..4).map(|_| Witness::new(world.node())).collect();
    let mut entries = vec![(heavy.public_key(), 70)];
    entries.extend(light.iter().map(|w| (w.public_key(), 5)));
    let roster = WitnessRoster::new(entries).unwrap();

    let mut payer = Payer::new(&world, 100 * ARX);
    let bob = Wallet::new();
    let dave = Wallet::new();
    let (to_bob, _) = payer.pay_twice(bob.id(), dave.id(), 60 * ARX);

    // Four of five witnesses, holding 20 of 90.
    let many: Vec<_> = light
        .iter_mut()
        .map(|w| ask(w, &payer, &to_bob).unwrap())
        .collect();
    assert!(!assess(&to_bob, &many, &roster).unwrap().is_final());

    // One witness holding 70 of 90.
    let one = vec![ask(&mut heavy, &payer, &to_bob).unwrap()];
    assert!(assess(&to_bob, &one, &roster).unwrap().is_final());
}

#[test]
fn confirmation_encoding_round_trips() {
    let world = World::new();
    let (mut witnesses, _roster) = world.witnesses(1);
    let mut payer = Payer::new(&world, 100 * ARX);
    let bob = Wallet::new();
    let dave = Wallet::new();
    let (to_bob, _) = payer.pay_twice(bob.id(), dave.id(), 60 * ARX);
    let confirmation = ask(&mut witnesses[0], &payer, &to_bob).unwrap();

    let bytes = confirmation.to_bytes();
    assert_eq!(bytes.len(), 128);
    assert_eq!(
        WitnessConfirmation::from_bytes(&bytes).unwrap(),
        confirmation
    );
    assert!(WitnessConfirmation::from_bytes(&bytes[..127]).is_err());
}

#[test]
fn malformed_rosters_are_refused() {
    let a = generate_keypair().1.to_bytes();
    let b = generate_keypair().1.to_bytes();
    assert!(WitnessRoster::new(vec![]).is_err());
    assert!(WitnessRoster::new(vec![(a, 0)]).is_err());
    assert!(WitnessRoster::new(vec![(a, 1), (a, 2)]).is_err());
    assert!(WitnessRoster::new(vec![(a, u64::MAX), (b, 1)]).is_err());
    assert!(WitnessRoster::new(vec![(a, 1), (b, 2)]).is_ok());
}
