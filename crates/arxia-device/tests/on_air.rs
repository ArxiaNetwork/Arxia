//! Devices on a shared, lossy broadcast medium.
//!
//! Nothing passes between devices except packets of at most 255 bytes.
//! Every device hears every packet that is not lost. A payer, a
//! receiver and three witnesses settle payments this way, including
//! when a large share of the packets is dropped.

use arxia_device::{Device, Event, RADIO_MTU};
use arxia_lattice::bundle::{encode, Frame};
use arxia_lattice::chain::{AccountChain, VectorClock};
use arxia_lattice::witness::WitnessRoster;
use arxia_lattice::{DurableWallet, IssuanceCertificate, IssuancePolicy, WalletConfig};
use arxia_storage::MemoryStorage;
use arxia_transport::{fragment, Fragment};
use ed25519_dalek::SigningKey;

const ARX: u64 = 1_000_000;
const WITNESS_SEEDS: [u8; 3] = [101, 102, 103];

type Node = Device<MemoryStorage>;

/// A deterministic generator, so that a lossy run can be repeated.
struct Dice(u64);

impl Dice {
    fn roll(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// True with probability `percent` in a hundred.
    fn chance(&mut self, percent: u64) -> bool {
        self.roll() % 100 < percent
    }
}

struct World {
    issuer_keys: Vec<SigningKey>,
    config: WalletConfig,
    /// Every device on the air; the first three are the witnesses.
    devices: Vec<Node>,
    dice: Dice,
    loss_percent: u64,
    packets: usize,
    largest_packet: usize,
    events: Vec<(usize, Event)>,
}

impl World {
    fn new(loss_percent: u64) -> Self {
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
        let roster = WitnessRoster::new(
            WITNESS_SEEDS
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
            witnesses: Some(roster),
        };
        let mut world = Self {
            issuer_keys,
            config,
            devices: Vec::new(),
            dice: Dice(0x9e37_79b9_7f4a_7c15),
            loss_percent,
            packets: 0,
            largest_packet: 0,
            events: Vec::new(),
        };
        for seed in WITNESS_SEEDS {
            let index = world.join(seed, None);
            assert!(world.devices[index].is_witness());
        }
        world
    }

    /// Add a device, with a certified balance or an empty account.
    /// Returns its index.
    fn join(&mut self, seed: u8, balance: Option<u64>) -> usize {
        let mut wallet =
            DurableWallet::open_with_entropy(MemoryStorage::default(), self.config.clone(), || {
                [seed; 32]
            })
            .unwrap();
        match balance {
            Some(amount) => {
                let policy = self.config.issuance.as_ref().unwrap();
                let mut certificate = IssuanceCertificate::new(wallet.id(), amount).unwrap();
                certificate.sign(policy, &self.issuer_keys[0]).unwrap();
                certificate.sign(policy, &self.issuer_keys[1]).unwrap();
                wallet.open_certified(&certificate).unwrap();
            }
            None => {
                wallet.open_account(0).unwrap();
            }
        }
        self.devices.push(Device::new(wallet, 3).unwrap());
        self.devices.len() - 1
    }

    fn id(&self, index: usize) -> String {
        self.devices[index].id().to_string()
    }

    /// Put packets on the air: every other device hears each one,
    /// unless it is lost on the way to that device.
    fn broadcast(&mut self, from: Option<usize>, packets: Vec<Vec<u8>>) {
        for packet in packets {
            self.packets += 1;
            self.largest_packet = self.largest_packet.max(packet.len());
            for index in 0..self.devices.len() {
                if Some(index) == from || self.dice.chance(self.loss_percent) {
                    continue;
                }
                self.devices[index].handle_packet(&packet);
            }
        }
    }

    /// One step: every device transmits what it has queued, then time
    /// advances for all of them.
    fn step(&mut self) {
        for index in 0..self.devices.len() {
            let mut packets = Vec::new();
            while let Some(packet) = self.devices[index].next_packet() {
                packets.push(packet);
            }
            self.broadcast(Some(index), packets);
            while let Some(event) = self.devices[index].next_event() {
                self.events.push((index, event));
            }
        }
        for device in &mut self.devices {
            device.tick();
        }
    }

    /// Run until no payment is waiting to settle, or `limit` steps.
    /// Returns the number of steps taken.
    fn run(&mut self, limit: usize) -> usize {
        for step in 1..=limit {
            self.step();
            // A few more steps let the last confirmations be heard.
            if self.devices.iter().all(|d| d.in_flight() == 0) {
                for _ in 0..3 {
                    self.step();
                }
                return step;
            }
        }
        limit
    }

    fn happened(&self, index: usize, wanted: fn(&Event) -> bool) -> bool {
        self.events
            .iter()
            .any(|(at, event)| *at == index && wanted(event))
    }
}

#[test]
fn a_payment_settles_over_the_air() {
    let mut world = World::new(0);
    let alice = world.join(1, Some(100 * ARX));
    let bob = world.join(2, None);

    let to = world.id(bob);
    world.devices[alice].pay(&to, 30 * ARX).unwrap();
    world.run(20);

    assert_eq!(world.devices[bob].balance(), 30 * ARX);
    assert_eq!(world.devices[alice].balance(), 70 * ARX);
    assert!(world.happened(bob, |e| matches!(e, Event::Received { .. })));
    assert!(world.happened(alice, |e| matches!(e, Event::Settled { .. })));
    assert!(world.largest_packet <= RADIO_MTU);
}

#[test]
fn received_funds_are_paid_on_over_the_air() {
    let mut world = World::new(0);
    let alice = world.join(1, Some(100 * ARX));
    let bob = world.join(2, None);
    let carol = world.join(3, None);

    let to = world.id(bob);
    world.devices[alice].pay(&to, 30 * ARX).unwrap();
    world.run(20);
    let to = world.id(carol);
    world.devices[bob].pay(&to, 20 * ARX).unwrap();
    world.run(20);

    assert_eq!(world.devices[alice].balance(), 70 * ARX);
    assert_eq!(world.devices[bob].balance(), 10 * ARX);
    assert_eq!(world.devices[carol].balance(), 20 * ARX);
}

#[test]
fn payments_settle_when_a_third_of_the_packets_are_lost() {
    // Each packet is lost independently on the way to each listener.
    let mut world = World::new(33);
    let alice = world.join(1, Some(100 * ARX));
    let bob = world.join(2, None);
    let carol = world.join(3, None);

    let to = world.id(bob);
    world.devices[alice].pay(&to, 30 * ARX).unwrap();
    let first = world.run(400);
    assert_eq!(
        world.devices[bob].balance(),
        30 * ARX,
        "after {first} steps"
    );

    let to = world.id(carol);
    world.devices[bob].pay(&to, 20 * ARX).unwrap();
    let second = world.run(400);
    assert_eq!(
        world.devices[carol].balance(),
        20 * ARX,
        "after {second} steps"
    );
    assert_eq!(world.devices[bob].balance(), 10 * ARX);
    assert!(first < 400 && second < 400, "{first} and {second} steps");
}

#[test]
fn nothing_is_credited_before_the_witnesses_confirm() {
    // The witnesses are out of reach: only the payer and the receiver
    // hear each other.
    let mut world = World::new(0);
    let alice = world.join(1, Some(100 * ARX));
    let bob = world.join(2, None);
    let to = world.id(bob);
    world.devices[alice].pay(&to, 30 * ARX).unwrap();

    for _ in 0..30 {
        let mut packets = Vec::new();
        while let Some(packet) = world.devices[alice].next_packet() {
            packets.push(packet);
        }
        for packet in &packets {
            world.devices[bob].handle_packet(packet);
        }
        world.devices[alice].tick();
        world.devices[bob].tick();
    }
    assert_eq!(world.devices[bob].balance(), 0);
    assert_eq!(world.devices[alice].in_flight(), 1);
}

/// The packets of a payment bundle signed outside any device.
fn rogue_packets(key_seed: u8, message: u8, frames: &[Frame]) -> Vec<Vec<u8>> {
    let key = SigningKey::from_bytes(&[key_seed; 32]);
    fragment(&key, [message; 16], &encode(frames).unwrap(), RADIO_MTU)
        .unwrap()
        .iter()
        .map(Fragment::to_bytes)
        .collect()
}

#[test]
fn two_payments_of_the_same_funds_do_not_both_settle() {
    // The payer keeps its key outside any device and signs two
    // payments for the same account position, one to Bob and one to
    // Dave, then transmits both.
    let mut world = World::new(0);
    let bob = world.join(2, None);
    let dave = world.join(4, None);

    let policy = world.config.issuance.clone().unwrap();
    let mut vclock = VectorClock::new();
    let mut payer = AccountChain::from_seed(&[42; 32]);
    let mut certificate = IssuanceCertificate::new(payer.id(), 100 * ARX).unwrap();
    certificate.sign(&policy, &world.issuer_keys[0]).unwrap();
    certificate.sign(&policy, &world.issuer_keys[1]).unwrap();
    let open = payer.open(100 * ARX, &mut vclock).unwrap();
    let to_bob = payer.send(&world.id(bob), 80 * ARX, &mut vclock).unwrap();
    payer.chain.pop();
    payer.balance = 100 * ARX;
    payer.nonce -= 1;
    let to_dave = payer.send(&world.id(dave), 80 * ARX, &mut vclock).unwrap();

    let bundle = |payment: &arxia_lattice::Block| {
        vec![
            Frame::Issuance(certificate.clone()),
            Frame::Block(open.clone()),
            Frame::Payment(payment.clone()),
        ]
    };
    world.broadcast(None, rogue_packets(42, 1, &bundle(&to_bob)));
    world.run(10);
    world.broadcast(None, rogue_packets(42, 2, &bundle(&to_dave)));
    world.run(10);
    // The payer insists.
    for round in 3..8 {
        world.broadcast(None, rogue_packets(42, round, &bundle(&to_dave)));
        world.run(5);
    }

    assert_eq!(world.devices[bob].balance(), 80 * ARX);
    assert_eq!(world.devices[dave].balance(), 0);
    // The two signatures were broadcast as a proof, and devices that
    // are not witnesses hold it too.
    for index in [bob, dave] {
        assert!(
            world.devices[index]
                .wallet()
                .wallet()
                .ledger()
                .equivocation_for(payer.id())
                .is_some(),
            "device {index} holds the proof"
        );
    }
    assert!(world.happened(0, |e| matches!(e, Event::Equivocation { .. })));
}

#[test]
fn garbage_on_the_air_is_ignored() {
    let mut world = World::new(0);
    let alice = world.join(1, Some(100 * ARX));
    let bob = world.join(2, None);

    let mut noise = Dice(7);
    let junk: Vec<Vec<u8>> = (0..200)
        .map(|n| (0..(n % 255) + 1).map(|_| noise.roll() as u8).collect())
        .collect();
    world.broadcast(None, junk);
    // A well-formed fragment whose content is not a bundle.
    let key = SigningKey::from_bytes(&[77; 32]);
    let not_a_bundle: Vec<Vec<u8>> = fragment(&key, [1; 16], &[0xff; 300], RADIO_MTU)
        .unwrap()
        .iter()
        .map(Fragment::to_bytes)
        .collect();
    world.broadcast(None, not_a_bundle);

    let to = world.id(bob);
    world.devices[alice].pay(&to, 30 * ARX).unwrap();
    world.run(20);
    assert_eq!(world.devices[bob].balance(), 30 * ARX);
}

#[test]
fn a_witness_that_restarts_keeps_its_word() {
    let mut world = World::new(0);
    let alice = world.join(1, Some(100 * ARX));
    let bob = world.join(2, None);
    let to = world.id(bob);
    world.devices[alice].pay(&to, 30 * ARX).unwrap();
    world.run(20);
    assert_eq!(world.devices[bob].balance(), 30 * ARX);

    // The first witness loses power and comes back from its storage.
    let witness = world.devices.remove(0);
    let storage = witness.into_wallet().into_storage();
    let wallet =
        DurableWallet::open_with_entropy(storage, world.config.clone(), || unreachable!()).unwrap();
    world.devices.insert(0, Device::new(wallet, 3).unwrap());

    // Payments keep settling with it back on the air.
    let carol = world.join(3, None);
    let to = world.id(carol);
    world.devices[bob].pay(&to, 10 * ARX).unwrap();
    world.run(20);
    assert_eq!(world.devices[carol].balance(), 10 * ARX);
}

#[test]
fn a_device_without_a_roster_cannot_go_on_the_air() {
    let wallet = DurableWallet::open(MemoryStorage::default()).unwrap();
    assert!(Device::new(wallet, 3).is_err());
}

/// Give the device at `index` a reserve account on its own storage.
fn add_reserve(world: &mut World, index: usize, seed: u8) {
    let mut reserve =
        DurableWallet::open_with_entropy(MemoryStorage::default(), world.config.clone(), || {
            [seed; 32]
        })
        .unwrap();
    reserve.open_account(0).unwrap();
    let device = world.devices.remove(index);
    world.devices.insert(index, device.with_reserve(reserve));
}

/// Run until the device at `index` reports its reserve certified.
fn run_until_certified(world: &mut World, index: usize) {
    for _ in 0..80 {
        world.step();
        if world.happened(index, |e| matches!(e, Event::ReserveCertified { .. })) {
            return;
        }
    }
    panic!("the reserve was not certified");
}

/// Move packets between two devices only: everyone else is out of
/// reach.
fn alone_together(world: &mut World, a: usize, b: usize, steps: usize) {
    for _ in 0..steps {
        for (from, to) in [(a, b), (b, a)] {
            let mut packets = Vec::new();
            while let Some(packet) = world.devices[from].next_packet() {
                packets.push(packet);
            }
            for packet in &packets {
                assert!(packet.len() <= RADIO_MTU);
                world.devices[to].handle_packet(packet);
            }
            while let Some(event) = world.devices[from].next_event() {
                world.events.push((from, event));
            }
        }
        world.devices[a].tick();
        world.devices[b].tick();
    }
}

#[test]
fn a_reserve_is_certified_then_pays_with_no_witness_in_reach() {
    let mut world = World::new(0);
    let alice = world.join(1, Some(100 * ARX));
    let bob = world.join(2, None);
    add_reserve(&mut world, alice, 11);

    // With the witnesses in reach, Alice sets 20 aside.
    world.devices[alice].fund_reserve(20 * ARX).unwrap();
    run_until_certified(&mut world, alice);
    assert_eq!(world.devices[alice].balance(), 80 * ARX);
    assert_eq!(world.devices[alice].reserve().unwrap().balance(), 20 * ARX);
    assert_eq!(
        world.devices[alice]
            .reserve_certificate()
            .map(|certificate| certificate.amount()),
        Some(20 * ARX)
    );

    // Later, Alice and Bob are alone. Bob has never heard of Alice.
    let to = world.id(bob);
    world.devices[alice].pay_from_reserve(&to, 5 * ARX).unwrap();
    alone_together(&mut world, alice, bob, 6);

    assert_eq!(world.devices[bob].balance(), 5 * ARX);
    assert_eq!(world.devices[alice].reserve().unwrap().balance(), 15 * ARX);
    assert!(world.happened(bob, |e| matches!(e, Event::ReceivedFromReserve { .. })));
    assert!(world.happened(alice, |e| matches!(e, Event::Delivered { .. })));
    assert_eq!(world.devices[alice].in_flight(), 0);

    // A second payment from the same reserve follows the first.
    world.devices[alice]
        .pay_from_reserve(&to, 10 * ARX)
        .unwrap();
    alone_together(&mut world, alice, bob, 6);
    assert_eq!(world.devices[bob].balance(), 15 * ARX);
}

#[test]
fn a_reserve_cannot_pay_more_than_it_holds() {
    let mut world = World::new(0);
    let alice = world.join(1, Some(100 * ARX));
    let bob = world.join(2, None);
    add_reserve(&mut world, alice, 11);
    world.devices[alice].fund_reserve(20 * ARX).unwrap();
    run_until_certified(&mut world, alice);

    let to = world.id(bob);
    assert!(world.devices[alice]
        .pay_from_reserve(&to, 21 * ARX)
        .is_err());
    assert_eq!(world.devices[alice].in_flight(), 0);
}

#[test]
fn a_receiver_can_decline_reserve_payments() {
    let mut world = World::new(0);
    let alice = world.join(1, Some(100 * ARX));
    let bob = world.join(2, None);
    add_reserve(&mut world, alice, 11);
    world.devices[alice].fund_reserve(20 * ARX).unwrap();
    run_until_certified(&mut world, alice);

    world.devices[bob].set_accept_reserve_payments(false);
    let to = world.id(bob);
    world.devices[alice].pay_from_reserve(&to, 5 * ARX).unwrap();
    alone_together(&mut world, alice, bob, 10);
    assert_eq!(world.devices[bob].balance(), 0);
    assert!(!world.happened(bob, |e| matches!(e, Event::ReceivedFromReserve { .. })));
}

#[test]
fn a_device_without_a_certified_reserve_cannot_pay_from_one() {
    let mut world = World::new(0);
    let alice = world.join(1, Some(100 * ARX));
    let bob = world.join(2, None);
    let to = world.id(bob);
    assert!(world.devices[alice].pay_from_reserve(&to, ARX).is_err());
    assert!(world.devices[alice].fund_reserve(ARX).is_err());

    // A reserve that exists but is not certified yet.
    add_reserve(&mut world, alice, 11);
    assert!(world.devices[alice].pay_from_reserve(&to, ARX).is_err());
}

#[test]
fn a_forged_reserve_certificate_buys_nothing() {
    // The payer builds the three blocks of a reserve itself and sends
    // them with no witness confirmation.
    let mut world = World::new(0);
    let bob = world.join(2, None);
    let policy = world.config.issuance.clone().unwrap();
    let mut vclock = VectorClock::new();
    let mut owner = AccountChain::from_seed(&[42; 32]);
    let mut certificate = IssuanceCertificate::new(owner.id(), 100 * ARX).unwrap();
    certificate.sign(&policy, &world.issuer_keys[0]).unwrap();
    certificate.sign(&policy, &world.issuer_keys[1]).unwrap();
    owner.open(100 * ARX, &mut vclock).unwrap();
    let mut reserve = AccountChain::from_seed(&[43; 32]);
    reserve.open(0, &mut vclock).unwrap();
    let funding = owner.send(reserve.id(), 50 * ARX, &mut vclock).unwrap();
    reserve.receive(&funding, &mut vclock).unwrap();
    let payment = reserve.send(&world.id(bob), 50 * ARX, &mut vclock).unwrap();

    let frames = vec![
        Frame::ReserveBlock(funding),
        Frame::ReserveBlock(reserve.chain[0].clone()),
        Frame::ReserveBlock(reserve.chain[1].clone()),
        Frame::Payment(payment),
    ];
    for packet in rogue_packets(43, 1, &frames) {
        world.devices[bob].handle_packet(&packet);
    }
    assert_eq!(world.devices[bob].balance(), 0);
}
