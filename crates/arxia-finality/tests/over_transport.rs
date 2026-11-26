//! A payment settled across a simulated radio link.
//!
//! Nothing is handed from one device to another except transport
//! messages of at most one LoRa packet each. Bundles are split into
//! signed fragments on one side and reassembled on the other.

use arxia_crypto::generate_keypair;
use arxia_finality::witness::{receive_final, Witness, WitnessRoster};
use arxia_lattice::bundle::{decode, encode, Frame};
use arxia_lattice::{DurableWallet, IssuanceCertificate, IssuancePolicy, WalletConfig};
use arxia_storage::MemoryStorage;
use arxia_transport::{
    fragment, Fragment, Reassembler, SimulatedTransport, TransportMessage, TransportTrait,
};
use ed25519_dalek::SigningKey;

const ARX: u64 = 1_000_000;
const MTU: usize = 256;

type Node = DurableWallet<MemoryStorage>;

/// One end of a link: a radio and the reassembly state behind it.
struct Radio {
    transport: SimulatedTransport,
    reassembler: Reassembler,
    next_message: u8,
}

impl Radio {
    fn new() -> Self {
        Self {
            // No simulated loss: the tests below drop and reorder
            // packets explicitly.
            transport: SimulatedTransport::new(0, 0.0, MTU),
            reassembler: Reassembler::new(),
            next_message: 0,
        }
    }

    /// Split `frames` into fragments signed by `key` and put them on
    /// the air. Returns the packets as sent.
    fn transmit(&mut self, key: &SigningKey, frames: &[Frame]) -> Vec<TransportMessage> {
        self.next_message += 1;
        let payload = encode(frames).unwrap();
        let from = hex::encode(key.verifying_key().to_bytes());
        let before = self.transport.sent_messages().len();
        for piece in fragment(key, [self.next_message; 16], &payload, MTU).unwrap() {
            self.transport
                .send(TransportMessage {
                    from: from.clone(),
                    to: String::new(),
                    payload: piece.to_bytes(),
                    timestamp: 0,
                })
                .unwrap();
        }
        self.transport.sent_messages()[before..].to_vec()
    }

    /// Take packets off the air. Returns each bundle that completes.
    fn hear(&mut self, packets: &[TransportMessage]) -> Vec<Vec<Frame>> {
        for packet in packets {
            assert!(packet.payload.len() <= MTU);
            self.transport.inject_message(packet.clone());
        }
        let mut bundles = Vec::new();
        while let Some(packet) = self.transport.try_recv() {
            let piece = Fragment::from_bytes(&packet.payload).unwrap();
            if let Some(whole) = self.reassembler.feed(piece).unwrap() {
                bundles.push(decode(&whole).unwrap());
            }
        }
        bundles
    }
}

struct World {
    issuer_keys: Vec<SigningKey>,
    policy: IssuancePolicy,
    witnesses: Vec<(Witness<MemoryStorage>, Radio)>,
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
                let wallet =
                    DurableWallet::open_with_issuance(MemoryStorage::default(), policy.clone())
                        .unwrap();
                (Witness::new(wallet), Radio::new())
            })
            .collect();
        let roster = WitnessRoster::new(
            witnesses
                .iter()
                .map(|(w, _)| (w.public_key(), 10))
                .collect(),
        )
        .unwrap();
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
        DurableWallet::open_with_config(MemoryStorage::default(), config).unwrap()
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

fn link_key(node: &Node) -> SigningKey {
    SigningKey::from_bytes(&node.wallet().seed())
}

#[test]
fn a_payment_settles_over_a_link_that_reorders_and_repeats_packets() {
    let mut world = World::new();
    let mut alice = world.node();
    let mut bob = world.node();
    alice
        .open_certified(&world.certify(alice.id(), 100 * ARX))
        .unwrap();
    bob.open_account(0).unwrap();
    let (mut alice_radio, mut bob_radio) = (Radio::new(), Radio::new());

    // Alice transmits the payment bundle.
    let payment = alice.send(bob.id(), 30 * ARX).unwrap();
    let frames = alice.payment_bundle(&payment).unwrap();
    let mut packets = alice_radio.transmit(&link_key(&alice), &frames);
    assert!(packets.len() > 1, "the bundle spans several packets");

    // The air delivers them back to front, each one twice.
    packets.reverse();
    let on_air: Vec<TransportMessage> = packets
        .iter()
        .flat_map(|packet| [packet.clone(), packet.clone()])
        .collect();

    // Every witness hears the bundle and transmits its confirmation.
    let mut confirmations_on_air = Vec::new();
    for (witness, radio) in &mut world.witnesses {
        let bundles = radio.hear(&on_air);
        let bundle = bundles.first().expect("the bundle is heard whole");
        for frame in bundle {
            match frame {
                Frame::Issuance(certificate) => witness.ingest_issuance(certificate).unwrap(),
                Frame::Block(block) => witness.ingest_all(std::slice::from_ref(block)).unwrap(),
                _ => {}
            }
        }
        let confirmation = witness.confirm(&payment).unwrap();
        // A witness signs its packets with a key of its own.
        let (radio_key, _) = generate_keypair();
        confirmations_on_air
            .extend(radio.transmit(&radio_key, &[Frame::Confirmation(confirmation)]));
    }

    // Bob hears the bundle and the confirmations, and credits.
    let bundle = bob_radio.hear(&on_air).remove(0);
    let (heard_payment, _) = bob.ingest_bundle(&bundle).unwrap();
    let confirmations: Vec<_> = bob_radio
        .hear(&confirmations_on_air)
        .into_iter()
        .flatten()
        .filter_map(|frame| match frame {
            Frame::Confirmation(confirmation) => Some(confirmation),
            _ => None,
        })
        .collect();
    assert_eq!(confirmations.len(), 3);
    receive_final(&mut bob, &heard_payment, &confirmations, &world.roster).unwrap();

    assert_eq!(bob.balance(), 30 * ARX);
    assert_eq!(alice.balance(), 70 * ARX);
}

#[test]
fn a_lost_packet_delivers_nothing_until_it_is_sent_again() {
    let world = World::new();
    let mut alice = world.node();
    let mut bob = world.node();
    alice
        .open_certified(&world.certify(alice.id(), 100 * ARX))
        .unwrap();
    bob.open_account(0).unwrap();
    let (mut alice_radio, mut bob_radio) = (Radio::new(), Radio::new());

    let payment = alice.send(bob.id(), 30 * ARX).unwrap();
    let frames = alice.payment_bundle(&payment).unwrap();
    let packets = alice_radio.transmit(&link_key(&alice), &frames);

    // One packet is lost: Bob has no bundle, and nothing was ingested.
    assert!(bob_radio.hear(&packets[1..]).is_empty());
    assert!(bob.wallet().ledger().get_chain(alice.id()).is_none());

    // The missing packet is sent again: the bundle completes.
    let bundles = bob_radio.hear(&packets[..1]);
    assert_eq!(bundles.len(), 1);
    let (heard_payment, _) = bob.ingest_bundle(&bundles[0]).unwrap();
    assert_eq!(heard_payment.hash, payment.hash);
}

#[test]
fn packets_altered_on_the_air_do_not_reach_the_ledger() {
    let world = World::new();
    let mut alice = world.node();
    let bob = world.node();
    alice
        .open_certified(&world.certify(alice.id(), 100 * ARX))
        .unwrap();
    let mut alice_radio = Radio::new();
    let payment = alice.send(bob.id(), 30 * ARX).unwrap();
    let frames = alice.payment_bundle(&payment).unwrap();
    let mut packets = alice_radio.transmit(&link_key(&alice), &frames);

    // Someone on the air flips a bit in the first packet's payload.
    let last = packets[0].payload.len() - 1;
    packets[0].payload[last] ^= 0x01;

    let mut reassembler = Reassembler::new();
    let altered = Fragment::from_bytes(&packets[0].payload).unwrap();
    assert!(reassembler.feed(altered).is_err());
    for packet in &packets[1..] {
        let piece = Fragment::from_bytes(&packet.payload).unwrap();
        assert_eq!(reassembler.feed(piece).unwrap(), None);
    }
}
