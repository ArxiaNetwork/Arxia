//! What a device does on the air.
//!
//! A [`Device`] owns a durable wallet and speaks in packets: bytes it
//! is handed when the radio hears something, and bytes it wants
//! transmitted. Everything between is here: splitting bundles into
//! signed fragments, reassembling what is heard, and the three roles a
//! device plays.
//!
//! - **Payer.** [`Device::pay`] signs a payment, which is on storage
//!   before anything is queued, and broadcasts a short bundle for the
//!   witnesses. Once the witnesses have settled the payment, the payer
//!   broadcasts the payment with its confirmations, which is all a
//!   receiver needs, until the receiver acknowledges it.
//! - **Witness.** A device whose key is on the roster replays every
//!   payment bundle it hears and, if its own ledger accepts the
//!   payment, broadcasts a confirmation. A second block for an account
//!   position it already holds is refused, and the two blocks are
//!   broadcast as an equivocation proof.
//! - **Receiver.** A payment addressed to the device is held until the
//!   confirmations heard for it hold more than two thirds of the
//!   roster weight, then credited and acknowledged. Nothing is
//!   credited before that.
//!
//! The radio is a broadcast medium and it loses packets. Nothing here
//! assumes a packet arrived: a payer repeats, a witness confirms again
//! each time it hears the payment, a receiver acknowledges again each
//! time it hears a payment it already credited, and every step is
//! idempotent. Repeats of a message share one identifier, so the
//! fragments a listener missed in one broadcast are filled in by the
//! next.
//!
//! An acknowledgement is a confirmation signed by the destination
//! account: it has no weight in settlement, and tells the payer it can
//! stop repeating.
//!
//! The device does not drive a radio. A caller moves bytes between
//! [`Device::handle_packet`], [`Device::next_packet`] and whatever
//! link it has, and calls [`Device::tick`] from time to time.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;

use arxia_core::ArxiaError;
use arxia_lattice::bundle::{decode, encode, Frame};
use arxia_lattice::witness::{assess, receive_final, WitnessConfirmation, WitnessRoster};
use arxia_lattice::{Block, BlockType, DurableWallet, EquivocationProof};
use arxia_storage::StorageBackend;
use arxia_transport::{fragment, Fragment, Reassembler};
use ed25519_dalek::SigningKey;

/// Largest packet a LoRa radio carries, in bytes.
pub const RADIO_MTU: usize = 255;

/// Payments addressed to this device that it holds at once while
/// waiting for confirmations. Further ones are ignored until one of
/// them settles; their payers keep repeating.
pub const MAX_PENDING: usize = 16;

/// Broadcasts of a settled payment that go unacknowledged before the
/// payer stops repeating it.
pub const MAX_UNACKNOWLEDGED_REPEATS: u32 = 40;

/// Something that happened, for the caller to show or log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A payment to this device was settled by the witnesses and
    /// credited.
    Received {
        /// Hash of the payment block.
        payment: String,
        /// Amount credited, in micro-ARX.
        amount: u64,
    },
    /// A payment this device made was settled by the witnesses.
    Settled {
        /// Hash of the payment block.
        payment: String,
    },
    /// The receiver acknowledged a payment this device made.
    Delivered {
        /// Hash of the payment block.
        payment: String,
    },
    /// A payment this device made was settled, but the receiver did
    /// not acknowledge it; the device stopped repeating it. The
    /// payment stands: the receiver credits it whenever it is shown
    /// the payment and its confirmations.
    Unacknowledged {
        /// Hash of the payment block.
        payment: String,
    },
    /// This device, as a witness, confirmed a payment.
    Confirmed {
        /// Hash of the payment block.
        payment: String,
    },
    /// This device, as a witness, refused a payment its ledger did not
    /// accept.
    Refused {
        /// Hash of the payment block.
        payment: String,
    },
    /// Two blocks signed for one account position were seen. The
    /// account is frozen in this device's ledger from that position.
    Equivocation {
        /// Hex-encoded public key of the account.
        account: String,
    },
    /// A payment to this device reached finality but could not be
    /// credited.
    NotCredited {
        /// Hash of the payment block.
        payment: String,
    },
}

/// A payment this device made, repeated until acknowledged.
struct Outgoing {
    payment: Block,
    /// What witnesses need: recent history, then the payment.
    for_witnesses: Vec<u8>,
    /// What the receiver needs once settled: confirmations, then the
    /// payment. Empty until the payment is settled.
    for_receiver: Vec<u8>,
    confirmations: Vec<WitnessConfirmation>,
    ticks_since_sent: u32,
    repeats_since_settled: u32,
}

/// A payment to this device, held until settled.
struct Incoming {
    payment: Block,
    confirmations: Vec<WitnessConfirmation>,
}

/// A device on the air. See the [crate documentation](crate).
pub struct Device<S: StorageBackend> {
    wallet: DurableWallet<S>,
    key: SigningKey,
    roster: WitnessRoster,
    is_witness: bool,
    reassembler: Reassembler,
    outbox: VecDeque<Vec<u8>>,
    events: VecDeque<Event>,
    outgoing: BTreeMap<String, Outgoing>,
    incoming: BTreeMap<String, Incoming>,
    credited: BTreeSet<String>,
    resend_every: u32,
}

fn add_confirmation(held: &mut Vec<WitnessConfirmation>, confirmation: &WitnessConfirmation) {
    if !held.iter().any(|c| c.witness() == confirmation.witness()) {
        held.push(confirmation.clone());
    }
}

fn destination_of(payment: &Block) -> Option<&str> {
    match &payment.block_type {
        BlockType::Send { destination, .. } => Some(destination),
        _ => None,
    }
}

impl<S: StorageBackend> Device<S> {
    /// Put a wallet on the air. The wallet's ledger must be configured
    /// with a witness roster: without one a device can neither settle
    /// nor witness anything.
    ///
    /// `resend_every` is the number of [`Device::tick`] calls between
    /// two broadcasts of a payment that is still in flight.
    ///
    /// # Errors
    ///
    /// [`arxia_core::WitnessFault::NoRoster`] if the wallet has no
    /// roster.
    pub fn new(wallet: DurableWallet<S>, resend_every: u32) -> Result<Self, ArxiaError> {
        let roster =
            wallet
                .wallet()
                .ledger()
                .witness_roster()
                .cloned()
                .ok_or(ArxiaError::Witness {
                    fault: arxia_core::WitnessFault::NoRoster,
                })?;
        let key = SigningKey::from_bytes(&wallet.wallet().seed());
        let is_witness = roster.weight_of(&key.verifying_key().to_bytes()).is_some();
        Ok(Self {
            wallet,
            key,
            roster,
            is_witness,
            reassembler: Reassembler::new(),
            outbox: VecDeque::new(),
            events: VecDeque::new(),
            outgoing: BTreeMap::new(),
            incoming: BTreeMap::new(),
            credited: BTreeSet::new(),
            resend_every: resend_every.max(1),
        })
    }

    /// Hex-encoded public key of the device's account.
    pub fn id(&self) -> &str {
        self.wallet.id()
    }

    /// Current balance in micro-ARX.
    pub fn balance(&self) -> u64 {
        self.wallet.balance()
    }

    /// Whether this device's key is on the witness roster.
    pub fn is_witness(&self) -> bool {
        self.is_witness
    }

    /// The wallet, for example to open the account.
    pub fn wallet_mut(&mut self) -> &mut DurableWallet<S> {
        &mut self.wallet
    }

    /// The wallet, read-only.
    pub fn wallet(&self) -> &DurableWallet<S> {
        &self.wallet
    }

    /// Take the device off the air and give its wallet back.
    pub fn into_wallet(self) -> DurableWallet<S> {
        self.wallet
    }

    /// Number of payments made by this device that are still being
    /// repeated: not settled yet, or settled and not acknowledged.
    pub fn in_flight(&self) -> usize {
        self.outgoing.len()
    }

    /// Sign a payment and queue it for broadcast. The block is on
    /// storage before anything is queued. Returns the hash of the
    /// payment block.
    ///
    /// # Errors
    ///
    /// Any error of [`DurableWallet::send`], or of encoding the
    /// bundle.
    pub fn pay(&mut self, destination: &str, amount: u64) -> Result<String, ArxiaError> {
        let payment = self.wallet.send(destination, amount)?;
        let for_witnesses = encode(&self.wallet.delta_bundle(&payment))?;
        self.broadcast(&for_witnesses);
        let hash = payment.hash.clone();
        self.outgoing.insert(
            hash.clone(),
            Outgoing {
                payment,
                for_witnesses,
                for_receiver: Vec::new(),
                confirmations: Vec::new(),
                ticks_since_sent: 0,
                repeats_since_settled: 0,
            },
        );
        Ok(hash)
    }

    /// Hand the device one packet heard on the air. Packets that are
    /// not valid fragments, or whose content is refused, are dropped.
    pub fn handle_packet(&mut self, packet: &[u8]) {
        let Ok(piece) = Fragment::from_bytes(packet) else {
            return;
        };
        if piece.header.peer_pubkey == self.key.verifying_key().to_bytes() {
            return;
        }
        let Ok(Some(message)) = self.reassembler.feed(piece) else {
            return;
        };
        let Ok(frames) = decode(&message) else {
            return;
        };
        self.handle_frames(&frames);
    }

    /// The next packet to transmit, if any.
    pub fn next_packet(&mut self) -> Option<Vec<u8>> {
        self.outbox.pop_front()
    }

    /// The next event to report, if any.
    pub fn next_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Advance time by one step. Every `resend_every` steps, each
    /// payment in flight is broadcast again: the bundle for the
    /// witnesses until it is settled, then the payment with its
    /// confirmations until the receiver acknowledges it.
    pub fn tick(&mut self) {
        let mut due: Vec<Vec<u8>> = Vec::new();
        let mut given_up: Vec<String> = Vec::new();
        for (hash, outgoing) in &mut self.outgoing {
            outgoing.ticks_since_sent += 1;
            if outgoing.ticks_since_sent < self.resend_every {
                continue;
            }
            outgoing.ticks_since_sent = 0;
            if outgoing.for_receiver.is_empty() {
                due.push(outgoing.for_witnesses.clone());
            } else if outgoing.repeats_since_settled >= MAX_UNACKNOWLEDGED_REPEATS {
                given_up.push(hash.clone());
            } else {
                outgoing.repeats_since_settled += 1;
                due.push(outgoing.for_receiver.clone());
            }
        }
        for message in due {
            self.broadcast(&message);
        }
        for hash in given_up {
            self.outgoing.remove(&hash);
            self.events
                .push_back(Event::Unacknowledged { payment: hash });
        }
    }

    /// Split a message into signed fragments and queue them.
    ///
    /// The message identifier is derived from the content, so every
    /// repeat of a message carries the same one: a listener that
    /// missed some fragments of one broadcast completes the message
    /// with the fragments of the next.
    fn broadcast(&mut self, message: &[u8]) {
        let digest = arxia_crypto::hash_blake3_bytes(message);
        let mut message_id = [0u8; 16];
        message_id.copy_from_slice(&digest[..16]);
        if let Ok(pieces) = fragment(&self.key, message_id, message, RADIO_MTU) {
            self.outbox.extend(pieces.iter().map(Fragment::to_bytes));
        }
    }

    fn broadcast_frames(&mut self, frames: &[Frame]) {
        if let Ok(message) = encode(frames) {
            self.broadcast(&message);
        }
    }

    fn handle_frames(&mut self, frames: &[Frame]) {
        let confirmations: Vec<&WitnessConfirmation> = frames
            .iter()
            .filter_map(|frame| match frame {
                Frame::Confirmation(confirmation) => Some(confirmation),
                _ => None,
            })
            .collect();
        // Confirmations first: they may complete something held.
        for confirmation in &confirmations {
            let hash = hex::encode(confirmation.block_hash());
            if let Some(incoming) = self.incoming.get_mut(&hash) {
                add_confirmation(&mut incoming.confirmations, confirmation);
            }
            self.note_for_outgoing(&hash, confirmation);
        }
        self.take_proofs(frames);

        let payment = frames.iter().find_map(|frame| match frame {
            Frame::Payment(block) => Some(block),
            _ => None,
        });
        if let Some(payment) = payment {
            if payment.account != self.wallet.id() {
                if self.is_witness {
                    self.witness(frames, payment);
                }
                self.hold_if_mine(payment, &confirmations);
            }
        }
        self.settle();
    }

    /// A confirmation of a payment this device made: an
    /// acknowledgement if it comes from the destination, otherwise a
    /// witness's.
    fn note_for_outgoing(&mut self, hash: &str, confirmation: &WitnessConfirmation) {
        let Some(outgoing) = self.outgoing.get_mut(hash) else {
            return;
        };
        let from_destination = destination_of(&outgoing.payment)
            .and_then(|destination| hex::decode(destination).ok())
            .is_some_and(|key| key.as_slice() == confirmation.witness().as_slice());
        if !from_destination {
            add_confirmation(&mut outgoing.confirmations, confirmation);
            return;
        }
        if !outgoing.for_receiver.is_empty() && confirmation.verifies() {
            self.outgoing.remove(hash);
            self.events.push_back(Event::Delivered {
                payment: String::from(hash),
            });
        }
    }

    /// Equivocation proofs travel in any message; take them in.
    fn take_proofs(&mut self, frames: &[Frame]) {
        let blocks: Vec<&Block> = frames
            .iter()
            .filter_map(|frame| match frame {
                Frame::EquivocationBlock(block) => Some(block),
                _ => None,
            })
            .collect();
        for pair in blocks.chunks_exact(2) {
            let Ok(proof) = EquivocationProof::new(pair[0].clone(), pair[1].clone()) else {
                continue;
            };
            let known = self
                .wallet
                .wallet()
                .ledger()
                .equivocation_for(proof.account())
                .is_some();
            if self.wallet.ingest_equivocation(&proof).is_ok() && !known {
                self.events.push_back(Event::Equivocation {
                    account: String::from(proof.account()),
                });
            }
        }
    }

    /// As a witness: replay the bundle, and confirm the payment if
    /// this device's own ledger accepts it.
    fn witness(&mut self, frames: &[Frame], payment: &Block) {
        let taken = self
            .wallet
            .ingest_bundle(frames)
            .and_then(|_| self.wallet.ingest(payment));
        match taken {
            Ok(()) => {
                if let Ok(confirmation) = WitnessConfirmation::sign(&self.key, payment) {
                    self.broadcast_frames(&[Frame::Confirmation(confirmation)]);
                    self.events.push_back(Event::Confirmed {
                        payment: payment.hash.clone(),
                    });
                }
            }
            Err(ArxiaError::NonceConflict { .. }) => {
                // Two blocks for one position: tell everyone.
                let proof = self
                    .wallet
                    .wallet()
                    .ledger()
                    .equivocation_for(&payment.account)
                    .cloned();
                if let Some(proof) = proof {
                    let (first, second) = proof.blocks();
                    self.broadcast_frames(&[
                        Frame::EquivocationBlock(first.clone()),
                        Frame::EquivocationBlock(second.clone()),
                    ]);
                    self.events.push_back(Event::Equivocation {
                        account: payment.account.clone(),
                    });
                }
                self.events.push_back(Event::Refused {
                    payment: payment.hash.clone(),
                });
            }
            Err(_) => self.events.push_back(Event::Refused {
                payment: payment.hash.clone(),
            }),
        }
    }

    /// Hold a payment addressed to this device until it settles, or
    /// acknowledge it again if it was already credited.
    fn hold_if_mine(&mut self, payment: &Block, confirmations: &[&WitnessConfirmation]) {
        if destination_of(payment) != Some(self.wallet.id()) {
            return;
        }
        if self.credited.contains(&payment.hash) {
            self.acknowledge(payment);
            return;
        }
        if !self.incoming.contains_key(&payment.hash) {
            if self.incoming.len() >= MAX_PENDING {
                return;
            }
            self.incoming.insert(
                payment.hash.clone(),
                Incoming {
                    payment: payment.clone(),
                    confirmations: Vec::new(),
                },
            );
        }
        // Confirmations that came in the same message as the payment.
        if let Some(incoming) = self.incoming.get_mut(&payment.hash) {
            for confirmation in confirmations {
                if hex::encode(confirmation.block_hash()) == payment.hash {
                    add_confirmation(&mut incoming.confirmations, confirmation);
                }
            }
        }
    }

    /// Tell the payer its payment was credited.
    fn acknowledge(&mut self, payment: &Block) {
        if let Ok(acknowledgement) = WitnessConfirmation::sign(&self.key, payment) {
            self.broadcast_frames(&[Frame::Confirmation(acknowledgement)]);
        }
    }

    /// Act on whatever reached finality.
    fn settle(&mut self) {
        let is_final = |payment: &Block, confirmations: &[WitnessConfirmation]| {
            assess(payment, confirmations, &self.roster).is_ok_and(|s| s.is_final())
        };
        let received: Vec<String> = self
            .incoming
            .iter()
            .filter(|(_, held)| is_final(&held.payment, &held.confirmations))
            .map(|(hash, _)| hash.clone())
            .collect();
        let settled: Vec<String> = self
            .outgoing
            .iter()
            .filter(|(_, sent)| {
                sent.for_receiver.is_empty() && is_final(&sent.payment, &sent.confirmations)
            })
            .map(|(hash, _)| hash.clone())
            .collect();

        for hash in received {
            let Some(held) = self.incoming.remove(&hash) else {
                continue;
            };
            let amount = match &held.payment.block_type {
                BlockType::Send { amount, .. } => *amount,
                _ => 0,
            };
            let credited = receive_final(
                &mut self.wallet,
                &held.payment,
                &held.confirmations,
                &self.roster,
            );
            self.credited.insert(hash.clone());
            match credited {
                Ok(_) => {
                    self.acknowledge(&held.payment);
                    self.events.push_back(Event::Received {
                        payment: hash,
                        amount,
                    });
                }
                Err(_) => self.events.push_back(Event::NotCredited { payment: hash }),
            }
        }
        for hash in settled {
            let Some(sent) = self.outgoing.get_mut(&hash) else {
                continue;
            };
            // The payer keeps the confirmations: its next payment
            // starts from this block.
            if self
                .wallet
                .ingest_settlement(&sent.payment, &sent.confirmations)
                .is_err()
            {
                continue;
            }
            let mut frames: Vec<Frame> = sent
                .confirmations
                .iter()
                .cloned()
                .map(Frame::Confirmation)
                .collect();
            frames.push(Frame::Payment(sent.payment.clone()));
            let Ok(for_receiver) = encode(&frames) else {
                continue;
            };
            sent.for_receiver = for_receiver.clone();
            sent.ticks_since_sent = 0;
            self.broadcast(&for_receiver);
            self.events.push_back(Event::Settled { payment: hash });
        }
    }
}
