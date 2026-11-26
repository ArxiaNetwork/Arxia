//! Bundles: what one device hands to another.
//!
//! A payment travels as a sequence of small frames: the issuance
//! certificates and the blocks the receiver needs to replay the
//! funding, then the payment block itself. Witness confirmations
//! travel the same way.
//!
//! # Frame format
//!
//! `[1B tag][1B payload length][payload]`
//!
//! | tag | payload |
//! |---|---|
//! | 1 | issuance certificate ([`IssuanceCertificate::to_bytes`]) |
//! | 2 | block, 193-byte compact form: history to replay |
//! | 3 | block, 193-byte compact form: the payment being made |
//! | 4 | witness confirmation, 128 bytes |
//!
//! The largest frame is [`MAX_FRAME_LEN`] bytes, below the LoRa MTU,
//! so each frame fits one radio packet. A bundle is the concatenation
//! of its frames; frames carry no ordering information beyond their
//! position.
//!
//! # Trust
//!
//! Decoding checks shape only. Every item is verified when it is
//! ingested: certificates against the issuance policy, blocks under
//! the ledger rules, confirmations against the witness roster.

use crate::block::Block;
use crate::durable::DurableWallet;
use crate::issuance::IssuanceCertificate;
use crate::serialization::{from_compact_bytes, to_compact_bytes};
use crate::witness::WitnessConfirmation;
use arxia_core::{ArxiaError, BundleFault};
use arxia_storage::StorageBackend;

/// Largest encoded frame: tag, length, and an issuance certificate
/// with three signatures.
pub const MAX_FRAME_LEN: usize = 2 + 236;

// A frame must fit one radio packet.
const _: () = assert!(MAX_FRAME_LEN <= arxia_core::constants::LORA_MTU);

const TAG_ISSUANCE: u8 = 1;
const TAG_BLOCK: u8 = 2;
const TAG_PAYMENT: u8 = 3;
const TAG_CONFIRMATION: u8 = 4;

fn fault(fault: BundleFault) -> ArxiaError {
    ArxiaError::Bundle { fault }
}

/// One item of a bundle.
#[derive(Debug, Clone)]
pub enum Frame {
    /// An issuance certificate.
    Issuance(IssuanceCertificate),
    /// A block of the history the receiver replays.
    Block(Block),
    /// The payment block.
    Payment(Block),
    /// A witness confirmation.
    Confirmation(WitnessConfirmation),
}

impl Frame {
    /// Encode one frame.
    ///
    /// # Errors
    ///
    /// Any error of [`to_compact_bytes`]; [`BundleFault::TooLong`] if
    /// the payload does not fit a frame.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ArxiaError> {
        let (tag, payload) = match self {
            Self::Issuance(certificate) => (TAG_ISSUANCE, certificate.to_bytes()),
            Self::Block(block) => (TAG_BLOCK, to_compact_bytes(block)?),
            Self::Payment(block) => (TAG_PAYMENT, to_compact_bytes(block)?),
            Self::Confirmation(confirmation) => {
                (TAG_CONFIRMATION, confirmation.to_bytes().to_vec())
            }
        };
        let length = u8::try_from(payload.len()).map_err(|_| fault(BundleFault::TooLong))?;
        if payload.len() + 2 > MAX_FRAME_LEN {
            return Err(fault(BundleFault::TooLong));
        }
        let mut bytes = Vec::with_capacity(payload.len() + 2);
        bytes.push(tag);
        bytes.push(length);
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    /// Decode the frame at the start of `bytes`. Returns the frame and
    /// the number of bytes it took.
    ///
    /// # Errors
    ///
    /// - [`BundleFault::Truncated`] if `bytes` ends inside a frame.
    /// - [`BundleFault::UnknownTag`] for a tag this version does not
    ///   know.
    /// - [`BundleFault::Payload`] if the payload does not decode.
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), ArxiaError> {
        let [tag, length, rest @ ..] = bytes else {
            return Err(fault(BundleFault::Truncated));
        };
        let length = usize::from(*length);
        let payload = rest.get(..length).ok_or(fault(BundleFault::Truncated))?;
        let bad_payload = |_| fault(BundleFault::Payload);
        let frame = match *tag {
            TAG_ISSUANCE => {
                Self::Issuance(IssuanceCertificate::from_bytes(payload).map_err(bad_payload)?)
            }
            TAG_BLOCK => Self::Block(from_compact_bytes(payload).map_err(bad_payload)?),
            TAG_PAYMENT => Self::Payment(from_compact_bytes(payload).map_err(bad_payload)?),
            TAG_CONFIRMATION => {
                Self::Confirmation(WitnessConfirmation::from_bytes(payload).map_err(bad_payload)?)
            }
            _ => return Err(fault(BundleFault::UnknownTag)),
        };
        Ok((frame, length + 2))
    }
}

/// Encode frames one after another.
///
/// # Errors
///
/// As [`Frame::to_bytes`].
pub fn encode(frames: &[Frame]) -> Result<Vec<u8>, ArxiaError> {
    let mut bytes = Vec::new();
    for frame in frames {
        bytes.extend_from_slice(&frame.to_bytes()?);
    }
    Ok(bytes)
}

/// Decode a concatenation of frames. All of `bytes` must be consumed.
///
/// # Errors
///
/// As [`Frame::from_bytes`].
pub fn decode(mut bytes: &[u8]) -> Result<Vec<Frame>, ArxiaError> {
    let mut frames = Vec::new();
    while !bytes.is_empty() {
        let (frame, taken) = Frame::from_bytes(bytes)?;
        frames.push(frame);
        bytes = &bytes[taken..];
    }
    Ok(frames)
}

impl<S: StorageBackend> DurableWallet<S> {
    /// Build the bundle for `payment`, a SEND this wallet signed: the
    /// issuance certificates and every block this wallet holds, in the
    /// order they were accepted, then the payment.
    ///
    /// The whole history is sent. It is always sufficient for the
    /// receiver to replay; sending only the part a given receiver
    /// lacks is a later refinement.
    ///
    /// # Errors
    ///
    /// Any backend error while reading the stored history.
    pub fn payment_bundle(&self, payment: &Block) -> Result<Vec<Frame>, ArxiaError> {
        let mut frames: Vec<Frame> = self
            .wallet()
            .ledger()
            .issuances()
            .cloned()
            .map(Frame::Issuance)
            .collect();
        frames.extend(
            self.history()?
                .into_iter()
                .filter(|block| block.hash != payment.hash)
                .map(Frame::Block),
        );
        // Confirmations of the settled blocks in that history, so that
        // a receiver who has since learned of an equivocation still
        // accepts what the witnesses decided.
        frames.extend(
            self.wallet()
                .ledger()
                .settlements()
                .flat_map(|(_hash, confirmations)| confirmations.iter().cloned())
                .map(Frame::Confirmation),
        );
        frames.push(Frame::Payment(payment.clone()));
        Ok(frames)
    }

    /// Take in the certificates and history blocks of a bundle, under
    /// the usual rules, and return its payment block and its
    /// confirmations without acting on them. The caller decides how
    /// the payment is settled.
    ///
    /// # Errors
    ///
    /// - Any error of [`DurableWallet::ingest_issuance`] or
    ///   [`DurableWallet::ingest`] for an item that is refused.
    /// - [`BundleFault::PaymentCount`] if the bundle does not carry
    ///   exactly one payment.
    pub fn ingest_bundle(
        &mut self,
        frames: &[Frame],
    ) -> Result<(Block, Vec<WitnessConfirmation>), ArxiaError> {
        let mut payments = Vec::new();
        let confirmations: Vec<WitnessConfirmation> = frames
            .iter()
            .filter_map(|frame| match frame {
                Frame::Confirmation(confirmation) => Some(confirmation.clone()),
                _ => None,
            })
            .collect();
        let has_roster = self.wallet().ledger().witness_roster().is_some();
        for frame in frames {
            match frame {
                Frame::Issuance(certificate) => self.ingest_issuance(certificate)?,
                Frame::Block(block) => {
                    // If the bundle proves the block final, record that
                    // first: a settled block is accepted even where the
                    // account is frozen. A block that is not final is
                    // simply ingested under the ordinary rules.
                    if has_roster && !confirmations.is_empty() {
                        match self.ingest_settlement(block, &confirmations) {
                            Ok(()) | Err(ArxiaError::Witness { .. }) => {}
                            Err(error) => return Err(error),
                        }
                    }
                    self.ingest(block)?;
                }
                Frame::Payment(block) => payments.push(block.clone()),
                Frame::Confirmation(_) => {}
            }
        }
        match <[Block; 1]>::try_from(payments) {
            Ok([payment]) => Ok((payment, confirmations)),
            Err(_) => Err(fault(BundleFault::PaymentCount)),
        }
    }
}
