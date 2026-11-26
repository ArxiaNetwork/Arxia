//! Witnesses: settlement confirmed by nearby nodes, with no internet.
//!
//! A receiver holding only the payer's blocks can check that a payment
//! is authentic and funded. It cannot see what the payer signed
//! elsewhere. Witnesses close that gap: nodes within radio reach that
//! each keep a ledger and sign a confirmation for a block only when
//! their own ledger accepts it.
//!
//! # What a witness guarantees
//!
//! [`Witness::confirm`] runs the block through the full ledger rules
//! and stores it before the confirmation is signed. A witness
//! therefore never confirms two different blocks for the same account
//! position: the second one is refused with
//! [`ArxiaError::NonceConflict`], and it stays refused after a
//! restart, because the first block is on storage.
//!
//! # What a receiver decides
//!
//! [`assess`] counts the weight of the roster witnesses that confirmed
//! exactly this block. A payment is final when that weight is more
//! than two thirds of the roster total. Two quorums of more than two
//! thirds share more than one third of the weight, so two conflicting
//! blocks cannot both become final unless witnesses holding more than
//! one third of the weight confirm both, which each of them refuses to
//! do.
//!
//! Nothing in the decision is supplied by the caller except the
//! roster, which is configuration. The amount, the account and the
//! position come from the block; the confirmations are bound to its
//! hash.
//!
//! # What is ignored
//!
//! A confirmation counts only if it names this block, comes from a
//! roster witness other than the paying account, verifies, and is the
//! first from that witness. Anything else is ignored rather than
//! fatal, so adding noise to a set of confirmations cannot block a
//! payment.
//!
//! # Scope
//!
//! The roster (which keys are witnesses, with what weight) is
//! configuration here. Deriving weights from bonds held on the ledger,
//! distributing roster updates, and penalties for a witness that signs
//! outside these rules are separate work.

use arxia_core::{ArxiaError, WitnessFault};
use arxia_lattice::{Block, DurableWallet, IssuanceCertificate};
use arxia_storage::StorageBackend;
use ed25519_dalek::SigningKey;

pub use arxia_lattice::witness::{
    assess, Settlement, WitnessConfirmation, WitnessRoster, CONFIRMATION_LEN,
    WITNESS_CONFIRMATION_DOMAIN,
};

fn fault(fault: WitnessFault) -> ArxiaError {
    ArxiaError::Witness { fault }
}

/// A node that confirms blocks its own ledger accepts.
pub struct Witness<S: StorageBackend> {
    wallet: DurableWallet<S>,
    key: SigningKey,
}

impl<S: StorageBackend> Witness<S> {
    /// Run a witness on top of a durable wallet. The witness signs
    /// with the wallet's account key, and its ledger is the wallet's.
    pub fn new(wallet: DurableWallet<S>) -> Self {
        let key = SigningKey::from_bytes(&wallet.wallet().seed());
        Self { wallet, key }
    }

    /// Public key of the witness.
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Give the wallet back, for example to restart the witness.
    pub fn into_wallet(self) -> DurableWallet<S> {
        self.wallet
    }

    /// Accept an issuance certificate, as
    /// [`DurableWallet::ingest_issuance`].
    ///
    /// # Errors
    ///
    /// As [`DurableWallet::ingest_issuance`].
    pub fn ingest_issuance(&mut self, certificate: &IssuanceCertificate) -> Result<(), ArxiaError> {
        self.wallet.ingest_issuance(certificate)
    }

    /// Accept the blocks that lead up to a payment, as
    /// [`DurableWallet::ingest_all`].
    ///
    /// # Errors
    ///
    /// As [`DurableWallet::ingest_all`].
    pub fn ingest_all(&mut self, blocks: &[Block]) -> Result<(), ArxiaError> {
        self.wallet.ingest_all(blocks)
    }

    /// Confirm `block`, if this witness's ledger accepts it.
    ///
    /// The block is stored before the confirmation is signed.
    /// Confirming a block already held returns the same confirmation
    /// again.
    ///
    /// # Errors
    ///
    /// - [`ArxiaError::NonceConflict`] if the ledger holds a different
    ///   block at that account position.
    /// - Any other error of [`DurableWallet::ingest`]: the block is
    ///   not authentic, not in sequence, not funded.
    pub fn confirm(&mut self, block: &Block) -> Result<WitnessConfirmation, ArxiaError> {
        self.wallet.ingest(block)?;
        WitnessConfirmation::sign(&self.key, block)
    }
}

/// Credit a payment only if it is final under `roster`.
///
/// # Errors
///
/// - [`WitnessFault::NotFinal`] if the confirmed weight is not more
///   than two thirds of the roster total. The wallet is untouched.
/// - Any error of [`assess`] or [`DurableWallet::receive`].
pub fn receive_final<S: StorageBackend>(
    wallet: &mut DurableWallet<S>,
    send_block: &Block,
    confirmations: &[WitnessConfirmation],
    roster: &WitnessRoster,
) -> Result<Block, ArxiaError> {
    let settlement = assess(send_block, confirmations, roster)?;
    if !settlement.is_final() {
        return Err(fault(WitnessFault::NotFinal {
            confirmed: settlement.confirmed_weight,
            total: settlement.total_weight,
        }));
    }
    wallet.receive(send_block)
}
