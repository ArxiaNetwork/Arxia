//! Witness confirmations and how a receiver counts them.
//!
//! A witness is a node that keeps a ledger and signs a confirmation
//! for a block only when its own ledger accepts it: [`Witness`]. This
//! module also holds the roster of recognised witnesses, the signed
//! confirmation, the count that decides whether a block is final,
//! and [`receive_final`], which credits only final payments.
//!
//! [`assess`] counts the weight of the roster witnesses that confirmed
//! exactly this block. A block is final when that weight is more than
//! two thirds of the roster total. Two quorums of more than two thirds
//! share more than one third of the weight, so two conflicting blocks
//! cannot both become final while witnesses holding more than one
//! third of the weight follow the rules.
//!
//! A confirmation counts only if it names this block, comes from a
//! roster witness other than the block's own account, verifies, and is
//! the first from that witness. Anything else is ignored rather than
//! fatal.

use alloc::collections::BTreeMap;
#[allow(unused_imports)]
use alloc::{
    borrow::ToOwned,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use crate::block::Block;
use crate::durable::DurableWallet;
use crate::issuance::IssuanceCertificate;
use crate::validation::verify_block;
use arxia_core::{ArxiaError, WitnessFault};
use arxia_storage::StorageBackend;
use ed25519_dalek::SigningKey;

/// Domain prefix of the message a witness signs.
pub const WITNESS_CONFIRMATION_DOMAIN: &[u8] = b"arxia-witness-confirmation-v1";

/// Encoded length of a [`WitnessConfirmation`].
pub const CONFIRMATION_LEN: usize = 32 + 32 + 64;

fn fault(fault: WitnessFault) -> ArxiaError {
    ArxiaError::Witness { fault }
}

fn hash_bytes(block: &Block) -> Result<[u8; 32], ArxiaError> {
    let bytes = hex::decode(&block.hash).map_err(|_| fault(WitnessFault::Undecodable))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| fault(WitnessFault::Undecodable))
}

fn key_bytes(hex_key: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_key).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

/// The witnesses a receiver recognises, and the weight of each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessRoster {
    weights: BTreeMap<[u8; 32], u64>,
    total: u64,
}

impl WitnessRoster {
    /// Build a roster from `(public key, weight)` pairs.
    ///
    /// # Errors
    ///
    /// [`WitnessFault::RosterInvalid`] if the roster is empty, a
    /// weight is zero, a key is repeated, or the total overflows. Any
    /// error of [`arxia_crypto::validate_pubkey_strict`] for a key
    /// that is not a valid public key.
    pub fn new(witnesses: Vec<([u8; 32], u64)>) -> Result<Self, ArxiaError> {
        let invalid = || fault(WitnessFault::RosterInvalid);
        if witnesses.is_empty() {
            return Err(invalid());
        }
        let mut weights = BTreeMap::new();
        let mut total = 0u64;
        for (key, weight) in witnesses {
            arxia_crypto::validate_pubkey_strict(&key)?;
            if weight == 0 || weights.insert(key, weight).is_some() {
                return Err(invalid());
            }
            total = total.checked_add(weight).ok_or_else(invalid)?;
        }
        Ok(Self { weights, total })
    }

    /// Weight of `key`, if it is a witness.
    pub fn weight_of(&self, key: &[u8; 32]) -> Option<u64> {
        self.weights.get(key).copied()
    }

    /// Sum of all weights.
    pub fn total_weight(&self) -> u64 {
        self.total
    }
}

/// A witness's signed statement that its ledger accepted a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessConfirmation {
    witness: [u8; 32],
    block_hash: [u8; 32],
    signature: [u8; 64],
}

impl WitnessConfirmation {
    fn message(witness: &[u8; 32], block_hash: &[u8; 32]) -> Vec<u8> {
        let mut message = Vec::with_capacity(WITNESS_CONFIRMATION_DOMAIN.len() + 64);
        message.extend_from_slice(WITNESS_CONFIRMATION_DOMAIN);
        message.extend_from_slice(witness);
        message.extend_from_slice(block_hash);
        message
    }

    /// Sign a confirmation of `block` with a witness key. The caller
    /// is a witness whose ledger has accepted the block.
    ///
    /// # Errors
    ///
    /// [`WitnessFault::Undecodable`] if the block hash is not 32 bytes
    /// of hex.
    pub fn sign(key: &SigningKey, block: &Block) -> Result<Self, ArxiaError> {
        let witness = key.verifying_key().to_bytes();
        let block_hash = hash_bytes(block)?;
        let message = Self::message(&witness, &block_hash);
        Ok(Self {
            witness,
            block_hash,
            signature: arxia_crypto::sign(key, &message),
        })
    }

    /// Public key of the witness.
    pub fn witness(&self) -> &[u8; 32] {
        &self.witness
    }

    /// Hash of the confirmed block.
    pub fn block_hash(&self) -> &[u8; 32] {
        &self.block_hash
    }

    /// Whether the signature verifies under the witness key.
    pub fn verifies(&self) -> bool {
        let message = Self::message(&self.witness, &self.block_hash);
        arxia_crypto::verify(&self.witness, &message, &self.signature).is_ok()
    }

    /// Encode for transport: witness key, block hash, signature.
    pub fn to_bytes(&self) -> [u8; CONFIRMATION_LEN] {
        let mut bytes = [0u8; CONFIRMATION_LEN];
        bytes[..32].copy_from_slice(&self.witness);
        bytes[32..64].copy_from_slice(&self.block_hash);
        bytes[64..].copy_from_slice(&self.signature);
        bytes
    }

    /// Decode a confirmation.
    ///
    /// # Errors
    ///
    /// [`WitnessFault::Undecodable`] if the length is not
    /// [`CONFIRMATION_LEN`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ArxiaError> {
        let bytes: &[u8; CONFIRMATION_LEN] = bytes
            .try_into()
            .map_err(|_| fault(WitnessFault::Undecodable))?;
        let mut witness = [0u8; 32];
        let mut block_hash = [0u8; 32];
        let mut signature = [0u8; 64];
        witness.copy_from_slice(&bytes[..32]);
        block_hash.copy_from_slice(&bytes[32..64]);
        signature.copy_from_slice(&bytes[64..]);
        Ok(Self {
            witness,
            block_hash,
            signature,
        })
    }
}

/// How far a block is confirmed under a roster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settlement {
    /// Weight of the roster witnesses that confirmed this block.
    pub confirmed_weight: u64,
    /// Total weight of the roster.
    pub total_weight: u64,
    /// Number of witnesses counted.
    pub witnesses: usize,
}

impl Settlement {
    /// Whether the confirmed weight is more than two thirds of the
    /// roster total.
    pub fn is_final(&self) -> bool {
        u128::from(self.confirmed_weight) * 3 > u128::from(self.total_weight) * 2
    }
}

/// The confirmations of `block` that [`assess`] counts under `roster`:
/// one per roster witness other than the block's own account, each
/// verified. This is the set worth keeping or passing on.
///
/// # Errors
///
/// As [`assess`].
pub fn counted(
    block: &Block,
    confirmations: &[WitnessConfirmation],
    roster: &WitnessRoster,
) -> Result<Vec<WitnessConfirmation>, ArxiaError> {
    verify_block(block)?;
    let block_hash = hash_bytes(block)?;
    let payer = key_bytes(&block.account);
    let mut kept: Vec<WitnessConfirmation> = Vec::new();
    for confirmation in confirmations {
        if confirmation.block_hash != block_hash
            || Some(confirmation.witness) == payer
            || kept.iter().any(|held| held.witness == confirmation.witness)
            || roster.weight_of(&confirmation.witness).is_none()
            || !confirmation.verifies()
        {
            continue;
        }
        kept.push(confirmation.clone());
    }
    Ok(kept)
}

/// Count the confirmations of `block` under `roster`.
///
/// # Errors
///
/// Any error of [`verify_block`] if `block` itself is
/// not authentic. Confirmations never cause an error: the ones that do
/// not count are ignored.
pub fn assess(
    block: &Block,
    confirmations: &[WitnessConfirmation],
    roster: &WitnessRoster,
) -> Result<Settlement, ArxiaError> {
    verify_block(block)?;
    let block_hash = hash_bytes(block)?;
    let payer = key_bytes(&block.account);

    let mut counted: Vec<[u8; 32]> = Vec::new();
    let mut confirmed_weight = 0u64;
    for confirmation in confirmations {
        if confirmation.block_hash != block_hash
            || Some(confirmation.witness) == payer
            || counted.contains(&confirmation.witness)
        {
            continue;
        }
        let Some(weight) = roster.weight_of(&confirmation.witness) else {
            continue;
        };
        if !confirmation.verifies() {
            continue;
        }
        counted.push(confirmation.witness);
        confirmed_weight = confirmed_weight.saturating_add(weight);
    }
    Ok(Settlement {
        confirmed_weight,
        total_weight: roster.total_weight(),
        witnesses: counted.len(),
    })
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

    /// Take in a bundle, as [`DurableWallet::ingest_bundle`]: its
    /// certificates and history under the ledger rules. Returns the
    /// payment and the confirmations it carried, without confirming
    /// anything.
    ///
    /// # Errors
    ///
    /// As [`DurableWallet::ingest_bundle`].
    pub fn ingest_bundle(
        &mut self,
        frames: &[crate::bundle::Frame],
    ) -> Result<(Block, Vec<WitnessConfirmation>), ArxiaError> {
        self.wallet.ingest_bundle(frames)
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
    // Keep the confirmations with the block, so that the payment stays
    // acceptable, and can be shown to be final, if the payer is later
    // found to have signed another block for the same position.
    // Recorded before the block is taken in: a settled block is accepted
    // without the history that precedes it.
    if wallet.wallet().ledger().witness_roster().is_some() {
        wallet.ingest_settlement(send_block, confirmations)?;
    }
    wallet.receive(send_block)
}
