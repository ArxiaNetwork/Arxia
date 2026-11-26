//! Certified reserves: paying where no witness is in reach.
//!
//! A payment is normally settled by witnesses. Two devices with nobody
//! else in radio reach have no witness to ask. A reserve prepares for
//! that case while witnesses are still reachable.
//!
//! # How a reserve is made
//!
//! The holder moves an amount from the main account to a second
//! account it also controls, the reserve account, and has the
//! witnesses confirm the RECEIVE on that account. The three blocks and
//! the confirmations form a [`ReserveCertificate`]:
//!
//! - `funding`: the SEND from the owner's account to the reserve
//!   account;
//! - `opening`: the reserve account's `Open` with a zero balance;
//! - `reserve`: the reserve account's RECEIVE of the funding, at
//!   position 2, confirmed by more than two thirds of the roster
//!   weight.
//!
//! # What a receiver checks, alone
//!
//! A receiver configured with the witness roster verifies the
//! certificate with nothing else: the witnesses already replayed the
//! history behind the funding, and their confirmations stand for it.
//! The receiver then accepts the reserve account's later blocks under
//! the ordinary ledger rules, so what one ledger credits from a
//! reserve never exceeds the certified amount.
//!
//! # What a reserve does not do
//!
//! Without a witness in reach, a receiver cannot know whether the same
//! reserve was also spent towards someone else. A reserve bounds that
//! exposure and attaches a consequence to it:
//!
//! - the amount at stake is the reserve, chosen in advance and shown
//!   to the receiver, not the owner's whole balance;
//! - two spends of one reserve position are an
//!   [`EquivocationProof`](crate::EquivocationProof) as for any
//!   account, and a ledger holding both the proof and the certificate
//!   also freezes the owner's account after the funding block.
//!
//! # Encoding
//!
//! [`ReserveCertificate::to_records`] yields three 193-byte compact
//! blocks followed by one 128-byte record per confirmation; each fits
//! the value limit of the flash backend.

use crate::block::{Block, BlockType};
use crate::serialization::{from_compact_bytes, to_compact_bytes};
use crate::validation::verify_block;
use crate::witness::{assess, WitnessConfirmation, WitnessRoster};
#[allow(unused_imports)]
use alloc::{
    borrow::ToOwned,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use arxia_core::{ArxiaError, ReserveFault, WitnessFault};

fn fault(fault: ReserveFault) -> ArxiaError {
    ArxiaError::Reserve { fault }
}

/// Proof that a reserve account holds an amount confirmed by
/// witnesses. See the [module documentation](self).
#[derive(Debug, Clone)]
pub struct ReserveCertificate {
    funding: Block,
    opening: Block,
    reserve: Block,
    amount: u64,
    confirmations: Vec<WitnessConfirmation>,
}

impl PartialEq for ReserveCertificate {
    fn eq(&self, other: &Self) -> bool {
        self.funding.hash == other.funding.hash
            && self.opening.hash == other.opening.hash
            && self.reserve.hash == other.reserve.hash
            && self.confirmations == other.confirmations
    }
}

impl Eq for ReserveCertificate {}

impl ReserveCertificate {
    /// Assemble a certificate and check its structure. Whether the
    /// confirmations reach finality is checked by
    /// [`ReserveCertificate::verify`], which needs a roster.
    ///
    /// # Errors
    ///
    /// - Any error of [`verify_block`] if a block is not authentic.
    /// - [`ReserveFault::Malformed`] if the three blocks do not have
    ///   the shape described in the [module documentation](self).
    pub fn new(
        funding: Block,
        opening: Block,
        reserve: Block,
        confirmations: Vec<WitnessConfirmation>,
    ) -> Result<Self, ArxiaError> {
        verify_block(&funding)?;
        verify_block(&opening)?;
        verify_block(&reserve)?;
        let malformed = || fault(ReserveFault::Malformed);

        let BlockType::Send {
            destination,
            amount,
        } = &funding.block_type
        else {
            return Err(malformed());
        };
        let amount = *amount;
        let opening_is_empty = matches!(opening.block_type, BlockType::Open { initial_balance: 0 });
        let cites_funding = matches!(
            &reserve.block_type,
            BlockType::Receive { source_hash } if *source_hash == funding.hash
        );
        let well_formed = opening_is_empty
            && cites_funding
            && *destination == reserve.account
            && funding.account != reserve.account
            && opening.account == reserve.account
            && opening.nonce == 1
            && opening.previous.is_empty()
            && opening.balance == 0
            && reserve.nonce == 2
            && reserve.previous == opening.hash
            && reserve.balance == amount;
        if !well_formed {
            return Err(malformed());
        }
        Ok(Self {
            funding,
            opening,
            reserve,
            amount,
            confirmations,
        })
    }

    /// Hex-encoded public key of the reserve account.
    pub fn account(&self) -> &str {
        &self.reserve.account
    }

    /// Hex-encoded public key of the account that funded the reserve.
    pub fn owner(&self) -> &str {
        &self.funding.account
    }

    /// Position of the funding block on the owner's chain.
    pub fn owner_nonce(&self) -> u64 {
        self.funding.nonce
    }

    /// The certified amount in micro-ARX.
    pub fn amount(&self) -> u64 {
        self.amount
    }

    /// The funding, opening and reserve blocks.
    pub fn blocks(&self) -> (&Block, &Block, &Block) {
        (&self.funding, &self.opening, &self.reserve)
    }

    /// The witness confirmations of the reserve block.
    pub fn confirmations(&self) -> &[WitnessConfirmation] {
        &self.confirmations
    }

    /// Check that the reserve block is final under `roster`.
    ///
    /// # Errors
    ///
    /// [`WitnessFault::NotFinal`] if the confirming weight is not more
    /// than two thirds of the roster total.
    pub fn verify(&self, roster: &WitnessRoster) -> Result<(), ArxiaError> {
        let settlement = assess(&self.reserve, &self.confirmations, roster)?;
        if !settlement.is_final() {
            return Err(ArxiaError::Witness {
                fault: WitnessFault::NotFinal {
                    confirmed: settlement.confirmed_weight,
                    total: settlement.total_weight,
                },
            });
        }
        Ok(())
    }

    /// Encode as storage or transport records: the three blocks, then
    /// one record per confirmation.
    ///
    /// # Errors
    ///
    /// Any error of [`to_compact_bytes`].
    pub fn to_records(&self) -> Result<Vec<Vec<u8>>, ArxiaError> {
        let mut records = vec![
            to_compact_bytes(&self.funding)?,
            to_compact_bytes(&self.opening)?,
            to_compact_bytes(&self.reserve)?,
        ];
        records.extend(self.confirmations.iter().map(|c| c.to_bytes().to_vec()));
        Ok(records)
    }

    /// Decode a certificate from the records of
    /// [`ReserveCertificate::to_records`], in the same order.
    ///
    /// # Errors
    ///
    /// [`ReserveFault::Undecodable`] if a record does not decode;
    /// otherwise as [`ReserveCertificate::new`].
    pub fn from_records(records: &[Vec<u8>]) -> Result<Self, ArxiaError> {
        let undecodable = |_| fault(ReserveFault::Undecodable);
        let [funding, opening, reserve, confirmations @ ..] = records else {
            return Err(fault(ReserveFault::Undecodable));
        };
        let confirmations = confirmations
            .iter()
            .map(|record| WitnessConfirmation::from_bytes(record).map_err(undecodable))
            .collect::<Result<Vec<_>, ArxiaError>>()?;
        Self::new(
            from_compact_bytes(funding).map_err(undecodable)?,
            from_compact_bytes(opening).map_err(undecodable)?,
            from_compact_bytes(reserve).map_err(undecodable)?,
            confirmations,
        )
    }
}
