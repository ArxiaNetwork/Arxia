//! Equivocation: two signed blocks for one account position.
//!
//! An account chain is a single line: each position holds one block.
//! Two different blocks at the same position, both carrying the
//! account's signature, can only come from the holder of the account
//! key. Together they are an [`EquivocationProof`]: anyone can verify
//! it with nothing but the two blocks, so it can be passed from node
//! to node like any other block.
//!
//! # Effect on a ledger
//!
//! [`Ledger::add_equivocation`](crate::Ledger::add_equivocation)
//! freezes the account from the conflicting position onward:
//!
//! - no block at that position or after it is accepted any more,
//!   unless the ledger already holds it;
//! - a SEND the ledger holds at that position or after it can no
//!   longer be received.
//!
//! Blocks before the conflicting position are untouched and stay
//! acceptable, so funds the account paid out earlier can still be
//! traced by a third party.
//!
//! The freeze stops what was not yet settled. A payment that was
//! already received keeps its RECEIVE.
//!
//! # Encoding
//!
//! Two blocks in the 193-byte compact form, lower hash first: 386
//! bytes.

use crate::block::Block;
use crate::serialization::{from_compact_bytes, to_compact_bytes};
use crate::validation::verify_block;
#[allow(unused_imports)]
use alloc::{
    borrow::ToOwned,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use arxia_core::constants::COMPACT_BLOCK_SIZE;
use arxia_core::{ArxiaError, EquivocationFault};

fn fault(fault: EquivocationFault) -> ArxiaError {
    ArxiaError::Equivocation { fault }
}

/// Two authentic blocks for the same account position.
#[derive(Debug, Clone)]
pub struct EquivocationProof {
    first: Block,
    second: Block,
}

impl PartialEq for EquivocationProof {
    fn eq(&self, other: &Self) -> bool {
        self.first.hash == other.first.hash && self.second.hash == other.second.hash
    }
}

impl Eq for EquivocationProof {}

impl EquivocationProof {
    /// Build a proof from two blocks. The order of the arguments does
    /// not matter.
    ///
    /// # Errors
    ///
    /// - Any error of [`verify_block`] if a block is not authentic.
    /// - [`EquivocationFault::NotAConflict`] if the blocks are not for
    ///   the same account and position, or are the same block.
    pub fn new(a: Block, b: Block) -> Result<Self, ArxiaError> {
        verify_block(&a)?;
        verify_block(&b)?;
        if a.account != b.account || a.nonce != b.nonce || a.hash == b.hash {
            return Err(fault(EquivocationFault::NotAConflict));
        }
        let (first, second) = if a.hash < b.hash { (a, b) } else { (b, a) };
        Ok(Self { first, second })
    }

    /// Hex-encoded public key of the account that signed both blocks.
    pub fn account(&self) -> &str {
        &self.first.account
    }

    /// The account position both blocks claim.
    pub fn nonce(&self) -> u64 {
        self.first.nonce
    }

    /// The two blocks, lower hash first.
    pub fn blocks(&self) -> (&Block, &Block) {
        (&self.first, &self.second)
    }

    /// Encode for storage or transport.
    ///
    /// # Errors
    ///
    /// Any error of [`to_compact_bytes`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, ArxiaError> {
        let mut bytes = to_compact_bytes(&self.first)?;
        bytes.extend_from_slice(&to_compact_bytes(&self.second)?);
        Ok(bytes)
    }

    /// Decode and verify a proof.
    ///
    /// # Errors
    ///
    /// [`EquivocationFault::Undecodable`] if the bytes are not two
    /// compact blocks; otherwise as [`EquivocationProof::new`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ArxiaError> {
        let undecodable = |_| fault(EquivocationFault::Undecodable);
        if bytes.len() != 2 * COMPACT_BLOCK_SIZE {
            return Err(fault(EquivocationFault::Undecodable));
        }
        let (first, second) = bytes.split_at(COMPACT_BLOCK_SIZE);
        Self::new(
            from_compact_bytes(first).map_err(undecodable)?,
            from_compact_bytes(second).map_err(undecodable)?,
        )
    }
}
