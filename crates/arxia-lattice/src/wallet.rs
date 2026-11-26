//! A ledger-backed account: one entry point for everything a device
//! accepts.
//!
//! [`AccountChain`] signs blocks for one account. [`Ledger`] decides
//! whether a block is acceptable given everything known so far:
//! authentic, in sequence, funded, received once. A [`Wallet`] owns
//! both and keeps them in step, so that a device cannot hold a balance
//! its own ledger would refuse.
//!
//! # What a receiver checks
//!
//! Blocks handed over by another device enter through
//! [`Wallet::ingest`], which applies the full ledger rules. A payment
//! is credited by [`Wallet::receive`] only when the SEND is accepted
//! by the ledger, which requires the sender's chain up to that SEND:
//! the payer hands over the blocks that fund the payment, and the
//! receiver replays them. A SEND whose funding the receiver cannot
//! replay is not credited.
//!
//! # Atomicity
//!
//! Every operation either updates the account and the ledger together
//! or leaves both untouched.
//!
//! # Scope
//!
//! The wallet enforces everything that can be decided from the blocks
//! a device holds. Two spends signed for the same account position are
//! detected as soon as both reach the same ledger
//! ([`ArxiaError::NonceConflict`]); a device that has seen only one of
//! them cannot know about the other. That case is covered by
//! confirmations from other nodes, outside this module.

use std::collections::HashSet;

use crate::block::Block;
use crate::chain::{AccountChain, VectorClock};
use crate::ledger::Ledger;
use crate::validation::verify_block;
use arxia_core::ArxiaError;

/// An account together with the ledger that validates it.
pub struct Wallet {
    account: AccountChain,
    ledger: Ledger,
    vclock: VectorClock,
}

/// Account-side state captured before an operation, restored if the
/// ledger refuses the resulting block.
struct Snapshot {
    chain_len: usize,
    balance: u64,
    nonce: u64,
    consumed_sources: HashSet<String>,
    vclock: VectorClock,
}

impl Wallet {
    /// Create a wallet with a fresh keypair and an empty ledger.
    pub fn new() -> Self {
        Self {
            account: AccountChain::new(),
            ledger: Ledger::new(),
            vclock: VectorClock::new(),
        }
    }

    /// Hex-encoded public key of the account.
    pub fn id(&self) -> &str {
        self.account.id()
    }

    /// Current balance in micro-ARX.
    pub fn balance(&self) -> u64 {
        self.account.balance
    }

    /// The account's own blocks, in order. This is what the holder
    /// hands to a receiver so the receiver can replay the funding of a
    /// payment.
    pub fn chain(&self) -> &[Block] {
        &self.account.chain
    }

    /// The ledger this wallet validates against.
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// Open the account.
    ///
    /// # Errors
    ///
    /// Any error of [`AccountChain::open`] or [`Ledger::add_block`].
    pub fn open(&mut self, initial_balance: u64) -> Result<Block, ArxiaError> {
        self.apply_own(|account, vclock| account.open(initial_balance, vclock))
    }

    /// Sign a SEND of `amount` to `destination`.
    ///
    /// # Errors
    ///
    /// Any error of [`AccountChain::send`] or [`Ledger::add_block`].
    pub fn send(&mut self, destination: &str, amount: u64) -> Result<Block, ArxiaError> {
        self.apply_own(|account, vclock| account.send(destination, amount, vclock))
    }

    /// Accept a block from another device under the full ledger rules.
    ///
    /// A block this ledger already holds is accepted again without
    /// effect, so overlapping hand-overs are harmless.
    ///
    /// # Errors
    ///
    /// - [`ArxiaError::NonceConflict`] if the ledger holds a different
    ///   authentic block at the same account position. Both blocks
    ///   carry the account's signature.
    /// - Any error of [`Ledger::add_block`] otherwise.
    pub fn ingest(&mut self, block: &Block) -> Result<(), ArxiaError> {
        let known = usize::try_from(block.nonce)
            .ok()
            .and_then(|nonce| nonce.checked_sub(1))
            .and_then(|index| self.ledger.get_chain(&block.account)?.get(index));
        if let Some(known) = known {
            verify_block(block)?;
            if known.hash == block.hash {
                return Ok(());
            }
            return Err(ArxiaError::NonceConflict {
                account: block.account.clone(),
                nonce: block.nonce,
                count: 2,
            });
        }
        self.ledger.add_block(block.clone())
    }

    /// Accept a sequence of blocks in order, stopping at the first one
    /// the ledger refuses. Blocks accepted before the refusal stay
    /// accepted: each was valid on its own.
    ///
    /// # Errors
    ///
    /// The error of the first refused block, as in [`Wallet::ingest`].
    pub fn ingest_all(&mut self, blocks: &[Block]) -> Result<(), ArxiaError> {
        blocks.iter().try_for_each(|block| self.ingest(block))
    }

    /// Credit a payment.
    ///
    /// `send_block` is ingested first, so it must extend a sender chain
    /// this ledger already holds: hand the sender's earlier blocks to
    /// [`Wallet::ingest_all`] beforehand.
    ///
    /// # Errors
    ///
    /// - Any error of [`Wallet::ingest`] for `send_block`, including
    ///   [`ArxiaError::InsufficientBalance`] when the sender did not
    ///   hold the amount.
    /// - Any error of [`AccountChain::receive`] or
    ///   [`Ledger::add_block`] for the resulting RECEIVE.
    pub fn receive(&mut self, send_block: &Block) -> Result<Block, ArxiaError> {
        self.ingest(send_block)?;
        self.apply_own(|account, vclock| account.receive(send_block, vclock))
    }

    /// Run an account operation and submit its block to the ledger.
    /// If either step fails, the account is put back as it was.
    fn apply_own<F>(&mut self, operation: F) -> Result<Block, ArxiaError>
    where
        F: FnOnce(&mut AccountChain, &mut VectorClock) -> Result<Block, ArxiaError>,
    {
        let snapshot = Snapshot {
            chain_len: self.account.chain.len(),
            balance: self.account.balance,
            nonce: self.account.nonce,
            consumed_sources: self.account.consumed_sources.clone(),
            vclock: self.vclock.clone(),
        };
        let outcome = operation(&mut self.account, &mut self.vclock)
            .and_then(|block| self.ledger.add_block(block.clone()).map(|()| block));
        if outcome.is_err() {
            self.account.chain.truncate(snapshot.chain_len);
            self.account.balance = snapshot.balance;
            self.account.nonce = snapshot.nonce;
            self.account.consumed_sources = snapshot.consumed_sources;
            self.vclock = snapshot.vclock;
        }
        outcome
    }
}

impl Default for Wallet {
    fn default() -> Self {
        Self::new()
    }
}
