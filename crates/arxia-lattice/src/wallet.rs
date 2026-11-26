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

use alloc::collections::BTreeSet;
#[allow(unused_imports)]
use alloc::{
    borrow::ToOwned,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use crate::block::Block;
use crate::chain::{AccountChain, VectorClock};
use crate::equivocation::EquivocationProof;
use crate::issuance::{IssuanceCertificate, IssuancePolicy};
use crate::ledger::Ledger;
use crate::reserve::ReserveCertificate;
use crate::validation::verify_block;
use crate::witness::{WitnessConfirmation, WitnessRoster};
use arxia_core::ArxiaError;

/// What a wallet's ledger is configured with. Both parts are optional;
/// the default has neither.
#[derive(Debug, Clone, Default)]
pub struct WalletConfig {
    /// Who may bring value into the ledger. See [`crate::issuance`].
    pub issuance: Option<IssuancePolicy>,
    /// The witnesses the ledger recognises. See [`crate::witness`] and
    /// [`crate::reserve`].
    pub witnesses: Option<WitnessRoster>,
}

impl WalletConfig {
    fn ledger(self) -> Ledger {
        let mut ledger = match self.issuance {
            Some(policy) => Ledger::with_issuance(policy),
            None => Ledger::new(),
        };
        if let Some(roster) = self.witnesses {
            ledger.set_witness_roster(roster);
        }
        ledger
    }
}

/// An account together with the ledger that validates it.
pub struct Wallet {
    account: AccountChain,
    ledger: Ledger,
    vclock: VectorClock,
    /// Blocks removed from the ledger when it followed the witnesses
    /// to a settled block, not yet collected by
    /// [`Wallet::take_replaced`].
    replaced: Vec<Block>,
}

/// Account-side state captured before an operation, restored if the
/// ledger refuses the resulting block.
struct Snapshot {
    chain_len: usize,
    balance: u64,
    nonce: u64,
    consumed_sources: BTreeSet<String>,
    vclock: VectorClock,
}

impl Wallet {
    /// Create a wallet for the account of a 32-byte signing seed, with
    /// an empty ledger built from `config`. This is the constructor for
    /// targets without an operating system: the caller obtains the seed
    /// from its own entropy source.
    pub fn from_seed(seed: &[u8; 32], config: WalletConfig) -> Self {
        Self {
            account: AccountChain::from_seed(seed),
            ledger: config.ledger(),
            vclock: VectorClock::new(),
            replaced: Vec::new(),
        }
    }

    /// Install the source of block timestamps. See
    /// [`AccountChain::set_clock`].
    pub fn set_clock(&mut self, clock: fn() -> u64) {
        self.account.set_clock(clock);
    }

    /// Create a wallet with a fresh keypair and an empty ledger.
    #[cfg(feature = "std")]
    pub fn new() -> Self {
        Self {
            account: AccountChain::new(),
            ledger: Ledger::new(),
            vclock: VectorClock::new(),
            replaced: Vec::new(),
        }
    }

    /// Create a wallet with a fresh keypair and an empty ledger under
    /// an issuance policy. See [`crate::issuance`].
    #[cfg(feature = "std")]
    pub fn with_issuance(policy: IssuancePolicy) -> Self {
        Self {
            account: AccountChain::new(),
            ledger: Ledger::with_issuance(policy),
            vclock: VectorClock::new(),
            replaced: Vec::new(),
        }
    }

    /// Create a wallet with a fresh keypair and an empty ledger built
    /// from `config`.
    #[cfg(feature = "std")]
    pub fn with_config(config: WalletConfig) -> Self {
        Self {
            account: AccountChain::new(),
            ledger: config.ledger(),
            vclock: VectorClock::new(),
            replaced: Vec::new(),
        }
    }

    /// As [`Wallet::restore`], under a configuration. Issuance and
    /// reserve certificates are verified and added before the blocks
    /// are replayed.
    ///
    /// # Errors
    ///
    /// Any error of [`Ledger::add_issuance`], [`Ledger::add_reserve`]
    /// or [`Ledger::add_block`].
    pub fn restore_with_config(
        seed: &[u8; 32],
        config: WalletConfig,
        issuance: &[IssuanceCertificate],
        reserves: &[ReserveCertificate],
        blocks: impl IntoIterator<Item = Block>,
    ) -> Result<Self, ArxiaError> {
        let mut ledger = config.ledger();
        for certificate in issuance {
            ledger.add_issuance(certificate)?;
        }
        for certificate in reserves {
            ledger.add_reserve(certificate)?;
        }
        Self::replay(seed, ledger, blocks)
    }

    /// Rebuild a wallet from its signing seed and the blocks it had
    /// accepted, in acceptance order. Every block goes through the
    /// ledger rules again; the account state is then taken from the
    /// ledger's copy of the account's own chain.
    ///
    /// # Errors
    ///
    /// Any error of [`Ledger::add_block`] for a block the ledger
    /// refuses.
    pub fn restore(
        seed: &[u8; 32],
        blocks: impl IntoIterator<Item = Block>,
    ) -> Result<Self, ArxiaError> {
        Self::replay(seed, Ledger::new(), blocks)
    }

    /// As [`Wallet::restore`], under an issuance policy. The
    /// certificates are verified and added before the blocks are
    /// replayed.
    ///
    /// # Errors
    ///
    /// Any error of [`Ledger::add_issuance`] or [`Ledger::add_block`].
    pub fn restore_with_issuance(
        seed: &[u8; 32],
        policy: IssuancePolicy,
        certificates: &[IssuanceCertificate],
        blocks: impl IntoIterator<Item = Block>,
    ) -> Result<Self, ArxiaError> {
        let mut ledger = Ledger::with_issuance(policy);
        for certificate in certificates {
            ledger.add_issuance(certificate)?;
        }
        Self::replay(seed, ledger, blocks)
    }

    fn replay(
        seed: &[u8; 32],
        mut ledger: Ledger,
        blocks: impl IntoIterator<Item = Block>,
    ) -> Result<Self, ArxiaError> {
        for block in blocks {
            ledger.add_block(block)?;
        }
        let account_id = AccountChain::from_validated(seed, &[]).id().to_string();
        let own_blocks = ledger
            .get_chain(&account_id)
            .map_or(&[][..], |chain| chain.as_slice());
        let account = AccountChain::from_validated(seed, own_blocks);
        Ok(Self {
            account,
            ledger,
            vclock: VectorClock::new(),
            replaced: Vec::new(),
        })
    }

    /// The 32-byte signing seed. This is the account's secret: whoever
    /// holds it can sign for the account.
    pub fn seed(&self) -> [u8; 32] {
        self.account.signing_key().to_bytes()
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

    /// Open the account with the balance a certificate states. The
    /// certificate is verified and kept first.
    ///
    /// # Errors
    ///
    /// Any error of [`Ledger::add_issuance`] or [`Wallet::open`].
    pub fn open_certified(
        &mut self,
        certificate: &IssuanceCertificate,
    ) -> Result<Block, ArxiaError> {
        self.ledger.add_issuance(certificate)?;
        self.open(certificate.amount())
    }

    /// Accept an issuance certificate from another device, so that the
    /// account it covers can be replayed. See
    /// [`Ledger::add_issuance`].
    ///
    /// # Errors
    ///
    /// Any error of [`Ledger::add_issuance`].
    pub fn ingest_issuance(&mut self, certificate: &IssuanceCertificate) -> Result<(), ArxiaError> {
        self.ledger.add_issuance(certificate)
    }

    /// The certificate of this wallet's own account, to hand over
    /// together with [`Wallet::chain`].
    pub fn issuance(&self) -> Option<&IssuanceCertificate> {
        self.ledger.issuance_for(self.account.id())
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
    ///   carry the account's signature: the pair is kept as an
    ///   [`EquivocationProof`] and the account is frozen from that
    ///   position (see [`crate::equivocation`]). The exception is an
    ///   incoming block the witnesses settled: the ledger then takes
    ///   it in place of the held one and this returns `Ok`.
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
            let proof = EquivocationProof::new(known.clone(), block.clone())?;
            self.ledger.add_equivocation(&proof)?;
            // If the witnesses settled the incoming block, follow them
            // and let the held one go, where that is safe. A wallet
            // never does this to its own account: it only signs on
            // top of what it signed.
            if block.account != self.account.id()
                && self.ledger.settlement_for(&block.hash).is_some()
            {
                if let Ok(removed) = self.ledger.replace_with_settled(block) {
                    self.replaced.extend(removed);
                    return Ok(());
                }
            }
            return Err(ArxiaError::NonceConflict {
                account: block.account.clone(),
                nonce: block.nonce,
                count: 2,
            });
        }
        self.ledger.add_block(block.clone())
    }

    /// Collect the blocks the ledger removed when it replaced an
    /// unsettled block by the settled one (see
    /// [`Ledger::replace_with_settled`]). A caller that mirrors the
    /// ledger elsewhere removes them there too.
    pub fn take_replaced(&mut self) -> Vec<Block> {
        core::mem::take(&mut self.replaced)
    }

    /// Record that `block` is final under the witness roster. See
    /// [`Ledger::add_settlement`].
    ///
    /// # Errors
    ///
    /// Any error of [`Ledger::add_settlement`].
    pub fn ingest_settlement(
        &mut self,
        block: &Block,
        confirmations: &[WitnessConfirmation],
    ) -> Result<(), ArxiaError> {
        self.ledger.add_settlement(block, confirmations)
    }

    /// Accept an equivocation proof from another device and freeze the
    /// account it names. See [`Ledger::add_equivocation`].
    ///
    /// # Errors
    ///
    /// Any error of [`Ledger::add_equivocation`].
    pub fn ingest_equivocation(&mut self, proof: &EquivocationProof) -> Result<(), ArxiaError> {
        self.ledger.add_equivocation(proof)
    }

    /// Verify and keep a reserve certificate, without its blocks. See
    /// [`Ledger::add_reserve`]. Most callers want
    /// [`Wallet::ingest_reserve`].
    ///
    /// # Errors
    ///
    /// Any error of [`Ledger::add_reserve`].
    pub fn ingest_reserve_certificate(
        &mut self,
        certificate: &ReserveCertificate,
    ) -> Result<(), ArxiaError> {
        self.ledger.add_reserve(certificate)
    }

    /// Accept a reserve: verify the certificate against the witness
    /// roster, then take in the reserve account's opening and reserve
    /// blocks. The funding history is not needed.
    ///
    /// # Errors
    ///
    /// Any error of [`Ledger::add_reserve`] or [`Wallet::ingest`].
    pub fn ingest_reserve(&mut self, certificate: &ReserveCertificate) -> Result<(), ArxiaError> {
        self.ledger.add_reserve(certificate)?;
        let (_funding, opening, reserve) = certificate.blocks();
        self.ingest(opening)?;
        self.ingest(reserve)
    }

    /// Credit a payment made from a reserve. `spends` are the reserve
    /// account's blocks after the certified one, in order; the last
    /// one is the payment to this wallet.
    ///
    /// # Errors
    ///
    /// Any error of [`Wallet::ingest_reserve`], [`Wallet::ingest_all`]
    /// or [`Wallet::receive`]. [`ArxiaError::NotSendBlock`] if `spends`
    /// is empty.
    pub fn receive_from_reserve(
        &mut self,
        certificate: &ReserveCertificate,
        spends: &[Block],
    ) -> Result<Block, ArxiaError> {
        let payment = spends.last().ok_or(ArxiaError::NotSendBlock)?;
        self.ingest_reserve(certificate)?;
        self.ingest_all(spends)?;
        self.receive(payment)
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

#[cfg(feature = "std")]
impl Default for Wallet {
    fn default() -> Self {
        Self::new()
    }
}
