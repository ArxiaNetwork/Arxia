//! A wallet whose state survives power loss.
//!
//! [`DurableWallet`] wraps a [`Wallet`] and a
//! [`StorageBackend`]. Every block the
//! wallet accepts or signs is written to storage, and the wallet is
//! rebuilt from storage alone when the device starts.
//!
//! # Durable before released
//!
//! A signed block is returned to the caller only after the storage
//! backend has accepted it. A device that loses power therefore comes
//! back in one of two states: the block was never returned and the
//! account position is still free, or the block is on storage and the
//! position is taken. It cannot come back having handed out a
//! signature it no longer remembers, which is what would let the same
//! position be signed twice.
//!
//! # Failed writes
//!
//! If the backend refuses a write, the operation returns the error,
//! the block is not released, and the wallet refuses further work with
//! [`StorageFault::ReopenRequired`]. Reopening from storage restores
//! the last durable state.
//!
//! # Opening
//!
//! [`DurableWallet::open`] replays every stored block through the
//! ledger rules, in the order the blocks were accepted. A record that
//! does not decode, or a block the ledger refuses, fails the open:
//! storage is checked, not trusted.
//!
//! # Layout
//!
//! - `w/k`: the 32-byte signing seed.
//! - `w/b/<sequence, 8 bytes big-endian>`: one block in the 193-byte
//!   compact form, in acceptance order.
//! - `w/i/<account, 32 bytes>`: the issuance certificate held for an
//!   account, when the wallet runs under an issuance policy.
//!
//! - `w/e/<account, 32 bytes><0 or 1>`: the two blocks of an
//!   equivocation proof, one record each.
//! - `w/r/<reserve account, 32 bytes><index>`: the records of a
//!   reserve certificate, when the wallet has a witness roster.
//!
//! All of them fit the limits of the flash backend.
//!
//! # Scope
//!
//! The signing seed is stored as is; encryption at rest belongs to the
//! storage layer or the hardware. A holder who restores an older copy
//! of the storage medium gets an older wallet: that case is covered by
//! confirmations from other nodes, not by local persistence.

use crate::block::Block;
use crate::equivocation::EquivocationProof;
use crate::issuance::{IssuanceCertificate, IssuancePolicy};
use crate::reserve::ReserveCertificate;
use crate::serialization::{from_compact_bytes, to_compact_bytes};
use crate::wallet::{Wallet, WalletConfig};
use arxia_core::{ArxiaError, StorageFault};
use arxia_storage::{BatchOp, StorageBackend};

const SEED_KEY: &[u8] = b"w/k";
const BLOCK_PREFIX: &[u8] = b"w/b/";
const ISSUANCE_PREFIX: &[u8] = b"w/i/";
const EQUIVOCATION_PREFIX: &[u8] = b"w/e/";
const RESERVE_PREFIX: &[u8] = b"w/r/";

/// A [`Wallet`] persisted through a storage backend.
pub struct DurableWallet<S: StorageBackend> {
    wallet: Wallet,
    storage: S,
    /// Number of blocks on storage; also the next sequence number.
    stored_blocks: u64,
    /// Set when a write failed after the in-memory state advanced.
    reopen_required: bool,
}

fn block_key(sequence: u64) -> Vec<u8> {
    let mut key = BLOCK_PREFIX.to_vec();
    key.extend_from_slice(&sequence.to_be_bytes());
    key
}

fn undecodable() -> ArxiaError {
    ArxiaError::Storage {
        fault: StorageFault::RecordUndecodable,
    }
}

impl<S: StorageBackend> DurableWallet<S> {
    /// Open the wallet held in `storage`, creating a new one if the
    /// storage holds none.
    ///
    /// # Errors
    ///
    /// - [`StorageFault::RecordUndecodable`] if the seed or a block
    ///   record does not decode.
    /// - Any ledger error if a stored block is refused on replay.
    /// - Any backend error.
    pub fn open(storage: S) -> Result<Self, ArxiaError> {
        Self::open_with_config(storage, WalletConfig::default())
    }

    /// As [`DurableWallet::open`], under an issuance policy. Stored
    /// certificates are verified against `policy` before the blocks
    /// are replayed. The policy is configuration: it is supplied on
    /// every open and is not read from storage.
    ///
    /// # Errors
    ///
    /// As [`DurableWallet::open`], plus any issuance error for a
    /// stored certificate the policy refuses.
    pub fn open_with_issuance(storage: S, policy: IssuancePolicy) -> Result<Self, ArxiaError> {
        Self::open_with_config(
            storage,
            WalletConfig {
                issuance: Some(policy),
                witnesses: None,
            },
        )
    }

    /// As [`DurableWallet::open`], under a configuration. Stored
    /// issuance and reserve certificates are verified against it
    /// before the blocks are replayed. The configuration is supplied
    /// on every open and is not read from storage.
    ///
    /// # Errors
    ///
    /// As [`DurableWallet::open`], plus any error for a stored
    /// certificate the configuration refuses.
    pub fn open_with_config(mut storage: S, config: WalletConfig) -> Result<Self, ArxiaError> {
        let seed = match storage.get(SEED_KEY)? {
            Some(bytes) => <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| undecodable())?,
            None => {
                let seed = Wallet::new().seed();
                storage.put(SEED_KEY, &seed)?;
                seed
            }
        };

        let mut records: Vec<Vec<u8>> = Vec::new();
        storage.scan_prefix(BLOCK_PREFIX, &mut |_key, value| {
            records.push(value.to_vec());
            true
        })?;
        let blocks = records
            .iter()
            .map(|record| from_compact_bytes(record).map_err(|_| undecodable()))
            .collect::<Result<Vec<Block>, ArxiaError>>()?;
        let stored_blocks = blocks.len() as u64;
        let issuance = if config.issuance.is_some() {
            let mut records: Vec<Vec<u8>> = Vec::new();
            storage.scan_prefix(ISSUANCE_PREFIX, &mut |_key, value| {
                records.push(value.to_vec());
                true
            })?;
            records
                .iter()
                .map(|record| IssuanceCertificate::from_bytes(record).map_err(|_| undecodable()))
                .collect::<Result<Vec<_>, ArxiaError>>()?
        } else {
            Vec::new()
        };
        let reserves = if config.witnesses.is_some() {
            // One certificate per reserve account: its records share
            // the account part of the key and come back in order.
            let mut grouped: Vec<(Vec<u8>, Vec<Vec<u8>>)> = Vec::new();
            storage.scan_prefix(RESERVE_PREFIX, &mut |key, value| {
                let account = key[..key.len().saturating_sub(1)].to_vec();
                match grouped.last_mut() {
                    Some((held, records)) if *held == account => records.push(value.to_vec()),
                    _ => grouped.push((account, vec![value.to_vec()])),
                }
                true
            })?;
            grouped
                .iter()
                .map(|(_account, records)| {
                    ReserveCertificate::from_records(records).map_err(|_| undecodable())
                })
                .collect::<Result<Vec<_>, ArxiaError>>()?
        } else {
            Vec::new()
        };
        let mut wallet = Wallet::restore_with_config(&seed, config, &issuance, &reserves, blocks)?;

        // Proofs are applied after the replay: the blocks an account
        // signed before it was frozen were accepted at the time and
        // must replay.
        let mut records: Vec<Vec<u8>> = Vec::new();
        storage.scan_prefix(EQUIVOCATION_PREFIX, &mut |_key, value| {
            records.push(value.to_vec());
            true
        })?;
        if !records.len().is_multiple_of(2) {
            return Err(undecodable());
        }
        for pair in records.chunks_exact(2) {
            let first = from_compact_bytes(&pair[0]).map_err(|_| undecodable())?;
            let second = from_compact_bytes(&pair[1]).map_err(|_| undecodable())?;
            wallet.ingest_equivocation(&EquivocationProof::new(first, second)?)?;
        }

        Ok(Self {
            wallet,
            storage,
            stored_blocks,
            reopen_required: false,
        })
    }

    /// The wallet as currently held in memory.
    pub fn wallet(&self) -> &Wallet {
        &self.wallet
    }

    /// Hex-encoded public key of the account.
    pub fn id(&self) -> &str {
        self.wallet.id()
    }

    /// Current balance in micro-ARX.
    pub fn balance(&self) -> u64 {
        self.wallet.balance()
    }

    /// The account's own blocks, in order.
    pub fn chain(&self) -> &[Block] {
        self.wallet.chain()
    }

    /// Every block on storage, in the order the blocks were accepted.
    /// Replaying them in this order satisfies the ledger rules.
    ///
    /// # Errors
    ///
    /// [`StorageFault::RecordUndecodable`] for a record that does not
    /// decode, or any backend error.
    pub fn history(&self) -> Result<Vec<Block>, ArxiaError> {
        let mut records: Vec<Vec<u8>> = Vec::new();
        self.storage.scan_prefix(BLOCK_PREFIX, &mut |_key, value| {
            records.push(value.to_vec());
            true
        })?;
        records
            .iter()
            .map(|record| from_compact_bytes(record).map_err(|_| undecodable()))
            .collect()
    }

    /// Give the storage backend back, for example to reopen it.
    pub fn into_storage(self) -> S {
        self.storage
    }

    /// Open the account. The block is durable before it is returned.
    ///
    /// # Errors
    ///
    /// As [`Wallet::open`], plus any backend error.
    pub fn open_account(&mut self, initial_balance: u64) -> Result<Block, ArxiaError> {
        self.ready()?;
        let block = self.wallet.open(initial_balance)?;
        self.persist(&block)?;
        Ok(block)
    }

    /// Open the account with the balance a certificate states. The
    /// certificate and the block are durable before the block is
    /// returned.
    ///
    /// # Errors
    ///
    /// As [`Wallet::open_certified`], plus any backend error.
    pub fn open_certified(
        &mut self,
        certificate: &IssuanceCertificate,
    ) -> Result<Block, ArxiaError> {
        self.ingest_issuance(certificate)?;
        self.open_account(certificate.amount())
    }

    /// Accept an issuance certificate from another device and make it
    /// durable.
    ///
    /// # Errors
    ///
    /// As [`Wallet::ingest_issuance`], plus any backend error.
    pub fn ingest_issuance(&mut self, certificate: &IssuanceCertificate) -> Result<(), ArxiaError> {
        self.ready()?;
        self.wallet.ingest_issuance(certificate)?;
        if self.wallet.ledger().issuance_policy().is_none() {
            return Ok(());
        }
        let record = certificate.to_bytes();
        let mut key = ISSUANCE_PREFIX.to_vec();
        key.extend_from_slice(&record[..32]);
        if let Err(error) = self.storage.put(&key, &record) {
            self.reopen_required = true;
            return Err(error);
        }
        Ok(())
    }

    /// Sign a SEND. The block is durable before it is returned.
    ///
    /// # Errors
    ///
    /// As [`Wallet::send`], plus any backend error.
    pub fn send(&mut self, destination: &str, amount: u64) -> Result<Block, ArxiaError> {
        self.ready()?;
        let block = self.wallet.send(destination, amount)?;
        self.persist(&block)?;
        Ok(block)
    }

    /// Accept a block from another device and make it durable.
    ///
    /// # Errors
    ///
    /// As [`Wallet::ingest`], plus any backend error.
    pub fn ingest(&mut self, block: &Block) -> Result<(), ArxiaError> {
        self.ready()?;
        let already_held = self.holds(block);
        match self.wallet.ingest(block) {
            Ok(()) => {}
            Err(conflict @ ArxiaError::NonceConflict { .. }) => {
                // The wallet kept the two blocks as a proof; make the
                // proof durable before reporting the conflict.
                self.persist_equivocation(&block.account)?;
                return Err(conflict);
            }
            Err(error) => return Err(error),
        }
        if !already_held {
            self.persist(block)?;
        }
        Ok(())
    }

    /// Accept a reserve and make it durable: the certificate first,
    /// then the reserve account's opening and reserve blocks.
    ///
    /// # Errors
    ///
    /// As [`Wallet::ingest_reserve`], plus any backend error.
    pub fn ingest_reserve(&mut self, certificate: &ReserveCertificate) -> Result<(), ArxiaError> {
        self.ready()?;
        self.wallet.ingest_reserve_certificate(certificate)?;
        let outcome = (|| {
            let account = hex::decode(certificate.account()).map_err(ArxiaError::HexDecode)?;
            let records = certificate.to_records()?;
            let keys: Vec<Vec<u8>> = (0..records.len())
                .map(|index| {
                    let mut key = RESERVE_PREFIX.to_vec();
                    key.extend_from_slice(&account);
                    // A certificate holds three blocks and at most one
                    // confirmation per roster witness.
                    key.push(index as u8);
                    key
                })
                .collect();
            let batch: Vec<BatchOp<'_>> = keys
                .iter()
                .zip(&records)
                .map(|(key, value)| BatchOp::Put { key, value })
                .collect();
            self.storage.apply_batch(&batch)
        })();
        if outcome.is_err() {
            self.reopen_required = true;
            return outcome;
        }
        let (_funding, opening, reserve) = certificate.blocks();
        self.ingest(opening)?;
        self.ingest(reserve)
    }

    /// Credit a payment made from a reserve, as
    /// [`Wallet::receive_from_reserve`]. Everything accepted is
    /// durable before the RECEIVE is returned.
    ///
    /// # Errors
    ///
    /// As [`Wallet::receive_from_reserve`], plus any backend error.
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

    /// Accept an equivocation proof from another device and make it
    /// durable.
    ///
    /// # Errors
    ///
    /// As [`Wallet::ingest_equivocation`], plus any backend error.
    pub fn ingest_equivocation(&mut self, proof: &EquivocationProof) -> Result<(), ArxiaError> {
        self.ready()?;
        self.wallet.ingest_equivocation(proof)?;
        self.persist_equivocation(proof.account())
    }

    /// Accept a sequence of blocks in order, as [`Wallet::ingest_all`].
    ///
    /// # Errors
    ///
    /// The error of the first refused block or failed write.
    pub fn ingest_all(&mut self, blocks: &[Block]) -> Result<(), ArxiaError> {
        blocks.iter().try_for_each(|block| self.ingest(block))
    }

    /// Credit a payment. Both the SEND and the resulting RECEIVE are
    /// durable before the RECEIVE is returned.
    ///
    /// # Errors
    ///
    /// As [`Wallet::receive`], plus any backend error.
    pub fn receive(&mut self, send_block: &Block) -> Result<Block, ArxiaError> {
        self.ingest(send_block)?;
        let block = self.wallet.receive(send_block)?;
        self.persist(&block)?;
        Ok(block)
    }

    fn ready(&self) -> Result<(), ArxiaError> {
        if self.reopen_required {
            return Err(ArxiaError::Storage {
                fault: StorageFault::ReopenRequired,
            });
        }
        Ok(())
    }

    /// Whether the ledger already holds exactly this block.
    fn holds(&self, block: &Block) -> bool {
        usize::try_from(block.nonce)
            .ok()
            .and_then(|nonce| nonce.checked_sub(1))
            .and_then(|index| self.wallet.ledger().get_chain(&block.account)?.get(index))
            .is_some_and(|known| known.hash == block.hash)
    }

    /// Write the proof the ledger holds for `account`, both blocks in
    /// one batch.
    fn persist_equivocation(&mut self, account: &str) -> Result<(), ArxiaError> {
        let Some(proof) = self.wallet.ledger().equivocation_for(account) else {
            return Ok(());
        };
        let (first, second) = proof.blocks();
        let outcome = (|| {
            let account_bytes = hex::decode(account).map_err(ArxiaError::HexDecode)?;
            let mut first_key = EQUIVOCATION_PREFIX.to_vec();
            first_key.extend_from_slice(&account_bytes);
            let mut second_key = first_key.clone();
            first_key.push(0);
            second_key.push(1);
            let first_record = to_compact_bytes(first)?;
            let second_record = to_compact_bytes(second)?;
            self.storage.apply_batch(&[
                BatchOp::Put {
                    key: &first_key,
                    value: &first_record,
                },
                BatchOp::Put {
                    key: &second_key,
                    value: &second_record,
                },
            ])
        })();
        if outcome.is_err() {
            self.reopen_required = true;
        }
        outcome
    }

    /// Write one accepted block. On failure the wallet stops accepting
    /// work: memory is ahead of storage until the wallet is reopened.
    fn persist(&mut self, block: &Block) -> Result<(), ArxiaError> {
        let outcome = to_compact_bytes(block)
            .and_then(|record| self.storage.put(&block_key(self.stored_blocks), &record));
        match outcome {
            Ok(()) => {
                self.stored_blocks += 1;
                Ok(())
            }
            Err(error) => {
                self.reopen_required = true;
                Err(error)
            }
        }
    }
}
