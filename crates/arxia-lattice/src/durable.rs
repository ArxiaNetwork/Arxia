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
//!
//! Both fit the limits of the flash backend.
//!
//! # Scope
//!
//! The signing seed is stored as is; encryption at rest belongs to the
//! storage layer or the hardware. A holder who restores an older copy
//! of the storage medium gets an older wallet: that case is covered by
//! confirmations from other nodes, not by local persistence.

use crate::block::Block;
use crate::serialization::{from_compact_bytes, to_compact_bytes};
use crate::wallet::Wallet;
use arxia_core::{ArxiaError, StorageFault};
use arxia_storage::StorageBackend;

const SEED_KEY: &[u8] = b"w/k";
const BLOCK_PREFIX: &[u8] = b"w/b/";

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
    pub fn open(mut storage: S) -> Result<Self, ArxiaError> {
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
        let wallet = Wallet::restore(&seed, blocks)?;

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
        self.wallet.ingest(block)?;
        if !already_held {
            self.persist(block)?;
        }
        Ok(())
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
