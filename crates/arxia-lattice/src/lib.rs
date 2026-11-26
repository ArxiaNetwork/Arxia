//! Block Lattice -- the core consensus data structure for Arxia.
//!
//! Each account maintains its own chain of blocks (OPEN, SEND, RECEIVE, REVOKE).
//! Inspired by Nano's block lattice, adapted for offline-first mesh networks.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod block;
pub mod bundle;
pub mod chain;
pub mod durable;
pub mod equivocation;
pub mod issuance;
pub mod ledger;
pub mod reserve;
pub mod serialization;
pub mod validation;
pub mod wallet;
pub mod witness;

pub use block::{Block, BlockType};
pub use chain::{AccountChain, VectorClock};
pub use durable::DurableWallet;
pub use equivocation::EquivocationProof;
pub use issuance::{IssuanceCertificate, IssuancePolicy};
pub use ledger::Ledger;
pub use reserve::ReserveCertificate;
pub use serialization::{from_compact_bytes, to_compact_bytes};
pub use validation::{verify_block, verify_chain_integrity};
pub use wallet::{Wallet, WalletConfig};
