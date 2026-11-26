//! Block Lattice -- the core consensus data structure for Arxia.
//!
//! Each account maintains its own chain of blocks (OPEN, SEND, RECEIVE, REVOKE).
//! Inspired by Nano's block lattice, adapted for offline-first mesh networks.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod block;
pub mod chain;
pub mod ledger;
pub mod serialization;
pub mod validation;
pub mod wallet;

pub use block::{Block, BlockType};
pub use chain::{AccountChain, VectorClock};
pub use ledger::Ledger;
pub use serialization::{from_compact_bytes, to_compact_bytes};
pub use validation::{verify_block, verify_chain_integrity};
pub use wallet::Wallet;
