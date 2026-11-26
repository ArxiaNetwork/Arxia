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
//! [`arxia_core::ArxiaError::NonceConflict`], and it stays refused after a
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

pub use arxia_lattice::witness::{
    assess, receive_final, Settlement, Witness, WitnessConfirmation, WitnessRoster,
    CONFIRMATION_LEN, WITNESS_CONFIRMATION_DOMAIN,
};
