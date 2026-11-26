//! Fragmentation / reassembly with signed per-fragment headers.
//!
//! # HIGH-013: reassembly contract
//!
//! Real transports (LoRa, BLE) fragment payloads larger than the
//! link MTU. A receiver that does not reassemble cannot
//! distinguish:
//!
//! - legitimate two-half traffic (fragment 1 + fragment 2 from
//!   the same peer for the same message),
//! - spoofed mix (fragment 1 from peer A + fragment 2 from peer
//!   B, or fragment 1 from peer A repeated as fragment 2 by
//!   peer B).
//!
//! The audit (HIGH-013):
//!
//! > attacker injects spoofed second-half fragments. On the real
//! > transport (not the simulator), either legitimate traffic
//! > fails (hangs) or spoofed fragments mix into legitimate
//! > blocks.
//!
//! ## Wire-level contract
//!
//! Every [`Fragment`] carries a [`FragmentHeader`] with:
//!
//! - `peer_pubkey: [u8; 32]` — the sender's Ed25519 pubkey. The
//!   reassembler buckets fragments per `peer_pubkey` ; fragments
//!   from a different pubkey for the same `message_id` are
//!   silently ignored (cannot mix).
//! - `message_id: [u8; 16]` — opaque caller-supplied identifier
//!   for one logical message. Distinct messages from the same
//!   peer use different `message_id` values.
//! - `seq: u16` — fragment sequence (0-indexed) within the
//!   message.
//! - `total: u16` — total fragment count for the message
//!   (`seq < total`). All fragments of a message MUST carry the
//!   same `total` ; mismatch is rejected.
//! - `signature: [u8; 64]` — Ed25519 signature over canonical
//!   bytes (domain || peer_pubkey || message_id || seq || total
//!   || payload). A spoofed fragment with the right
//!   peer_pubkey but no matching key fails the signature check.
//!
//! ## Reassembly state machine
//!
//! [`Reassembler::feed`] is the single entry point:
//!
//! 1. Verify the per-fragment signature.
//! 2. Look up (or create) the per-(peer_pubkey, message_id)
//!    buffer.
//! 3. Reject the fragment if it disagrees with prior fragments'
//!    `total` (mismatched-total spoof).
//! 4. Reject if `seq >= total` (out-of-range spoof).
//! 5. If `seq` is already filled with a different payload,
//!    reject (replay-with-mutation spoof). If filled with the
//!    same payload, accept idempotently (network duplicate).
//! 6. Insert the fragment payload at index `seq`.
//! 7. If all `total` slots are filled, return
//!    `Ok(Some(reassembled_payload))` and drop the buffer.
//!    Otherwise return `Ok(None)`.
//!
//! Per-peer buffer count is bounded by
//! [`MAX_INFLIGHT_MESSAGES_PER_PEER`] ; over the cap a new
//! `message_id` evicts the oldest pending message
//! (drop-oldest), with the eviction count observable via
//! [`Reassembler::evicted_count`].

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec;
use alloc::vec::Vec;

/// Maximum number of concurrent in-flight messages per peer
/// before the reassembler starts evicting the oldest.
///
/// HIGH-013: defends against a peer that opens
/// thousands of distinct `message_id` values without ever
/// completing any of them (memory amplification). Realistic
/// LoRa link rates rarely exceed 4 in-flight messages per peer
/// at MTU 256 ; 16 leaves headroom.
pub const MAX_INFLIGHT_MESSAGES_PER_PEER: usize = 16;

/// Domain-separation prefix for the Ed25519 signature on a
/// [`Fragment`]. Distinct from
/// [`crate::traits::TRANSPORT_MESSAGE_DOMAIN`] so a fragment
/// signature cannot be replayed as a top-level transport
/// message signature, and vice-versa.
pub const FRAGMENT_DOMAIN: &[u8] = b"arxia-transport-fragment-v1";

/// Errors returned by [`Reassembler::feed`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReassemblyError {
    /// The Ed25519 signature in [`Fragment::header`] does not
    /// verify under the carried `peer_pubkey`.
    InvalidSignature,
    /// Fragment claims a `total` that disagrees with prior
    /// fragments of the same (peer_pubkey, message_id).
    TotalMismatch {
        /// Total carried by this fragment.
        got: u16,
        /// Total recorded by the first-seen fragment.
        expected: u16,
    },
    /// Fragment's `seq >= total`.
    SeqOutOfRange {
        /// The offending sequence number.
        seq: u16,
        /// The total announced by the message.
        total: u16,
    },
    /// Fragment's `total` is zero (a logically impossible
    /// message — there's nothing to reassemble).
    EmptyMessage,
    /// The bytes are too short to hold a fragment header.
    Undecodable,
    /// The link MTU leaves no room for a payload after the fragment
    /// header.
    MtuTooSmall {
        /// The MTU that was given.
        mtu: usize,
    },
    /// The message needs more fragments than a 16-bit count can
    /// express at this MTU.
    TooManyFragments,
    /// A fragment with the same (peer_pubkey, message_id, seq)
    /// was already received and its payload differs. This is
    /// the replay-with-mutation spoof from the audit.
    PayloadMismatch {
        /// Sequence number where the mismatch was detected.
        seq: u16,
    },
}

impl core::fmt::Display for ReassemblyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidSignature => f.write_str("fragment signature does not verify"),
            Self::TotalMismatch { got, expected } => write!(
                f,
                "fragment total {got} disagrees with prior total {expected}"
            ),
            Self::SeqOutOfRange { seq, total } => {
                write!(f, "fragment seq {seq} out of range (total {total})")
            }
            Self::EmptyMessage => f.write_str("fragment claims total=0 (no message to reassemble)"),
            Self::Undecodable => f.write_str("bytes too short for a fragment header"),
            Self::MtuTooSmall { mtu } => {
                write!(f, "MTU {mtu} leaves no room for a fragment payload")
            }
            Self::TooManyFragments => f.write_str("message needs more than 65535 fragments"),
            Self::PayloadMismatch { seq } => {
                write!(
                    f,
                    "fragment seq {seq} payload mismatch (replay-with-mutation)"
                )
            }
        }
    }
}

impl core::error::Error for ReassemblyError {}

/// Per-fragment header. Bound to the payload via the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentHeader {
    /// 32-byte Ed25519 public key of the fragment's sender.
    pub peer_pubkey: [u8; 32],
    /// 16-byte caller-supplied message identifier. Same value
    /// across all fragments of one logical message.
    pub message_id: [u8; 16],
    /// 0-indexed fragment sequence number within the message.
    pub seq: u16,
    /// Total fragment count for the message. All fragments
    /// MUST carry the same `total`.
    pub total: u16,
    /// Ed25519 signature over [`Fragment::canonical_bytes`].
    pub signature: [u8; 64],
}

/// A single transport-layer fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    /// Signed header.
    pub header: FragmentHeader,
    /// Fragment payload bytes (a slice of the original message).
    pub payload: Vec<u8>,
}

/// Encoded length of a [`FragmentHeader`]: public key, message id,
/// sequence, total, signature.
pub const FRAGMENT_HEADER_LEN: usize = 32 + 16 + 2 + 2 + 64;

/// Split `payload` into signed fragments that each fit `mtu` bytes
/// once encoded with [`Fragment::to_bytes`].
///
/// This is the sending side of [`Reassembler::feed`]: feeding the
/// returned fragments, in any order and with repetitions, yields
/// `payload` back.
///
/// `message_id` identifies this message among those of the same
/// sender; two messages in flight at once must not share one.
///
/// # Errors
///
/// - [`ReassemblyError::EmptyMessage`] if `payload` is empty.
/// - [`ReassemblyError::MtuTooSmall`] if `mtu` does not exceed
///   [`FRAGMENT_HEADER_LEN`].
/// - [`ReassemblyError::TooManyFragments`] if the count does not fit
///   16 bits.
pub fn fragment(
    signing_key: &ed25519_dalek::SigningKey,
    message_id: [u8; 16],
    payload: &[u8],
    mtu: usize,
) -> Result<Vec<Fragment>, ReassemblyError> {
    if payload.is_empty() {
        return Err(ReassemblyError::EmptyMessage);
    }
    let room = mtu
        .checked_sub(FRAGMENT_HEADER_LEN)
        .filter(|room| *room > 0)
        .ok_or(ReassemblyError::MtuTooSmall { mtu })?;
    let total = u16::try_from(payload.len().div_ceil(room))
        .map_err(|_| ReassemblyError::TooManyFragments)?;
    let peer_pubkey = signing_key.verifying_key().to_bytes();
    Ok(payload
        .chunks(room)
        .zip(0u16..)
        .map(|(chunk, seq)| {
            let canonical = Fragment::canonical_bytes(&peer_pubkey, &message_id, seq, total, chunk);
            Fragment {
                header: FragmentHeader {
                    peer_pubkey,
                    message_id,
                    seq,
                    total,
                    signature: arxia_crypto::sign(signing_key, &canonical),
                },
                payload: chunk.to_vec(),
            }
        })
        .collect())
}

impl Fragment {
    /// Encode for the wire: the header fields in declaration order,
    /// integers big-endian, then the payload.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FRAGMENT_HEADER_LEN + self.payload.len());
        bytes.extend_from_slice(&self.header.peer_pubkey);
        bytes.extend_from_slice(&self.header.message_id);
        bytes.extend_from_slice(&self.header.seq.to_be_bytes());
        bytes.extend_from_slice(&self.header.total.to_be_bytes());
        bytes.extend_from_slice(&self.header.signature);
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    /// Decode a fragment from the wire. The signature is not checked
    /// here; [`Reassembler::feed`] does that.
    ///
    /// # Errors
    ///
    /// [`ReassemblyError::Undecodable`] if `bytes` is shorter than a
    /// header.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ReassemblyError> {
        if bytes.len() < FRAGMENT_HEADER_LEN {
            return Err(ReassemblyError::Undecodable);
        }
        let (header, payload) = bytes.split_at(FRAGMENT_HEADER_LEN);
        let mut peer_pubkey = [0u8; 32];
        let mut message_id = [0u8; 16];
        let mut signature = [0u8; 64];
        peer_pubkey.copy_from_slice(&header[..32]);
        message_id.copy_from_slice(&header[32..48]);
        signature.copy_from_slice(&header[52..]);
        Ok(Self {
            header: FragmentHeader {
                peer_pubkey,
                message_id,
                seq: u16::from_be_bytes([header[48], header[49]]),
                total: u16::from_be_bytes([header[50], header[51]]),
                signature,
            },
            payload: payload.to_vec(),
        })
    }

    /// Build the canonical bytes that the sender signs.
    pub fn canonical_bytes(
        peer_pubkey: &[u8; 32],
        message_id: &[u8; 16],
        seq: u16,
        total: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FRAGMENT_DOMAIN.len() + 32 + 16 + 2 + 2 + payload.len());
        buf.extend_from_slice(FRAGMENT_DOMAIN);
        buf.extend_from_slice(peer_pubkey);
        buf.extend_from_slice(message_id);
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.extend_from_slice(&total.to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    /// Verify the Ed25519 signature on this fragment.
    pub fn verify(&self) -> Result<(), ReassemblyError> {
        let canonical = Self::canonical_bytes(
            &self.header.peer_pubkey,
            &self.header.message_id,
            self.header.seq,
            self.header.total,
            &self.payload,
        );
        arxia_crypto::verify(&self.header.peer_pubkey, &canonical, &self.header.signature)
            .map_err(|_| ReassemblyError::InvalidSignature)
    }
}

/// Per-(peer_pubkey, message_id) reassembly buffer.
#[derive(Debug, Clone)]
struct PendingMessage {
    /// Total fragment count, locked at first-seen fragment.
    total: u16,
    /// Per-seq slot (None if not yet received).
    slots: Vec<Option<Vec<u8>>>,
    /// Number of slots filled (for fast completion check).
    filled: u16,
}

/// Reassembler: feeds fragments in any order and emits the
/// completed message when all slots are filled.
#[derive(Debug, Clone, Default)]
pub struct Reassembler {
    /// Per-peer FIFO of (message_id → PendingMessage). FIFO
    /// order lets us drop-oldest on overflow per peer.
    peers: BTreeMap<[u8; 32], VecDeque<([u8; 16], PendingMessage)>>,
    /// Cumulative count of pending messages evicted to make
    /// room for new ones. Saturates at u64::MAX.
    evicted: u64,
}

impl Reassembler {
    /// Empty reassembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cumulative number of evicted in-flight messages.
    pub fn evicted_count(&self) -> u64 {
        self.evicted
    }

    /// Number of distinct peers with at least one in-flight message.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Number of in-flight (incomplete) messages from a peer.
    pub fn in_flight_for(&self, peer_pubkey: &[u8; 32]) -> usize {
        self.peers.get(peer_pubkey).map(|q| q.len()).unwrap_or(0)
    }

    /// Feed a fragment.
    ///
    /// Returns `Ok(Some(payload))` if the fragment completes a
    /// message ; `Ok(None)` if the message is still partial ;
    /// `Err(ReassemblyError)` if the fragment is malformed,
    /// signature invalid, or contradicts previously-received
    /// fragments of the same logical message.
    pub fn feed(&mut self, fragment: Fragment) -> Result<Option<Vec<u8>>, ReassemblyError> {
        // 1. Signature check (binds peer_pubkey, message_id,
        //    seq, total, and payload).
        fragment.verify()?;

        let total = fragment.header.total;
        let seq = fragment.header.seq;
        if total == 0 {
            return Err(ReassemblyError::EmptyMessage);
        }
        if seq >= total {
            return Err(ReassemblyError::SeqOutOfRange { seq, total });
        }

        // 2. Per-peer queue.
        let queue = self.peers.entry(fragment.header.peer_pubkey).or_default();

        // 3. Find or create the per-message entry.
        let pos = queue
            .iter()
            .position(|(mid, _)| mid == &fragment.header.message_id);
        let pending: &mut PendingMessage = match pos {
            Some(idx) => {
                let (_, p) = &mut queue[idx];
                if p.total != total {
                    return Err(ReassemblyError::TotalMismatch {
                        got: total,
                        expected: p.total,
                    });
                }
                p
            }
            None => {
                if queue.len() >= MAX_INFLIGHT_MESSAGES_PER_PEER {
                    queue.pop_front();
                    self.evicted = self.evicted.saturating_add(1);
                }
                let total_usize = total as usize;
                queue.push_back((
                    fragment.header.message_id,
                    PendingMessage {
                        total,
                        slots: vec![None; total_usize],
                        filled: 0,
                    },
                ));
                let last = queue.len() - 1;
                &mut queue[last].1
            }
        };

        // 4. Fill the slot, with mutation-detection.
        let seq_usize = seq as usize;
        match &pending.slots[seq_usize] {
            Some(existing) if existing != &fragment.payload => {
                return Err(ReassemblyError::PayloadMismatch { seq });
            }
            Some(_) => {
                // Idempotent re-receive: same payload.
                return Ok(None);
            }
            None => {
                pending.slots[seq_usize] = Some(fragment.payload);
                pending.filled = pending.filled.saturating_add(1);
            }
        }

        // 5. Complete?
        if pending.filled == pending.total {
            // Concatenate slots and remove from queue. By the
            // `filled == total` invariant every slot is `Some`,
            // so we can flatten to skip the unreachable `None`
            // arm and silence clippy's `if_let_some_else_none`
            // (which sees the literal pattern).
            let mut out: Vec<u8> = Vec::new();
            for bytes in pending.slots.drain(..).flatten() {
                out.extend_from_slice(&bytes);
            }
            // Remove the completed message_id from the queue.
            let mid = fragment.header.message_id;
            queue.retain(|(m, _)| m != &mid);
            if queue.is_empty() {
                self.peers.remove(&fragment.header.peer_pubkey);
            }
            return Ok(Some(out));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arxia_crypto::{generate_keypair, sign};

    /// Build a signed fragment from the inner payload + headers.
    fn make_fragment(
        sk: &ed25519_dalek::SigningKey,
        peer_pubkey: [u8; 32],
        message_id: [u8; 16],
        seq: u16,
        total: u16,
        payload: Vec<u8>,
    ) -> Fragment {
        let canonical = Fragment::canonical_bytes(&peer_pubkey, &message_id, seq, total, &payload);
        let signature = sign(sk, &canonical);
        Fragment {
            header: FragmentHeader {
                peer_pubkey,
                message_id,
                seq,
                total,
                signature,
            },
            payload,
        }
    }

    // ============================================================
    // HIGH-013 — fragment / reassembly contract.
    // ============================================================

    #[test]
    fn test_reassembly_completes_in_order_two_fragment_message() {
        // PRIMARY HIGH-013 PIN: a happy-path 2-fragment message
        // reassembles to the original payload.
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let mid = [0xAA; 16];
        let f0 = make_fragment(&sk, pk, mid, 0, 2, b"hello-".to_vec());
        let f1 = make_fragment(&sk, pk, mid, 1, 2, b"world".to_vec());
        let mut r = Reassembler::new();
        assert!(r.feed(f0).unwrap().is_none());
        let done = r.feed(f1).unwrap().expect("complete after second fragment");
        assert_eq!(done, b"hello-world");
        assert_eq!(r.peer_count(), 0, "peer queue cleared after completion");
    }

    #[test]
    fn test_reassembly_completes_out_of_order() {
        // Fragments may arrive in any order ; reassembly
        // assembles them in seq order.
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let mid = [0xBB; 16];
        let f0 = make_fragment(&sk, pk, mid, 0, 3, b"AAA".to_vec());
        let f1 = make_fragment(&sk, pk, mid, 1, 3, b"BBB".to_vec());
        let f2 = make_fragment(&sk, pk, mid, 2, 3, b"CCC".to_vec());
        let mut r = Reassembler::new();
        assert!(r.feed(f2).unwrap().is_none());
        assert!(r.feed(f0).unwrap().is_none());
        let done = r.feed(f1).unwrap().expect("complete after all 3");
        assert_eq!(done, b"AAABBBCCC");
    }

    #[test]
    fn test_reassembly_rejects_invalid_signature() {
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let mid = [0xCC; 16];
        let mut f0 = make_fragment(&sk, pk, mid, 0, 2, b"x".to_vec());
        f0.header.signature = [0u8; 64]; // tamper
        let mut r = Reassembler::new();
        assert_eq!(r.feed(f0).unwrap_err(), ReassemblyError::InvalidSignature);
    }

    #[test]
    fn test_reassembly_rejects_interleaved_spoofed_fragments() {
        // PRIMARY HIGH-013 PIN: audit's exact attack scenario.
        // Peer A sends fragment 0 ; peer B (different keypair)
        // injects a fragment 1 with the same message_id.
        // Reassembler MUST NOT mix them — peer B's fragment
        // goes to a separate per-peer bucket and never
        // completes peer A's message.
        let (sk_a, vk_a) = generate_keypair();
        let (sk_b, vk_b) = generate_keypair();
        let pk_a = vk_a.to_bytes();
        let pk_b = vk_b.to_bytes();
        assert_ne!(pk_a, pk_b);
        let mid = [0xDD; 16];

        let f_a0 = make_fragment(&sk_a, pk_a, mid, 0, 2, b"alice-half-1".to_vec());
        let f_b1 = make_fragment(&sk_b, pk_b, mid, 1, 2, b"eve-spoofed-half-2".to_vec());

        let mut r = Reassembler::new();
        assert!(r.feed(f_a0).unwrap().is_none());
        // Spoofed fragment from B is bucketed under B's pubkey,
        // not A's. A's message remains incomplete.
        let result = r.feed(f_b1).unwrap();
        assert!(
            result.is_none(),
            "spoofed B fragment must not complete A's message"
        );
        // A still has 1 in-flight message ; B has 1 in-flight ;
        // neither completes.
        assert_eq!(r.in_flight_for(&pk_a), 1);
        assert_eq!(r.in_flight_for(&pk_b), 1);
    }

    #[test]
    fn test_reassembly_rejects_total_mismatch_within_message() {
        // Adversary sends two fragments for the same
        // (peer_pubkey, message_id) with disagreeing totals.
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let mid = [0xEE; 16];
        let f0 = make_fragment(&sk, pk, mid, 0, 2, b"a".to_vec());
        let f1_bad = make_fragment(&sk, pk, mid, 1, 5, b"b".to_vec());
        let mut r = Reassembler::new();
        r.feed(f0).unwrap();
        assert_eq!(
            r.feed(f1_bad).unwrap_err(),
            ReassemblyError::TotalMismatch {
                got: 5,
                expected: 2
            }
        );
    }

    #[test]
    fn test_reassembly_rejects_seq_out_of_range() {
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let mid = [0x11; 16];
        let f_bad = make_fragment(&sk, pk, mid, 5, 3, b"x".to_vec());
        let mut r = Reassembler::new();
        assert_eq!(
            r.feed(f_bad).unwrap_err(),
            ReassemblyError::SeqOutOfRange { seq: 5, total: 3 }
        );
    }

    #[test]
    fn test_reassembly_rejects_empty_message() {
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let mid = [0x22; 16];
        let f_empty = make_fragment(&sk, pk, mid, 0, 0, Vec::new());
        let mut r = Reassembler::new();
        assert_eq!(r.feed(f_empty).unwrap_err(), ReassemblyError::EmptyMessage);
    }

    #[test]
    fn test_reassembly_rejects_replay_with_mutation() {
        // Same (peer_pubkey, message_id, seq), DIFFERENT
        // payload. Replay-with-mutation spoof — must reject.
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let mid = [0x33; 16];
        let f0 = make_fragment(&sk, pk, mid, 0, 2, b"original".to_vec());
        // Same headers but different payload — but the
        // signature is recomputed over the new payload, so
        // signature is valid for THIS payload. The
        // PayloadMismatch rejection is the in-buffer
        // contradiction, not a sig failure.
        let f0_dup = make_fragment(&sk, pk, mid, 0, 2, b"mutated!".to_vec());
        let mut r = Reassembler::new();
        r.feed(f0).unwrap();
        assert_eq!(
            r.feed(f0_dup).unwrap_err(),
            ReassemblyError::PayloadMismatch { seq: 0 }
        );
    }

    #[test]
    fn test_reassembly_idempotent_on_exact_duplicate() {
        // Network duplicate: same (peer_pubkey, message_id,
        // seq, payload) twice. Accept the second silently.
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let mid = [0x44; 16];
        let f0 = make_fragment(&sk, pk, mid, 0, 2, b"x".to_vec());
        let mut r = Reassembler::new();
        assert!(r.feed(f0.clone()).unwrap().is_none());
        // Re-feed same fragment: not an error, still pending.
        assert!(r.feed(f0).unwrap().is_none());
        // Now feed the second slot to complete.
        let f1 = make_fragment(&sk, pk, mid, 1, 2, b"y".to_vec());
        let done = r.feed(f1).unwrap().unwrap();
        assert_eq!(done, b"xy");
    }

    #[test]
    fn test_reassembly_evicts_oldest_when_inflight_cap_exceeded() {
        // Peer opens MAX_INFLIGHT + 1 distinct message_ids.
        // The oldest is evicted.
        let (sk, vk) = generate_keypair();
        let pk = vk.to_bytes();
        let mut r = Reassembler::new();
        for i in 0..MAX_INFLIGHT_MESSAGES_PER_PEER as u8 {
            let mut mid = [0u8; 16];
            mid[0] = i;
            let f = make_fragment(&sk, pk, mid, 0, 2, vec![i]);
            r.feed(f).unwrap();
        }
        assert_eq!(r.in_flight_for(&pk), MAX_INFLIGHT_MESSAGES_PER_PEER);
        assert_eq!(r.evicted_count(), 0);

        // Open one more message_id ; oldest gets evicted.
        let mut mid_overflow = [0u8; 16];
        mid_overflow[0] = 0xFF;
        let f_overflow = make_fragment(&sk, pk, mid_overflow, 0, 2, vec![0xFF]);
        r.feed(f_overflow).unwrap();
        assert_eq!(
            r.in_flight_for(&pk),
            MAX_INFLIGHT_MESSAGES_PER_PEER,
            "queue still bounded after overflow"
        );
        assert_eq!(r.evicted_count(), 1);
    }

    #[test]
    fn test_reassembly_multiple_peers_independent() {
        // Two peers, each completing their own message
        // concurrently, no interference.
        let (sk_a, vk_a) = generate_keypair();
        let (sk_b, vk_b) = generate_keypair();
        let pk_a = vk_a.to_bytes();
        let pk_b = vk_b.to_bytes();
        let mid = [0x55; 16];
        let mut r = Reassembler::new();
        r.feed(make_fragment(&sk_a, pk_a, mid, 0, 2, b"A0".to_vec()))
            .unwrap();
        r.feed(make_fragment(&sk_b, pk_b, mid, 0, 2, b"B0".to_vec()))
            .unwrap();
        let a_done = r
            .feed(make_fragment(&sk_a, pk_a, mid, 1, 2, b"A1".to_vec()))
            .unwrap()
            .unwrap();
        let b_done = r
            .feed(make_fragment(&sk_b, pk_b, mid, 1, 2, b"B1".to_vec()))
            .unwrap()
            .unwrap();
        assert_eq!(a_done, b"A0A1");
        assert_eq!(b_done, b"B0B1");
    }
}
