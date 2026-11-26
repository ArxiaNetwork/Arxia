//! The sending side of reassembly: split, encode, decode, feed.

use arxia_crypto::generate_keypair;
use arxia_transport::{fragment, Fragment, Reassembler, ReassemblyError, FRAGMENT_HEADER_LEN};

const MTU: usize = 256;

fn message(length: usize) -> Vec<u8> {
    (0..length).map(|i| (i * 31 % 251) as u8).collect()
}

#[test]
fn a_message_splits_into_fragments_that_fit_the_mtu() {
    let (key, _) = generate_keypair();
    let payload = message(1_000);
    let fragments = fragment(&key, [7; 16], &payload, MTU).unwrap();
    // 140 payload bytes per fragment at this MTU.
    assert_eq!(fragments.len(), 8);
    for piece in &fragments {
        assert!(piece.to_bytes().len() <= MTU);
        assert!(piece.verify().is_ok());
    }
    assert_eq!(fragments[0].to_bytes().len(), MTU);
}

#[test]
fn fragments_reassemble_in_any_order_with_repetitions() {
    let (key, _) = generate_keypair();
    let payload = message(1_000);
    let fragments = fragment(&key, [7; 16], &payload, MTU).unwrap();

    // Over the wire, back to front, each fragment sent twice.
    let wire: Vec<Vec<u8>> = fragments
        .iter()
        .rev()
        .flat_map(|piece| [piece.to_bytes(), piece.to_bytes()])
        .collect();
    let mut reassembler = Reassembler::new();
    let mut delivered = Vec::new();
    for bytes in &wire {
        if let Some(whole) = reassembler
            .feed(Fragment::from_bytes(bytes).unwrap())
            .unwrap()
        {
            delivered.push(whole);
        }
    }
    assert_eq!(delivered.first(), Some(&payload));
}

#[test]
fn a_missing_fragment_delivers_nothing() {
    let (key, _) = generate_keypair();
    let payload = message(1_000);
    let fragments = fragment(&key, [7; 16], &payload, MTU).unwrap();
    let mut reassembler = Reassembler::new();
    for piece in fragments.iter().skip(1) {
        assert_eq!(reassembler.feed(piece.clone()).unwrap(), None);
    }
    // The missing one arrives: the message completes.
    assert_eq!(
        reassembler.feed(fragments[0].clone()).unwrap(),
        Some(payload)
    );
}

#[test]
fn a_fragment_altered_on_the_way_is_refused() {
    let (key, _) = generate_keypair();
    let fragments = fragment(&key, [7; 16], &message(300), MTU).unwrap();
    let mut bytes = fragments[0].to_bytes();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let mut reassembler = Reassembler::new();
    assert_eq!(
        reassembler.feed(Fragment::from_bytes(&bytes).unwrap()),
        Err(ReassemblyError::InvalidSignature)
    );
}

#[test]
fn a_one_fragment_message_round_trips() {
    let (key, _) = generate_keypair();
    let payload = message(40);
    let fragments = fragment(&key, [1; 16], &payload, MTU).unwrap();
    assert_eq!(fragments.len(), 1);
    let decoded = Fragment::from_bytes(&fragments[0].to_bytes()).unwrap();
    assert_eq!(decoded, fragments[0]);
    assert_eq!(Reassembler::new().feed(decoded).unwrap(), Some(payload));
}

#[test]
fn inputs_that_cannot_be_fragmented_are_refused() {
    let (key, _) = generate_keypair();
    assert_eq!(
        fragment(&key, [0; 16], &[], MTU),
        Err(ReassemblyError::EmptyMessage)
    );
    assert_eq!(
        fragment(&key, [0; 16], &message(10), FRAGMENT_HEADER_LEN),
        Err(ReassemblyError::MtuTooSmall {
            mtu: FRAGMENT_HEADER_LEN
        })
    );
    // One payload byte per fragment: 70,000 bytes need 70,000 of them.
    assert_eq!(
        fragment(&key, [0; 16], &message(70_000), FRAGMENT_HEADER_LEN + 1),
        Err(ReassemblyError::TooManyFragments)
    );
    assert_eq!(
        Fragment::from_bytes(&[0u8; FRAGMENT_HEADER_LEN - 1]),
        Err(ReassemblyError::Undecodable)
    );
}
