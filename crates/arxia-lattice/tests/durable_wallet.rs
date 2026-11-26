//! A wallet that survives restarts and power loss.
//!
//! "Restart" here means dropping the wallet and opening a new one from
//! the same storage, which is all a device has after losing power.

use arxia_core::{ArxiaError, StorageFault};
use arxia_lattice::{DurableWallet, Wallet};
use arxia_storage::{BatchOp, MemoryStorage, StorageBackend};
use arxia_storage_redb::RedbStorage;

const ARX: u64 = 1_000_000;

/// Storage that can be told to refuse writes, standing in for a device
/// that loses power or a medium that fails mid-operation.
#[derive(Default)]
struct FlakyStorage {
    inner: MemoryStorage,
    refuse_writes: bool,
}

impl FlakyStorage {
    fn refusal() -> ArxiaError {
        ArxiaError::Storage {
            fault: StorageFault::WouldBlock,
        }
    }
}

impl StorageBackend for FlakyStorage {
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), ArxiaError> {
        if self.refuse_writes {
            return Err(Self::refusal());
        }
        self.inner.put(key, value)
    }
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ArxiaError> {
        self.inner.get(key)
    }
    fn delete(&mut self, key: &[u8]) -> Result<bool, ArxiaError> {
        if self.refuse_writes {
            return Err(Self::refusal());
        }
        self.inner.delete(key)
    }
    fn contains(&self, key: &[u8]) -> Result<bool, ArxiaError> {
        self.inner.contains(key)
    }
    fn scan_prefix(
        &self,
        prefix: &[u8],
        visit: &mut dyn FnMut(&[u8], &[u8]) -> bool,
    ) -> Result<(), ArxiaError> {
        self.inner.scan_prefix(prefix, visit)
    }
    fn apply_batch(&mut self, ops: &[BatchOp<'_>]) -> Result<(), ArxiaError> {
        if self.refuse_writes {
            return Err(Self::refusal());
        }
        self.inner.apply_batch(ops)
    }
}

fn restart<S: StorageBackend>(wallet: DurableWallet<S>) -> DurableWallet<S> {
    DurableWallet::open(wallet.into_storage()).unwrap()
}

#[test]
fn identity_balance_and_chain_survive_a_restart() {
    let mut alice = DurableWallet::open(MemoryStorage::default()).unwrap();
    let bob = Wallet::new();
    alice.open_account(100 * ARX).unwrap();
    alice.send(bob.id(), 30 * ARX).unwrap();
    let id = alice.id().to_string();
    let last_hash = alice.chain().last().unwrap().hash.clone();

    let alice = restart(alice);
    assert_eq!(alice.id(), id);
    assert_eq!(alice.balance(), 70 * ARX);
    assert_eq!(alice.chain().len(), 2);
    assert_eq!(alice.chain().last().unwrap().hash, last_hash);
}

#[test]
fn a_released_block_holds_its_position_after_a_restart() {
    // Alice signs a payment and loses power right after handing it
    // over. When the device comes back, that position is taken: the
    // next payment extends the chain instead of replacing the first.
    let mut alice = DurableWallet::open(MemoryStorage::default()).unwrap();
    let mut bob = Wallet::new();
    bob.open(0).unwrap();
    alice.open_account(100 * ARX).unwrap();
    let first = alice.send(bob.id(), 30 * ARX).unwrap();

    let mut alice = restart(alice);
    let second = alice.send(bob.id(), 10 * ARX).unwrap();
    assert_eq!(second.nonce, first.nonce + 1);
    assert_eq!(second.previous, first.hash);

    // A receiver accepts both, in order.
    bob.ingest_all(alice.chain()).unwrap();
    bob.receive(&first).unwrap();
    bob.receive(&second).unwrap();
    assert_eq!(bob.balance(), 40 * ARX);
    assert_eq!(alice.balance(), 60 * ARX);
}

#[test]
fn a_block_that_could_not_be_stored_is_not_released() {
    let mut alice = DurableWallet::open(FlakyStorage::default()).unwrap();
    let bob = Wallet::new();
    alice.open_account(100 * ARX).unwrap();

    // The medium fails while the payment is being written.
    let mut storage = alice.into_storage();
    storage.refuse_writes = true;
    let mut alice = DurableWallet::open(storage).unwrap();
    assert!(alice.send(bob.id(), 30 * ARX).is_err());

    // Nothing more is signed until the wallet is reopened.
    assert!(matches!(
        alice.send(bob.id(), 1),
        Err(ArxiaError::Storage {
            fault: StorageFault::ReopenRequired
        })
    ));

    // After the restart the position is still free and the balance is
    // whole: no signature left the device.
    let mut storage = alice.into_storage();
    storage.refuse_writes = false;
    let mut alice = DurableWallet::open(storage).unwrap();
    assert_eq!(alice.balance(), 100 * ARX);
    assert_eq!(alice.chain().len(), 1);
    let payment = alice.send(bob.id(), 30 * ARX).unwrap();
    assert_eq!(payment.nonce, 2);
}

#[test]
fn received_funds_survive_a_restart_and_can_be_spent() {
    let mut alice = Wallet::new();
    let mut bob = DurableWallet::open(MemoryStorage::default()).unwrap();
    let mut carol = Wallet::new();
    alice.open(100 * ARX).unwrap();
    bob.open_account(0).unwrap();
    carol.open(0).unwrap();
    let pay_bob = alice.send(bob.id(), 30 * ARX).unwrap();
    bob.ingest_all(alice.chain()).unwrap();
    bob.receive(&pay_bob).unwrap();

    let mut bob = restart(bob);
    assert_eq!(bob.balance(), 30 * ARX);

    // The payment cannot be credited a second time after the restart.
    assert!(matches!(
        bob.receive(&pay_bob),
        Err(ArxiaError::DuplicateReceive { .. })
    ));

    let pay_carol = bob.send(carol.id(), 20 * ARX).unwrap();
    carol.ingest_all(alice.chain()).unwrap();
    carol.ingest_all(bob.chain()).unwrap();
    carol.receive(&pay_carol).unwrap();
    assert_eq!(carol.balance(), 20 * ARX);
    assert_eq!(bob.balance(), 10 * ARX);
}

#[test]
fn altered_storage_fails_the_open() {
    let mut alice = DurableWallet::open(MemoryStorage::default()).unwrap();
    alice.open_account(100 * ARX).unwrap();
    let mut storage = alice.into_storage();

    // Raise the stored opening balance without the signing key.
    let mut key = b"w/b/".to_vec();
    key.extend_from_slice(&0u64.to_be_bytes());
    let mut record = storage.get(&key).unwrap().unwrap();
    // Byte 70 lies in the balance field of the compact layout.
    record[70] ^= 0x01;
    storage.put(&key, &record).unwrap();

    assert!(DurableWallet::open(storage).is_err());
}

#[test]
fn truncated_record_fails_the_open() {
    let mut alice = DurableWallet::open(MemoryStorage::default()).unwrap();
    alice.open_account(100 * ARX).unwrap();
    let mut storage = alice.into_storage();
    let mut key = b"w/b/".to_vec();
    key.extend_from_slice(&0u64.to_be_bytes());
    storage.put(&key, &[0u8; 12]).unwrap();
    assert!(matches!(
        DurableWallet::open(storage),
        Err(ArxiaError::Storage {
            fault: StorageFault::RecordUndecodable
        })
    ));
}

#[test]
fn wallet_reopens_from_a_database_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.redb");
    let bob = Wallet::new();

    let (id, last_hash) = {
        let mut alice = DurableWallet::open(RedbStorage::open(&path).unwrap()).unwrap();
        alice.open_account(100 * ARX).unwrap();
        alice.send(bob.id(), 25 * ARX).unwrap();
        (
            alice.id().to_string(),
            alice.chain().last().unwrap().hash.clone(),
        )
    };

    let alice = DurableWallet::open(RedbStorage::open(&path).unwrap()).unwrap();
    assert_eq!(alice.id(), id);
    assert_eq!(alice.balance(), 75 * ARX);
    assert_eq!(alice.chain().last().unwrap().hash, last_hash);
}
