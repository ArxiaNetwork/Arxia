//! Crash-atomicity under a real process kill.
//!
//! A child process (this same test binary, re-invoked with
//! `ARXIA_KILL9_CHILD_DB` set) writes sealed batches in a tight loop:
//! eight payload keys plus a `last_seq` marker, all in one
//! `apply_batch`, so "the marker reads S" and "batch S committed in
//! full" are the same statement. The parent kills it mid-stream with
//! `TerminateProcess` — no signal handler, no destructor, no flush —
//! reopens the database, and checks the only acceptable outcome:
//!
//! - the database opens (a crashed writer must not brick the store),
//! - every batch `1..=last_seq` is present in full, bytes verified,
//! - nothing beyond `last_seq` exists, not one key.
//!
//! Several rounds run against the same file, so the sequence is
//! crash -> repair/reopen -> keep writing -> crash again, which is a
//! node's actual life on flaky power.
//!
//! # What this does and does not prove
//!
//! Proven here: crash-atomicity (no torn batch is ever visible), and
//! that commits survive the death of the process that made them — a
//! backend switched to `Durability::None` fails this test, verified
//! by mutation, because redb keeps non-durable commits process-local
//! and the kill takes them with it.
//!
//! Not proven: power-loss durability. `TerminateProcess` does not
//! drop the OS page cache or the drive's write cache, so this test
//! cannot see whether `Durability::Immediate`'s fsync truly reached
//! stable media. That needs hardware whose plug can be pulled; it is
//! planned for the T-Beam bench.
//!
//! # Large values, and what a kill cannot reach
//!
//! redb 4.1.0 had two crash windows around file growth, fixed in 4.2.0
//! (see docs/dependency-risks.md, "redb crash windows during file
//! growth"). Both need a storage-level failure: a file extension or a
//! header write that never reached the disk. A process kill cannot
//! produce that, because the operating system keeps every write the
//! process completed, so this harness does not reproduce them and
//! passes on 4.1.0 as well. What it checks is the recovery contract
//! without help: the file is no longer pre-grown before the first kill
//! window, and a second test writes eight 64 KiB values per batch, so
//! every batch spans many pages and the file grows several times during
//! the run (redb doubles it), with the kill point swept across the
//! batch.

use arxia_storage::{BatchOp, StorageBackend};
use arxia_storage_redb::RedbStorage;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

const CHILD_ENV: &str = "ARXIA_KILL9_CHILD_DB";
/// Value length the parent asks the child to write.
const PAYLOAD_LEN_ENV: &str = "ARXIA_KILL9_PAYLOAD_LEN";
const PAYLOAD_KEYS_PER_BATCH: usize = 8;
/// Steady-state payload: small values, mostly page reuse.
const PAYLOAD_LEN: usize = 256;
/// Large payload: eight new 64 KiB values per batch, nothing ever
/// deleted. redb doubles the file when it runs out of space, so the
/// file grows several times during the run, not on every commit.
const LARGE_PAYLOAD_LEN: usize = 64 * 1024;

fn payload_key(seq: u64, i: usize) -> Vec<u8> {
    format!("b:{seq:010}:{i}").into_bytes()
}

/// Deterministic per-(seq, i) payload so the verifier checks bytes,
/// not mere existence: a header naming the batch and key, then a fill
/// byte that also depends on both. Built with a single fill rather than
/// an iterator chain, so that even in a debug build the writer spends
/// its time inside the commit, where the kill is meant to land.
fn payload_value(seq: u64, i: usize, len: usize) -> Vec<u8> {
    let mut value = format!("payload-{seq}-{i}-").into_bytes();
    value.truncate(len);
    value.resize(len, (seq as u8).wrapping_mul(31) ^ (i as u8));
    value
}

fn read_last_seq(store: &RedbStorage) -> u64 {
    match store.get(b"last_seq").expect("read last_seq") {
        Some(bytes) => String::from_utf8(bytes)
            .expect("last_seq utf8")
            .parse()
            .expect("last_seq number"),
        None => 0,
    }
}

/// Child mode: the database path and payload length the parent passed.
fn child_mode() -> Option<(String, usize)> {
    let db_path = std::env::var(CHILD_ENV).ok()?;
    let len = std::env::var(PAYLOAD_LEN_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(PAYLOAD_LEN);
    Some((db_path, len))
}

/// The writer the parent kills. Never returns.
fn writer_child(db_path: &str, payload_len: usize) -> ! {
    let mut store = RedbStorage::open(db_path).expect("child: open db");
    let mut seq = read_last_seq(&store);

    loop {
        seq += 1;
        let keys: Vec<Vec<u8>> = (0..PAYLOAD_KEYS_PER_BATCH)
            .map(|i| payload_key(seq, i))
            .collect();
        let values: Vec<Vec<u8>> = (0..PAYLOAD_KEYS_PER_BATCH)
            .map(|i| payload_value(seq, i, payload_len))
            .collect();
        let marker = seq.to_string().into_bytes();

        let mut ops: Vec<BatchOp<'_>> = keys
            .iter()
            .zip(&values)
            .map(|(k, v)| BatchOp::Put { key: k, value: v })
            .collect();
        // The seal: committed in the same transaction as the payload,
        // so the marker cannot run ahead of or behind the data.
        ops.push(BatchOp::Put {
            key: b"last_seq",
            value: &marker,
        });

        store.apply_batch(&ops).expect("child: apply_batch");
        // Parent reads this to know a batch landed; flush is what
        // makes the line observable before a kill.
        println!("COMMITTED {seq}");
        use std::io::Write;
        std::io::stdout().flush().expect("child: flush");
    }
}

fn spawn_writer(db_path: &std::path::Path, test_name: &str, payload_len: usize) -> Child {
    Command::new(std::env::current_exe().expect("current exe"))
        .args([test_name, "--exact", "--nocapture"])
        .env(CHILD_ENV, db_path)
        .env(PAYLOAD_LEN_ENV, payload_len.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn writer child")
}

/// Wait for `min_batches` commits, then kill without warning.
/// Returns the highest sequence the parent saw committed.
///
/// The pipe is drained by a dedicated thread for the whole lifetime of
/// the child. That detail is what gives the kill teeth: if the parent
/// simply stopped reading once its threshold was reached, the pipe
/// buffer would fill and the child would block on its stdout flush —
/// which sits *between* batches — so every kill would land at a batch
/// boundary and mid-commit kills would never be exercised. (The first
/// version of this harness had exactly that flaw, found because a
/// deliberately non-atomic backend survived it.) With the drain thread
/// running, the child spends its time inside `apply_batch`, and that
/// is where the kill lands.
fn kill_after(child: &mut Child, min_batches: u64, kill_fraction: f64) -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let stdout = child.stdout.take().expect("child stdout");
    let highest = Arc::new(AtomicU64::new(0));
    let highest_for_reader = Arc::clone(&highest);

    let started = Instant::now();
    // Nanoseconds since `started` at which the latest line arrived —
    // one atomic, written only by the drain thread.
    let last_line_nanos = Arc::new(AtomicU64::new(0));
    let last_line_nanos_for_reader = Arc::clone(&last_line_nanos);

    let drain = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if let Some(rest) = line.strip_prefix("COMMITTED ") {
                if let Ok(seq) = rest.trim().parse::<u64>() {
                    let nanos = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
                    last_line_nanos_for_reader.store(nanos, Ordering::Release);
                    highest_for_reader.store(seq, Ordering::Release);
                }
            }
        }
    });

    // Busy-wait on the child's progress; the child is doing fsyncs, so
    // yielding is plenty. Record when the first line arrives so batch
    // cadence can be measured over the observation window.
    let mut first_seen: Option<(u64, u64)> = None; // (seq, nanos)
    loop {
        let seq = highest.load(Ordering::Acquire);
        if seq > 0 && first_seen.is_none() {
            first_seen = Some((seq, last_line_nanos.load(Ordering::Acquire)));
        }
        if seq >= min_batches {
            break;
        }
        if child.try_wait().expect("try_wait").is_some() {
            panic!(
                "child exited on its own after {seq} batches — its \
                 writes failed before the kill; nothing was tested"
            );
        }
        std::thread::yield_now();
    }

    // The COMMITTED line that tripped the threshold was printed at a
    // batch boundary, and a kill issued immediately would land a few
    // microseconds later — right at the start of the next batch, before
    // any of its writes are durable. Killing there looks atomic even
    // for a backend that is not: the kill point must be decorrelated
    // from the boundary that triggered it. (Found because a
    // deliberately per-op-committing backend survived the naive
    // version of this harness three runs out of three.) So: measure
    // the child's real batch cadence over the observation window and
    // sleep a per-round fraction of one batch duration before killing,
    // placing the kill inside the write stream regardless of how fast
    // this machine commits.
    let (first_seq, first_nanos) = first_seen.expect("saw at least one line");
    let last_seq = highest.load(Ordering::Acquire);
    let last_nanos = last_line_nanos.load(Ordering::Acquire);
    if last_seq > first_seq && last_nanos > first_nanos {
        let per_batch = (last_nanos - first_nanos) / (last_seq - first_seq);
        let delay = (per_batch as f64 * kill_fraction) as u64;
        std::thread::sleep(Duration::from_nanos(delay));
    }

    child.kill().expect("kill child");
    child.wait().expect("reap child");
    drain.join().expect("join drain thread");
    highest.load(Ordering::Acquire)
}

/// Every batch `1..=last_seq` complete and byte-correct; nothing at
/// all beyond. `seen_by_parent` bounds where `last_seq` may legally
/// fall: no lower than the last line the parent read, no higher than
/// that plus the pipe's worth of in-flight batches.
fn verify_all_or_nothing(
    store: &RedbStorage,
    seen_by_parent: u64,
    probe_beyond: u64,
    payload_len: usize,
) {
    let last_seq = read_last_seq(store);
    assert!(
        last_seq >= seen_by_parent,
        "last_seq {last_seq} lost batches the parent saw committed ({seen_by_parent})"
    );

    for seq in 1..=last_seq {
        for i in 0..PAYLOAD_KEYS_PER_BATCH {
            let key = payload_key(seq, i);
            let got = store
                .get(&key)
                .expect("get")
                .unwrap_or_else(|| panic!("batch {seq} incomplete: key {i} missing"));
            assert_eq!(
                got,
                payload_value(seq, i, payload_len),
                "batch {seq} key {i}: payload bytes corrupted"
            );
        }
    }

    for seq in (last_seq + 1)..=(last_seq + probe_beyond) {
        for i in 0..PAYLOAD_KEYS_PER_BATCH {
            assert!(
                store.get(&payload_key(seq, i)).expect("get").is_none(),
                "torn batch visible: key {i} of uncommitted batch {seq} exists"
            );
        }
    }
}

/// Run the kill rounds against one file and return the final
/// `last_seq`. Each round waits for `min_batches` more commits, then
/// kills at `kill_fraction` of one batch duration.
fn run_rounds(test_name: &str, payload_len: usize, rounds: &[(u64, f64)]) -> u64 {
    let dir = tempfile::tempdir().expect("create temp dir");
    let db_path = dir.path().join("kill9.redb");

    let mut cumulative = 0u64;
    for &(min_batches, kill_fraction) in rounds {
        let mut child = spawn_writer(&db_path, test_name, payload_len);
        let seen = kill_after(&mut child, cumulative + min_batches, kill_fraction);

        let store = RedbStorage::open(&db_path)
            .expect("a crashed writer must not leave the database unopenable");
        verify_all_or_nothing(&store, seen, 50, payload_len);
        cumulative = read_last_seq(&store);
        // Drop the parent's handle before the next child opens the
        // file — only one process may hold the database at a time.
        drop(store);
    }
    cumulative
}

#[test]
fn batches_survive_a_process_kill() {
    // Child mode: this same test, re-invoked by `spawn_writer` with
    // the env var set, becomes the writer and never returns.
    if let Some((db_path, payload_len)) = child_mode() {
        writer_child(&db_path, payload_len);
    }

    // Rounds on one file: crash, reopen, keep writing, crash again.
    // The fractions sweep the kill point across the interior of a
    // batch, early, middle and late, so it cannot be systematically
    // synchronised with any phase of the commit.
    let cumulative = run_rounds(
        "batches_survive_a_process_kill",
        PAYLOAD_LEN,
        &[(25, 0.15), (30, 0.35), (30, 0.55), (30, 0.75), (30, 0.95)],
    );

    assert!(
        cumulative >= 145,
        "five rounds should have accumulated at least the sum of the \
         thresholds, got {cumulative}"
    );
}

#[test]
fn batches_survive_a_process_kill_with_large_values() {
    if let Some((db_path, payload_len)) = child_mode() {
        writer_child(&db_path, payload_len);
    }

    // Every batch adds 512 KiB of new keys, and the file grows several
    // times during the run. Eight kills on one file, with the kill
    // point swept across the batch.
    let cumulative = run_rounds(
        "batches_survive_a_process_kill_with_large_values",
        LARGE_PAYLOAD_LEN,
        &[
            (4, 0.10),
            (4, 0.25),
            (4, 0.40),
            (4, 0.55),
            (4, 0.70),
            (4, 0.85),
            (4, 0.95),
            (4, 0.50),
        ],
    );

    assert!(
        cumulative >= 32,
        "eight rounds should have accumulated at least the sum of the \
         thresholds, got {cumulative}"
    );
}
