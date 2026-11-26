//! Settlement between separate operating-system processes.
//!
//! Every step below is one run of the example binary. The processes
//! share no memory: each device keeps its own database, and the only
//! things that pass between devices are files of frames.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const ARX: u64 = 1_000_000;

/// A directory holding an authority, a network file and devices.
struct World {
    root: tempfile::TempDir,
    network: String,
    witnesses: Vec<String>,
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_offline_settlement"))
        .args(args)
        .output()
        .expect("the example binary runs")
}

/// Run a step that must succeed and return what it printed.
fn ok(args: &[&str]) -> String {
    let output = run(args);
    assert!(
        output.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// Run a step that must be refused and return the reason.
fn refused(args: &[&str]) -> String {
    let output = run(args);
    assert!(!output.status.success(), "{args:?} was expected to fail");
    String::from_utf8_lossy(&output.stderr).trim().to_string()
}

impl World {
    /// An authority and three witnesses of equal weight.
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let path = |name: &str| root.path().join(name).to_string_lossy().to_string();
        ok(&["authority-init", "--dir", &path("authority")]);

        let witnesses: Vec<String> = (0..3).map(|i| path(&format!("witness-{i}"))).collect();
        let mut args: Vec<String> = vec![
            "network".into(),
            "--issuers".into(),
            Path::new(&path("authority"))
                .join("issuers.json")
                .to_string_lossy()
                .to_string(),
            "--out".into(),
            path("network.json"),
        ];
        for witness in &witnesses {
            let key = ok(&["init", "--data", witness]);
            args.push("--witness".into());
            args.push(format!("{key}:10"));
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        ok(&args);

        Self {
            network: path("network.json"),
            witnesses,
            root,
        }
    }

    fn path(&self, name: &str) -> String {
        self.root.path().join(name).to_string_lossy().to_string()
    }

    /// Create a device and return its account key.
    fn device(&self, name: &str) -> String {
        ok(&["init", "--data", &self.path(name)])
    }

    /// Open a device's account, with a certified balance or empty.
    fn open(&self, name: &str, key: &str, balance: Option<u64>) {
        let data = self.path(name);
        let mut args = vec!["open", "--data", &data, "--network", &self.network];
        let certificate = self.path(&format!("{name}.certificate"));
        let amount = balance.unwrap_or(0).to_string();
        if balance.is_some() {
            ok(&[
                "certify",
                "--dir",
                &self.path("authority"),
                "--account",
                key,
                "--amount",
                &amount,
                "--out",
                &certificate,
            ]);
            args.extend(["--certificate", &certificate]);
        }
        ok(&args);
    }

    fn balance(&self, name: &str) -> u64 {
        ok(&[
            "balance",
            "--data",
            &self.path(name),
            "--network",
            &self.network,
        ])
        .parse()
        .unwrap()
    }

    /// `from` signs a payment; the bundle lands in a file.
    fn pay(&self, from: &str, to_key: &str, amount: u64, bundle: &str) -> PathBuf {
        let out = self.path(bundle);
        ok(&[
            "pay",
            "--data",
            &self.path(from),
            "--network",
            &self.network,
            "--to",
            to_key,
            "--amount",
            &amount.to_string(),
            "--out",
            &out,
        ]);
        PathBuf::from(out)
    }

    /// Ask every witness to confirm a bundle. Returns the confirmation
    /// files of those that did, and the reasons of those that did not.
    fn confirm(&self, bundle: &Path, tag: &str) -> (Vec<String>, Vec<String>) {
        let mut files = Vec::new();
        let mut reasons = Vec::new();
        for (index, witness) in self.witnesses.iter().enumerate() {
            let out = self.path(&format!("{tag}.confirmation-{index}"));
            let output = run(&[
                "witness",
                "--data",
                witness,
                "--network",
                &self.network,
                "--in",
                &bundle.to_string_lossy(),
                "--out",
                &out,
            ]);
            if output.status.success() {
                files.push(out);
            } else {
                reasons.push(String::from_utf8_lossy(&output.stderr).trim().to_string());
            }
        }
        (files, reasons)
    }

    fn receive_args(&self, name: &str, bundle: &Path, confirmations: &[String]) -> Vec<String> {
        let mut args = vec![
            "receive".to_string(),
            "--data".into(),
            self.path(name),
            "--network".into(),
            self.network.clone(),
            "--in".into(),
            bundle.to_string_lossy().to_string(),
        ];
        for confirmation in confirmations {
            args.push("--confirmation".into());
            args.push(confirmation.clone());
        }
        args
    }

    fn receive(&self, name: &str, bundle: &Path, confirmations: &[String]) {
        let args = self.receive_args(name, bundle, confirmations);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        ok(&args);
    }

    fn receive_refused(&self, name: &str, bundle: &Path, confirmations: &[String]) -> String {
        let args = self.receive_args(name, bundle, confirmations);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        refused(&args)
    }
}

#[test]
fn two_payments_settle_between_separate_processes() {
    let world = World::new();
    let alice = world.device("alice");
    let bob = world.device("bob");
    let carol = world.device("carol");
    world.open("alice", &alice, Some(100 * ARX));
    world.open("bob", &bob, None);
    world.open("carol", &carol, None);

    // Alice pays Bob.
    let bundle = world.pay("alice", &bob, 30 * ARX, "alice-to-bob");
    let (confirmations, reasons) = world.confirm(&bundle, "first");
    assert_eq!(confirmations.len(), 3, "{reasons:?}");
    world.receive("bob", &bundle, &confirmations);
    assert_eq!(world.balance("alice"), 70 * ARX);
    assert_eq!(world.balance("bob"), 30 * ARX);

    // Bob pays Carol with what he just received.
    let bundle = world.pay("bob", &carol, 20 * ARX, "bob-to-carol");
    let (confirmations, reasons) = world.confirm(&bundle, "second");
    assert_eq!(confirmations.len(), 3, "{reasons:?}");
    world.receive("carol", &bundle, &confirmations);

    assert_eq!(world.balance("alice"), 70 * ARX);
    assert_eq!(world.balance("bob"), 10 * ARX);
    assert_eq!(world.balance("carol"), 20 * ARX);
}

#[test]
fn a_payment_is_not_credited_without_enough_confirmations() {
    let world = World::new();
    let alice = world.device("alice");
    let bob = world.device("bob");
    world.open("alice", &alice, Some(100 * ARX));
    world.open("bob", &bob, None);

    let bundle = world.pay("alice", &bob, 30 * ARX, "alice-to-bob");
    let reason = world.receive_refused("bob", &bundle, &[]);
    assert!(reason.contains("not final"), "{reason}");

    let (confirmations, _) = world.confirm(&bundle, "first");
    let reason = world.receive_refused("bob", &bundle, &confirmations[..2]);
    assert!(reason.contains("not final"), "{reason}");
    assert_eq!(world.balance("bob"), 0);

    // With the third confirmation the same bundle is credited.
    world.receive("bob", &bundle, &confirmations);
    assert_eq!(world.balance("bob"), 30 * ARX);
}

#[test]
fn a_restored_copy_of_a_wallet_cannot_pay_a_second_time() {
    // Alice copies her device's storage, pays Bob, then restores the
    // copy and pays Dave with the same funds. The restored device has
    // no memory of the first payment and signs the second one.
    let world = World::new();
    let alice = world.device("alice");
    let bob = world.device("bob");
    let dave = world.device("dave");
    world.open("alice", &alice, Some(100 * ARX));
    world.open("bob", &bob, None);
    world.open("dave", &dave, None);

    std::fs::create_dir_all(world.path("alice-copy")).unwrap();
    std::fs::copy(
        Path::new(&world.path("alice")).join("wallet.redb"),
        Path::new(&world.path("alice-copy")).join("wallet.redb"),
    )
    .unwrap();

    let to_bob = world.pay("alice", &bob, 80 * ARX, "alice-to-bob");
    let (confirmations, _) = world.confirm(&to_bob, "first");
    world.receive("bob", &to_bob, &confirmations);
    assert_eq!(world.balance("bob"), 80 * ARX);

    let to_dave = world.pay("alice-copy", &dave, 80 * ARX, "alice-to-dave");

    // Every witness refuses: it already holds another block for that
    // position of Alice's account.
    let (confirmations, reasons) = world.confirm(&to_dave, "second");
    assert!(confirmations.is_empty());
    assert_eq!(reasons.len(), 3);
    assert!(
        reasons
            .iter()
            .all(|reason| reason.contains("nonce conflict")),
        "{reasons:?}"
    );

    world.receive_refused("dave", &to_dave, &[]);
    assert_eq!(world.balance("dave"), 0);
    assert_eq!(world.balance("bob"), 80 * ARX);
}

#[test]
fn a_reserve_pays_a_receiver_with_no_witness_in_reach() {
    let world = World::new();
    let alice = world.device("alice");
    let reserve = world.device("reserve");
    let bob = world.device("bob");
    world.open("alice", &alice, Some(100 * ARX));
    world.open("reserve", &reserve, None);
    world.open("bob", &bob, None);

    // Alice funds the reserve with an ordinary, witnessed payment.
    let funding = world.pay("alice", &reserve, 20 * ARX, "funding");
    let (confirmations, _) = world.confirm(&funding, "funding");
    world.receive("reserve", &funding, &confirmations);

    // The witnesses confirm the reserve's RECEIVE; the reserve is
    // certified.
    let request = world.path("reserve.request");
    ok(&[
        "request",
        "--data",
        &world.path("reserve"),
        "--network",
        &world.network,
        "--out",
        &request,
    ]);
    let (confirmations, reasons) = world.confirm(Path::new(&request), "reserve");
    assert_eq!(confirmations.len(), 3, "{reasons:?}");
    let certify = |files: &[String]| -> Vec<String> {
        let mut args = vec![
            "reserve".to_string(),
            "--data".into(),
            world.path("reserve"),
            "--network".into(),
            world.network.clone(),
        ];
        for file in files {
            args.push("--confirmation".into());
            args.push(file.clone());
        }
        args
    };
    let too_few = certify(&confirmations[..2]);
    let too_few: Vec<&str> = too_few.iter().map(String::as_str).collect();
    assert!(refused(&too_few).contains("not final"));
    let enough = certify(&confirmations);
    let enough: Vec<&str> = enough.iter().map(String::as_str).collect();
    assert_eq!(ok(&enough), (20 * ARX).to_string());

    // Later, with no witness to ask, the reserve pays Bob.
    let payment = world.pay("reserve", &bob, 5 * ARX, "reserve-to-bob");
    let mut args = world.receive_args("bob", &payment, &[]);
    args.extend(["--mode".to_string(), "isolated".to_string()]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    ok(&args);
    assert_eq!(world.balance("bob"), 5 * ARX);
    assert_eq!(world.balance("reserve"), 15 * ARX);
}

#[test]
fn an_isolated_payment_from_an_ordinary_account_is_refused() {
    let world = World::new();
    let alice = world.device("alice");
    let bob = world.device("bob");
    world.open("alice", &alice, Some(100 * ARX));
    world.open("bob", &bob, None);

    let payment = world.pay("alice", &bob, 10 * ARX, "alice-to-bob");
    let mut args = world.receive_args("bob", &payment, &[]);
    args.extend(["--mode".to_string(), "isolated".to_string()]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    assert!(refused(&args).contains("certified reserve"));
    assert_eq!(world.balance("bob"), 0);
}

#[test]
fn a_balance_without_a_certificate_is_refused() {
    // A device is handed a certificate made out to another account.
    let world = World::new();
    let alice = world.device("alice");
    let mallory = world.device("mallory");
    world.open("alice", &alice, Some(100 * ARX));
    let reason = refused(&[
        "open",
        "--data",
        &world.path("mallory"),
        "--network",
        &world.network,
        "--certificate",
        &world.path("alice.certificate"),
    ]);
    assert!(reason.contains("issuance"), "{reason}");
    let _ = mallory;
}

#[test]
fn malformed_command_lines_are_reported_not_crashed() {
    assert!(refused(&[]).contains("command"));
    assert!(refused(&["launch"]).contains("unknown command"));
    assert!(refused(&["init"]).contains("--data"));
    assert!(refused(&["init", "data"]).contains("--flag"));
    assert!(refused(&["init", "--data"]).contains("needs a value"));
}
