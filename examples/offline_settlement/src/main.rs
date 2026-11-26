//! Offline settlement between separate processes.
//!
//! Each invocation is one device doing one thing: a wallet signing a
//! payment, a witness confirming it, a receiver crediting it. Devices
//! share nothing but the files they hand to each other, which stand in
//! for radio packets: a bundle is a sequence of frames, each small
//! enough for one LoRa packet (see `arxia_lattice::bundle`).
//!
//! State lives in a redb database per device and survives between
//! invocations. Every block is on storage before the file that carries
//! it is written.
//!
//! This is a demonstration of the settlement rules end to end. It is
//! not the node: keys and seeds are kept in plain files, there is no
//! transport, and none of the requirements of
//! `docs/SECURITY_INTERFACES.md` are claimed.
//!
//! ```text
//! offline_settlement authority-init --dir AUTH
//! offline_settlement init     --data DIR
//! offline_settlement network  --issuers AUTH/issuers.json --witness KEY:WEIGHT... --out NET
//! offline_settlement certify  --dir AUTH --account KEY --amount N --out CERT
//! offline_settlement open     --data DIR --network NET [--certificate CERT]
//! offline_settlement pay      --data DIR --network NET --to KEY --amount N --out BUNDLE
//! offline_settlement witness  --data DIR --network NET --in BUNDLE --out CONFIRMATION
//! offline_settlement receive  --data DIR --network NET --in BUNDLE [--confirmation FILE]...
//! offline_settlement balance  --data DIR --network NET
//! ```
//!
//! Amounts are in micro-ARX.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use arxia_finality::witness::{receive_final, Witness, WitnessRoster};
use arxia_lattice::bundle::{decode, encode, Frame};
use arxia_lattice::{DurableWallet, IssuanceCertificate, IssuancePolicy, WalletConfig};
use arxia_storage_redb::RedbStorage;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

type Outcome<T> = Result<T, Box<dyn Error>>;
type Device = DurableWallet<RedbStorage>;

/// Issuer public keys and how many must sign.
#[derive(Serialize, Deserialize)]
struct Issuers {
    threshold: usize,
    issuers: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct WitnessEntry {
    key: String,
    weight: u64,
}

/// What every device of one network is configured with.
#[derive(Serialize, Deserialize)]
struct Network {
    threshold: usize,
    issuers: Vec<String>,
    witnesses: Vec<WitnessEntry>,
}

/// Command-line flags, in order of appearance.
struct Flags(Vec<(String, String)>);

impl Flags {
    fn parse(args: &[String]) -> Outcome<Self> {
        let mut flags = Vec::new();
        let mut rest = args.iter();
        while let Some(name) = rest.next() {
            let name = name
                .strip_prefix("--")
                .ok_or_else(|| format!("expected a --flag, got '{name}'"))?;
            let value = rest
                .next()
                .ok_or_else(|| format!("--{name} needs a value"))?;
            flags.push((name.to_string(), value.clone()));
        }
        Ok(Self(flags))
    }

    fn all(&self, name: &str) -> Vec<&str> {
        self.0
            .iter()
            .filter(|(flag, _)| flag == name)
            .map(|(_, value)| value.as_str())
            .collect()
    }

    fn one(&self, name: &str) -> Outcome<&str> {
        match self.all(name).as_slice() {
            [value] => Ok(value),
            [] => Err(format!("--{name} is required").into()),
            _ => Err(format!("--{name} was given more than once").into()),
        }
    }

    fn optional(&self, name: &str) -> Outcome<Option<&str>> {
        match self.all(name).as_slice() {
            [] => Ok(None),
            [value] => Ok(Some(value)),
            _ => Err(format!("--{name} was given more than once").into()),
        }
    }

    fn amount(&self) -> Outcome<u64> {
        Ok(self.one("amount")?.parse()?)
    }
}

fn key_from_hex(text: &str) -> Outcome<[u8; 32]> {
    let bytes = hex::decode(text.trim())?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| "a key must be 32 bytes of hex".into())
}

fn policy(threshold: usize, issuers: &[String]) -> Outcome<IssuancePolicy> {
    let keys = issuers
        .iter()
        .map(|key| key_from_hex(key))
        .collect::<Outcome<Vec<_>>>()?;
    Ok(IssuancePolicy::new(keys, threshold)?)
}

impl Network {
    fn load(path: &str) -> Outcome<Self> {
        Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
    }

    fn roster(&self) -> Outcome<WitnessRoster> {
        let entries = self
            .witnesses
            .iter()
            .map(|entry| Ok((key_from_hex(&entry.key)?, entry.weight)))
            .collect::<Outcome<Vec<_>>>()?;
        Ok(WitnessRoster::new(entries)?)
    }

    fn config(&self) -> Outcome<WalletConfig> {
        Ok(WalletConfig {
            issuance: Some(policy(self.threshold, &self.issuers)?),
            witnesses: Some(self.roster()?),
        })
    }
}

fn database(data: &str) -> Outcome<RedbStorage> {
    fs::create_dir_all(data)?;
    Ok(RedbStorage::open(Path::new(data).join("wallet.redb"))?)
}

/// Open the device in `--data` under the configuration in `--network`.
fn device(flags: &Flags) -> Outcome<(Device, Network)> {
    let network = Network::load(flags.one("network")?)?;
    let wallet = DurableWallet::open_with_config(database(flags.one("data")?)?, network.config()?)?;
    Ok((wallet, network))
}

fn authority_init(flags: &Flags) -> Outcome<()> {
    let dir = PathBuf::from(flags.one("dir")?);
    fs::create_dir_all(&dir)?;
    let mut issuers = Vec::new();
    for index in 0..3 {
        // A wallet is the workspace's way to obtain a fresh key.
        let seed = arxia_lattice::Wallet::new().seed();
        let key = SigningKey::from_bytes(&seed);
        fs::write(dir.join(format!("issuer-{index}.seed")), hex::encode(seed))?;
        issuers.push(hex::encode(key.verifying_key().to_bytes()));
    }
    let issuers = Issuers {
        threshold: 2,
        issuers,
    };
    fs::write(
        dir.join("issuers.json"),
        serde_json::to_string_pretty(&issuers)?,
    )?;
    Ok(())
}

fn certify(flags: &Flags) -> Outcome<()> {
    let dir = PathBuf::from(flags.one("dir")?);
    let issuers: Issuers = serde_json::from_str(&fs::read_to_string(dir.join("issuers.json"))?)?;
    let policy = policy(issuers.threshold, &issuers.issuers)?;
    let mut certificate = IssuanceCertificate::new(flags.one("account")?, flags.amount()?)?;
    for index in 0..issuers.threshold {
        let seed = key_from_hex(&fs::read_to_string(
            dir.join(format!("issuer-{index}.seed")),
        )?)?;
        certificate.sign(&policy, &SigningKey::from_bytes(&seed))?;
    }
    fs::write(flags.one("out")?, certificate.to_bytes())?;
    Ok(())
}

fn init(flags: &Flags) -> Outcome<()> {
    let wallet = DurableWallet::open(database(flags.one("data")?)?)?;
    println!("{}", wallet.id());
    Ok(())
}

fn network(flags: &Flags) -> Outcome<()> {
    let issuers: Issuers = serde_json::from_str(&fs::read_to_string(flags.one("issuers")?)?)?;
    let witnesses = flags
        .all("witness")
        .into_iter()
        .map(|entry| {
            let (key, weight) = entry.split_once(':').ok_or("--witness takes KEY:WEIGHT")?;
            Ok(WitnessEntry {
                key: key.to_string(),
                weight: weight.parse()?,
            })
        })
        .collect::<Outcome<Vec<_>>>()?;
    let network = Network {
        threshold: issuers.threshold,
        issuers: issuers.issuers,
        witnesses,
    };
    // Refuse to write a configuration no device could load.
    network.config()?;
    fs::write(flags.one("out")?, serde_json::to_string_pretty(&network)?)?;
    Ok(())
}

fn open(flags: &Flags) -> Outcome<()> {
    let (mut wallet, _network) = device(flags)?;
    match flags.optional("certificate")? {
        Some(path) => {
            let certificate = IssuanceCertificate::from_bytes(&fs::read(path)?)?;
            wallet.open_certified(&certificate)?;
        }
        None => {
            wallet.open_account(0)?;
        }
    }
    println!("{}", wallet.balance());
    Ok(())
}

fn pay(flags: &Flags) -> Outcome<()> {
    let (mut wallet, _network) = device(flags)?;
    // The payment is on storage before the bundle is written.
    let payment = wallet.send(flags.one("to")?, flags.amount()?)?;
    let bundle = wallet.payment_bundle(&payment)?;
    fs::write(flags.one("out")?, encode(&bundle)?)?;
    println!("{}", wallet.balance());
    Ok(())
}

fn witness(flags: &Flags) -> Outcome<()> {
    let (mut wallet, _network) = device(flags)?;
    let frames = decode(&fs::read(flags.one("in")?)?)?;
    let (payment, _confirmations) = wallet.ingest_bundle(&frames)?;
    // Confirming stores the payment in the witness's own ledger first;
    // a different block for the same account position is refused.
    let confirmation = Witness::new(wallet).confirm(&payment)?;
    fs::write(
        flags.one("out")?,
        encode(&[Frame::Confirmation(confirmation)])?,
    )?;
    Ok(())
}

fn receive(flags: &Flags) -> Outcome<()> {
    let (mut wallet, network) = device(flags)?;
    let frames = decode(&fs::read(flags.one("in")?)?)?;
    let (payment, mut confirmations) = wallet.ingest_bundle(&frames)?;
    for path in flags.all("confirmation") {
        for frame in decode(&fs::read(path)?)? {
            if let Frame::Confirmation(confirmation) = frame {
                confirmations.push(confirmation);
            }
        }
    }
    // Credited only when the witnesses that confirmed this exact block
    // hold more than two thirds of the roster weight.
    receive_final(&mut wallet, &payment, &confirmations, &network.roster()?)?;
    println!("{}", wallet.balance());
    Ok(())
}

fn balance(flags: &Flags) -> Outcome<()> {
    let (wallet, _network) = device(flags)?;
    println!("{}", wallet.balance());
    Ok(())
}

/// Dispatch one command line.
pub fn run(args: &[String]) -> Outcome<()> {
    let (command, rest) = args.split_first().ok_or("a command is required")?;
    let flags = Flags::parse(rest)?;
    match command.as_str() {
        "authority-init" => authority_init(&flags),
        "certify" => certify(&flags),
        "init" => init(&flags),
        "network" => network(&flags),
        "open" => open(&flags),
        "pay" => pay(&flags),
        "witness" => witness(&flags),
        "receive" => receive(&flags),
        "balance" => balance(&flags),
        other => Err(format!("unknown command '{other}'").into()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = run(&args) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
