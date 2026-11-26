//! Issuance: who may bring value into a ledger.
//!
//! An `Open` block states an opening balance. Under an
//! [`IssuancePolicy`], a ledger accepts a non-zero opening balance only
//! when an [`IssuanceCertificate`] for that account and that exact
//! amount carries valid signatures from enough of the policy's issuer
//! keys. An account can always be opened with a zero balance.
//!
//! # Certificates travel with payments
//!
//! A certificate is a small, self-contained statement. The holder of
//! an account hands it over together with the account's chain, so a
//! receiver with no network can check the origin of the funds with
//! nothing but the policy it was configured with.
//!
//! # What is signed
//!
//! Each issuer signs [`ISSUANCE_DOMAIN`] followed by the 32-byte
//! account key and the amount as eight big-endian bytes. The domain
//! prefix keeps an issuance signature from being valid as anything
//! else.
//!
//! # Counting signatures
//!
//! Only valid signatures from distinct issuers count. A signature that
//! does not verify, a repeated issuer or an index outside the policy
//! is ignored rather than fatal, so adding noise to a valid
//! certificate cannot invalidate it.
//!
//! # Encoding
//!
//! `[32B account][8B amount][1B count]` then `count` entries of
//! `[1B issuer index][64B signature]`. Three signatures take 236
//! bytes, within the value limit of the flash backend.

use arxia_core::{ArxiaError, IssuanceFault};
use ed25519_dalek::SigningKey;

/// Domain prefix of the message issuers sign.
pub const ISSUANCE_DOMAIN: &[u8] = b"arxia-issuance-v1";

/// Largest number of issuer keys a policy can hold.
pub const MAX_ISSUERS: usize = 16;

const HEADER_LEN: usize = 32 + 8 + 1;
const ENTRY_LEN: usize = 1 + 64;

fn fault(fault: IssuanceFault) -> ArxiaError {
    ArxiaError::Issuance { fault }
}

/// The issuer keys of a ledger and how many of them must sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuancePolicy {
    issuers: Vec<[u8; 32]>,
    threshold: usize,
}

impl IssuancePolicy {
    /// Build a policy from issuer public keys and a signature
    /// threshold.
    ///
    /// # Errors
    ///
    /// [`IssuanceFault::PolicyInvalid`] if the threshold is zero or
    /// above the number of issuers, if there are more than
    /// [`MAX_ISSUERS`] keys, or if a key is repeated. Any error of
    /// [`arxia_crypto::validate_pubkey_strict`] for a key that is not
    /// a valid public key.
    pub fn new(issuers: Vec<[u8; 32]>, threshold: usize) -> Result<Self, ArxiaError> {
        if threshold == 0 || threshold > issuers.len() || issuers.len() > MAX_ISSUERS {
            return Err(fault(IssuanceFault::PolicyInvalid));
        }
        for (position, key) in issuers.iter().enumerate() {
            arxia_crypto::validate_pubkey_strict(key)?;
            if issuers[..position].contains(key) {
                return Err(fault(IssuanceFault::PolicyInvalid));
            }
        }
        Ok(Self { issuers, threshold })
    }

    /// Number of distinct issuers that must sign a certificate.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Position of `key` among the issuers, if it is one.
    pub fn index_of(&self, key: &[u8; 32]) -> Option<u8> {
        self.issuers
            .iter()
            .position(|issuer| issuer == key)
            .and_then(|position| u8::try_from(position).ok())
    }

    /// Check that `certificate` carries enough valid signatures.
    ///
    /// # Errors
    ///
    /// [`IssuanceFault::InsufficientSignatures`] otherwise.
    pub fn verify(&self, certificate: &IssuanceCertificate) -> Result<(), ArxiaError> {
        let message = certificate.message();
        let mut counted = [false; MAX_ISSUERS];
        let mut valid = 0usize;
        for (index, signature) in &certificate.signatures {
            let position = usize::from(*index);
            let Some(issuer) = self.issuers.get(position) else {
                continue;
            };
            if counted[position] {
                continue;
            }
            if arxia_crypto::verify(issuer, &message, signature).is_ok() {
                counted[position] = true;
                valid += 1;
            }
        }
        if valid < self.threshold {
            return Err(fault(IssuanceFault::InsufficientSignatures {
                valid,
                required: self.threshold,
            }));
        }
        Ok(())
    }
}

/// A statement by the issuers that `account` may open with `amount`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuanceCertificate {
    account: [u8; 32],
    amount: u64,
    signatures: Vec<(u8, [u8; 64])>,
}

impl IssuanceCertificate {
    /// Start a certificate for `account` (hex-encoded public key) and
    /// `amount` in micro-ARX, with no signature yet.
    ///
    /// # Errors
    ///
    /// [`IssuanceFault::Undecodable`] if `account` is not 64 hex
    /// characters.
    pub fn new(account: &str, amount: u64) -> Result<Self, ArxiaError> {
        let bytes = hex::decode(account).map_err(|_| fault(IssuanceFault::Undecodable))?;
        let account = <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| fault(IssuanceFault::Undecodable))?;
        Ok(Self {
            account,
            amount,
            signatures: Vec::new(),
        })
    }

    /// Hex-encoded public key of the account.
    pub fn account(&self) -> String {
        hex::encode(self.account)
    }

    /// Certified opening balance in micro-ARX.
    pub fn amount(&self) -> u64 {
        self.amount
    }

    /// The bytes each issuer signs.
    pub fn message(&self) -> Vec<u8> {
        let mut message = Vec::with_capacity(ISSUANCE_DOMAIN.len() + 40);
        message.extend_from_slice(ISSUANCE_DOMAIN);
        message.extend_from_slice(&self.account);
        message.extend_from_slice(&self.amount.to_be_bytes());
        message
    }

    /// Add the signature of one issuer. `key` must be one of the
    /// policy's issuer keys.
    ///
    /// # Errors
    ///
    /// - [`IssuanceFault::UnknownIssuer`] if `key` is not in `policy`.
    /// - [`IssuanceFault::TooManySignatures`] if the certificate is
    ///   already full.
    pub fn sign(&mut self, policy: &IssuancePolicy, key: &SigningKey) -> Result<(), ArxiaError> {
        let index = policy
            .index_of(key.verifying_key().as_bytes())
            .ok_or(fault(IssuanceFault::UnknownIssuer))?;
        if self.signatures.len() >= MAX_ISSUERS {
            return Err(fault(IssuanceFault::TooManySignatures));
        }
        let signature = arxia_crypto::sign(key, &self.message());
        self.signatures.push((index, signature));
        Ok(())
    }

    /// Encode for storage or transport.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_LEN + self.signatures.len() * ENTRY_LEN);
        bytes.extend_from_slice(&self.account);
        bytes.extend_from_slice(&self.amount.to_be_bytes());
        // `sign` and `from_bytes` both bound the count by MAX_ISSUERS.
        bytes.push(self.signatures.len() as u8);
        for (index, signature) in &self.signatures {
            bytes.push(*index);
            bytes.extend_from_slice(signature);
        }
        bytes
    }

    /// Decode a certificate. The length must match the stated number
    /// of signatures exactly.
    ///
    /// # Errors
    ///
    /// [`IssuanceFault::Undecodable`] for any other shape.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ArxiaError> {
        let undecodable = || fault(IssuanceFault::Undecodable);
        if bytes.len() < HEADER_LEN {
            return Err(undecodable());
        }
        let (header, entries) = bytes.split_at(HEADER_LEN);
        let count = usize::from(header[40]);
        if count > MAX_ISSUERS || entries.len() != count * ENTRY_LEN {
            return Err(undecodable());
        }
        let account = <[u8; 32]>::try_from(&header[..32]).map_err(|_| undecodable())?;
        let amount =
            u64::from_be_bytes(<[u8; 8]>::try_from(&header[32..40]).map_err(|_| undecodable())?);
        let signatures = entries
            .chunks_exact(ENTRY_LEN)
            .map(|entry| {
                <[u8; 64]>::try_from(&entry[1..])
                    .map(|signature| (entry[0], signature))
                    .map_err(|_| undecodable())
            })
            .collect::<Result<Vec<_>, ArxiaError>>()?;
        Ok(Self {
            account,
            amount,
            signatures,
        })
    }
}
