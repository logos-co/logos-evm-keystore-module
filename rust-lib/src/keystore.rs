//! Keystore core — pure, offline Ethereum key management and signing.
//!
//! No network, no Logos dependencies; this module is unit-testable on its own
//! (`cargo test`). Private keys live only inside a `Keystore`: on disk as
//! scrypt-encrypted JSON vaults (eth-keystore / Web3 Secure Storage), and in
//! memory only while an account is unlocked. Nothing here ever returns a raw
//! private key across its API — only addresses, signed payloads, and
//! (re-encrypted) vault JSON.

use std::path::{Path, PathBuf};

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy::eips::eip2718::Encodable2718;
use alloy::primitives::{Address, Bytes, TxKind, B256, U256};
use alloy::signers::local::{
    coins_bip39::{English, Mnemonic},
    MnemonicBuilder, PrivateKeySigner,
};
use alloy::signers::SignerSync;
use serde::Deserialize;
use thiserror::Error;
use zeroize::Zeroizing;

/// BIP-44 Ethereum account path, account 0, external chain: m/44'/60'/0'/0/<index>.
fn eth_derivation_path(index: u32) -> String {
    format!("m/44'/60'/0'/0/{index}")
}

#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("account not found: {0}")]
    NotFound(String),
    #[error("account is locked: {0}")]
    Locked(String),
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("invalid private key: {0}")]
    InvalidKey(String),
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
    #[error("vault error: {0}")]
    Vault(String),
    #[error("signing error: {0}")]
    Signing(String),
    #[error("io error: {0}")]
    Io(String),
}

type Result<T> = std::result::Result<T, KeystoreError>;

/// Manages a directory of scrypt vault files. One vault file per account, named
/// `<lowercase-hex-address>.json`.
///
/// There is deliberately NO cache of unlocked signers. Signing *is* vault
/// access: a key is derived from the vault password for one operation and wiped
/// when that operation ends. The previous design kept a `HashMap<Address,
/// Unlocked>` whose entries carried an *optional* deadline, and the only caller
/// passed `None` — so an unlock was an unlimited, process-lifetime signer that
/// any module able to reach this one could spend.
pub struct Keystore {
    dir: PathBuf,
}

/// Fields of an unsigned transaction, as JSON from the caller. All numeric
/// fields are hex (`0x…`) or decimal strings to avoid precision loss across the
/// JSON boundary. `fee_mode` selects EIP-1559 (default) vs legacy.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedTx {
    pub to: Option<String>,
    /// Contract creation must be asked for explicitly. Previously an absent or
    /// blank `to` fell through to `TxKind::Create`, so a transfer whose
    /// recipient failed to render became a contract deployment that burned the
    /// value.
    #[serde(default)]
    pub create: bool,
    /// Present only so an access-list-bearing tx is REFUSED with a reason
    /// rather than silently stripped: the signer previously hardcoded
    /// `access_list: Default::default()`, so a caller's EIP-2930 list was
    /// dropped and the signature covered a different transaction than the one
    /// requested.
    #[serde(default)]
    pub access_list: Option<serde_json::Value>,
    #[serde(default)]
    pub value: String,
    pub nonce: String,
    #[serde(default)]
    pub gas_limit: String,
    #[serde(default)]
    pub data: String,
    #[serde(default)]
    pub fee_mode: String, // "eip1559" (default) | "legacy"
    #[serde(default)]
    pub max_fee_per_gas: String,
    #[serde(default)]
    pub max_priority_fee_per_gas: String,
    #[serde(default)]
    pub gas_price: String,
}

fn parse_u128(s: &str, what: &str) -> Result<u128> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    let v = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u128::from_str_radix(hex, 16)
    } else {
        s.parse::<u128>()
    };
    v.map_err(|e| KeystoreError::InvalidParams(format!("{what}: {e}")))
}

fn parse_u64(s: &str, what: &str) -> Result<u64> {
    // A wrapping `as u64` here silently truncated: `0x10000000000000005` and
    // `0x5` produced BYTE-IDENTICAL signed transactions, so a render built from
    // the caller's string and a signature built from this value could disagree
    // about the nonce. Reject instead.
    let wide = parse_u128(s, what)?;
    u64::try_from(wide)
        .map_err(|_| KeystoreError::InvalidParams(format!("{what}: {wide} does not fit in u64")))
}

fn parse_u256(s: &str, what: &str) -> Result<U256> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(U256::ZERO);
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        U256::from_str_radix(hex, 16).map_err(|e| KeystoreError::InvalidParams(format!("{what}: {e}")))
    } else {
        s.parse::<U256>().map_err(|e| KeystoreError::InvalidParams(format!("{what}: {e}")))
    }
}

fn parse_address(s: &str) -> Result<Address> {
    // Accept with or without `0x`, any case (no EIP-55 checksum requirement) —
    // decode the 20 raw bytes directly rather than going through the
    // checksum-validating FromStr.
    let t = s.trim();
    let hexpart = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    let bytes = hex::decode(hexpart).map_err(|e| KeystoreError::InvalidAddress(format!("{s}: {e}")))?;
    if bytes.len() != 20 {
        return Err(KeystoreError::InvalidAddress(format!("{s}: expected 20 bytes, got {}", bytes.len())));
    }
    Ok(Address::from_slice(&bytes))
}

/// Tighten a path's mode. No-op off unix, where the enclosing directory ACL is
/// the control instead.
fn restrict_permissions(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| KeystoreError::Io(e.to_string()))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

fn vault_name(addr: &Address) -> String {
    // lowercase hex, no 0x — stable filename + easy listing
    format!("{:x}", addr)
}

impl Keystore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Derive the signer for `address` from its vault. The returned signer is
    /// live only for the caller's scope — there is nowhere else it is kept.
    pub fn signer_for(&self, address: &str, password: &str) -> Result<PrivateKeySigner> {
        let addr = parse_address(address)?;
        let path = self.vault_path(&addr);
        if !path.exists() {
            return Err(KeystoreError::NotFound(address.to_string()));
        }
        let key = Zeroizing::new(
            eth_keystore::decrypt_key(&path, password).map_err(|e| KeystoreError::Vault(e.to_string()))?,
        );
        PrivateKeySigner::from_slice(&key).map_err(|e| KeystoreError::InvalidKey(e.to_string()))
    }

    fn ensure_dir(&self) -> Result<()> {
        std::fs::create_dir_all(&self.dir).map_err(|e| KeystoreError::Io(e.to_string()))?;
        // create_dir_all honours the umask, so the vault directory was 0755.
        restrict_permissions(&self.dir, 0o700)
    }

    fn vault_path(&self, addr: &Address) -> PathBuf {
        self.dir.join(format!("{}.json", vault_name(addr)))
    }

    /// Generate a fresh BIP-39 mnemonic of `words` (12/15/18/21/24). Does NOT
    /// persist anything — the caller decides whether to import it.
    pub fn create_mnemonic(words: u32) -> Result<String> {
        let count = match words {
            12 | 15 | 18 | 21 | 24 => words as usize,
            _ => return Err(KeystoreError::InvalidParams(format!("word count must be 12/15/18/21/24, got {words}"))),
        };
        let mut rng = rand::thread_rng();
        let mnemonic = Mnemonic::<English>::new_with_count(&mut rng, count)
            .map_err(|e| KeystoreError::InvalidParams(e.to_string()))?;
        Ok(mnemonic.to_phrase())
    }

    fn persist_signer(&self, signer: &PrivateKeySigner, password: &str) -> Result<Address> {
        self.ensure_dir()?;
        let addr = signer.address();
        // `to_bytes()` hands back the raw secp256k1 secret. Own it in a
        // Zeroizing so it is wiped when this scope ends, on every path.
        let key = Zeroizing::new(signer.to_bytes().0);
        let mut rng = rand::thread_rng();
        let name = format!("{}.json", vault_name(&addr));
        eth_keystore::encrypt_key(&self.dir, &mut rng, key.as_slice(), password, Some(&name))
            .map_err(|e| KeystoreError::Vault(e.to_string()))?;
        // encrypt_key uses File::create, i.e. 0644 at the default umask.
        restrict_permissions(&self.vault_path(&addr), 0o600)?;
        Ok(addr)
    }

    /// Create a brand-new random account, persisting its scrypt vault.
    pub fn new_account(&self, password: &str) -> Result<Address> {
        let signer = PrivateKeySigner::random();
        self.persist_signer(&signer, password)
    }

    /// Import a raw private key (hex, with or without 0x), persisting a vault.
    pub fn import_private_key(&self, priv_hex: &str, password: &str) -> Result<Address> {
        let signer = signer_from_hex(priv_hex)?;
        self.persist_signer(&signer, password)
    }

    /// Derive account `index` from a mnemonic (+ optional BIP-39 passphrase) and
    /// persist its vault under `password`.
    pub fn import_mnemonic(&self, phrase: &str, bip39_passphrase: &str, index: u32, password: &str) -> Result<Address> {
        let signer = signer_from_mnemonic(phrase, bip39_passphrase, index)?;
        self.persist_signer(&signer, password)
    }

    /// Import an existing scrypt keystore JSON, re-encrypting under `new_password`.
    pub fn import_keystore_json(&self, key_json: &str, password: &str, new_password: &str) -> Result<Address> {
        check_kdf_params(key_json)?;
        let tmp = tempfile_with(key_json)?;
        let key = Zeroizing::new(
            eth_keystore::decrypt_key(tmp.path(), password)
                .map_err(|e| KeystoreError::Vault(e.to_string()))?,
        );
        let signer = PrivateKeySigner::from_slice(&key).map_err(|e| KeystoreError::InvalidKey(e.to_string()))?;
        self.persist_signer(&signer, new_password)
    }

    /// Export an account as a fresh scrypt keystore JSON (string), without
    /// touching the on-disk vault. Requires the vault password.
    pub fn export_keystore_json(&self, address: &str, password: &str) -> Result<String> {
        let addr = parse_address(address)?;
        let path = self.vault_path(&addr);
        // Validate the password decrypts, then re-emit canonical JSON contents.
        eth_keystore::decrypt_key(&path, password).map_err(|e| KeystoreError::Vault(e.to_string()))?;
        std::fs::read_to_string(&path).map_err(|e| KeystoreError::Io(e.to_string()))
    }

    pub fn list_accounts(&self) -> Vec<Address> {
        let mut out = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for e in entries.flatten() {
                let name = e.file_name();
                let name = name.to_string_lossy();
                if let Some(stem) = name.strip_suffix(".json") {
                    if let Ok(addr) = format!("0x{stem}").parse::<Address>() {
                        out.push(addr);
                    }
                }
            }
        }
        out.sort();
        out
    }

    pub fn has_address(&self, address: &str) -> bool {
        match parse_address(address) {
            Ok(addr) => self.vault_path(&addr).exists(),
            Err(_) => false,
        }
    }

    pub fn delete_account(&self, address: &str, password: &str) -> Result<bool> {
        let addr = parse_address(address)?;
        let path = self.vault_path(&addr);
        if !path.exists() {
            return Ok(false);
        }
        // Require the correct password before destroying the vault.
        eth_keystore::decrypt_key(&path, password).map_err(|e| KeystoreError::Vault(e.to_string()))?;
        std::fs::remove_file(&path).map_err(|e| KeystoreError::Io(e.to_string()))?;
        Ok(true)
    }

    /// EIP-191 personal_sign over `message` — derives, signs, wipes.
    pub fn sign_message(&self, address: &str, password: &str, message: &str) -> Result<String> {
        sign_message_with(&self.signer_for(address, password)?, message)
    }

    /// Sign an unsigned tx, returning the broadcast-ready EIP-2718 envelope hex.
    pub fn sign_transaction(
        &self,
        address: &str,
        password: &str,
        unsigned_tx_json: &str,
        chain_id: u64,
    ) -> Result<String> {
        sign_transaction_with(&self.signer_for(address, password)?, unsigned_tx_json, chain_id)
    }

    /// Sign a raw 32-byte digest. See [`sign_digest_with`] for the caveat.
    pub fn sign_digest(&self, address: &str, password: &str, digest_hex: &str) -> Result<String> {
        sign_digest_with(&self.signer_for(address, password)?, digest_hex)
    }
}

/// EIP-191 personal_sign. Refuses text that can render differently than it
/// signs (see [`check_displayable`]).
pub fn sign_message_with(signer: &PrivateKeySigner, message: &str) -> Result<String> {
    check_displayable(message, "message")?;
    let sig = signer
        .sign_message_sync(message.as_bytes())
        .map_err(|e| KeystoreError::Signing(e.to_string()))?;
    Ok(format!("0x{}", hex::encode(sig.as_bytes())))
}

/// Sign an unsigned tx and return the raw, broadcast-ready signed tx hex
/// (EIP-2718 envelope). Supports legacy (EIP-155) and EIP-1559.
pub fn sign_transaction_with(
    signer: &PrivateKeySigner,
    unsigned_tx_json: &str,
    chain_id: u64,
) -> Result<String> {
    let tx: UnsignedTx = serde_json::from_str(unsigned_tx_json)
        .map_err(|e| KeystoreError::InvalidParams(format!("tx json: {e}")))?;
    sign_parsed_tx(signer, &tx, chain_id)
}

/// Sign an ALREADY-PARSED transaction. The approval path parses once, commits
/// to the parsed value, and signs from that same value — so the bytes a human
/// was shown and the bytes that get signed cannot drift apart.
pub fn sign_parsed_tx(signer: &PrivateKeySigner, tx: &UnsignedTx, chain_id: u64) -> Result<String> {
    let to = match (tx.to.as_deref().map(str::trim).filter(|s| !s.is_empty()), tx.create) {
        (Some(_), true) => {
            return Err(KeystoreError::InvalidParams(
                "tx json: `to` and `create: true` are mutually exclusive".into(),
            ))
        }
        (Some(s), false) => TxKind::Call(parse_address(s)?),
        (None, true) => TxKind::Create,
        (None, false) => {
            return Err(KeystoreError::InvalidParams(
                "tx json: `to` is required; set `create: true` to deploy a contract".into(),
            ))
        }
    };

    if tx.access_list.as_ref().is_some_and(|v| !v.is_null()) {
        return Err(KeystoreError::InvalidParams(
            "tx json: access lists are not supported by this signer — remove `access_list` \
             rather than have it silently dropped from the signed payload"
                .into(),
        ));
    }

    let value = parse_u256(&tx.value, "value")?;
    let nonce = parse_u64(&tx.nonce, "nonce")?;
    let gas_limit = parse_u64(&tx.gas_limit, "gas_limit")?;
    let input = parse_bytes(&tx.data)?;

    let legacy = match tx.fee_mode.trim() {
        "" | "eip1559" => false,
        "legacy" => true,
        other => {
            return Err(KeystoreError::InvalidParams(format!(
                "tx json: fee_mode must be \"eip1559\" or \"legacy\", got {other:?}"
            )))
        }
    };

    let raw = if legacy {
        let t = TxLegacy {
            chain_id: Some(chain_id),
            nonce,
            gas_price: parse_u128(&tx.gas_price, "gas_price")?,
            gas_limit,
            to,
            value,
            input,
        };
        let sig = signer
            .sign_hash_sync(&t.signature_hash())
            .map_err(|e| KeystoreError::Signing(e.to_string()))?;
        TxEnvelope::Legacy(t.into_signed(sig)).encoded_2718()
    } else {
        let t = TxEip1559 {
            chain_id,
            nonce,
            gas_limit,
            max_fee_per_gas: parse_u128(&tx.max_fee_per_gas, "max_fee_per_gas")?,
            max_priority_fee_per_gas: parse_u128(&tx.max_priority_fee_per_gas, "max_priority_fee_per_gas")?,
            to,
            value,
            input,
            access_list: Default::default(),
        };
        let sig = signer
            .sign_hash_sync(&t.signature_hash())
            .map_err(|e| KeystoreError::Signing(e.to_string()))?;
        TxEnvelope::Eip1559(t.into_signed(sig)).encoded_2718()
    };

    Ok(format!("0x{}", hex::encode(raw)))
}

/// Sign a raw 32-byte digest (ECDSA over the hash — no EIP-191/712 prefix).
///
/// This signs an OPAQUE hash: unlike a transaction, nothing here can be
/// rendered, so the approval layer must commit to a typed preimage and describe
/// that instead.
pub fn sign_digest_with(signer: &PrivateKeySigner, digest_hex: &str) -> Result<String> {
    let digest = parse_b256(digest_hex)?;
    let sig = signer
        .sign_hash_sync(&digest)
        .map_err(|e| KeystoreError::Signing(e.to_string()))?;
    Ok(format!("0x{}", hex::encode(sig.as_bytes())))
}

/// Parse a 32-byte hash hex (`0x`-prefixed or bare) into a `B256`.
fn parse_b256(s: &str) -> Result<B256> {
    let s = s.trim();
    let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    let bytes = hex::decode(h).map_err(|e| KeystoreError::InvalidParams(format!("digest hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(KeystoreError::InvalidParams(format!(
            "digest must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(B256::from_slice(&bytes))
}

/// Upper bounds on the KDF work a *caller-supplied* vault may ask us to
/// perform. `eth_keystore::decrypt_key` feeds these straight to scrypt, so an
/// unclamped `n` is a one-file denial of service: `n = u32::MAX` asks for a
/// ~4 TiB allocation and aborts the whole module process.
const MAX_SCRYPT_LOG_N: u32 = 18; // 2^18 = 262144, the Web3/geth standard
const MAX_SCRYPT_R: u64 = 16;
const MAX_SCRYPT_P: u64 = 16;
const MAX_PBKDF2_C: u64 = 10_000_000;
const MAX_KDF_MEMORY_BYTES: u64 = 512 * 1024 * 1024;

/// Reject a vault whose KDF parameters are out of range, BEFORE any derivation
/// is attempted.
fn check_kdf_params(key_json: &str) -> Result<()> {
    let v: serde_json::Value = serde_json::from_str(key_json)
        .map_err(|e| KeystoreError::Vault(format!("keystore json: {e}")))?;
    let crypto = v
        .get("crypto")
        .or_else(|| v.get("Crypto"))
        .ok_or_else(|| KeystoreError::Vault("keystore json: missing `crypto`".into()))?;
    let kdf = crypto.get("kdf").and_then(|k| k.as_str()).unwrap_or_default();
    let params = crypto
        .get("kdfparams")
        .ok_or_else(|| KeystoreError::Vault("keystore json: missing `crypto.kdfparams`".into()))?;
    let num = |k: &str| params.get(k).and_then(|x| x.as_u64());

    let bad = |m: String| Err(KeystoreError::Vault(format!("keystore json: {m}")));

    if let Some(dklen) = num("dklen") {
        if dklen != 32 {
            return bad(format!("dklen must be 32, got {dklen}"));
        }
    }

    match kdf {
        "scrypt" => {
            let n = num("n").ok_or_else(|| KeystoreError::Vault("keystore json: scrypt `n` missing".into()))?;
            let r = num("r").unwrap_or(8);
            let p = num("p").unwrap_or(1);
            if !n.is_power_of_two() {
                return bad(format!("scrypt n must be a power of two, got {n}"));
            }
            if n.trailing_zeros() > MAX_SCRYPT_LOG_N {
                return bad(format!("scrypt n = {n} exceeds 2^{MAX_SCRYPT_LOG_N}"));
            }
            if r > MAX_SCRYPT_R || p > MAX_SCRYPT_P {
                return bad(format!("scrypt r/p out of range: r={r}, p={p}"));
            }
            // 128 * r * n is scrypt's working-set size.
            let mem = 128u64.saturating_mul(r).saturating_mul(n);
            if mem > MAX_KDF_MEMORY_BYTES {
                return bad(format!("scrypt would need {mem} bytes, over the {MAX_KDF_MEMORY_BYTES} limit"));
            }
        }
        "pbkdf2" => {
            let c = num("c").ok_or_else(|| KeystoreError::Vault("keystore json: pbkdf2 `c` missing".into()))?;
            if c > MAX_PBKDF2_C {
                return bad(format!("pbkdf2 c = {c} exceeds {MAX_PBKDF2_C}"));
            }
        }
        other => return bad(format!("unsupported kdf {other:?}")),
    }
    Ok(())
}

/// Longest message we will sign. Anything larger cannot be shown to a human in
/// full, and a signer must not sign what an approver cannot display.
const MAX_MESSAGE_BYTES: usize = 8 * 1024;

/// Refuse text whose rendering can differ from its bytes: C0/C1 controls,
/// bidirectional overrides, and zero-width characters. These are exactly the
/// characters that let a display say one thing while the signature covers
/// another.
pub(crate) fn check_displayable(text: &str, what: &str) -> Result<()> {
    if text.len() > MAX_MESSAGE_BYTES {
        return Err(KeystoreError::InvalidParams(format!(
            "{what}: {} bytes exceeds the {MAX_MESSAGE_BYTES}-byte limit",
            text.len()
        )));
    }
    for c in text.chars() {
        let bad = matches!(c,
            // C0 controls except tab/newline/carriage-return, and DEL + C1.
            '\u{0}'..='\u{8}' | '\u{B}' | '\u{C}' | '\u{E}'..='\u{1F}' | '\u{7F}'..='\u{9F}'
            // Bidirectional embedding/override/isolate controls.
            | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}'
            // Zero-width and other invisible formatting.
            | '\u{200B}'..='\u{200D}' | '\u{2060}' | '\u{FEFF}'
        );
        if bad {
            return Err(KeystoreError::InvalidParams(format!(
                "{what}: refusing U+{:04X} — it can render differently than it signs",
                c as u32
            )));
        }
    }
    Ok(())
}

fn parse_bytes(s: &str) -> Result<Bytes> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Bytes::new());
    }
    let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    let v = hex::decode(h).map_err(|e| KeystoreError::InvalidParams(format!("data: {e}")))?;
    Ok(Bytes::from(v))
}

fn signer_from_hex(priv_hex: &str) -> Result<PrivateKeySigner> {
    let h = priv_hex.trim();
    let h = h.strip_prefix("0x").or_else(|| h.strip_prefix("0X")).unwrap_or(h);
    let bytes = hex::decode(h).map_err(|e| KeystoreError::InvalidKey(e.to_string()))?;
    PrivateKeySigner::from_slice(&bytes).map_err(|e| KeystoreError::InvalidKey(e.to_string()))
}

fn signer_from_mnemonic(phrase: &str, passphrase: &str, index: u32) -> Result<PrivateKeySigner> {
    let mut builder = MnemonicBuilder::<English>::default()
        .phrase(phrase)
        .derivation_path(eth_derivation_path(index))
        .map_err(|e| KeystoreError::InvalidParams(e.to_string()))?;
    if !passphrase.is_empty() {
        builder = builder.password(passphrase);
    }
    builder.build().map_err(|e| KeystoreError::InvalidParams(e.to_string()))
}

/// A temp file that deletes itself. `eth-keystore` is path-based, so importing
/// a vault JSON requires putting it on disk briefly.
///
/// The previous version wrote `$TMPDIR/logos-ks-import-<nanos>.json` at the
/// default umask (0644) and **never removed it**, so every import left a
/// world-readable copy of the caller's encrypted vault — salt and KDF params
/// included — in shared temp, under a guessable name.
struct TempVaultFile(PathBuf);

impl Drop for TempVaultFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

impl TempVaultFile {
    fn path(&self) -> &Path {
        &self.0
    }
}

fn tempfile_with(contents: &str) -> Result<TempVaultFile> {
    use rand::RngCore;
    use std::io::Write;

    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut path = std::env::temp_dir();
    path.push(format!("logos-ks-import-{}.json", hex::encode(nonce)));

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true); // O_EXCL: never adopt an existing path
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&path).map_err(|e| KeystoreError::Io(e.to_string()))?;
    // Own the path before the first fallible write, so an error still unlinks.
    let guard = TempVaultFile(path);
    f.write_all(contents.as_bytes()).map_err(|e| KeystoreError::Io(e.to_string()))?;
    f.sync_all().map_err(|e| KeystoreError::Io(e.to_string()))?;
    Ok(guard)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::consensus::transaction::SignerRecoverable;
    use alloy::eips::eip2718::Decodable2718;
    use alloy::primitives::address;

    // Foundry's canonical test mnemonic → account 0.
    const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";
    const ACCT0: Address = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
    const ACCT0_PK: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    // ---- hardening regressions -------------------------------------------
    // One test per defect fixed in this pass. Each asserts the DANGEROUS
    // behaviour is gone, not merely that the happy path still works.

    /// Build a signed tx for `tx_json`. There is no unlock step: the key is
    /// derived from the vault password for this one signature.
    fn sign_with(dir: &std::path::Path, tx_json: &str) -> Result<String> {
        let ks = Keystore::new(dir);
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        ks.sign_transaction(&addr.to_string(), "pw", tx_json, 1)
    }

    #[test]
    fn there_is_no_unlocked_state_to_reuse() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let a = ks.import_private_key(ACCT0_PK, "pw").unwrap().to_string();

        // A correct-password signature must not leave anything behind that a
        // later wrong-password call could spend. Under the old cache, the
        // second call here succeeded.
        assert!(ks.sign_message(&a, "pw", "first").is_ok());
        assert!(ks.sign_message(&a, "wrong", "second").is_err());
        assert!(ks.sign_message(&a, "pw", "third").is_ok());
    }

    #[test]
    fn nonce_that_overflows_u64_is_rejected_not_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let tx = |nonce: &str| {
            format!(
                r#"{{"to":"0x{:x}","value":"0x0","nonce":"{nonce}","gas_limit":"0x5208",
                    "fee_mode":"eip1559","max_fee_per_gas":"0x1","max_priority_fee_per_gas":"0x1"}}"#,
                ACCT0
            )
        };
        // 0x10000000000000005 truncates to 0x5 in a wrapping cast: the two used
        // to produce byte-identical signed transactions.
        let big = sign_with(dir.path(), &tx("0x10000000000000005"));
        assert!(big.is_err(), "an out-of-range nonce must not sign");
        let small = sign_with(dir.path(), &tx("0x5")).unwrap();
        assert!(!small.is_empty());
    }

    #[test]
    fn unknown_tx_fields_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let tx = format!(
            r#"{{"to":"0x{:x}","value":"0x0","nonce":"0x1","gas_limit":"0x5208",
                "fee_mode":"eip1559","max_fee_per_gas":"0x1","max_priority_fee_per_gas":"0x1",
                "chainId":"0x1"}}"#,
            ACCT0
        );
        // A camelCase or typo'd key silently defaulted to 0 before.
        assert!(sign_with(dir.path(), &tx).is_err());
    }

    #[test]
    fn absent_to_is_refused_rather_than_deploying_a_contract() {
        let dir = tempfile::tempdir().unwrap();
        let no_to = r#"{"value":"0x0","nonce":"0x1","gas_limit":"0x5208","fee_mode":"eip1559",
                        "max_fee_per_gas":"0x1","max_priority_fee_per_gas":"0x1"}"#;
        let blank_to = r#"{"to":"","value":"0x0","nonce":"0x1","gas_limit":"0x5208","fee_mode":"eip1559",
                           "max_fee_per_gas":"0x1","max_priority_fee_per_gas":"0x1"}"#;
        for tx in [no_to, blank_to] {
            let e = sign_with(dir.path(), tx).unwrap_err();
            assert!(format!("{e}").contains("`to` is required"), "got {e}");
        }
        // Deployment is still possible, but only when asked for explicitly.
        let create = r#"{"create":true,"value":"0x0","nonce":"0x1","gas_limit":"0x5208",
                         "data":"0x60006000","fee_mode":"eip1559",
                         "max_fee_per_gas":"0x1","max_priority_fee_per_gas":"0x1"}"#;
        assert!(sign_with(dir.path(), create).is_ok());
    }

    #[test]
    fn fee_mode_is_a_closed_set_and_is_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let tx = |mode: &str| {
            format!(
                r#"{{"to":"0x{:x}","value":"0x0","nonce":"0x1","gas_limit":"0x5208",
                    "fee_mode":"{mode}","gas_price":"0x7",
                    "max_fee_per_gas":"0x1","max_priority_fee_per_gas":"0x1"}}"#,
                ACCT0
            )
        };
        // " legacy" used to fall through to EIP-1559 and silently drop gas_price.
        assert!(sign_with(dir.path(), &tx(" legacy")).is_ok());
        // A typo used to be indistinguishable from the default.
        let e = sign_with(dir.path(), &tx("eip1599")).unwrap_err();
        assert!(format!("{e}").contains("fee_mode"), "got {e}");
    }

    #[test]
    fn an_access_list_is_refused_rather_than_silently_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let tx = format!(
            r#"{{"to":"0x{:x}","value":"0x0","nonce":"0x1","gas_limit":"0x5208",
                "fee_mode":"eip1559","max_fee_per_gas":"0x1","max_priority_fee_per_gas":"0x1",
                "access_list":[{{"address":"0x{:x}","storageKeys":[]}}]}}"#,
            ACCT0, ACCT0
        );
        let e = sign_with(dir.path(), &tx).unwrap_err();
        assert!(format!("{e}").contains("access list"), "got {e}");
    }

    #[test]
    fn sign_message_refuses_text_that_renders_differently_than_it_signs() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        let a = addr.to_string();

        for bad in ["send 1 ETH\u{202E}drow", "zero\u{200B}width", "nul\u{0}byte"] {
            assert!(ks.sign_message(&a, "pw", bad).is_err(), "must refuse {bad:?}");
        }
        // Ordinary text, including newlines, still signs.
        assert!(ks.sign_message(&a, "pw", "hello\nworld").is_ok());
        // And an oversize message is refused rather than signed unseen.
        let huge = "a".repeat(MAX_MESSAGE_BYTES + 1);
        assert!(ks.sign_message(&a, "pw", &huge).is_err());
    }

    #[test]
    fn hostile_kdf_params_are_rejected_before_any_derivation() {
        // n = u32::MAX asked scrypt for a ~4 TiB allocation, aborting the
        // process from a single caller-supplied file.
        let hostile = r#"{"version":3,"crypto":{"kdf":"scrypt","ciphertext":"00","cipher":"aes-128-ctr",
            "cipherparams":{"iv":"00"},"mac":"00",
            "kdfparams":{"n":4294967295,"r":8,"p":1,"dklen":32,"salt":"00"}}}"#;
        // u32::MAX is not a power of two, so it is caught by that rule first.
        let e = check_kdf_params(hostile).unwrap_err();
        assert!(format!("{e}").contains("power of two"), "got {e}");

        // A power of two that is merely far too large hits the size rule, which
        // is the one that stops the enormous allocation.
        let huge = hostile.replace("4294967295", "1073741824"); // 2^30
        let e = check_kdf_params(&huge).unwrap_err();
        assert!(format!("{e}").contains("exceeds") || format!("{e}").contains("bytes"), "got {e}");

        // Oversized r is refused too.
        let big_r = hostile.replace("4294967295", "262144").replace("\"r\":8", "\"r\":64");
        assert!(check_kdf_params(&big_r).is_err());

        // A standard vault passes.
        let ok = hostile.replace("4294967295", "262144");
        assert!(check_kdf_params(&ok).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn the_vault_directory_and_files_are_not_group_or_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("vaults");
        let ks = Keystore::new(&sub);
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();

        let dmode = std::fs::metadata(&sub).unwrap().permissions().mode() & 0o777;
        assert_eq!(dmode, 0o700, "vault dir was {dmode:o}");
        let vault = sub.join(format!("{:x}.json", addr));
        let fmode = std::fs::metadata(&vault).unwrap().permissions().mode() & 0o777;
        assert_eq!(fmode, 0o600, "vault file was {fmode:o}");
    }

    #[test]
    fn importing_a_vault_leaves_no_temp_copy_behind() {
        let src = tempfile::tempdir().unwrap();
        let ks_src = Keystore::new(src.path());
        let addr = ks_src.import_private_key(ACCT0_PK, "pw").unwrap();
        let json = ks_src.export_keystore_json(&addr.to_string(), "pw").unwrap();

        let before = temp_import_files();
        let dst = tempfile::tempdir().unwrap();
        Keystore::new(dst.path()).import_keystore_json(&json, "pw", "pw2").unwrap();
        let after = temp_import_files();
        assert_eq!(before, after, "import left a copy of the vault in the temp dir");
    }

    fn temp_import_files() -> Vec<std::ffi::OsString> {
        let mut v: Vec<_> = std::fs::read_dir(std::env::temp_dir())
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name())
            .filter(|n| n.to_string_lossy().starts_with("logos-ks-import-"))
            .collect();
        v.sort();
        v
    }

    #[test]
    fn hd_derivation_matches_known_vector() {
        let signer = signer_from_mnemonic(TEST_MNEMONIC, "", 0).unwrap();
        assert_eq!(signer.address(), ACCT0);
        let signer1 = signer_from_mnemonic(TEST_MNEMONIC, "", 1).unwrap();
        assert_eq!(signer1.address(), address!("70997970C51812dc3A010C7d01b50e0d17dc79C8"));
    }

    #[test]
    fn private_key_import_matches_address() {
        let signer = signer_from_hex(ACCT0_PK).unwrap();
        assert_eq!(signer.address(), ACCT0);
    }

    #[test]
    fn create_mnemonic_lengths() {
        assert_eq!(Keystore::create_mnemonic(12).unwrap().split_whitespace().count(), 12);
        assert_eq!(Keystore::create_mnemonic(24).unwrap().split_whitespace().count(), 24);
        assert!(Keystore::create_mnemonic(13).is_err());
    }

    #[test]
    fn vault_roundtrip_and_listing() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        assert_eq!(addr, ACCT0);
        assert!(ks.has_address(&addr.to_string()));
        assert_eq!(ks.list_accounts(), vec![ACCT0]);

        // The vault password is the gate on every signature — there is no
        // unlocked state to be in.
        assert!(ks.signer_for(&addr.to_string(), "wrong").is_err());
        assert_eq!(ks.signer_for(&addr.to_string(), "pw").unwrap().address(), ACCT0);
    }

    #[test]
    fn sign_message_recovers_signer() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        let sig_hex = ks.sign_message(&addr.to_string(), "pw", "hello logos").unwrap();
        let sig: alloy::primitives::Signature =
            sig_hex.strip_prefix("0x").unwrap().parse::<alloy::primitives::Signature>().unwrap();
        let recovered = sig.recover_address_from_msg("hello logos").unwrap();
        assert_eq!(recovered, ACCT0);
    }

    #[test]
    fn a_wrong_password_cannot_sign() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        assert!(ks.sign_message(&addr.to_string(), "wrong", "x").is_err());
    }

    #[test]
    fn sign_digest_recovers_signer_from_prehash() {
        use alloy::primitives::b256;
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        // A raw 32-byte digest (e.g. an ERC-4337 UserOperation hash) — signed with
        // no prefix, so it recovers via the prehash (not the EIP-191 msg) path.
        let digest = b256!("00000000000000000000000000000000000000000000000000000000deadbeef");
        let sig_hex = ks.sign_digest(&addr.to_string(), "pw", &digest.to_string()).unwrap();
        let sig: alloy::primitives::Signature =
            sig_hex.strip_prefix("0x").unwrap().parse().unwrap();
        assert_eq!(sig.recover_address_from_prehash(&digest).unwrap(), ACCT0);
        // Bare (no 0x) hex also accepted; wrong length rejected.
        assert!(ks.sign_digest(&addr.to_string(), "pw", &hex::encode(digest)).is_ok());
        assert!(ks.sign_digest(&addr.to_string(), "pw", "0x1234").is_err());
    }

    #[test]
    fn sign_digest_requires_the_vault_password() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        let digest = "0x00000000000000000000000000000000000000000000000000000000deadbeef";
        assert!(ks.sign_digest(&addr.to_string(), "wrong", digest).is_err());
    }

    #[test]
    fn sign_eip1559_recovers_signer() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        let unsigned = serde_json::json!({
            "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            "value": "0xde0b6b3a7640000",
            "nonce": "0x0",
            "gas_limit": "0x5208",
            "max_fee_per_gas": "0x77359400",
            "max_priority_fee_per_gas": "0x3b9aca00",
            "fee_mode": "eip1559"
        })
        .to_string();
        let raw = ks.sign_transaction(&addr.to_string(), "pw", &unsigned, 1).unwrap();
        assert!(raw.starts_with("0x02")); // typed EIP-1559 envelope
        // decode + recover
        let bytes = hex::decode(raw.strip_prefix("0x").unwrap()).unwrap();
        let env = TxEnvelope::decode_2718(&mut bytes.as_slice()).unwrap();
        assert_eq!(env.recover_signer().unwrap(), ACCT0);
    }

    #[test]
    fn sign_legacy_recovers_signer() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        let unsigned = serde_json::json!({
            "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            "value": "0x1",
            "nonce": "0x0",
            "gas_limit": "0x5208",
            "gas_price": "0x3b9aca00",
            "fee_mode": "legacy"
        })
        .to_string();
        let raw = ks.sign_transaction(&addr.to_string(), "pw", &unsigned, 1).unwrap();
        let bytes = hex::decode(raw.strip_prefix("0x").unwrap()).unwrap();
        let env = TxEnvelope::decode_2718(&mut bytes.as_slice()).unwrap();
        assert_eq!(env.recover_signer().unwrap(), ACCT0);
    }
}
