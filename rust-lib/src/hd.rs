//! HD derivation core — pure logic, no I/O and no Logos runtime, so it is exercised by
//! `cargo test --no-default-features` exactly like `gate.rs`.
//!
//! `coins-bip32` does the BIP-32 arithmetic. What lives here is the part that has
//! historically made a wallet derive addresses no other wallet recovers: the path, the
//! version bytes, and how long seed material stays alive.

use std::fmt;

use alloy::primitives::Address;
use alloy::signers::local::{
    coins_bip39::{English, Mnemonic},
    PrivateKeySigner,
};
use coins_bip32::{
    ecdsa::SigningKey,
    enc::{MainnetEncoder, XKeyEncoder},
    primitives::{Hint, XKeyInfo},
    xkeys::{Parent, XPriv},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::keystore::{check_displayable, KeystoreError};

type Result<T> = std::result::Result<T, KeystoreError>;

/// BIP-44 purpose, and the SLIP-44 coin type for Ethereum. Neither is configurable
/// anywhere in this module: a "custom path" that can change them is a way to make funds
/// unrecoverable, dressed as a feature.
pub const PURPOSE: u32 = 44;
pub const COIN_TYPE_ETH: u32 = 60;
/// Anything at or above this is a hardened index.
pub const HARDENED: u32 = 0x8000_0000;
/// The key we may retain sits three levels down: `m/44'/60'/<account>'`.
const ACCOUNT_DEPTH: u8 = 3;

fn bad(msg: String) -> KeystoreError {
    KeystoreError::InvalidParams(msg)
}

fn bip32(e: impl fmt::Display) -> KeystoreError {
    KeystoreError::InvalidParams(format!("bip32: {e}"))
}

/// A validated `m/44'/60'/<account>'/<change>/<index>`.
///
/// Constructed only through `new` or `parse`, both of which enforce the layout — so a
/// value of this type cannot name a path BIP-44 does not define.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bip44Path {
    pub account: u32,
    pub change: u32,
    pub index: u32,
}

impl Bip44Path {
    pub fn new(account: u32, change: u32, index: u32) -> Result<Self> {
        if account >= HARDENED {
            return Err(bad(format!("bip44Account must be below 2^31, got {account}")));
        }
        if change > 1 {
            return Err(bad(format!("change must be 0 (external) or 1 (change), got {change}")));
        }
        if index >= HARDENED {
            return Err(bad(format!("index must be below 2^31, got {index}")));
        }
        Ok(Self { account, change, index })
    }

    /// Parse a full five-level path. See [`split_path`] for why we never hand the string
    /// to the crate's own parser.
    pub fn parse(s: &str) -> Result<Self> {
        let c = split_path(s, 5)?;
        expect_prefix(s, &c)?;
        if c[3].1 || c[4].1 {
            return Err(bad(format!("path {s:?}: change and index must not be hardened")));
        }
        Self::new(c[2].0, c[3].0, c[4].0)
    }

    /// Parse the three-level account prefix a group is pinned to, returning its account.
    pub fn parse_account_prefix(s: &str) -> Result<u32> {
        let c = split_path(s, 3)?;
        expect_prefix(s, &c)?;
        Ok(c[2].0)
    }

    /// `m/44'/60'/<account>'` — what an EXTKEY group stores, and only that.
    pub fn account_prefix(account: u32) -> String {
        format!("m/{PURPOSE}'/{COIN_TYPE_ETH}'/{account}'")
    }
}

impl fmt::Display for Bip44Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "m/{PURPOSE}'/{COIN_TYPE_ETH}'/{}'/{}/{}",
            self.account, self.change, self.index
        )
    }
}

/// One segment: ASCII digits, optionally hardened by a trailing `'` or `h`.
fn parse_component(seg: &str) -> Result<(u32, bool)> {
    let (digits, hardened) = match seg.strip_suffix('\'').or_else(|| seg.strip_suffix('h')) {
        Some(d) => (d, true),
        None => (seg, false),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad(format!("path segment {seg:?} is not a plain index")));
    }
    let v: u32 = digits
        .parse()
        .map_err(|_| bad(format!("path segment {seg:?} does not fit in u32")))?;
    // coins-bip32's `harden_index` is a bare `index + 2^31`: 2147483648' panics in debug
    // and wraps in release, deriving a different key than the string names.
    if v >= HARDENED {
        return Err(bad(format!("path segment {seg:?} is at or above the 2^31 index limit")));
    }
    Ok((v, hardened))
}

/// Split a path into exactly `want` levels below `m`.
///
/// The leading `m` is matched HERE, positionally. coins-bip32 filters an `m` segment
/// wherever it appears, so `"m/44'/60'/m/0/0"` parses there as a four-level path — a
/// silently different account.
fn split_path(s: &str, want: usize) -> Result<Vec<(u32, bool)>> {
    let mut it = s.split('/');
    if it.next() != Some("m") {
        return Err(bad(format!("path {s:?} must start with \"m/\"")));
    }
    let segs: Vec<&str> = it.collect();
    if segs.len() != want {
        return Err(bad(format!(
            "path {s:?} has {} levels below m, expected {want}",
            segs.len()
        )));
    }
    segs.iter().map(|seg| parse_component(seg)).collect()
}

fn expect_prefix(s: &str, c: &[(u32, bool)]) -> Result<()> {
    if c[0] != (PURPOSE, true) || c[1] != (COIN_TYPE_ETH, true) {
        return Err(bad(format!(
            "path {s:?}: this keystore derives only m/{PURPOSE}'/{COIN_TYPE_ETH}'/… (Ethereum)"
        )));
    }
    if !c[2].1 {
        return Err(bad(format!("path {s:?}: the BIP-44 account level must be hardened")));
    }
    Ok(())
}

/// A BIP-39 seed: the one place 64 bytes of root secret exist in this module.
///
/// Wiped on drop, so every path that builds one wipes it — including the error paths,
/// because nothing else ever owns it.
pub struct Seed(Zeroizing<[u8; 64]>);

impl Drop for Seed {
    fn drop(&mut self) {
        #[cfg(test)]
        probe::note();
        self.0.zeroize();
    }
}

/// Redacted: a seed must never reach a log through a stray `{:?}`.
impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed(<redacted>)")
    }
}

impl Zeroize for Seed {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for Seed {}

impl Seed {
    /// BIP-39 phrase (+ optional passphrase) → seed.
    pub fn from_mnemonic(phrase: &str, bip39_passphrase: &str) -> Result<Self> {
        check_passphrase(bip39_passphrase)?;
        // The phrase's whitespace IS normalized (a pasted phrase carries newlines and
        // double spaces) and the passphrase's is not: `to_seed` re-renders the phrase from
        // the wordlist before salting, so only the words matter, while the passphrase is
        // salted byte-for-byte.
        let words = Zeroizing::new(phrase.split_whitespace().collect::<Vec<_>>().join(" "));
        let mnemonic = Mnemonic::<English>::new_from_phrase(&words)
            .map_err(|e| KeystoreError::InvalidParams(format!("mnemonic: {e}")))?;
        // `to_seed` builds two heap strings of its own (the phrase, and "mnemonic" +
        // passphrase) and does not wipe them; we can only own what it hands back.
        let mut raw = mnemonic
            .to_seed(Some(bip39_passphrase))
            .map_err(|e| KeystoreError::InvalidParams(format!("mnemonic: {e}")))?;
        let seed = Self(Zeroizing::new(raw));
        raw.zeroize();
        Ok(seed)
    }

    /// The root node. `Hint::Legacy`, never the crate's default — see [`encode_account_key`].
    pub fn master(&self) -> Result<XPriv> {
        master_from_seed(self.0.as_slice())
    }

    /// The account key at `m/44'/60'/<account>'`. This is the deepest key this module
    /// will ever store: it reaches every address under one Ethereum account and nothing
    /// else, because the account level is hardened.
    pub fn account_key(&self, account: u32) -> Result<XPriv> {
        if account >= HARDENED {
            return Err(bad(format!("bip44Account must be below 2^31, got {account}")));
        }
        let indices = [PURPOSE + HARDENED, COIN_TYPE_ETH + HARDENED, account + HARDENED];
        derive_indices(&self.master()?, &indices)
    }

    pub fn signer_at(&self, path: &Bip44Path) -> Result<PrivateKeySigner> {
        signer_in_account(&self.account_key(path.account)?, path.change, path.index)
    }

    #[cfg(test)]
    pub(crate) fn bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// The BIP-32 root node for raw seed bytes, hinted Legacy so it serializes as `xprv…`.
pub fn master_from_seed(seed: &[u8]) -> Result<XPriv> {
    XPriv::root_from_seed(seed, Some(Hint::Legacy)).map_err(bip32)
}

fn derive_indices(key: &XPriv, indices: &[u32]) -> Result<XPriv> {
    let mut cur = key.clone();
    for i in indices {
        cur = cur.derive_child(*i).map_err(bip32)?;
    }
    Ok(cur)
}

/// The two non-hardened levels below an account key: `<change>/<index>`.
pub fn key_in_account(account_key: &XPriv, change: u32, index: u32) -> Result<XPriv> {
    if change > 1 {
        return Err(bad(format!("change must be 0 (external) or 1 (change), got {change}")));
    }
    if index >= HARDENED {
        return Err(bad(format!("index must be below 2^31, got {index}")));
    }
    derive_indices(account_key, &[change, index])
}

pub fn signer_in_account(account_key: &XPriv, change: u32, index: u32) -> Result<PrivateKeySigner> {
    signer_of(&key_in_account(account_key, change, index)?)
}

pub fn address_in_account(account_key: &XPriv, change: u32, index: u32) -> Result<Address> {
    Ok(signer_in_account(account_key, change, index)?.address())
}

pub fn signer_of(key: &XPriv) -> Result<PrivateKeySigner> {
    let k: &SigningKey = key.as_ref();
    let mut buf = Zeroizing::new([0u8; 32]);
    buf.copy_from_slice(k.to_bytes().as_slice());
    PrivateKeySigner::from_slice(buf.as_slice()).map_err(|e| KeystoreError::InvalidKey(e.to_string()))
}

/// Serialize an account key as `xprv…`, never `zprv…`.
///
/// coins-bip32 picks the version bytes from a *hint*, and the hint a mnemonic's master key
/// carries is SegWit — so the unnormalized form of an Ethereum account key serializes as a
/// BIP-84 `zprv`, which no Ethereum tool accepts. The key bytes are the same either way,
/// which is precisely why no address-level test catches it.
pub fn encode_account_key(key: &XPriv) -> Result<Zeroizing<String>> {
    let info: &XKeyInfo = key.as_ref();
    if info.depth != ACCOUNT_DEPTH {
        return Err(bad(format!(
            "refusing to store a depth-{} extended key; only an account key (depth {ACCOUNT_DEPTH}) may be kept",
            info.depth
        )));
    }
    encode_key(key)
}

/// Serialize any extended private key, re-hinted Legacy. `encode_account_key` is the only
/// caller outside tests — a depth other than the account level has no business being stored.
pub(crate) fn encode_key(key: &XPriv) -> Result<Zeroizing<String>> {
    let info: &XKeyInfo = key.as_ref();
    let k: &SigningKey = key.as_ref();
    let normalized = XPriv::new(
        SigningKey::from_bytes(&k.to_bytes()).map_err(bip32)?,
        XKeyInfo { hint: Hint::Legacy, ..*info },
    );
    MainnetEncoder::xpriv_to_base58(&normalized).map(Zeroizing::new).map_err(bip32)
}

/// Read an account key back. A root key is refused: a group opened from one would reach
/// every BIP-44 account and every coin, not just its own, and nothing downstream would say so.
pub fn decode_account_key(s: &str) -> Result<XPriv> {
    let key = MainnetEncoder::xpriv_from_base58(s.trim()).map_err(bip32)?;
    let info: &XKeyInfo = key.as_ref();
    if info.depth != ACCOUNT_DEPTH {
        return Err(bad(format!(
            "extended key is at depth {}, expected an account key at depth {ACCOUNT_DEPTH}",
            info.depth
        )));
    }
    Ok(key)
}

/// The BIP-39 passphrase is part of the secret and is deliberately NOT trimmed: a trailing
/// space is a different passphrase, and trimming would derive accounts no other wallet
/// recovers.
///
/// Non-ASCII is refused rather than derived. BIP-39 salts with the NFKD form of the
/// passphrase; coins-bip39 salts with the raw bytes it was given, so `"café"` typed NFC and
/// NFD produce different accounts here and a normalizing wallet disagrees with both. ASCII
/// is NFKD-invariant, so refusing now keeps the option of normalizing later without
/// changing any address that is derivable today.
fn check_passphrase(p: &str) -> Result<()> {
    check_displayable(p, "bip39 passphrase")?;
    if !p.is_ascii() {
        return Err(bad(
            "bip39 passphrase must be ASCII: BIP-39 salts with the NFKD form and this build \
             salts with the raw bytes, so a non-ASCII passphrase can derive different \
             accounts here than in another wallet"
                .into(),
        ));
    }
    Ok(())
}

/// Test-only drop counter. Proves the wipe actually runs on a given path — including the
/// error paths — without reading freed memory. Thread-local, so parallel tests do not
/// observe each other's seeds.
#[cfg(test)]
pub(crate) mod probe {
    use std::cell::Cell;

    thread_local! {
        static SEED_DROPS: Cell<usize> = const { Cell::new(0) };
    }

    pub(crate) fn note() {
        let _ = SEED_DROPS.try_with(|c| c.set(c.get() + 1));
    }

    pub(crate) fn count() -> usize {
        SEED_DROPS.with(|c| c.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    // ── Published vectors ────────────────────────────────────────────────
    // Every expected value below comes from a published document, not from this crate:
    // the BIP-32 chains from the BIP-32 specification, the BIP-39 rows from
    // trezor/python-mnemonic's `vectors.json` (the reference set BIP-39 points at), and
    // the Ethereum keys from Anvil's published development accounts. They were each
    // re-derived by an independent implementation before being pinned here, so a test
    // passing is not `coins-bip32` agreeing with itself.

    // BIP-32 test vector 1, transcribed from the BIP-32 document.
    const V1_SEED: &str = "000102030405060708090a0b0c0d0e0f";
    const V1: &[(&[u32], &str)] = &[
        // m
        (&[], "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"),
        // m/0'
        (&[0x80000000], "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"),
        // m/0'/1
        (&[0x80000000, 1], "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"),
        // m/0'/1/2'
        (&[0x80000000, 1, 0x80000002], "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"),
        // m/0'/1/2'/2
        (&[0x80000000, 1, 0x80000002, 2], "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"),
        // m/0'/1/2'/2/1000000000
        (&[0x80000000, 1, 0x80000002, 2, 1000000000], "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"),
    ];
    // BIP-32 test vector 2, transcribed from the BIP-32 document.
    const V2_SEED: &str = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
    const V2: &[(&[u32], &str)] = &[
        // m
        (&[], "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"),
        // m/0
        (&[0], "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"),
        // m/0/2147483647'
        (&[0, 0xFFFFFFFF], "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"),
        // m/0/2147483647'/1
        (&[0, 0xFFFFFFFF, 1], "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"),
        // m/0/2147483647'/1/2147483646'
        (&[0, 0xFFFFFFFF, 1, 0xFFFFFFFE], "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"),
        // m/0/2147483647'/1/2147483646'/2
        (&[0, 0xFFFFFFFF, 1, 0xFFFFFFFE, 2], "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"),
    ];
    // BIP-32 test vector 3, transcribed from the BIP-32 document.
    const V3_SEED: &str = "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be";
    const V3: &[(&[u32], &str)] = &[
        // m
        (&[], "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"),
        // m/0'
        (&[0x80000000], "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"),
    ];

    // BIP-39 vectors, transcribed from trezor/python-mnemonic vectors.json
    // (the reference set the BIP-39 document points at). Passphrase: "TREZOR".
    const BIP39_PASSPHRASE: &str = "TREZOR";
    /// (phrase, 64-byte seed, root xprv)
    const BIP39: &[(&str, &str, &str)] = &[
        ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
         "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
         "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"),
        ("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
         "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
         "xprv9s21ZrQH143K2V4oox4M8Zmhi2Fjx5XK4Lf7GKRvPSgydU3mjZuKGCTg7UPiBUD7ydVPvSLtg9hjp7MQTYsW67rZHAXeccqYqrsx8LcXnyd"),
        ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
         "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
         "xprv9s21ZrQH143K3mEDrypcZ2usWqFgzKB6jBBx9B6GfC7fu26X6hPRzVjzkqkPvDqp6g5eypdk6cyhGnBngbjeHTe4LsuLG1cCmKJka5SMkmU"),
        ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
         "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
         "xprv9s21ZrQH143K32qBagUJAMU2LsHg3ka7jqMcV98Y7gVeVyNStwYS3U7yVVoDZ4btbRNf4h6ibWpY22iRmXq35qgLs79f312g2kj5539ebPM"),
        ("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
         "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
         "xprv9s21ZrQH143K2WFF16X85T2QCpndrGwx6GueB72Zf3AHwHJaknRXNF37ZmDrtHrrLSHvbuRejXcnYxoZKvRquTPyp2JiNG3XcjQyzSEgqCB"),
        ("ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
         "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
         "xprv9s21ZrQH143K2oZ9stBYpoaZ2ktHj7jLz7iMqpgg1En8kKFTXJHsjxry1JbKH19YrDTicVwKPehFKTbmaxgVEc5TpHdS1aYhB2s9aFJBeJH"),
        ("light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
         "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",
         "xprv9s21ZrQH143K3wtsvY8L2aZyxkiWULZH4vyQE5XkHTXkmx8gHo6RUEfH3Jyr6NwkJhvano7Xb2o6UqFKWHVo5scE31SGDCAUsgVhiUuUDyh"),
        ("void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
         "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
         "xprv9s21ZrQH143K39rnQJknpH1WEPFJrzmAqqasiDcVrNuk926oizzJDDQkdiTvNPr2FYDYzWgiMiC63YmfPAa2oPyNB23r2g7d1yiK6WpqaQS"),
    ];

    /// Foundry/Anvil's default development mnemonic, and its published account #0 key.
    const FOUNDRY: &str = "test test test test test test test test test test test junk";
    const FOUNDRY_PK0: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    /// The addresses Anvil prints on startup for `FOUNDRY`, m/44'/60'/0'/0/0..3. Published
    /// by Foundry, so a test that asserts them fails if derivation moves wholesale.
    const FOUNDRY_ACCTS: [Address; 4] = [
        address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
        address!("70997970C51812dc3A010C7d01b50e0d17dc79C8"),
        address!("3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"),
        address!("90F79bf6EB2c4f870365E785982E1f101E93b906"),
    ];
    /// The all-zero-entropy BIP-39 phrase, the most widely republished test wallet there is.
    const ABANDON: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn seed(phrase: &str, passphrase: &str) -> Seed {
        Seed::from_mnemonic(phrase, passphrase).unwrap()
    }

    fn addr_at(phrase: &str, passphrase: &str, account: u32, change: u32, index: u32) -> Address {
        let p = Bip44Path::new(account, change, index).unwrap();
        seed(phrase, passphrase).signer_at(&p).unwrap().address()
    }

    #[test]
    fn bip32_published_vectors_reproduce_exactly() {
        for (label, hex_seed, chains) in
            [("1", V1_SEED, V1), ("2", V2_SEED, V2), ("3", V3_SEED, V3)]
        {
            let root = master_from_seed(&hex::decode(hex_seed).unwrap()).unwrap();
            for (indices, expected) in chains {
                let key = derive_indices(&root, indices).unwrap();
                assert_eq!(
                    encode_key(&key).unwrap().as_str(),
                    *expected,
                    "BIP-32 vector {label}, chain {indices:?}"
                );
            }
        }
    }

    #[test]
    fn bip39_published_vectors_reproduce_seed_and_root() {
        for (phrase, expected_seed, expected_root) in BIP39 {
            let s = seed(phrase, BIP39_PASSPHRASE);
            assert_eq!(hex::encode(s.bytes()), *expected_seed, "seed for {phrase:?}");
            assert_eq!(
                encode_key(&s.master().unwrap()).unwrap().as_str(),
                *expected_root,
                "root xprv for {phrase:?}"
            );
        }
    }

    #[test]
    fn ethereum_addresses_at_consecutive_indices_match_the_published_keys() {
        // Anvil prints these on startup; index 0's private key is the anchor that ties our
        // path to a published key rather than to our own arithmetic.
        for (i, want) in FOUNDRY_ACCTS.iter().enumerate() {
            assert_eq!(addr_at(FOUNDRY, "", 0, 0, i as u32), *want, "index {i}");
        }

        let s = seed(FOUNDRY, "");
        let signer = s.signer_at(&Bip44Path::new(0, 0, 0).unwrap()).unwrap();
        assert_eq!(hex::encode(signer.to_bytes()), FOUNDRY_PK0);

        // The change level is real, not decoration: 0 and 1 are different accounts.
        assert_eq!(addr_at(FOUNDRY, "", 0, 1, 0), address!("4b39F7b0624b9dB86AD293686bc38B903142dbBc"));
        assert_ne!(addr_at(FOUNDRY, "", 0, 1, 0), addr_at(FOUNDRY, "", 0, 0, 0));

        // A second, independently published wallet, so the match is not one lucky phrase.
        assert_eq!(addr_at(ABANDON, "", 0, 0, 0), address!("9858EfFD232B4033E47d90003D41EC34EcaEda94"));
        assert_eq!(addr_at(ABANDON, "", 0, 0, 1), address!("6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0"));
        assert_eq!(addr_at(ABANDON, "", 0, 0, 2), address!("b6716976A3ebe8D39aCEB04372f22Ff8e6802D7A"));
    }

    #[test]
    fn a_bip39_passphrase_yields_a_completely_different_wallet() {
        // Same phrase, one extra secret: a disjoint tree, not a variation on the first.
        let plain: Vec<Address> = (0..3).map(|i| addr_at(ABANDON, "", 0, 0, i)).collect();
        let with_pass: Vec<Address> = (0..3).map(|i| addr_at(ABANDON, "TREZOR", 0, 0, i)).collect();

        assert_eq!(with_pass[0], address!("9c32F71D4DB8Fb9e1A58B0a80dF79935e7256FA6"));
        assert_eq!(with_pass[1], address!("7AF7283bd1462C3b957e8FAc28Dc19cBbF2FAdfe"));
        assert_eq!(with_pass[2], address!("05f48E30fCb69ADcd2A591Ebc7123be8BE72D7a1"));
        for a in &with_pass {
            assert!(!plain.contains(a), "{a} appears in both trees");
        }

        // And it is not trimmed: a trailing space is a different passphrase. Trimming here
        // would derive accounts no other wallet recovers.
        assert_ne!(addr_at(ABANDON, "TREZOR ", 0, 0, 0), with_pass[0]);
    }

    #[test]
    fn bip44_hardens_purpose_coin_and_account_and_nothing_below() {
        let s = seed(FOUNDRY, "");
        let root = s.master().unwrap();
        let want = s.signer_at(&Bip44Path::new(0, 0, 0).unwrap()).unwrap().address();

        let h = HARDENED;
        // The layout, spelled out as raw indices: 44' / 60' / 0' / 0 / 0.
        let same = derive_indices(&root, &[44 + h, 60 + h, h, 0, 0]).unwrap();
        assert_eq!(address_in_account(&derive_indices(&root, &[44 + h, 60 + h, h]).unwrap(), 0, 0).unwrap(), want);
        assert_eq!(signer_of(&same).unwrap().address(), want);

        // Move the hardening by one level, in either direction, and it is a different key.
        for wrong in [
            &[44, 60, 0, 0, 0][..],                    // nothing hardened
            &[44 + h, 60 + h, h, h, 0][..],            // change hardened
            &[44 + h, 60 + h, h, 0, h][..],            // index hardened
            &[44 + h, 60, h, 0, 0][..],                // coin type not hardened
            &[44, 60 + h, h, 0, 0][..],                // purpose not hardened
        ] {
            let other = derive_indices(&root, wrong).unwrap();
            assert_ne!(signer_of(&other).unwrap().address(), want, "indices {wrong:?}");
        }

        // Four levels is not five: m/44'/60'/0'/0 is its own key, not the account at index 0.
        let four = derive_indices(&root, &[44 + h, 60 + h, h, 0]).unwrap();
        assert_ne!(signer_of(&four).unwrap().address(), want);
    }

    #[test]
    fn an_account_key_reaches_every_index_under_it() {
        // This is what makes storing the ACCOUNT key sufficient — and why the storage
        // choice has to be per group rather than per account.
        let s = seed(FOUNDRY, "");
        let account = s.account_key(0).unwrap();

        // Against the PUBLISHED addresses, not against `signer_at`: comparing the account
        // key's walk to the seed's walk only proves the two agree, so a derivation that
        // moved wholesale would move both sides together and still pass.
        for (index, want) in FOUNDRY_ACCTS.iter().enumerate() {
            assert_eq!(address_in_account(&account, 0, index as u32).unwrap(), *want, "index {index}");
        }
        // The change level too, published in `ethereum_addresses_at_consecutive_indices…`.
        assert_eq!(
            address_in_account(&account, 1, 0).unwrap(),
            address!("4b39F7b0624b9dB86AD293686bc38B903142dbBc")
        );

        // Having anchored both, the two routes may be compared: whatever the seed reaches,
        // the stored account key reaches without it.
        for change in 0..=1 {
            for index in 0..3 {
                let full = s.signer_at(&Bip44Path::new(0, change, index).unwrap()).unwrap().address();
                assert_eq!(address_in_account(&account, change, index).unwrap(), full);
            }
        }
    }

    #[test]
    fn an_account_key_cannot_reach_another_bip44_account() {
        // And this is what bounds it: the account level is hardened, so account 1 is
        // unreachable from account 0's key however far you walk.
        let s = seed(FOUNDRY, "");
        let account0 = s.account_key(0).unwrap();
        let other = addr_at(FOUNDRY, "", 1, 0, 0);
        assert_eq!(other, address!("8C8d35429F74ec245F8Ef2f4Fd1e551cFF97d650"));

        for change in 0..=1 {
            for index in 0..64 {
                assert_ne!(address_in_account(&account0, change, index).unwrap(), other);
            }
        }
    }

    #[test]
    fn a_stored_account_key_is_an_xprv_never_a_zprv() {
        // Invisible in every address-level test: the key bytes are identical and only the
        // four version bytes differ, but no Ethereum tool accepts a zprv.
        let s = seed(FOUNDRY, "");
        let account = s.account_key(0).unwrap();
        let encoded = encode_account_key(&account).unwrap();
        assert!(encoded.starts_with("xprv"), "encoded as {}", &encoded[..4]);
        assert_eq!(
            encoded.as_str(),
            "xprv9yeny6n2dNUokQFykGoZU6BDLeKbEBUoBeCFe2VF6MXdrHrprMYRc4tddncDRxrJCy7GtPDk68zRcgWtGFveqdCV5NyhZwVgMoZVbTm78vx"
        );

        // The crate's own default hint is SegWit, which is where the zprv came from.
        let unhinted = XPriv::root_from_seed(s.bytes(), None)
            .unwrap()
            .derive_path("m/44'/60'/0'")
            .unwrap();
        assert!(MainnetEncoder::xpriv_to_base58(&unhinted).unwrap().starts_with("zprv"));

        // Round-trip: the decoded key derives the same addresses.
        let back = decode_account_key(&encoded).unwrap();
        assert_eq!(
            address_in_account(&back, 0, 7).unwrap(),
            address_in_account(&account, 0, 7).unwrap()
        );
    }

    #[test]
    fn a_root_extended_key_is_refused_where_an_account_key_is_expected() {
        // Storing the root would hand over every coin and every BIP-44 account to buy
        // exactly the addresses the account key already reaches.
        let s = seed(FOUNDRY, "");
        let root = encode_key(&s.master().unwrap()).unwrap();
        assert!(root.starts_with("xprv"));
        assert!(decode_account_key(&root).is_err(), "a root xprv must not open a group");
        assert!(encode_account_key(&s.master().unwrap()).is_err(), "a root xprv must not be stored");

        // Nor is a key from the wrong depth accepted in either direction.
        let too_deep = key_in_account(&s.account_key(0).unwrap(), 0, 0).unwrap();
        assert!(encode_account_key(&too_deep).is_err());
    }

    #[test]
    fn paths_that_would_derive_something_plausible_and_wrong_are_refused() {
        for bad_path in [
            // coins-bip32 filters an `m` anywhere, turning this into a FOUR-level path.
            "m/44'/60'/m/0/0",
            // `harden_index` is a bare add: this panics in debug and wraps in release.
            "m/44'/60'/2147483648'/0/0",
            "m/44'/60'/0'/0/2147483648",
            // No root marker, so the first level is not pinned to purpose 44'.
            "44'/60'/0'/0/0",
            // Another coin's tree, and another purpose's.
            "m/44'/61'/0'/0/0",
            "m/49'/60'/0'/0/0",
            // Hardening in the wrong place, and missing where BIP-44 requires it.
            "m/44'/60'/0/0/0",
            "m/44'/60'/0'/0'/0",
            "m/44'/60'/0'/0/0'",
            // Wrong number of levels.
            "m/44'/60'/0'/0",
            "m/44'/60'/0'/0/0/0",
            "m",
            // Malformed segments that a permissive parser would coerce.
            "m/44'/60'/0'/0/",
            "m/44'/60'/0'/0/+1",
            "m/44'/60'/0'/0/-1",
            "m/44'/60'/0'/0/0x1",
            "m/44'/60'/0'/2/0",
            "",
        ] {
            assert!(Bip44Path::parse(bad_path).is_err(), "{bad_path:?} must be refused");
        }

        // The prefix parser refuses the same class, so a hand-edited groups.json cannot
        // redirect derivation into another coin's tree.
        for bad_prefix in ["m/44'/60'/0'/0", "m/44'/0'/0'", "44'/60'/0'", "m/44'/60'/0", "m/44'/60'/m"] {
            assert!(Bip44Path::parse_account_prefix(bad_prefix).is_err(), "{bad_prefix:?}");
        }
        assert_eq!(Bip44Path::parse_account_prefix("m/44'/60'/3'").unwrap(), 3);

        // `h` is the other spelling of `'`, and both must mean hardened.
        assert_eq!(Bip44Path::parse("m/44h/60h/0h/0/5").unwrap(), Bip44Path::new(0, 0, 5).unwrap());
    }

    #[test]
    fn a_canonical_path_round_trips_through_parse_and_display() {
        for (a, c, i) in [(0, 0, 0), (3, 1, 7), (0x7FFF_FFFF, 1, 0x7FFF_FFFF)] {
            let p = Bip44Path::new(a, c, i).unwrap();
            assert_eq!(Bip44Path::parse(&p.to_string()).unwrap(), p);
        }
        assert_eq!(Bip44Path::new(2, 1, 9).unwrap().to_string(), "m/44'/60'/2'/1/9");
        assert_eq!(Bip44Path::account_prefix(2), "m/44'/60'/2'");
        assert!(Bip44Path::new(HARDENED, 0, 0).is_err());
        assert!(Bip44Path::new(0, 2, 0).is_err());
        assert!(Bip44Path::new(0, 0, HARDENED).is_err());
    }

    #[test]
    fn an_empty_passphrase_derives_what_the_pre_hd_import_derived() {
        // The salt is "mnemonic" + passphrase, so an empty passphrase and no passphrase are
        // the same salt. Accounts imported before this feature existed must not move.
        let m = Mnemonic::<English>::new_from_phrase(FOUNDRY).unwrap();
        assert_eq!(seed(FOUNDRY, "").bytes()[..], m.to_seed(None).unwrap()[..]);

        // And the phrase's own whitespace is not part of the secret, so a pasted phrase
        // with newlines derives the same wallet as the canonical single-spaced form.
        let spaced = format!("  {}\n", FOUNDRY.replace(' ', "  \n "));
        assert_eq!(addr_at(&spaced, "", 0, 0, 0), addr_at(FOUNDRY, "", 0, 0, 0));
    }

    #[test]
    fn a_non_ascii_bip39_passphrase_is_refused_rather_than_silently_diverging() {
        for p in ["café", "café", "日本語", "naïve"] {
            let e = Seed::from_mnemonic(FOUNDRY, p).unwrap_err();
            assert!(format!("{e}").contains("ASCII"), "got {e}");
        }
        // The displayable rules still apply on top: a bidi override in a passphrase can
        // make the field render one thing and salt another.
        assert!(Seed::from_mnemonic(FOUNDRY, "pass\u{202E}word").is_err());
        // Ordinary ASCII, including a space and punctuation, is accepted verbatim.
        assert!(Seed::from_mnemonic(FOUNDRY, "correct horse battery staple!").is_ok());
    }

    #[test]
    fn seed_material_is_wiped_on_success_and_on_every_error_path() {
        let start = probe::count();

        // Success: the seed is dropped when the derivation returns.
        let _ = addr_at(FOUNDRY, "", 0, 0, 0);
        assert_eq!(probe::count(), start + 1, "a successful derivation must wipe its seed");

        // Failure AFTER the seed exists — an out-of-range level, refused mid-derivation.
        {
            let s = seed(FOUNDRY, "");
            assert!(key_in_account(&s.account_key(0).unwrap(), 2, 0).is_err());
            assert!(s.account_key(HARDENED).is_err());
        }
        assert_eq!(probe::count(), start + 2, "a failed derivation must wipe its seed too");

        // Failure BEFORE it exists: a refused phrase or passphrase builds no seed at all,
        // which is the same property stated the other way round.
        assert!(Seed::from_mnemonic("not a mnemonic at all", "").is_err());
        assert!(Seed::from_mnemonic(FOUNDRY, "café").is_err());
        assert_eq!(probe::count(), start + 2);

        // And the wipe is a real wipe, not just a drop.
        let mut s = seed(FOUNDRY, "");
        assert!(s.bytes().iter().any(|b| *b != 0));
        s.zeroize();
        assert!(s.bytes().iter().all(|b| *b == 0));
    }
}
