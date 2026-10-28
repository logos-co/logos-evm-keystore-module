//! The keystore's bookkeeping — wallets, accounts and their names — one document per seed, sealed
//! under this module's key for that seed from the signer manager (`data_key(seed, "index")`). A
//! locked seed's document is not read, so nothing lists its accounts.
//!
//! Plain in `seeds.json` is only what a locked seed needs: its groups' sealed unlock roots, the
//! random ids of its files, and a check of its unlock key that finds it again on a re-import. A
//! seed whose key hasn't come yet (just added, or no signer manager here) keeps its document plain
//! in `index.pending.json` until it does; `""` there holds what no seed claims.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use logos_signer_interface::wallets::{self, DataKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::atomic;
use crate::keystore::{Group, KeystoreError, Provenance};
use crate::layout::{Doc, Root, Slot};
use crate::unlockkey::SealedRoot;

type Result<T> = std::result::Result<T, KeystoreError>;

/// The scope this module asks `data_key` for.
pub const SCOPE: &str = "index";
/// The pending document's slot for entries no seed claims.
pub const UNCLAIMED: &str = "";
const NAME: &str = "keystore_module index";
const VERSION: u32 = 1;

/// This process's keys for the seeds it opened, by the keystore's own seed id. Shared with the
/// thread that asks the signer manager for them.
#[derive(Clone, Default)]
pub struct KeyRing(Arc<Mutex<BTreeMap<String, DataKey>>>);

impl KeyRing {
    fn get(&self, seed: &str) -> Option<DataKey> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).get(seed).cloned()
    }

    fn insert(&self, seed: &str, key: DataKey) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).insert(seed.to_string(), key);
    }

    /// Forget every key: every sealed seed reads as locked again.
    pub fn clear(&self) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

/// One seed's bookkeeping, as the four documents older builds kept beside the vaults.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SeedDoc {
    #[serde(default)]
    pub groups: BTreeMap<String, Group>,
    #[serde(default)]
    pub accounts: BTreeMap<String, Provenance>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default, rename = "groupLabels")]
    pub group_labels: BTreeMap<String, String>,
    /// The wallet's name, by its seed: one per seed, over every account file of it.
    #[serde(default, rename = "walletNames")]
    pub wallet_names: BTreeMap<String, String>,
}

impl SeedDoc {
    fn is_empty(&self) -> bool {
        self.groups.is_empty()
            && self.accounts.is_empty()
            && self.labels.is_empty()
            && self.group_labels.is_empty()
            && self.wallet_names.is_empty()
    }

    /// Add what `other` holds that this doesn't.
    fn absorb(&mut self, other: &SeedDoc) {
        for (k, v) in &other.groups {
            self.groups.entry(k.clone()).or_insert_with(|| v.clone());
        }
        for (k, v) in &other.accounts {
            self.accounts.entry(k.clone()).or_insert_with(|| v.clone());
        }
        for (k, v) in &other.labels {
            self.labels.entry(k.clone()).or_insert_with(|| v.clone());
        }
        for (k, v) in &other.group_labels {
            self.group_labels.entry(k.clone()).or_insert_with(|| v.clone());
        }
        for (k, v) in &other.wallet_names {
            self.wallet_names.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
}

/// What `seeds.json` keeps of a seed: what unlocks it, and the files that are its.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SeedFiles {
    /// [`check_of`] its unlock key at index 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<String>,
    /// Its groups, each with its sealed unlock root where it keeps one.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub groups: BTreeMap<String, Option<SealedRoot>>,
    /// Its accounts' vault ids.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vaults: Vec<String>,
    /// The kept phrases its groups were made from.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub phrases: Vec<String>,
}

impl SeedFiles {
    fn of(doc: &SeedDoc) -> Self {
        let check = doc
            .groups
            .values()
            .find_map(|g| g.check.clone())
            .or_else(|| doc.accounts.values().find_map(|p| p.check.clone()));
        let mut vaults: Vec<String> = doc.accounts.values().filter(|p| !p.vault.is_empty()).map(|p| p.vault.clone()).collect();
        vaults.sort();
        vaults.dedup();
        let mut phrases: Vec<String> = doc.groups.values().filter_map(|g| g.phrase.clone()).collect();
        phrases.sort();
        phrases.dedup();
        SeedFiles {
            check,
            groups: doc.groups.iter().map(|(id, g)| (id.clone(), g.unlock.clone())).collect(),
            vaults,
            phrases,
        }
    }
}

/// A seed's check: finds a locked seed again from its unlock key, and nothing else. Salted by the
/// seed's random id, over a key that is never public.
pub fn check_of(seed: &str, unlock_key: &[u8; 33]) -> String {
    let mut h = Sha256::new();
    h.update(b"logos-keystore-unlock-check-v1\0");
    h.update(seed.as_bytes());
    h.update(b"\0");
    h.update(unlock_key);
    hex::encode(h.finalize())
}

/// The files of seeds that are locked here: listed by nothing until they unlock.
#[derive(Clone, Debug, Default)]
pub struct Hidden {
    pub vaults: BTreeSet<String>,
    pub groups: BTreeSet<String>,
    pub phrases: BTreeSet<String>,
}

#[derive(Default, Serialize, Deserialize)]
struct SealedFile {
    v: u32,
    seeds: BTreeMap<String, String>,
}

/// The index as read once: every seed's plain files, its box, and what this process can open.
pub struct State {
    pub seeds: BTreeMap<String, SeedFiles>,
    sealed: BTreeMap<String, String>,
    pending: BTreeMap<String, SeedDoc>,
    open: BTreeMap<String, SeedDoc>,
}

fn aad(seed: &str) -> String {
    format!("{NAME}\0{seed}")
}

fn corrupt(doc: Doc, e: impl std::fmt::Display) -> KeystoreError {
    KeystoreError::Corrupt(doc.file().into(), e.to_string())
}

fn read<T: serde::de::DeserializeOwned + Default>(root: &Root, doc: Doc) -> Result<T> {
    match std::fs::read_to_string(root.path(&Slot::Doc(doc))) {
        Ok(txt) => serde_json::from_str(&txt).map_err(|e| corrupt(doc, e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(corrupt(doc, e)),
    }
}

fn write<T: Serialize>(root: &Root, doc: Doc, value: &T) -> Result<()> {
    let txt = serde_json::to_string_pretty(value).map_err(|e| KeystoreError::Vault(e.to_string()))?;
    atomic::write_doc(root.as_path(), &root.path(&Slot::Doc(doc)), txt.as_bytes()).map_err(|e| KeystoreError::Io(e.to_string()))
}

fn seal(key: &DataKey, seed: &str, doc: &SeedDoc) -> Result<String> {
    let plain = Zeroizing::new(serde_json::to_vec(doc).map_err(|e| KeystoreError::Vault(e.to_string()))?);
    wallets::seal(key, &plain, &aad(seed)).map_err(|e| KeystoreError::Vault(e.to_string()))
}

fn unseal(key: &DataKey, seed: &str, sealed: &str) -> Result<SeedDoc> {
    let plain = wallets::open(key, sealed, &aad(seed)).map_err(|e| KeystoreError::Vault(e.to_string()))?;
    serde_json::from_slice(&plain).map_err(|e| corrupt(Doc::Index, format!("{seed}: {e}")))
}

/// Read the index, opening every box this process holds the key for.
pub fn load(root: &Root, keys: &KeyRing) -> Result<State> {
    let seeds: BTreeMap<String, SeedFiles> = read(root, Doc::Seeds)?;
    let file: SealedFile = read(root, Doc::Index)?;
    if !file.seeds.is_empty() && file.v != VERSION {
        return Err(corrupt(Doc::Index, format!("version {}", file.v)));
    }
    let pending: BTreeMap<String, SeedDoc> = read(root, Doc::Pending)?;
    let mut open = BTreeMap::new();
    for (seed, sealed) in &file.seeds {
        // A key of another generation (another process sealed it again) leaves it locked here.
        if let Some(doc) = keys.get(seed).and_then(|k| unseal(&k, seed, sealed).ok()) {
            open.insert(seed.clone(), doc);
        }
    }
    Ok(State { seeds, sealed: file.seeds, pending, open })
}

impl State {
    fn locked(&self, seed: &str) -> bool {
        self.sealed.contains_key(seed) && !self.open.contains_key(seed)
    }

    /// Every document this process can read, by seed.
    fn readable(&self) -> BTreeMap<String, &SeedDoc> {
        let mut out: BTreeMap<String, &SeedDoc> = self.open.iter().map(|(s, d)| (s.clone(), d)).collect();
        for (s, d) in &self.pending {
            // A box beside a pending copy is a seal a crash interrupted: the box is the truth.
            if !self.sealed.contains_key(s) {
                out.insert(s.clone(), d);
            }
        }
        out
    }

    /// Every readable seed's bookkeeping, as one.
    pub fn merged(&self) -> SeedDoc {
        let mut out = SeedDoc::default();
        for doc in self.readable().values() {
            out.absorb(doc);
        }
        out
    }

    /// Seeds whose box this process can't open.
    pub fn locked_seeds(&self) -> Vec<String> {
        self.sealed.keys().filter(|s| !self.open.contains_key(*s)).cloned().collect()
    }

    pub fn is_locked(&self, seed: &str) -> bool {
        self.locked(seed)
    }

    /// The files of every locked seed.
    pub fn hidden(&self) -> Hidden {
        let mut out = Hidden::default();
        for seed in self.locked_seeds() {
            if let Some(f) = self.seeds.get(&seed) {
                out.vaults.extend(f.vaults.iter().cloned());
                out.groups.extend(f.groups.keys().cloned());
                out.phrases.extend(f.phrases.iter().cloned());
            }
        }
        out
    }

    /// The locked seed whose unlock key this is, if any.
    pub fn locked_seed_of(&self, unlock_key: &[u8; 33]) -> Option<String> {
        self.locked_seeds()
            .into_iter()
            .find(|s| self.seeds.get(s).and_then(|f| f.check.as_deref()) == Some(check_of(s, unlock_key).as_str()))
    }

    /// The seed whose plain files name this group, readable or not.
    pub fn seed_naming_group(&self, group: &str) -> Option<String> {
        self.seeds.iter().find(|(_, f)| f.groups.contains_key(group)).map(|(s, _)| s.clone())
    }

    /// The seed whose plain files name this vault.
    pub fn seed_naming_vault(&self, vault: &str) -> Option<String> {
        self.seeds.iter().find(|(_, f)| f.vaults.iter().any(|v| v == vault)).map(|(s, _)| s.clone())
    }

    /// Seeds still waiting for a key, and sealed seeds this process can't open with the
    /// generation their box needs.
    pub fn closed(&self) -> Vec<(String, Option<u32>)> {
        let mut out: Vec<(String, Option<u32>)> = self
            .sealed
            .iter()
            .filter(|(s, _)| !self.open.contains_key(*s))
            .map(|(s, b)| (s.clone(), wallets::generation(b).ok()))
            .collect();
        out.extend(
            self.pending
                .keys()
                .filter(|s| s.as_str() != UNCLAIMED && !self.sealed.contains_key(*s))
                .map(|s| (s.clone(), None)),
        );
        out
    }
}

/// The seed a group belongs to: its record's seed link, else itself; a group with no record here
/// belongs to the seed whose files name it.
pub fn group_seed(doc: &SeedDoc, state: &State, group: &str) -> String {
    match doc.groups.get(group) {
        Some(g) => g.seed.as_ref().map_or_else(|| group.to_string(), |s| s.id.clone()),
        None => state.seed_naming_group(group).unwrap_or_default(),
    }
}

/// The seed an account belongs to: its group's, else its own as an imported key.
pub fn account_seed(doc: &SeedDoc, state: &State, p: &Provenance) -> String {
    if !p.group.is_empty() {
        return group_seed(doc, state, &p.group);
    }
    if !p.seed.is_empty() {
        return p.seed.clone();
    }
    state.seed_naming_vault(&p.vault).unwrap_or_default()
}

/// Every entry to the seed it belongs to. An entry of a seed this process can't open stays where
/// no seed claims it rather than being written into a box it can't read.
fn partition(doc: &SeedDoc, state: &State) -> BTreeMap<String, SeedDoc> {
    let mut out: BTreeMap<String, SeedDoc> = BTreeMap::new();
    let claim = |seed: String| if state.locked(&seed) { UNCLAIMED.to_string() } else { seed };
    for (id, g) in &doc.groups {
        out.entry(claim(group_seed(doc, state, id))).or_default().groups.insert(id.clone(), g.clone());
    }
    for (addr, p) in &doc.accounts {
        out.entry(claim(account_seed(doc, state, p))).or_default().accounts.insert(addr.clone(), p.clone());
    }
    for (addr, label) in &doc.labels {
        let seed = doc.accounts.get(addr).map(|p| account_seed(doc, state, p)).unwrap_or_default();
        out.entry(claim(seed)).or_default().labels.insert(addr.clone(), label.clone());
    }
    for (id, name) in &doc.group_labels {
        out.entry(claim(group_seed(doc, state, id))).or_default().group_labels.insert(id.clone(), name.clone());
    }
    for (seed, name) in &doc.wallet_names {
        out.entry(claim(seed.clone())).or_default().wallet_names.insert(seed.clone(), name.clone());
    }
    out
}

/// Write `doc` back as every readable seed's bookkeeping: each seed's part sealed under its key,
/// or pending until it has one, and its plain files beside. Locked seeds are left as they are.
pub fn store(root: &Root, keys: &KeyRing, state: &State, doc: &SeedDoc) -> Result<()> {
    let mut parts = partition(doc, state);
    let readable = state.readable();
    let mut seeds = state.seeds.clone();
    let mut sealed = state.sealed.clone();
    let mut pending = state.pending.clone();
    let touched: BTreeSet<String> = readable.keys().chain(parts.keys()).cloned().collect();
    for seed in touched {
        let part = parts.remove(&seed).unwrap_or_default();
        let unchanged = readable.get(&seed).is_some_and(|d| **d == part);
        // A pending seed whose key has come is sealed even when nothing else moved.
        let unsealed = seed != UNCLAIMED && !sealed.contains_key(&seed) && keys.get(&seed).is_some();
        if unchanged && !unsealed {
            continue;
        }
        if seed == UNCLAIMED {
            if part.is_empty() {
                pending.remove(&seed);
            } else {
                pending.insert(seed, part);
            }
            continue;
        }
        if part.is_empty() {
            sealed.remove(&seed);
            pending.remove(&seed);
            seeds.remove(&seed);
            continue;
        }
        seeds.insert(seed.clone(), SeedFiles::of(&part));
        match keys.get(&seed) {
            Some(key) => {
                sealed.insert(seed.clone(), seal(&key, &seed, &part)?);
                pending.remove(&seed);
            }
            None => {
                pending.insert(seed, part);
            }
        }
    }
    // The plain files first: a crash between leaves a file named by a seed and listed by none,
    // never one a locked seed holds and nothing hides.
    if seeds != state.seeds {
        write(root, Doc::Seeds, &seeds)?;
    }
    if sealed != state.sealed {
        write(root, Doc::Index, &SealedFile { v: VERSION, seeds: sealed })?;
    }
    if pending != state.pending {
        write(root, Doc::Pending, &pending)?;
    }
    Ok(())
}

/// Open a seed's document with `box_key`, the key of its box's generation, and seal it again under
/// `current`, which this process keeps. A pending document is sealed for the first time. `false`
/// when this keystore keeps nothing for the seed.
pub fn open_seed(root: &Root, keys: &KeyRing, seed: &str, box_key: &DataKey, current: &DataKey) -> Result<bool> {
    let state = load(root, keys)?;
    let doc = match (state.sealed.get(seed), state.pending.get(seed)) {
        (Some(b), _) => unseal(box_key, seed, b)?,
        (None, Some(d)) if seed != UNCLAIMED => d.clone(),
        _ => return Ok(false),
    };
    let mut sealed = state.sealed.clone();
    sealed.insert(seed.to_string(), seal(current, seed, &doc)?);
    write(root, Doc::Index, &SealedFile { v: VERSION, seeds: sealed })?;
    if state.pending.contains_key(seed) {
        let mut pending = state.pending.clone();
        pending.remove(seed);
        write(root, Doc::Pending, &pending)?;
    }
    let files = SeedFiles::of(&doc);
    if state.seeds.get(seed) != Some(&files) {
        let mut seeds = state.seeds.clone();
        seeds.insert(seed.to_string(), files);
        write(root, Doc::Seeds, &seeds)?;
    }
    keys.insert(seed, current.clone());
    Ok(true)
}
