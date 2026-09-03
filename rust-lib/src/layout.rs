//! Every path this keystore may write, and the classification of everything found under it.
//!
//! One authority, so a guard can no longer check one representation while the data sits in
//! another. `Slot` is the only path builder and `Slot::rel` matches exhaustively, so a new
//! variant does not compile until it has a place. `scan` is total: every entry is either a
//! directory it descends into or a path it files under one of `Scan`'s buckets, the last of
//! which is "unexplained" — so a write that invents a path is reported anyway.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// Staging directories are named after what they hold, so a copy a SIGKILL leaves behind is
/// nameable — and therefore classifiable and deletable.
pub const STAGE_PREFIX: &str = ".stage-";
/// What follows `STAGE_PREFIX` for scratch space: `.stage-import-<32 hex>`.
const IMPORT_INFIX: &str = "import-";
/// The one file an import stage holds — the caller's vault, on disk because
/// `eth_keystore::decrypt_key` is path-based.
const IMPORT_FILE: &str = "import.json";
/// Deepest path the layout explains: `groups/.stage-<id>/<id>.json`.
const MAX_DEPTH: usize = 3;

/// A bookkeeping document. Not a secret — an attacker holding the directory already reads
/// the addresses off the vault filenames.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Doc {
    Groups,
    Accounts,
    Labels,
    /// Wallet names. Its own document rather than a field of `groups.json`, so a name is
    /// still readable for a group that document does not know about.
    GroupLabels,
}

impl Doc {
    pub fn file(self) -> &'static str {
        match self {
            Doc::Groups => "groups.json",
            Doc::Accounts => "accounts.json",
            Doc::Labels => "labels.json",
            Doc::GroupLabels => "group-labels.json",
        }
    }

    pub const ALL: [Doc; 4] = [Doc::Groups, Doc::Accounts, Doc::Labels, Doc::GroupLabels];

    fn of_file(name: &str) -> Option<Doc> {
        Doc::ALL.into_iter().find(|d| d.file() == name)
    }
}

/// What a staging directory holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StageKind {
    /// `<ks>/.stage-<addr>` — an account vault being written or re-encrypted.
    Vault(String),
    /// `<ks>/groups/.stage-<id>` — a group's derivation key.
    Group(String),
    /// `<ks>/.stage-import-<nonce>` — scratch for a write we hand to a path-based library.
    Import(String),
}

impl StageKind {
    /// Fresh scratch space. Random so two imports cannot collide on one path, and inside
    /// `<ks>/` so the scan names it and `settle` sweeps what a kill leaves.
    pub fn import() -> Self {
        use rand::RngCore;
        let mut b = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut b);
        StageKind::Import(hex::encode(b))
    }
}

/// Every path this keystore may write. A new one is a new variant, and `rel` below then
/// fails to compile until it is given a name the scan can recognise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Slot {
    /// `<ks>/<addr>.json` — one account's scrypt vault.
    Vault(String),
    /// `<ks>/groups/<id>.json` — one group's derivation key.
    GroupKey(String),
    /// `<ks>/groups` — the key directory itself.
    GroupDir,
    Doc(Doc),
    Stage(StageKind),
    /// `<ks>/.lock` — cross-process exclusion for the bookkeeping read-modify-write.
    Lock,
}

impl Slot {
    /// The ONLY path builder in this crate.
    pub fn rel(&self) -> PathBuf {
        match self {
            Slot::Vault(addr) => PathBuf::from(format!("{addr}.json")),
            Slot::GroupKey(id) => Path::new("groups").join(format!("{id}.json")),
            Slot::GroupDir => PathBuf::from("groups"),
            Slot::Doc(d) => PathBuf::from(d.file()),
            Slot::Stage(StageKind::Vault(addr)) => PathBuf::from(format!("{STAGE_PREFIX}{addr}")),
            Slot::Stage(StageKind::Group(id)) => Path::new("groups").join(format!("{STAGE_PREFIX}{id}")),
            Slot::Stage(StageKind::Import(n)) => PathBuf::from(format!("{STAGE_PREFIX}{IMPORT_INFIX}{n}")),
            Slot::Lock => PathBuf::from(".lock"),
        }
    }

    /// The file a staging directory holds, once its write lands.
    pub fn staged_name(kind: &StageKind) -> String {
        match kind {
            StageKind::Vault(addr) => format!("{addr}.json"),
            StageKind::Group(id) => format!("{id}.json"),
            StageKind::Import(_) => IMPORT_FILE.to_string(),
        }
    }
}

/// The keystore directory. There is deliberately no `join` on it: a writer that wants a
/// path has to name a `Slot`, and `as_path` exists only for the three operations that take
/// the directory itself — creating it, reading it, and staging inside it.
#[derive(Clone, Debug)]
pub struct Root(PathBuf);

impl Root {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self(dir.into())
    }

    pub fn path(&self, slot: &Slot) -> PathBuf {
        self.0.join(slot.rel())
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Resolve a path the scan itself reported. The components are re-validated so a
    /// hand-supplied string can never reach outside `<ks>/`.
    pub fn reported(&self, rel: &str) -> Option<PathBuf> {
        let mut p = self.0.clone();
        for part in rel.split('/') {
            if part.is_empty() || part == "." || part == ".." || part.contains(std::path::MAIN_SEPARATOR) {
                return None;
            }
            p.push(part);
        }
        Some(p)
    }
}

/// A path present but unreadable. Its own type because "unreadable" has to stay
/// distinguishable from "absent": treating the two alike is the defect this module keeps
/// finding, one directory at a time.
#[derive(Clone, Debug)]
pub struct Unreadable {
    pub what: String,
    pub why: String,
}

/// Everything `<ks>/` holds, classified. Nothing is dropped: the last two buckets take
/// whatever the layout does not explain, so a guard is never looking somewhere the data is
/// not.
#[derive(Clone, Debug, Default)]
pub struct Scan {
    /// Live account vaults at `<ks>/<addr>.json`, as lowercase hex without `0x`.
    pub vaults: Vec<String>,
    /// Account vaults an interrupted write left at `<ks>/.stage-<addr>/<addr>.json`. Every
    /// bit as live: same ciphertext, same password, same account.
    pub staged_vaults: Vec<String>,
    /// Staging directories for a vault, whether or not a key is still inside.
    pub vault_stages: Vec<String>,
    /// Scratch directories left by an interrupted import. They hold the CALLER's vault
    /// ciphertext — offline-crackable, so named here rather than left in shared temp.
    pub import_stages: Vec<String>,
    /// Live derivation keys at `<ks>/groups/<id>.json`.
    pub keys: Vec<String>,
    /// Derivation keys left at `<ks>/groups/.stage-<id>/<id>.json`.
    pub staged: Vec<String>,
    /// Documents a write did not finish publishing. Explained, so they are not treated as
    /// key material — but reported, so they are never silently dropped either.
    pub doc_stages: Vec<String>,
    /// Unexplained material that COULD be a derivation key — a key that opens a whole
    /// wallet — wherever under `<ks>/` it sits. See `could_be_key` for the evidence.
    pub possible_keys: Vec<String>,
    /// Unexplained material that could not be one. At worst one account, so this reports
    /// rather than refusing — a keystore must not be bricked by a `.DS_Store`.
    pub unexplained: Vec<String>,
    /// Every symlink found, as `<rel> -> <target>`. A link is unexplained material like any
    /// other; this says WHERE it points, because what it aims at is outside this scan.
    pub links: Vec<String>,
}

impl Scan {
    fn sort(&mut self) {
        for v in [
            &mut self.vaults,
            &mut self.staged_vaults,
            &mut self.vault_stages,
            &mut self.import_stages,
            &mut self.keys,
            &mut self.staged,
            &mut self.doc_stages,
            &mut self.possible_keys,
            &mut self.unexplained,
            &mut self.links,
        ] {
            v.sort();
            v.dedup();
        }
    }

    /// Ids naming a derivation key on disk, wherever it sits. The set that must be deletable.
    pub fn key_ids(&self) -> Vec<String> {
        let mut out = self.keys.clone();
        out.extend(self.staged.iter().cloned());
        out.sort();
        out.dedup();
        out
    }

    /// Everything here that could open a WHOLE wallet: live derivation keys, staged ones,
    /// and unexplained material the evidence cannot rule out.
    ///
    /// The ONE query a decision about minting asks. Reading a bucket instead asks where
    /// material sits; this asks what it could be, which is the question.
    pub fn possible_key_material(&self) -> Vec<String> {
        let rel = |p: PathBuf| p.to_string_lossy().into_owned();
        let mut out: Vec<String> =
            self.keys.iter().map(|id| rel(Slot::GroupKey(id.clone()).rel())).collect();
        out.extend(self.staged.iter().map(|id| {
            let k = StageKind::Group(id.clone());
            rel(Slot::Stage(k.clone()).rel().join(Slot::staged_name(&k)))
        }));
        out.extend(self.possible_keys.iter().cloned());
        out.sort();
        out.dedup();
        out
    }

    /// Everything the layout does not explain, both severities. What a reader is SHOWN: a
    /// bucket is a severity, never a filter on what gets reported.
    pub fn stray(&self) -> Vec<String> {
        let mut out = self.unexplained.clone();
        out.extend(self.possible_keys.iter().cloned());
        out.sort();
        out.dedup();
        out
    }

    /// Every path the layout does not explain, wherever it sits. The set a caller may name
    /// to remove — `stray` plus the document writes that were interrupted rather than stray.
    pub fn unexplained_all(&self) -> Vec<String> {
        let mut out = self.stray();
        out.extend(self.doc_stages.iter().cloned());
        out.sort();
        out.dedup();
        out
    }

    /// Addresses whose key is on disk, at either path.
    pub fn account_ids(&self) -> Vec<String> {
        let mut out = self.vaults.clone();
        out.extend(self.staged_vaults.iter().cloned());
        out.sort();
        out.dedup();
        out
    }
}

/// What one entry under `<ks>/` is. Directories have their own variants rather than being
/// skipped: a classifier that only ran on FILES made an unrecognised directory — including
/// an empty one where a key belongs — invisible to every authority above it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    Vault(String),
    StagedVault(String),
    GroupKey(String),
    StagedGroupKey(String),
    Doc(Doc),
    DocStage,
    Lock,
    GroupDir,
    VaultStage(String),
    GroupStage(String),
    ImportStage(String),
    ImportScratch(String),
    /// Not from any `Slot`. Treated as material until someone proves otherwise.
    Unexplained,
}

/// What the filesystem says one entry is. Every one of these reaches `classify`, so a name
/// recognised for one kind is refused for the others — a directory named like a vault is
/// not a vault, and a symlink is never either.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
    /// Socket, fifo, device — anything else `read_dir` can hand back.
    Other,
}

impl Kind {
    pub const ALL: [Kind; 4] = [Kind::File, Kind::Dir, Kind::Symlink, Kind::Other];

    /// From a `read_dir` file type, which describes the LINK and never its target.
    fn of(t: std::fs::FileType) -> Kind {
        if t.is_symlink() {
            Kind::Symlink
        } else if t.is_dir() {
            Kind::Dir
        } else if t.is_file() {
            Kind::File
        } else {
            Kind::Other
        }
    }
}

fn is_hex(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Group ids reach the filesystem, so they are validated as ids rather than trusted as
/// names: `g_` + 16 random bytes in hex.
pub fn is_group_id(id: &str) -> bool {
    id.len() == 34 && id.starts_with("g_") && is_hex(&id[2..], 32)
}

/// A vault filename is the address as `vault_name` writes it: 40 lowercase hex, no `0x`.
/// Anything else is unexplained rather than a vault — a name we could not have written
/// does not name a file we can open.
fn vault_stem(name: &str) -> Option<String> {
    name.strip_suffix(".json").filter(|s| is_hex(s, 40)).map(str::to_string)
}

fn group_stem(name: &str) -> Option<String> {
    name.strip_suffix(".json").filter(|s| is_group_id(s)).map(str::to_string)
}

/// Which staging directory a NAME denotes. The three shapes are distinguishable from each
/// other, so one parser serves and `classify` checks the position separately.
fn stage_name(name: &str) -> Option<StageKind> {
    let rest = name.strip_prefix(STAGE_PREFIX)?;
    if let Some(nonce) = rest.strip_prefix(IMPORT_INFIX) {
        return is_hex(nonce, 32).then(|| StageKind::Import(nonce.into()));
    }
    if is_hex(rest, 40) {
        return Some(StageKind::Vault(rest.into()));
    }
    is_group_id(rest).then(|| StageKind::Group(rest.into()))
}

/// Whether a NAME is one this keystore could have written for a derivation key, or for the
/// stage that holds one. Without a password the name is the evidence, so material wearing
/// one is treated as a key wherever it sits.
fn names_key_material(name: &str) -> bool {
    group_stem(name).is_some()
        || is_group_id(name)
        || matches!(stage_name(name), Some(StageKind::Group(_)))
}

/// What a password-less look at one entry's CONTENTS found. Its NAME is judged separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Seen {
    /// Read or enumerated in full, and holding nothing that could be a key.
    Nothing,
    /// A vault's bytes — or a directory this scan could not enumerate and a file it could
    /// not read, because "could not look" is not "nothing there".
    Maybe,
}

/// A vault is under a kilobyte, and this runs on every scan.
const VAULT_PROBE_LIMIT: u64 = 64 * 1024;

/// Whether these bytes are a Web3 Secure Storage vault — the shape this keystore writes for
/// an account key AND for a whole-wallet derivation key. Which of the two it holds cannot be
/// told apart without the password, so an unexplained one is taken for the worse case.
fn looks_like_a_vault(raw: &str) -> bool {
    let v: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let Some(c) = v.get("crypto").or_else(|| v.get("Crypto")) else { return false };
    c.get("ciphertext").is_some() && c.get("kdf").is_some()
}

/// Look inside one unexplained FILE, without a password. Directories are answered by the
/// walk itself, which is the only thing that knows whether it got inside one.
fn look(path: &Path, kind: Kind) -> Seen {
    match kind {
        Kind::File => match std::fs::metadata(path).map(|m| m.len()) {
            Ok(n) if n > VAULT_PROBE_LIMIT => Seen::Nothing,
            Ok(_) => match std::fs::read_to_string(path) {
                Ok(raw) if looks_like_a_vault(&raw) => Seen::Maybe,
                Ok(_) => Seen::Nothing,
                Err(_) => Seen::Maybe,
            },
            Err(_) => Seen::Maybe,
        },
        _ => Seen::Nothing,
    }
}

/// Could this unexplained path be a derivation key — the key that opens a WHOLE wallet?
///
/// The evidence available without a password is its NAME and what a look inside found.
/// Sitting in the key directory ADDS to that and never subtracts: the same bytes one
/// directory over open the same wallet, and a prefix test called them harmless.
fn could_be_key(rel: &[String], seen: Seen) -> bool {
    seen == Seen::Maybe
        || rel.iter().any(|n| names_key_material(n))
        || rel.first().is_some_and(|f| f == "groups")
}

fn file_under_root(name: &str) -> Entry {
    if let Some(addr) = vault_stem(name) {
        return Entry::Vault(addr);
    }
    if let Some(doc) = Doc::of_file(name) {
        return Entry::Doc(doc);
    }
    if name == ".lock" {
        return Entry::Lock;
    }
    if name.starts_with(crate::atomic::DOC_STAGE_PREFIX) {
        return Entry::DocStage;
    }
    Entry::Unexplained
}

/// Classify one ENTRY, relative to `<ks>/`: every shape this keystore writes, at the kind
/// it writes it as. Everything else falls to `Unexplained` — there is no silent else, and
/// no kind that skips the classifier.
pub fn classify(rel: &[String], kind: Kind) -> Entry {
    let at = |i: usize| rel[i].as_str();
    match (rel.len(), kind) {
        (1, Kind::File) => file_under_root(at(0)),
        (1, Kind::Dir) => match stage_name(at(0)) {
            Some(StageKind::Vault(a)) => Entry::VaultStage(a),
            Some(StageKind::Import(n)) => Entry::ImportStage(n),
            _ if at(0) == "groups" => Entry::GroupDir,
            _ => Entry::Unexplained,
        },
        (2, Kind::File) => match stage_name(at(0)) {
            // A stage holds one file, under the name it is staging and nothing else.
            Some(StageKind::Vault(a)) if vault_stem(at(1)).as_deref() == Some(a.as_str()) => {
                Entry::StagedVault(a)
            }
            Some(StageKind::Import(n)) if at(1) == IMPORT_FILE => Entry::ImportScratch(n),
            None if at(0) == "groups" => match group_stem(at(1)) {
                Some(id) => Entry::GroupKey(id),
                None => Entry::Unexplained,
            },
            _ => Entry::Unexplained,
        },
        (2, Kind::Dir) => match (at(0), stage_name(at(1))) {
            ("groups", Some(StageKind::Group(id))) => Entry::GroupStage(id),
            _ => Entry::Unexplained,
        },
        (3, Kind::File) if at(0) == "groups" => match (stage_name(at(1)), group_stem(at(2))) {
            (Some(StageKind::Group(staged)), Some(id)) if staged == id => Entry::StagedGroupKey(id),
            _ => Entry::Unexplained,
        },
        // Symlinks and sockets are never recognised whatever they are named: following one
        // aims a write out of `<ks>/`, where nothing can name what landed.
        _ => Entry::Unexplained,
    }
}

/// Walk `<ks>/`, classifying every path.
///
/// This REPORTS; it does not guard. The one refusal left is about the honesty of the report
/// itself: an unreadable ROOT means the scan saw nothing at all, and answering "no accounts"
/// to someone holding a funded wallet is a lie rather than a gap. Every directory below it
/// is reported when it cannot be read — refusing there wedged the whole store, listing and
/// signing and repair included, over one bad directory.
pub fn scan(root: &Root) -> Result<Scan, Unreadable> {
    let mut out = Scan::default();
    let refused = |why: String| Unreadable { what: "the keystore directory".into(), why };
    let entries = match std::fs::read_dir(root.as_path()) {
        Ok(e) => e,
        // Absent is empty. That is the green field, and it has to keep working.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(refused(e.to_string())),
    };
    if !walk(entries, &mut Vec::new(), &mut out) {
        return Err(refused("it could not be read to the end".into()));
    }
    out.sort();
    Ok(out)
}

fn rel_str(rel: &[String]) -> String {
    rel.join("/")
}

/// Open a subdirectory and walk it. `false` means this scan could not see inside — which is
/// reported by the caller, never refused.
fn descend(dir: &Path, rel: &mut Vec<String>, out: &mut Scan) -> bool {
    std::fs::read_dir(dir).map(|e| walk(e, rel, out)).unwrap_or(false)
}

/// Classify every entry of one already-opened directory. `false` means it could not be read
/// to the end, so what this scan says about its contents is incomplete.
fn walk(entries: std::fs::ReadDir, rel: &mut Vec<String>, out: &mut Scan) -> bool {
    for entry in entries {
        let Ok(entry) = entry else { return false };
        rel.push(entry.file_name().to_string_lossy().into_owned());
        // EVERY entry is classified, whatever its type — that is the totality this scan
        // rests on. A kind we cannot even read is `Other`, which is unexplained, not absent.
        let kind = entry.file_type().map(Kind::of).unwrap_or(Kind::Other);
        if kind == Kind::Symlink {
            let target = std::fs::read_link(entry.path()).unwrap_or_default();
            out.links.push(format!("{} -> {}", rel_str(rel), target.display()));
        }
        let what = classify(rel, kind);
        // Descend BEFORE filing, so "could not look inside" is decided in one place — by the
        // walk that tried — rather than by a separate probe that could disagree with it.
        // Symlinks are never followed; a link is filed as what it is and where it points.
        let readable = kind != Kind::Dir
            || rel.len() >= MAX_DEPTH
            || descend(&entry.path(), rel, out);
        let seen = match what {
            // Deeper than the layout explains, or shut: either way this scan cannot say.
            Entry::Unexplained if kind == Kind::Dir => {
                if readable && rel.len() < MAX_DEPTH { Seen::Nothing } else { Seen::Maybe }
            }
            Entry::Unexplained => look(&entry.path(), kind),
            // A directory the layout explains by NAME whose contents it could not read.
            // Reported here rather than refusing the scan: it may hold a key, and a
            // keystore that cannot be listed or repaired is the worse failure.
            _ if !readable => {
                out.possible_keys.push(rel_str(rel));
                Seen::Nothing
            }
            _ => Seen::Nothing,
        };
        file(out, rel, what, seen);
        rel.pop();
    }
    true
}

/// File one classified entry. Unexplained material is split by what it COULD BE — the one
/// severity decision in this crate, and the only caller of `could_be_key`.
fn file(out: &mut Scan, rel: &[String], what: Entry, seen: Seen) {
    match what {
        Entry::Vault(a) => out.vaults.push(a),
        Entry::StagedVault(a) => out.staged_vaults.push(a),
        Entry::VaultStage(a) => out.vault_stages.push(a),
        Entry::ImportStage(n) => out.import_stages.push(n),
        Entry::GroupKey(id) => out.keys.push(id),
        Entry::StagedGroupKey(id) => out.staged.push(id),
        Entry::DocStage => out.doc_stages.push(rel_str(rel)),
        // Explained and holding nothing of its own: the material inside is what gets filed.
        Entry::Doc(_) | Entry::Lock | Entry::GroupDir | Entry::GroupStage(_) | Entry::ImportScratch(_) => {}
        Entry::Unexplained => {
            let path = rel_str(rel);
            if could_be_key(rel, seen) {
                out.possible_keys.push(path)
            } else {
                out.unexplained.push(path)
            }
        }
    }
}

// ── cross-process exclusion ─────────────────────────────────────────────────

/// How long a mutation waits for a peer before refusing.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_millis(1000);
const LOCK_POLL: std::time::Duration = std::time::Duration::from_millis(25);

thread_local! {
    /// std documents that re-locking one file from the same process may deadlock, so
    /// nesting is a hard error rather than a hang. The design constraint is that the lock
    /// is taken once, at one level, and never from inside a locked region.
    static HELD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Held for one bookkeeping read-modify-write, and released at the end of it. Never held
/// across a scrypt derivation: two processes both waiting out an N=2^18 KDF is a hang, and
/// the lost update this exists to stop happens in the file write, not in the crypto.
pub struct Guard(File);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.unlock();
        HELD.with(|h| h.set(false));
    }
}

/// `File::lock` is `flock(2)` on unix and `LockFileEx` on Windows — advisory there,
/// MANDATORY here. Both are what `std` stabilised in 1.89, which is the builder's rustc.
///
/// Refuses rather than blocking: waiting behind a hung peer while a user waits on a wallet
/// is worse than a legible refusal, and this module fails closed everywhere else.
pub fn lock(root: &Root) -> Result<Guard, Unreadable> {
    if HELD.with(|h| h.get()) {
        return Err(Unreadable {
            what: "the keystore lock".into(),
            why: "already held by this thread — it is taken once per operation, never nested".into(),
        });
    }
    let path = root.path(&Slot::Lock);
    let f = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| Unreadable { what: path.display().to_string(), why: e.to_string() })?;

    let deadline = std::time::Instant::now() + LOCK_WAIT;
    loop {
        match f.try_lock() {
            Ok(()) => {
                HELD.with(|h| h.set(true));
                return Ok(Guard(f));
            }
            Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                std::thread::sleep(LOCK_POLL)
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(Unreadable {
                    what: path.display().to_string(),
                    why: "another process is changing this keystore".into(),
                })
            }
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(Unreadable { what: path.display().to_string(), why: e.to_string() })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266";
    const G: &str = "g_0123456789abcdef0123456789abcdef";

    fn parts(p: &Path) -> Vec<String> {
        p.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect()
    }

    /// Every shape the layout explains, with the ONE kind that may wear it.
    fn explained() -> Vec<(Vec<String>, Kind, Entry)> {
        let p = |s: &str| s.split('/').map(str::to_string).collect::<Vec<_>>();
        let import = StageKind::import();
        let n = match &import {
            StageKind::Import(n) => n.clone(),
            _ => unreachable!(),
        };
        vec![
            (p(&format!("{A}.json")), Kind::File, Entry::Vault(A.into())),
            (p("groups.json"), Kind::File, Entry::Doc(Doc::Groups)),
            (p("accounts.json"), Kind::File, Entry::Doc(Doc::Accounts)),
            (p("labels.json"), Kind::File, Entry::Doc(Doc::Labels)),
            (p("group-labels.json"), Kind::File, Entry::Doc(Doc::GroupLabels)),
            (p(".lock"), Kind::File, Entry::Lock),
            (p(&format!("{}x", crate::atomic::DOC_STAGE_PREFIX)), Kind::File, Entry::DocStage),
            (p("groups"), Kind::Dir, Entry::GroupDir),
            (p(&format!(".stage-{A}")), Kind::Dir, Entry::VaultStage(A.into())),
            (p(&format!(".stage-{A}/{A}.json")), Kind::File, Entry::StagedVault(A.into())),
            (p(&format!("groups/{G}.json")), Kind::File, Entry::GroupKey(G.into())),
            (p(&format!("groups/.stage-{G}")), Kind::Dir, Entry::GroupStage(G.into())),
            (p(&format!("groups/.stage-{G}/{G}.json")), Kind::File, Entry::StagedGroupKey(G.into())),
            (p(&format!(".stage-import-{n}")), Kind::Dir, Entry::ImportStage(n.clone())),
            (p(&format!(".stage-import-{n}/import.json")), Kind::File, Entry::ImportScratch(n)),
        ]
    }

    #[test]
    fn every_slot_that_names_a_path_is_recognised_again_by_the_scan() {
        // The round trip that keeps the two halves from drifting: what `Slot` builds is what
        // `classify` names. A new variant breaks `Slot::rel` first, and lands here next.
        let cases: Vec<(Slot, Entry)> = vec![
            (Slot::Vault(A.into()), Entry::Vault(A.into())),
            (Slot::GroupKey(G.into()), Entry::GroupKey(G.into())),
            (Slot::Doc(Doc::Groups), Entry::Doc(Doc::Groups)),
            (Slot::Doc(Doc::Accounts), Entry::Doc(Doc::Accounts)),
            (Slot::Doc(Doc::Labels), Entry::Doc(Doc::Labels)),
            (Slot::Doc(Doc::GroupLabels), Entry::Doc(Doc::GroupLabels)),
            (Slot::Lock, Entry::Lock),
        ];
        for (slot, want) in cases {
            assert_eq!(classify(&parts(&slot.rel()), Kind::File), want, "{slot:?}");
        }

        // A stage is a DIRECTORY, and the file it comes to hold is a file. Both halves of
        // every stage kind round-trip, the import scratch included.
        for kind in [StageKind::Vault(A.into()), StageKind::Group(G.into()), StageKind::import()] {
            let dir = Slot::Stage(kind.clone()).rel();
            let inside = dir.join(Slot::staged_name(&kind));
            assert_ne!(classify(&parts(&dir), Kind::Dir), Entry::Unexplained, "{kind:?}");
            assert_ne!(classify(&parts(&inside), Kind::File), Entry::Unexplained, "{kind:?}");
        }
    }

    #[test]
    fn the_classifier_is_total_over_entry_kinds() {
        // HOLE 2: the classifier classified FILES, so an unrecognised DIRECTORY was
        // invisible. Every explained shape is now recognised for exactly one kind — and for
        // the other three it is unexplained, never dropped.
        for (rel, kind, want) in explained() {
            assert_eq!(classify(&rel, kind), want, "{rel:?} as {kind:?}");
            for other in Kind::ALL.into_iter().filter(|k| *k != kind) {
                assert_eq!(
                    classify(&rel, other),
                    Entry::Unexplained,
                    "{rel:?} was recognised as a {other:?}"
                );
            }
        }
    }

    #[test]
    fn anything_the_layout_did_not_write_is_unexplained_rather_than_dropped() {
        // The silent else, in every shape it took. None of these is a path this module can
        // produce, and none of them may vanish from the report — whatever kind it wears.
        for rel in [
            vec!["backup.json"],
            vec!["notes.txt"],
            vec![".DS_Store"],
            vec!["groups.json.tmp"],
            // A checksummed name we could not have written: it does not name a file we can
            // open, so it is not a vault.
            vec!["F39Fd6e51aad88F6F4ce6aB8827279cffFb92266.json"],
            // The old hand-rolled rekey stage, and the live account key inside it.
            vec![".rekey-f39fd6e51aad88f6f4ce6ab8827279cfffb92266"],
            vec![".rekey-f39fd6e51aad88f6f4ce6ab8827279cfffb92266", "f39fd6e51aad88f6f4ce6ab8827279cfffb92266.json"],
            // A stage holding something other than what it is named for.
            vec![".stage-f39fd6e51aad88f6f4ce6ab8827279cfffb92266", "other.json"],
            vec![".stage-import-0123456789abcdef0123456789abcdef", "other.json"],
            // An import stage whose nonce is not one we could have minted.
            vec![".stage-import-nope"],
            vec!["groups", "backup.json"],
            vec!["groups", ".stage-g_0123456789abcdef0123456789abcdef", "elsewhere.json"],
            vec!["groups", "x", "y", "z"],
            // HOLE 2's own shapes: a directory at depth 2, and one where a key belongs.
            vec!["a", "b"],
            vec!["groups", "g_0123456789abcdef0123456789abcdef.json", "inner"],
        ] {
            let rel: Vec<String> = rel.into_iter().map(str::to_string).collect();
            for kind in Kind::ALL {
                assert_eq!(classify(&rel, kind), Entry::Unexplained, "{rel:?} as {kind:?}");
            }
        }
    }

    #[test]
    fn every_entry_kind_the_filesystem_can_hand_back_is_reported() {
        // Totality on the real filesystem rather than on the type: one of each kind, at a
        // name the layout does not explain, and every one of them named by the scan.
        let dir = tempfile::tempdir().unwrap();
        let root = Root::new(dir.path().to_path_buf());
        std::fs::create_dir_all(root.as_path()).unwrap();
        std::fs::write(root.as_path().join("stray.txt"), "x").unwrap();
        std::fs::create_dir_all(root.as_path().join("stray-dir")).unwrap();
        // An EMPTY directory where a key belongs: F2, the original footgun still alive.
        std::fs::create_dir_all(root.as_path().join("groups").join(format!("{G}.json"))).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/passwd", root.as_path().join("link.json")).unwrap();
            let sock = root.as_path().join("sock");
            let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
            let s = scan(&root).unwrap();
            for want in ["stray.txt", "stray-dir", "link.json", "sock"] {
                assert!(s.unexplained.iter().any(|p| p == want), "{want} was dropped: {s:?}");
            }
            assert_eq!(s.possible_keys, vec![format!("groups/{G}.json")]);
        }
    }

    #[test]
    fn severity_follows_what_the_material_could_be_and_not_where_it_sits() {
        // A1. The guard keyed on a PATH PREFIX, so the same vault one directory over was
        // described by this authority and ignored by the decision. Every name below could
        // name a key, so every one of them is possible key material wherever it sits.
        for parent in ["groups", "groups.bak", "locked", ".stage-g_0123456789abcdef0123456789abcdef", "x"] {
            for name in [format!("{G}.json"), G.to_string(), format!(".stage-{G}")] {
                let rel = vec![parent.to_string(), name.clone()];
                assert!(could_be_key(&rel, Seen::Nothing), "{parent}/{name} was called harmless");
            }
        }
        // A name that says nothing is still key material when the bytes do, or when this
        // scan could not look at all.
        assert!(could_be_key(&["k.json".into()], Seen::Maybe));
        assert!(could_be_key(&["opaque".into()], Seen::Maybe));
        // What stays merely reported: nothing about it says "key", and we read it fine.
        for rel in [vec![".DS_Store"], vec!["notes.txt"], vec!["backup", "notes.txt"]] {
            let rel: Vec<String> = rel.into_iter().map(str::to_string).collect();
            assert!(!could_be_key(&rel, Seen::Nothing), "{rel:?} would brick a keystore");
        }
    }

    #[test]
    fn a_vault_under_a_name_that_says_nothing_is_still_possible_key_material() {
        // The residual A1 hole a NAME test alone cannot reach: rename the key to `k.json`
        // and no name says "key". Its bytes do — a derivation key and an account key wear
        // the same vault shape, and which one this is needs the password.
        let dir = tempfile::tempdir().unwrap();
        let root = Root::new(dir.path().to_path_buf());
        std::fs::create_dir_all(root.as_path()).unwrap();
        let vault = r#"{"crypto":{"cipher":"aes-128-ctr","ciphertext":"ab","kdf":"scrypt"},"id":"x","version":3}"#;
        std::fs::write(root.as_path().join("k.json"), vault).unwrap();
        std::fs::write(root.as_path().join("notes.txt"), "hand-edited").unwrap();

        let s = scan(&root).unwrap();
        assert_eq!(s.possible_keys, vec!["k.json".to_string()], "{s:?}");
        assert_eq!(s.unexplained, vec!["notes.txt".to_string()], "{s:?}");
    }

    #[test]
    fn no_path_lands_in_two_severity_buckets() {
        // A severity is an answer, so one path must have exactly one. An unreadable
        // directory was filed twice — once by its parent and once by the failed descent.
        let dir = tempfile::tempdir().unwrap();
        let root = Root::new(dir.path().to_path_buf());
        std::fs::create_dir_all(root.as_path().join("shut")).unwrap();
        std::fs::write(root.as_path().join("notes.txt"), "x").unwrap();
        crate::atomic::set_mode(&root.as_path().join("shut"), 0o000).unwrap();

        let s = scan(&root).unwrap();
        crate::atomic::set_mode(&root.as_path().join("shut"), 0o700).unwrap();
        for p in s.stray() {
            assert!(
                s.unexplained.contains(&p) != s.possible_keys.contains(&p),
                "{p} is in {} severity buckets",
                s.unexplained.contains(&p) as u8 + s.possible_keys.contains(&p) as u8
            );
        }
        assert_eq!(s.possible_keys, vec!["shut".to_string()]);
        assert_eq!(s.unexplained, vec!["notes.txt".to_string()]);
    }

    #[test]
    fn a_directory_the_scan_cannot_see_inside_is_possible_key_material() {
        // Both ways a scan goes blind: no permission, and deeper than the layout explains.
        let dir = tempfile::tempdir().unwrap();
        let root = Root::new(dir.path().to_path_buf());
        std::fs::create_dir_all(root.as_path().join("deep").join("er").join("est")).unwrap();
        let shut = root.as_path().join("shut");
        std::fs::create_dir_all(&shut).unwrap();
        crate::atomic::set_mode(&shut, 0o000).unwrap();

        let s = scan(&root).unwrap();
        crate::atomic::set_mode(&shut, 0o700).unwrap();
        assert!(s.possible_keys.contains(&"shut".to_string()), "{s:?}");
        assert!(s.possible_keys.contains(&"deep/er/est".to_string()), "{s:?}");
    }

    #[test]
    fn an_unreadable_directory_below_the_root_is_reported_rather_than_refusing_the_scan() {
        // The wedge this round removed. `groups/` refused the whole scan when it could not
        // be read, so an unreadable key directory made the store unlistable, unsignable and
        // unrepairable at once. The scan no longer decides anything about minting, so being
        // unable to see inside one directory costs a REPORT, not the keystore.
        let dir = tempfile::tempdir().unwrap();
        let root = Root::new(dir.path().to_path_buf());
        std::fs::write(root.path(&Slot::Vault(A.into())), "{}").unwrap();
        for shut in ["groups", "anything-else"] {
            std::fs::create_dir_all(root.as_path().join(shut)).unwrap();
            crate::atomic::set_mode(&root.as_path().join(shut), 0o000).unwrap();

            let s = scan(&root).expect("one unreadable directory refused the whole scan");
            crate::atomic::set_mode(&root.as_path().join(shut), 0o700).unwrap();
            // Still named, and at the severity that says a whole-wallet key could be inside.
            assert!(s.possible_keys.contains(&shut.to_string()), "{shut}: {s:?}");
            // And the rest of the keystore is still answered, which is the point.
            assert_eq!(s.vaults, vec![A.to_string()], "{shut}");
            std::fs::remove_dir_all(root.as_path().join(shut)).unwrap();
        }
    }

    #[test]
    fn an_unreadable_keystore_directory_refuses_rather_than_reporting_an_empty_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let root = Root::new(dir.path().join("ks"));
        // Absent is empty; that is the green-field case and it has to keep working.
        assert!(scan(&root).unwrap().vaults.is_empty());

        std::fs::create_dir_all(root.as_path()).unwrap();
        std::fs::write(root.path(&Slot::Vault(A.into())), "{}").unwrap();
        assert_eq!(scan(&root).unwrap().vaults, vec![A.to_string()]);

        crate::atomic::set_mode(root.as_path(), 0o000).unwrap();
        let refused = scan(&root);
        crate::atomic::set_mode(root.as_path(), 0o700).unwrap();
        assert!(refused.is_err(), "an unreadable directory reported an empty wallet");
    }

    #[test]
    fn the_lock_refuses_a_second_holder_rather_than_waiting_out_a_hung_peer() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        let root = Root::new(dir.path().to_path_buf());

        // Separate open file descriptions, which is what makes this the same test across
        // processes: flock and LockFileEx both conflict per description, not per process.
        let held = lock(&root).unwrap();
        let peer = std::thread::spawn({
            let root = root.clone();
            move || lock(&root).map(|_| ()).map_err(|u| u.why)
        })
        .join()
        .unwrap();
        assert!(peer.is_err(), "a second holder was let in");
        assert!(peer.unwrap_err().contains("another process"), "the refusal must say why");

        drop(held);
        assert!(lock(&root).is_ok(), "the lock was not released");
    }

    #[test]
    fn nesting_the_lock_is_an_error_rather_than_a_deadlock() {
        // std documents that re-locking one file from the same process may deadlock, so the
        // design constraint — taken once, never from inside a locked region — is enforced
        // rather than merely written down.
        let dir = tempfile::tempdir().unwrap();
        let root = Root::new(dir.path().to_path_buf());
        let _held = lock(&root).unwrap();
        match lock(&root) {
            Ok(_) => panic!("a nested lock was granted, which std says may deadlock"),
            Err(u) => assert!(u.why.contains("never nested"), "{}", u.why),
        }
    }
}

