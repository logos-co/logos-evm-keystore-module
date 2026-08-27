//! The approval record: the state machine between "a module asked for a
//! signature" and "a human approved it".
//!
//! Pure and offline — no Logos dependency — so the whole machine is unit
//! testable with `cargo test --no-default-features`. The caller-identity gate
//! and the JSON envelope live in `glue.rs`; everything about *what is signed*
//! and *what a human is shown* lives here.
//!
//! Two invariants shape the design and are asserted by the tests:
//!
//! 1. **One parse.** The intent is parsed ONCE into typed legs. The render the
//!    human reads and the bytes that get signed are produced from that same
//!    parsed value, and `approve` re-derives the commitment before signing, so
//!    the two cannot drift apart.
//! 2. **At most one record is `Rendered`.** Acknowledging a second record
//!    demotes the first. Without this, an asynchronous UI update between "the
//!    human read handle A" and "the human clicked Approve" could submit
//!    handle B — every other invariant intact, and a signature over something
//!    nobody saw.

use std::time::{Duration, Instant};

use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::keystore::{
    check_displayable, sign_digest_with, sign_message_with, sign_parsed_tx, Keystore, KeystoreError,
    UnsignedTx,
};

type Result<T> = std::result::Result<T, KeystoreError>;

/// How long an offered record waits for an approver to acknowledge it. After
/// the ack there is deliberately NO deadline: a human is deciding.
pub const ACK_DEADLINE: Duration = Duration::from_millis(3000);

/// Caps. A requester cannot flood the approver's queue.
pub const MAX_PENDING_PER_REQUESTER: usize = 4;
pub const MAX_PENDING_TOTAL: usize = 16;
/// Largest intent we will parse, before parsing it.
pub const MAX_INTENT_BYTES: usize = 64 * 1024;
/// How long a settled record is kept so the requester can still read its
/// outcome. Dropping it immediately turns "your approval expired" into "no such
/// handle", which a requester cannot distinguish from a bug of its own.
pub const SETTLED_RETENTION: Duration = Duration::from_secs(120);

// ── the intent ──────────────────────────────────────────────────────────────

/// One thing to sign. Legs are signed in order, under a single key derivation.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields, rename_all = "snake_case")]
pub enum Leg {
    /// A transaction. `tx` is the same shape the signer has always taken.
    Tx { chain_id: u64, tx: UnsignedTx },
    /// EIP-191 personal_sign over printable text.
    Message { text: String },
    /// A raw 32-byte digest. Opaque by construction: `purpose` is the only
    /// thing that can be shown, and it is a claim by the requester.
    Digest { digest: String, purpose: String },
}

/// What a requester submits.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    /// The account to sign with.
    pub address: String,
    /// A short requester-supplied label for the whole bundle, shown as a claim.
    #[serde(default)]
    pub purpose: String,
    pub legs: Vec<Leg>,
}

// ── the record ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Offered to approvers; not yet claimed.
    Offered,
    /// An approver has fetched the render and is showing it to a human.
    Rendered,
    /// Terminal.
    Settled(Outcome),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Approved,
    Rejected,
    ExpiredNoAck,
    Cancelled,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Approved => "approved",
            Outcome::Rejected => "rejected",
            Outcome::ExpiredNoAck => "expired_no_ack",
            Outcome::Cancelled => "cancelled",
        }
    }
}

struct Record {
    handle: String,
    receipt_hash: [u8; 32],
    requester: String,
    intent: Intent,
    bundle_id: [u8; 32],
    render_lines: Vec<String>,
    state: State,
    offered_at: Instant,
    settled_at: Option<Instant>,
    /// Signatures, once approved. Erased on ack_result.
    results: Option<Vec<String>>,
}

/// The pending-approval store.
pub struct Approvals {
    records: Vec<Record>,
    /// Monotonic counter folded into handles so two records minted in the same
    /// instant cannot collide.
    seq: u64,
    /// Overridable so the expiry path is testable without sleeping.
    ack_deadline: Duration,
}

impl Default for Approvals {
    fn default() -> Self {
        Self::new()
    }
}

/// What `acknowledge` hands an approver.
pub struct Rendered {
    pub handle: String,
    pub bundle_id: String,
    pub requester: String,
    pub render_lines: Vec<String>,
}

/// A queue summary — never leg detail.
pub struct Summary {
    pub handle: String,
    pub requester: String,
    pub state: &'static str,
    pub purpose: String,
    pub leg_count: usize,
    pub age_ms: u128,
}

impl Approvals {
    pub fn new() -> Self {
        Self { records: Vec::new(), seq: 0, ack_deadline: ACK_DEADLINE }
    }

    /// Override the ack deadline. Shortening it only ever fails closed sooner.
    pub fn set_ack_deadline(&mut self, d: Duration) {
        self.ack_deadline = d;
    }

    /// Demote any `Rendered` record whose ack deadline has passed, and settle
    /// `Offered` records that nobody claimed. Lazy: run at the head of every
    /// entry point, so the call a stale record would otherwise block is exactly
    /// the call that clears it. No background thread.
    fn sweep(&mut self) {
        let now = Instant::now();
        for r in &mut self.records {
            if r.state == State::Offered && now.duration_since(r.offered_at) > self.ack_deadline {
                r.state = State::Settled(Outcome::ExpiredNoAck);
            }
            if matches!(r.state, State::Settled(_)) && r.settled_at.is_none() {
                r.settled_at = Some(now);
            }
        }
        // A settled record is kept until its results have been collected AND
        // the retention window has passed, so a requester always gets a real
        // answer rather than NotFound.
        self.records.retain(|r| {
            let Some(at) = r.settled_at else { return true };
            r.results.is_some() || now.duration_since(at) < SETTLED_RETENTION
        });
    }

    fn find(&mut self, handle: &str) -> Option<&mut Record> {
        self.records.iter_mut().find(|r| r.handle == handle)
    }

    /// Open an approval request. Returns `(handle, receipt)`. The receipt is
    /// returned exactly once and is never stored in the clear — it is what
    /// binds `fetch_result` to the requester, because the handle itself is
    /// broadcast on an unauthenticated event plane.
    pub fn request(&mut self, requester: &str, intent_json: &str) -> Result<(String, String)> {
        self.sweep();

        if intent_json.len() > MAX_INTENT_BYTES {
            return Err(KeystoreError::InvalidParams(format!(
                "intent: {} bytes exceeds the {MAX_INTENT_BYTES}-byte limit",
                intent_json.len()
            )));
        }
        let live = |r: &&Record| !matches!(r.state, State::Settled(_));
        if self.records.iter().filter(live).count() >= MAX_PENDING_TOTAL {
            return Err(KeystoreError::InvalidParams("too many pending approvals".into()));
        }
        if self
            .records
            .iter()
            .filter(live)
            .filter(|r| r.requester == requester)
            .count()
            >= MAX_PENDING_PER_REQUESTER
        {
            return Err(KeystoreError::InvalidParams(
                "too many pending approvals for this requester".into(),
            ));
        }

        let intent: Intent = serde_json::from_str(intent_json)
            .map_err(|e| KeystoreError::InvalidParams(format!("intent: {e}")))?;
        if intent.legs.is_empty() {
            return Err(KeystoreError::InvalidParams("intent: no legs".into()));
        }
        check_displayable(&intent.purpose, "purpose")?;

        let bundle_id = commitment(&intent)?;
        let render_lines = render(&intent, &bundle_id)?;

        self.seq += 1;
        let handle = format!("ksh_{}", token_hex(self.seq));
        let receipt = format!("ksc_{}", token_hex(self.seq));

        self.records.push(Record {
            handle: handle.clone(),
            receipt_hash: sha256(receipt.as_bytes()),
            requester: requester.to_string(),
            intent,
            bundle_id,
            render_lines,
            state: State::Offered,
            offered_at: Instant::now(),
            settled_at: None,
            results: None,
        });
        Ok((handle, receipt))
    }

    pub fn pending(&mut self) -> Vec<Summary> {
        self.sweep();
        let now = Instant::now();
        self.records
            .iter()
            .filter(|r| !matches!(r.state, State::Settled(_)))
            .map(|r| Summary {
                handle: r.handle.clone(),
                requester: r.requester.clone(),
                state: match r.state {
                    State::Offered => "offered",
                    State::Rendered => "rendered",
                    State::Settled(_) => "settled",
                },
                purpose: r.intent.purpose.clone(),
                leg_count: r.intent.legs.len(),
                age_ms: now.duration_since(r.offered_at).as_millis(),
            })
            .collect()
    }

    /// Claim a record for display. **Demotes any other `Rendered` record**, so
    /// exactly one thing can be on screen at a time.
    pub fn acknowledge(&mut self, handle: &str) -> Result<Rendered> {
        self.sweep();
        if !self.records.iter().any(|r| r.handle == handle) {
            return Err(KeystoreError::NotFound(handle.to_string()));
        }
        for r in &mut self.records {
            if r.state == State::Rendered && r.handle != handle {
                r.state = State::Offered;
            }
        }
        let r = self.find(handle).expect("checked above");
        match r.state {
            State::Settled(o) => {
                return Err(KeystoreError::InvalidParams(format!(
                    "already settled: {}",
                    o.as_str()
                )))
            }
            _ => r.state = State::Rendered,
        }
        Ok(Rendered {
            handle: r.handle.clone(),
            bundle_id: hex::encode(r.bundle_id),
            requester: r.requester.clone(),
            render_lines: r.render_lines.clone(),
        })
    }

    /// The human said yes. Re-derives the commitment from the stored parsed
    /// intent and checks it against what the approver echoed back, derives the
    /// key ONCE, signs every leg in order, then wipes.
    pub fn approve(
        &mut self,
        ks: &Keystore,
        handle: &str,
        bundle_id_echo: &str,
        password: &str,
    ) -> Result<usize> {
        self.sweep();
        let r = self
            .find(handle)
            .ok_or_else(|| KeystoreError::NotFound(handle.to_string()))?;

        if r.state != State::Rendered {
            return Err(KeystoreError::InvalidParams(
                "approve: this handle was not the one being rendered".into(),
            ));
        }

        // Re-derive rather than trust the stored value, and check the approver
        // echoed the same thing it displayed.
        let fresh = commitment(&r.intent)?;
        if fresh != r.bundle_id {
            return Err(KeystoreError::InvalidParams("approve: commitment drift".into()));
        }
        if bundle_id_echo.trim().trim_start_matches("0x") != hex::encode(fresh) {
            return Err(KeystoreError::InvalidParams(
                "approve: bundle_id does not match the rendered request".into(),
            ));
        }

        // ONE derivation for the whole bundle.
        let signer = ks.signer_for(&r.intent.address, password)?;
        let mut out = Vec::with_capacity(r.intent.legs.len());
        for leg in &r.intent.legs {
            out.push(match leg {
                Leg::Tx { chain_id, tx } => sign_parsed_tx(&signer, tx, *chain_id)?,
                Leg::Message { text } => sign_message_with(&signer, text)?,
                Leg::Digest { digest, .. } => sign_digest_with(&signer, digest)?,
            });
        }
        drop(signer);

        let n = out.len();
        r.results = Some(out);
        r.state = State::Settled(Outcome::Approved);
        Ok(n)
    }

    pub fn reject(&mut self, handle: &str) -> Result<()> {
        self.sweep();
        let r = self
            .find(handle)
            .ok_or_else(|| KeystoreError::NotFound(handle.to_string()))?;
        if let State::Settled(o) = r.state {
            return Err(KeystoreError::InvalidParams(format!("already settled: {}", o.as_str())));
        }
        r.state = State::Settled(Outcome::Rejected);
        Ok(())
    }

    /// Bare state for the requester. Never the intent, never the results.
    pub fn status(&mut self, handle: &str, receipt: &str) -> Result<(&'static str, Option<&'static str>)> {
        self.sweep();
        let want = sha256(receipt.as_bytes());
        let r = self
            .records
            .iter()
            .find(|r| r.handle == handle && ct_eq(&r.receipt_hash, &want))
            .ok_or_else(|| KeystoreError::NotFound(handle.to_string()))?;
        Ok(match r.state {
            State::Offered => ("offered", None),
            State::Rendered => ("rendered", None),
            State::Settled(o) => ("settled", Some(o.as_str())),
        })
    }

    /// Collect the signatures. Idempotent until `ack_result` — a dropped reply
    /// must not cost the human a second password entry.
    pub fn fetch_result(&mut self, handle: &str, receipt: &str) -> Result<Vec<String>> {
        self.sweep();
        let want = sha256(receipt.as_bytes());
        let r = self
            .records
            .iter()
            .find(|r| r.handle == handle && ct_eq(&r.receipt_hash, &want))
            .ok_or_else(|| KeystoreError::NotFound(handle.to_string()))?;
        r.results
            .clone()
            .ok_or_else(|| KeystoreError::InvalidParams("no result for this handle".into()))
    }

    /// The requester has the signatures. Erase them.
    pub fn ack_result(&mut self, handle: &str, receipt: &str) -> Result<()> {
        let want = sha256(receipt.as_bytes());
        let Some(r) = self
            .records
            .iter_mut()
            .find(|r| r.handle == handle && ct_eq(&r.receipt_hash, &want))
        else {
            return Err(KeystoreError::NotFound(handle.to_string()));
        };
        r.results = None;
        self.sweep();
        Ok(())
    }

    /// The requester gave up.
    pub fn cancel(&mut self, handle: &str, receipt: &str) -> Result<()> {
        let want = sha256(receipt.as_bytes());
        let Some(r) = self
            .records
            .iter_mut()
            .find(|r| r.handle == handle && ct_eq(&r.receipt_hash, &want))
        else {
            return Err(KeystoreError::NotFound(handle.to_string()));
        };
        if !matches!(r.state, State::Settled(_)) {
            r.state = State::Settled(Outcome::Cancelled);
        }
        r.results = None;
        self.sweep();
        Ok(())
    }
}

// ── commitment and render ───────────────────────────────────────────────────

/// SHA-256 over OUR canonical re-encoding of the parsed intent — never over the
/// requester's bytes, so reformatting, key order and whitespace cannot change
/// what the commitment covers.
fn commitment(intent: &Intent) -> Result<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(b"logos-keystore-approval-v1\n");
    h.update(intent.address.trim().to_lowercase().as_bytes());
    h.update(b"\n");
    for leg in &intent.legs {
        match leg {
            Leg::Tx { chain_id, tx } => {
                h.update(b"tx\n");
                h.update(chain_id.to_string().as_bytes());
                h.update(b"\n");
                for field in [
                    tx.to.clone().unwrap_or_default(),
                    tx.create.to_string(),
                    tx.value.clone(),
                    tx.nonce.clone(),
                    tx.gas_limit.clone(),
                    tx.data.clone(),
                    tx.fee_mode.clone(),
                    tx.max_fee_per_gas.clone(),
                    tx.max_priority_fee_per_gas.clone(),
                    tx.gas_price.clone(),
                ] {
                    h.update(field.trim().to_lowercase().as_bytes());
                    h.update(b"\x1f");
                }
            }
            Leg::Message { text } => {
                h.update(b"message\n");
                h.update(text.as_bytes());
            }
            Leg::Digest { digest, purpose } => {
                h.update(b"digest\n");
                h.update(digest.trim().trim_start_matches("0x").to_lowercase().as_bytes());
                h.update(b"\x1f");
                h.update(purpose.as_bytes());
            }
        }
        h.update(b"\n");
    }
    Ok(h.finalize().into())
}

/// The lines an approver shows, VERBATIM. Produced here because this is the
/// only party that has parsed the intent — an approver cannot tell
/// requester-supplied text from the signer's own.
fn render(intent: &Intent, bundle_id: &[u8; 32]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    out.push(format!("Account: {}", intent.address.trim()));
    if !intent.purpose.trim().is_empty() {
        out.push(format!("Purpose (claimed by the requester): {}", intent.purpose.trim()));
    }
    out.push(format!("Commitment: {}", hex::encode(bundle_id)));
    out.push(format!("{} item(s) to sign:", intent.legs.len()));

    for (i, leg) in intent.legs.iter().enumerate() {
        let n = i + 1;
        match leg {
            Leg::Tx { chain_id, tx } => {
                out.push(format!("  [{n}] Transaction on chain {chain_id}"));
                match tx.to.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    Some(to) => out.push(format!("      To: {to}")),
                    None => out.push("      ** CONTRACT CREATION — no recipient **".into()),
                }
                out.push(format!("      Value: {}", norm_num(&tx.value)));
                out.push(format!("      Nonce: {}", norm_num(&tx.nonce)));
                out.push(format!("      Gas limit: {}", norm_num(&tx.gas_limit)));
                let data = tx.data.trim();
                if data.is_empty() || data == "0x" {
                    out.push("      Data: (none)".into());
                } else {
                    let d = data.trim_start_matches("0x");
                    if d.len() >= 8 {
                        out.push(format!("      Selector: 0x{}", &d[..8]));
                    }
                    // The full calldata, never elided: a summary a human cannot
                    // check against the bytes is worse than no summary.
                    out.push(format!("      Data: 0x{d}"));
                }
            }
            Leg::Message { text } => {
                check_displayable(text, "message")?;
                out.push(format!("  [{n}] Sign text message"));
                out.push(format!("      Text: {text}"));
                out.push(format!("      Bytes: 0x{}", hex::encode(text.as_bytes())));
            }
            Leg::Digest { digest, purpose } => {
                check_displayable(purpose, "purpose")?;
                out.push(format!("  [{n}] Sign an OPAQUE 32-byte digest"));
                out.push(format!("      Purpose (claimed by the requester): {purpose}"));
                out.push(format!("      Digest: {}", digest.trim()));
                out.push("      This signer cannot show you what this authorises.".into());
            }
        }
    }
    Ok(out)
}

/// Render a hex-or-decimal numeric field as both, so a human is not asked to
/// convert in their head.
fn norm_num(s: &str) -> String {
    let t = s.trim();
    if t.is_empty() {
        return "0".into();
    }
    match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(h) => match u128::from_str_radix(h, 16) {
            Ok(v) => format!("{t} ({v})"),
            Err(_) => t.to_string(),
        },
        None => t.to_string(),
    }
}

// ── small helpers ───────────────────────────────────────────────────────────

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Constant-time compare for the receipt digest.
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// 128 bits of randomness, rendered so it can never be mistaken for a number or
/// a hex quantity by an argument parser that guesses types.
fn token_hex(seq: u64) -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    // Fold in the sequence so two mints in one instant cannot collide even if
    // the RNG is somehow degenerate.
    format!("{}{:x}", hex::encode(b), seq)
}

/// Zeroize a password the caller handed us as a plain `String`.
pub fn scrub(mut s: String) {
    let z = Zeroizing::new(std::mem::take(&mut s));
    drop(z);
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const ACCT0: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    fn fixture() -> (tempfile::TempDir, Keystore, Approvals) {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        ks.import_private_key(PK, "pw").unwrap();
        (dir, ks, Approvals::new())
    }

    fn tx_intent(nonce: &str) -> String {
        format!(
            r#"{{"address":"{ACCT0}","purpose":"send","legs":[
                {{"kind":"tx","chain_id":1,"tx":{{
                    "to":"{ACCT0}","value":"0x0","nonce":"{nonce}","gas_limit":"0x5208",
                    "fee_mode":"eip1559","max_fee_per_gas":"0x1","max_priority_fee_per_gas":"0x1"}}}}]}}"#
        )
    }

    #[test]
    fn approve_refuses_a_handle_that_is_not_the_one_being_rendered() {
        let (_d, ks, mut ap) = fixture();
        let (h1, _r1) = ap.request("wallet_backend", &tx_intent("0x1")).unwrap();
        let (h2, _r2) = ap.request("wallet_backend", &tx_intent("0x2")).unwrap();

        let v1 = ap.acknowledge(&h1).unwrap();
        // A second acknowledge DEMOTES the first: an async UI update between
        // render and click must not be able to submit the other handle.
        let _v2 = ap.acknowledge(&h2).unwrap();

        let err = ap.approve(&ks, &h1, &v1.bundle_id, "pw").unwrap_err();
        assert!(format!("{err}").contains("not the one being rendered"), "got {err}");

        // The one actually on screen still approves.
        let v2 = ap.acknowledge(&h2).unwrap();
        assert_eq!(ap.approve(&ks, &h2, &v2.bundle_id, "pw").unwrap(), 1);
    }

    #[test]
    fn approve_requires_the_bundle_id_that_was_displayed() {
        let (_d, ks, mut ap) = fixture();
        let (h, _r) = ap.request("wallet_backend", &tx_intent("0x1")).unwrap();
        ap.acknowledge(&h).unwrap();
        let wrong = "00".repeat(32);
        assert!(ap.approve(&ks, &h, &wrong, "pw").is_err());
    }

    #[test]
    fn a_wrong_password_neither_signs_nor_settles_the_record() {
        let (_d, ks, mut ap) = fixture();
        let (h, r) = ap.request("wallet_backend", &tx_intent("0x1")).unwrap();
        let v = ap.acknowledge(&h).unwrap();

        assert!(ap.approve(&ks, &h, &v.bundle_id, "wrong").is_err());
        // Still rendered, so the human can simply retype.
        assert_eq!(ap.status(&h, &r).unwrap().0, "rendered");
        assert_eq!(ap.approve(&ks, &h, &v.bundle_id, "pw").unwrap(), 1);
    }

    #[test]
    fn results_are_idempotent_until_acked_then_erased() {
        let (_d, ks, mut ap) = fixture();
        let (h, r) = ap.request("wallet_backend", &tx_intent("0x1")).unwrap();
        let v = ap.acknowledge(&h).unwrap();
        ap.approve(&ks, &h, &v.bundle_id, "pw").unwrap();

        // A dropped reply must not cost a second password entry.
        let a = ap.fetch_result(&h, &r).unwrap();
        let b = ap.fetch_result(&h, &r).unwrap();
        assert_eq!(a, b);
        assert!(a[0].starts_with("0x"));

        ap.ack_result(&h, &r).unwrap();
        assert!(ap.fetch_result(&h, &r).is_err());
    }

    #[test]
    fn the_receipt_not_the_handle_is_what_authorises_collection() {
        let (_d, ks, mut ap) = fixture();
        let (h, r) = ap.request("wallet_backend", &tx_intent("0x1")).unwrap();
        let v = ap.acknowledge(&h).unwrap();
        ap.approve(&ks, &h, &v.bundle_id, "pw").unwrap();
        // The handle is broadcast on an unauthenticated event plane, so it must
        // suffice for nothing on its own.
        assert!(ap.fetch_result(&h, "ksc_not_the_receipt").is_err());
        assert!(ap.fetch_result(&h, &r).is_ok());
    }

    #[test]
    fn the_commitment_covers_the_parsed_value_not_the_requesters_bytes() {
        let (_d, _ks, mut ap) = fixture();
        let pretty = tx_intent("0x1");
        let compact: String = pretty.split_whitespace().collect::<Vec<_>>().join(" ");
        let (h1, _) = ap.request("a", &pretty).unwrap();
        let (h2, _) = ap.request("b", &compact).unwrap();
        let v1 = ap.acknowledge(&h1).unwrap();
        let v2 = ap.acknowledge(&h2).unwrap();
        assert_eq!(v1.bundle_id, v2.bundle_id, "reformatting must not change the commitment");

        // But a changed field must.
        let (h3, _) = ap.request("c", &tx_intent("0x2")).unwrap();
        let v3 = ap.acknowledge(&h3).unwrap();
        assert_ne!(v1.bundle_id, v3.bundle_id);
    }

    #[test]
    fn the_render_shows_full_calldata_and_flags_contract_creation() {
        let (_d, _ks, mut ap) = fixture();
        let intent = format!(
            r#"{{"address":"{ACCT0}","legs":[
                {{"kind":"tx","chain_id":1,"tx":{{
                    "create":true,"value":"0x0","nonce":"0x1","gas_limit":"0x5208",
                    "data":"0xdeadbeefcafe","fee_mode":"eip1559",
                    "max_fee_per_gas":"0x1","max_priority_fee_per_gas":"0x1"}}}}]}}"#
        );
        let (h, _) = ap.request("wallet_backend", &intent).unwrap();
        let v = ap.acknowledge(&h).unwrap();
        let all = v.render_lines.join("\n");
        assert!(all.contains("CONTRACT CREATION"), "{all}");
        assert!(all.contains("0xdeadbeefcafe"), "calldata must not be elided: {all}");
        assert!(all.contains("Selector: 0xdeadbeef"), "{all}");
    }

    #[test]
    fn an_opaque_digest_is_rendered_as_opaque() {
        let (_d, _ks, mut ap) = fixture();
        let intent = format!(
            r#"{{"address":"{ACCT0}","legs":[{{"kind":"digest",
                "digest":"0x{}","purpose":"ERC-4337 UserOperation"}}]}}"#,
            "11".repeat(32)
        );
        let (h, _) = ap.request("railgun_module", &intent).unwrap();
        let v = ap.acknowledge(&h).unwrap();
        let all = v.render_lines.join("\n");
        assert!(all.contains("OPAQUE"), "{all}");
        assert!(all.contains("cannot show you what this authorises"), "{all}");
        assert!(all.contains("claimed by the requester"), "purpose must be marked a claim: {all}");
    }

    #[test]
    fn a_bundle_is_one_decision_over_several_legs() {
        let (_d, ks, mut ap) = fixture();
        let intent = format!(
            r#"{{"address":"{ACCT0}","purpose":"shield","legs":[
                {{"kind":"tx","chain_id":1,"tx":{{"to":"{ACCT0}","value":"0x0","nonce":"0x1",
                  "gas_limit":"0x5208","fee_mode":"eip1559","max_fee_per_gas":"0x1",
                  "max_priority_fee_per_gas":"0x1"}}}},
                {{"kind":"tx","chain_id":1,"tx":{{"to":"{ACCT0}","value":"0x0","nonce":"0x2",
                  "gas_limit":"0x5208","fee_mode":"eip1559","max_fee_per_gas":"0x1",
                  "max_priority_fee_per_gas":"0x1"}}}}]}}"#
        );
        let (h, r) = ap.request("wallet_backend", &intent).unwrap();
        let v = ap.acknowledge(&h).unwrap();
        // One password entry, two signatures.
        assert_eq!(ap.approve(&ks, &h, &v.bundle_id, "pw").unwrap(), 2);
        assert_eq!(ap.fetch_result(&h, &r).unwrap().len(), 2);
    }

    #[test]
    fn an_unacknowledged_request_expires_and_says_why() {
        let (_d, _ks, mut ap) = fixture();
        ap.set_ack_deadline(Duration::from_millis(0));
        let (h, r) = ap.request("wallet_backend", &tx_intent("0x1")).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        let (state, reason) = ap.status(&h, &r).unwrap();
        assert_eq!(state, "settled");
        assert_eq!(reason, Some("expired_no_ack"));
        // And it can no longer be acknowledged.
        assert!(ap.acknowledge(&h).is_err());
    }

    #[test]
    fn a_requester_cannot_flood_the_queue() {
        let (_d, _ks, mut ap) = fixture();
        for i in 0..MAX_PENDING_PER_REQUESTER {
            ap.request("noisy", &tx_intent(&format!("0x{i}"))).unwrap();
        }
        assert!(ap.request("noisy", &tx_intent("0xff")).is_err());
        // A different requester is unaffected.
        assert!(ap.request("quiet", &tx_intent("0x1")).is_ok());
    }

    #[test]
    fn an_oversize_or_empty_intent_is_refused_before_parsing() {
        let (_d, _ks, mut ap) = fixture();
        let huge = format!(r#"{{"address":"{ACCT0}","purpose":"{}","legs":[]}}"#, "a".repeat(MAX_INTENT_BYTES));
        assert!(ap.request("x", &huge).is_err());
        assert!(ap.request("x", &format!(r#"{{"address":"{ACCT0}","legs":[]}}"#)).is_err());
    }
}
