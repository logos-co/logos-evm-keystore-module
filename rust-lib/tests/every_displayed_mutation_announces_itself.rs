//! Every mutation that moves something a reader displays must announce it, on the success
//! path and nowhere else.
//!
//! `glue.rs` sits behind the `logos_module` feature and `--no-default-features` cannot compile
//! it, so it is read as text. Two rules keep that honest: a check names the SITE it is about,
//! never a region; and every check ships with the mutant it exists to kill, asserted here — so
//! a check that stopped discriminating fails instead of passing.
//!
//! The defect: `set_label` renamed an account and emitted nothing, so the wallet went on
//! showing the old name until its view was closed and reopened.

const GLUE: &str = include_str!("../src/glue.rs");
const EMIT: &str = "emit_accounts_changed";

/// Mutations that move something a reader shows — the account set, or the names and wallets
/// it is displayed under. `change_password` is deliberately absent: it re-encrypts a vault
/// and moves nothing displayed.
const ANNOUNCES: &[&str] = &[
    "import_mnemonic",
    "derive_next_account",
    "derive_account_at",
    "create_unrelated_account",
    "import_private_key",
    "import_keystore_json",
    "delete_account",
    "set_label",
    "set_group_label",
    "remove_group",
    "forget_derivation",
    "remove_unexplained",
    "settle",
];

/// Methods that must stay silent: they persist nothing, or nothing a reader shows. Listed so
/// a stray emit on a read path — every consumer re-reading on its own read — fails here.
const SILENT: &[&str] = &[
    // Configuration: it moves who may call, never what a reader shows.
    "configure",
    "create_mnemonic",
    "preview_addresses",
    "export_keystore_json",
    "change_password",
    "list_accounts",
    "get_labels",
    "get_group_labels",
    "list_groups",
    "list_derivation_keys",
    "caller_identity",
];

/// The file with comments and string literals blanked, byte offsets preserved: brace and
/// paren counting must not be fooled by a `{` inside a `json!` string.
fn code_only(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = b.to_vec();
    let (mut i, mut in_str, mut in_comment) = (0usize, false, false);
    while i < b.len() {
        match (in_str, in_comment, b[i]) {
            (false, false, b'"') => in_str = true,
            (false, false, b'/') if b.get(i + 1) == Some(&b'/') => {
                in_comment = true;
                out[i] = b' ';
            }
            (true, _, b'\\') => {
                out[i] = b' ';
                out[i + 1] = b' ';
                i += 2;
                continue;
            }
            (true, _, b'"') => in_str = false,
            (_, true, b'\n') => in_comment = false,
            (true, _, _) | (_, true, _) => out[i] = b' ',
            _ => {}
        }
        i += 1;
    }
    String::from_utf8(out).expect("blanking replaces bytes one for one")
}

fn sites(hay: &str, needle: &str) -> Vec<usize> {
    let (mut out, mut from) = (Vec::new(), 0);
    while let Some(rel) = hay[from..].find(needle) {
        out.push(from + rel);
        from += rel + needle.len();
    }
    out
}

/// The offset just past the close of the delimiter pair opened at or after `from`.
fn closes(code: &str, from: usize, open: char, shut: char) -> usize {
    let at = from + code[from..].find(open).expect("a pair to close");
    let mut depth = 0i32;
    for (k, c) in code[at..].char_indices() {
        if c == open {
            depth += 1;
        } else if c == shut {
            depth -= 1;
            if depth == 0 {
                return at + k + 1;
            }
        }
    }
    code.len()
}

/// The body of every definition of `fn <name>`. A trait declaration reaches `;` before any
/// `{`, so it opens no scope and is skipped.
fn bodies<'a>(code: &'a str, name: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    for at in sites(code, &format!("fn {name}(")) {
        let after = closes(code, at, '(', ')');
        let Some(rel) = code[after..].find(['{', ';']) else { continue };
        if code.as_bytes()[after + rel] == b';' {
            continue;
        }
        let open = after + rel;
        out.push(&code[open..closes(code, open, '{', '}')]);
    }
    out
}

fn body_of<'a>(code: &'a str, name: &str) -> &'a str {
    let found = bodies(code, name);
    assert_eq!(found.len(), 1, "expected exactly one definition of `{name}` in glue.rs");
    found[0]
}

/// The spans of the `Ok(..) => { .. }` arms in `body` — the success paths, and the only place
/// an announcement may stand.
fn ok_arms(body: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for at in sites(body, "Ok(") {
        let after = closes(body, at, '(', ')');
        let rest = body[after..].trim_start();
        if !rest.starts_with("=>") {
            continue;
        }
        if !rest[2..].trim_start().starts_with('{') {
            continue;
        }
        let open = after + body[after..].find('{').expect("the arm's block");
        out.push((open, closes(body, open, '{', '}')));
    }
    out
}

/// How many announcements stand on a success path, and how many stand anywhere else — an
/// `Err` arm, or ahead of the match, which announces a change that may not have happened.
fn announcements(body: &str) -> (usize, usize) {
    let arms = ok_arms(body);
    let (mut on_success, mut stray) = (0, 0);
    for at in sites(body, EMIT) {
        if arms.iter().any(|&(a, b)| at > a && at < b) {
            on_success += 1;
        } else {
            stray += 1;
        }
    }
    (on_success, stray)
}

#[test]
fn every_mutation_a_reader_can_see_announces_itself_on_the_success_path() {
    let code = code_only(GLUE);
    for m in ANNOUNCES {
        let (on_success, stray) = announcements(body_of(&code, m));
        assert_eq!(on_success, 1, "`{m}` must announce exactly once, from its `Ok` arm");
        assert_eq!(stray, 0, "`{m}` announces off the success path");
    }
}

#[test]
fn nothing_else_announces_and_no_read_path_does() {
    let code = code_only(GLUE);
    for m in SILENT {
        assert!(!body_of(&code, m).contains(EMIT), "`{m}` must not announce");
    }
    // Closure: the listed mutations are ALL of them, so an emit added to an unlisted method
    // is a rule nobody wrote down rather than a silent extension of this one.
    assert_eq!(
        sites(&code, EMIT).len(),
        ANNOUNCES.len(),
        "glue.rs announces from a site this test does not name"
    );
}

/// The rename that started this: a reader shows a name in place of an address, and the count
/// in the payload does not move when the name does.
#[test]
fn a_rename_announces_even_though_it_moves_no_count() {
    let code = code_only(GLUE);
    assert!(ANNOUNCES.contains(&"set_label"));
    assert_eq!(announcements(body_of(&code, "set_label")), (1, 0));
    assert_eq!(announcements(body_of(&code, "set_group_label")), (1, 0));
}

// ── the mutants each check above exists to kill ──────────────────────────────────
// Applied to the REAL `set_label` body, so a check that stopped discriminating fails here.

fn set_label_body() -> String {
    body_of(&code_only(GLUE), "set_label").to_string()
}

#[test]
fn a_deleted_announcement_is_rejected() {
    let mutant = set_label_body().replace(&format!("{EMIT}(self.account_count());"), "");
    assert_eq!(announcements(&mutant), (0, 0));
}

#[test]
fn an_announcement_moved_to_the_refusal_path_is_rejected() {
    let real = set_label_body();
    let mutant = real
        .replace(&format!("{EMIT}(self.account_count());"), "")
        .replacen("Err(e) => err(e),", &format!("Err(e) => {{ {EMIT}(0); err(e) }},"), 1);
    let (on_success, stray) = announcements(&mutant);
    assert_eq!(on_success, 0, "an Err arm is not a success path");
    assert_eq!(stray, 1);
}

#[test]
fn an_unconditional_announcement_ahead_of_the_match_is_rejected() {
    let real = set_label_body();
    let mutant = real.replacen("match self.ks()", &format!("{EMIT}(0); match self.ks()"), 1);
    let (on_success, stray) = announcements(&mutant);
    assert_eq!(on_success, 1, "the real one still stands");
    assert_eq!(stray, 1, "and the unconditional one is counted as a stray");
}
