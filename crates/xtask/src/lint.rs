//! No-shell-out audit (REQ-1a, AC-24).
//!
//! Parses the `src/` tree of every orchestrator-side crate and reports any
//! `Command::new("<target>")` whose literal target is a banned external tool.
//! `jj`, `git`, `gh`, `crosslink`, and `zellij` all have Rust library bindings
//! the orchestrator must use instead; `claude` and `claude-sandbox` have none,
//! so they are not banned and need no separate exception list here.
//!
//! Test code is exempt: the test harness legitimately drives the real CLIs
//! (e.g. `zellij list-panes` in AC-27). The scanner skips `#[cfg(test)]`
//! modules, `#[test]`/`#[cfg(test)]` functions, and any file under a `tests`
//! directory.
//!
//! The scan parses with `syn` rather than grepping text, so a banned name
//! appearing in a comment, doc string, or unrelated string literal can never
//! false-positive. Known limitations — acceptable for a first-party guardrail,
//! not a sandbox: a renamed import (`use Command as C; C::new("jj")`) or a
//! non-literal target (`Command::new(&var)`) is not detected. Orchestrator
//! style keeps these literal; the lint catches accidental regressions, not
//! deliberate evasion.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use proc_macro2::{TokenStream, TokenTree};
use syn::visit::Visit;

/// External tools that must be driven through a library binding, never a
/// subprocess, in orchestrator-side code.
const BANNED: &[&str] = &["jj", "git", "gh", "crosslink", "zellij"];

/// Crates under `crates/` that the audit does not scan.
///
/// - `xtask` is itself a dev tool, not orchestrator runtime code, so it is
///   free to shell out.
/// - `zellij_host` deliberately drives the `zellij` CLI as a subprocess: a
///   feasibility spike found zellij's library crates cannot host worker panes
///   without a daemonized server process and offer no per-pane environment
///   API. This is a scoped exception to REQ-1a, recorded in REQ-1d of
///   `.design/vdd-orchestrator.md`; the orchestrator core still reaches zellij
///   only through `zellij_host`'s adapter surface.
const EXEMPT_CRATES: &[&str] = &["xtask", "zellij_host"];

/// A single forbidden `Command::new(...)` call site.
struct Violation {
    file: PathBuf,
    line: usize,
    column: usize,
    target: String,
}

/// Run the no-shell-out audit. Returns [`ExitCode::SUCCESS`] when the workspace
/// is clean and [`ExitCode::FAILURE`] when any violation is found or the scan
/// itself cannot complete.
pub fn run() -> ExitCode {
    let root = workspace_root();
    let crates_dir = root.join("crates");

    let mut files = Vec::new();
    if let Err(e) = collect_scan_targets(&crates_dir, &mut files) {
        eprintln!("xtask lint: cannot enumerate {}: {e}", crates_dir.display());
        return ExitCode::FAILURE;
    }
    files.sort();

    let mut violations = Vec::new();
    for file in &files {
        match scan_file(file) {
            Ok(found) => violations.extend(found),
            Err(e) => {
                // A file we cannot parse is a file we cannot audit. `cargo
                // clippy` runs before this in `just lint` and would already
                // have rejected a genuine syntax error, so treat this as fatal.
                eprintln!("xtask lint: cannot parse {}: {e}", file.display());
                return ExitCode::FAILURE;
            }
        }
    }

    report(&root, &violations, files.len())
}

/// The workspace root, two directories above this crate's manifest
/// (`crates/xtask` → `crates` → root). Resolved from `CARGO_MANIFEST_DIR` so
/// the lint works regardless of the caller's working directory.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("xtask manifest lives two levels below the workspace root")
        .to_path_buf()
}

/// Collect every non-test `.rs` file under the `src/` tree of every
/// non-exempt crate. New orchestrator-side crates are picked up automatically;
/// escaping the audit requires a deliberate entry in [`EXEMPT_CRATES`].
fn collect_scan_targets(crates_dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(crates_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        if EXEMPT_CRATES.contains(&name.to_string_lossy().as_ref()) {
            continue;
        }
        let src = entry.path().join("src");
        if src.is_dir() {
            collect_rs_files(&src, out)?;
        }
    }
    Ok(())
}

/// Recursively collect `.rs` files, skipping anything under a `tests`
/// directory and any file named `tests.rs` (the conventional home of a
/// `#[cfg(test)] mod tests;` whose gate lives on the `mod` declaration, not in
/// the file itself).
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            if path.file_name().is_some_and(|n| n == "tests") {
                continue;
            }
            collect_rs_files(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs")
            && path.file_name().is_some_and(|n| n != "tests.rs")
        {
            out.push(path);
        }
    }
    Ok(())
}

/// Parse one file and return its violations.
fn scan_file(path: &Path) -> Result<Vec<Violation>, syn::Error> {
    let source = std::fs::read_to_string(path)
        .map_err(|e| syn::Error::new(proc_macro2::Span::call_site(), e))?;
    let ast = syn::parse_file(&source)?;
    let mut scanner = Scanner {
        file: path.to_path_buf(),
        violations: Vec::new(),
    };
    scanner.visit_file(&ast);
    Ok(scanner.violations)
}

/// Print the result and pick the process exit code.
fn report(root: &Path, violations: &[Violation], scanned: usize) -> ExitCode {
    if violations.is_empty() {
        println!("xtask lint: clean — no forbidden shell-out calls ({scanned} file(s) scanned)");
        return ExitCode::SUCCESS;
    }

    eprintln!(
        "xtask lint: {} forbidden shell-out call(s) found (REQ-1a, AC-24)\n",
        violations.len()
    );
    for v in violations {
        let shown = v.file.strip_prefix(root).unwrap_or(&v.file);
        eprintln!(
            "  {}:{}:{}: Command::new({:?}) — drive `{}` through a library binding",
            shown.display(),
            v.line,
            v.column,
            v.target,
            v.target,
        );
    }
    eprintln!(
        "\nOrchestrator-side code must use jj-lib, octocrab, crosslink_api, and the\n\
         zellij crates instead of subprocesses. If a flagged call is genuine\n\
         test-harness code, move it under a `#[cfg(test)]` item."
    );
    ExitCode::FAILURE
}

/// `syn` visitor that records banned `Command::new` call sites and prunes
/// test-gated subtrees so they are never reported.
struct Scanner {
    file: PathBuf,
    violations: Vec<Violation>,
}

impl<'ast> Visit<'ast> for Scanner {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if !attrs_mark_test(&node.attrs) {
            syn::visit::visit_item_mod(self, node);
        }
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if !attrs_mark_test(&node.attrs) {
            syn::visit::visit_item_fn(self, node);
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if !attrs_mark_test(&node.attrs) {
            syn::visit::visit_impl_item_fn(self, node);
        }
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Some(literal) = banned_command_target(node) {
            let start = literal.span().start();
            self.violations.push(Violation {
                file: self.file.clone(),
                line: start.line,
                // proc-macro2 columns are 0-based; report 1-based for editors.
                column: start.column + 1,
                target: literal.value(),
            });
        }
        syn::visit::visit_expr_call(self, node);
    }
}

/// If `call` is `Command::new("<banned>")` with a string-literal target in
/// [`BANNED`], return that literal so the caller can locate it precisely.
fn banned_command_target(call: &syn::ExprCall) -> Option<&syn::LitStr> {
    let syn::Expr::Path(func) = call.func.as_ref() else {
        return None;
    };
    let segments = &func.path.segments;
    // Accept `Command::new`, `process::Command::new`,
    // `std::process::Command::new` — anything ending in `Command::new`.
    if segments.last()?.ident != "new" {
        return None;
    }
    if segments.iter().rev().nth(1)?.ident != "Command" {
        return None;
    }
    let syn::Expr::Lit(arg) = call.args.first()? else {
        return None;
    };
    let syn::Lit::Str(literal) = &arg.lit else {
        return None;
    };
    BANNED
        .contains(&literal.value().as_str())
        .then_some(literal)
}

/// True when an attribute set marks an item as test-only: `#[test]`,
/// `#[tokio::test]` (any path ending in `test`), or a `#[cfg(...)]` whose
/// predicate mentions the `test` configuration option.
fn attrs_mark_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if attr
            .path()
            .segments
            .last()
            .is_some_and(|s| s.ident == "test")
        {
            return true;
        }
        if attr.path().is_ident("cfg") {
            if let syn::Meta::List(list) = &attr.meta {
                return tokens_contain_ident(&list.tokens, "test");
            }
        }
        false
    })
}

/// True when `ident` appears as an identifier anywhere in `tokens`, including
/// nested groups (so `cfg(all(test, feature = "x"))` is recognized). Matching
/// on the identifier rather than a substring avoids flagging `cfg(feature =
/// "tested")`.
fn tokens_contain_ident(tokens: &TokenStream, ident: &str) -> bool {
    tokens.clone().into_iter().any(|tt| match tt {
        TokenTree::Ident(i) => i == ident,
        TokenTree::Group(g) => tokens_contain_ident(&g.stream(), ident),
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a source snippet and return the violations the scanner finds.
    fn scan(source: &str) -> Vec<Violation> {
        let ast = syn::parse_file(source).expect("snippet parses");
        let mut scanner = Scanner {
            file: PathBuf::from("snippet.rs"),
            violations: Vec::new(),
        };
        scanner.visit_file(&ast);
        scanner.violations
    }

    #[test]
    fn flags_a_banned_command() {
        let v = scan(r#"fn f() { std::process::Command::new("jj").arg("status"); }"#);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].target, "jj");
    }

    #[test]
    fn flags_every_banned_target() {
        for target in BANNED {
            let src = format!(r#"fn f() {{ Command::new("{target}"); }}"#);
            assert_eq!(scan(&src).len(), 1, "should flag {target}");
        }
    }

    #[test]
    fn allows_claude_and_unbanned_targets() {
        assert!(scan(r#"fn f() { Command::new("claude-sandbox"); }"#).is_empty());
        assert!(scan(r#"fn f() { Command::new("claude"); }"#).is_empty());
        assert!(scan(r#"fn f() { Command::new("bash"); }"#).is_empty());
    }

    #[test]
    fn ignores_banned_name_in_a_comment_or_string() {
        // A grep-based lint would false-positive on both of these.
        assert!(scan("fn f() { /* Command::new(\"jj\") */ let _ = 1; }").is_empty());
        assert!(scan(r#"fn f() { let _ = "Command::new(\"git\")"; }"#).is_empty());
    }

    #[test]
    fn exempts_cfg_test_module() {
        let src = "#[cfg(test)]\nmod t { fn f() { Command::new(\"git\"); } }";
        assert!(scan(src).is_empty());
    }

    #[test]
    fn exempts_cfg_test_module_with_compound_predicate() {
        let src = "#[cfg(all(test, feature = \"x\"))]\nmod t { fn f() { Command::new(\"gh\"); } }";
        assert!(scan(src).is_empty());
    }

    #[test]
    fn exempts_test_functions() {
        assert!(scan("#[test]\nfn t() { Command::new(\"zellij\"); }").is_empty());
        assert!(scan("#[tokio::test]\nasync fn t() { Command::new(\"jj\"); }").is_empty());
    }

    #[test]
    fn does_not_exempt_unrelated_cfg() {
        // `cfg(feature = "tested")` must not be mistaken for a test gate.
        let src = "#[cfg(feature = \"tested\")]\nfn f() { Command::new(\"jj\"); }";
        assert_eq!(scan(src).len(), 1);
    }
}
