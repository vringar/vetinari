//! `xtask` — repo-local maintenance commands.
//!
//! `xtask lint` runs two build-failing gates:
//! - the no-shell-out audit (REQ-1a, AC-24): it parses every orchestrator-side
//!   crate's `src/` tree and fails if any non-test code constructs a
//!   `std::process::Command` targeting `jj`, `git`, `gh`, `crosslink`, or
//!   `zellij`. Those operations must go through library bindings.
//! - the single-crosslink guard (AC-28a): it runs `cargo metadata` and fails if
//!   more than one `crosslink` resolves in the graph (the `links = "sqlite3"`
//!   single-copy constraint). Also available standalone as
//!   `xtask check-crosslink`.

use std::process::ExitCode;

mod lint;
mod single_crosslink;

/// Exit code for an `xtask` subcommand that is recognized but not yet
/// implemented. `just lint` treats this as a clean skip; any other non-zero
/// code is a real failure. No current subcommand returns it — it is kept so
/// future subcommands can land incrementally without breaking the recipe.
const EXIT_NOT_IMPLEMENTED: u8 = 2;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("help") | Some("--help") | Some("-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some("lint") => {
            // Run BOTH gates so all problems print in one pass; the recipe fails
            // if either does. AC-24 first (no cargo needed), then AC-28a.
            let audit_ok = lint::run();
            let crosslink_ok = single_crosslink::run();
            bool_exit(audit_ok && crosslink_ok)
        }
        Some("check-crosslink") => bool_exit(single_crosslink::run()),
        Some(other) => {
            eprintln!("xtask: unknown subcommand `{other}` (try `xtask help`)");
            ExitCode::FAILURE
        }
    }
}

/// Map a clean/dirty boolean to a process exit code.
fn bool_exit(ok: bool) -> ExitCode {
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn print_help() {
    println!("xtask — repo maintenance helper");
    println!();
    println!("Usage: xtask <command>");
    println!();
    println!("Commands:");
    println!("  lint             no-shell-out audit (AC-24) + single-crosslink guard (AC-28a)");
    println!("  check-crosslink  single-crosslink guard only (AC-28a)");
    println!("  help             show this message");
    println!();
    println!(
        "Recognized-but-unimplemented subcommands exit {EXIT_NOT_IMPLEMENTED}; \
         `just lint` skips that cleanly."
    );
}
