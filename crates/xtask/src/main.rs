//! `xtask` — repo-local maintenance commands.
//!
//! `xtask lint` runs the no-shell-out audit (REQ-1a, AC-24): it parses every
//! orchestrator-side crate's `src/` tree and fails the build if any non-test
//! code constructs a `std::process::Command` targeting `jj`, `git`, `gh`,
//! `crosslink`, or `zellij`. Those operations must go through library
//! bindings; shelling out to them is the regression this gate prevents.

use std::process::ExitCode;

mod lint;

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
        Some("lint") => lint::run(),
        Some(other) => {
            eprintln!("xtask: unknown subcommand `{other}` (try `xtask help`)");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!("xtask — repo maintenance helper");
    println!();
    println!("Usage: xtask <command>");
    println!();
    println!("Commands:");
    println!("  lint    no-shell-out audit (REQ-1a, AC-24)");
    println!("  help    show this message");
    println!();
    println!(
        "Recognized-but-unimplemented subcommands exit {EXIT_NOT_IMPLEMENTED}; \
         `just lint` skips that cleanly."
    );
}
