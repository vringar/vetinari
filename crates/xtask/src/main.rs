//! `xtask` — repo-local maintenance commands.
//!
//! The no-shell-out lint (AC-24, REQ-1a) lands in crosslink issue #6. For F1
//! the binary exists so the workspace produces a discoverable
//! `target/debug/xtask` that `just lint` and friends can target once #6
//! implements the subcommands. Until then unknown subcommands exit `2` so the
//! just recipe can distinguish "not yet implemented" (skip cleanly) from "lint
//! found violations" (fail the build).

use std::process::ExitCode;

/// Exit code used for "subcommand is recognized but not yet implemented".
/// `just lint` treats this as a skip; any other non-zero is a real failure.
const EXIT_NOT_IMPLEMENTED: u8 = 2;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("help") | Some("--help") | Some("-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some("lint") => {
            eprintln!(
                "xtask lint: not yet implemented (lands in crosslink issue #6, F6). Skipping."
            );
            ExitCode::from(EXIT_NOT_IMPLEMENTED)
        }
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
    println!("Commands (all unimplemented until #6 lands):");
    println!("  lint    no-shell-out audit (REQ-1a, AC-24)");
    println!();
    println!("This is a skeleton from #1 (F1). See crosslink issue #6 for the");
    println!("implementation that wires real subcommands.");
}
