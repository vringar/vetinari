//! A4 (#24) — the AC-15 iteration-2 end-to-end test.
//!
//! This is a **content-driven** end-to-end proof of the full iteration-2
//! adversarial loop: unlike the round-count-scripted A2 tests
//! (`pump_adversary_loop.rs`) and the A3 detector tests (`convergence.rs`), the
//! fakes here react to the *actual change content*, so the loop composes on a
//! real flaw rather than a scripted counter.
//!
//! ## The AC-15 scenario, closed honestly
//!
//! The design's AC-15 seeds a deliberate flaw: the Implementer commit produces
//! code with an `unsafe { }` block masked behind a safe-looking API; the
//! Adversary flags it; the orchestrator translates the finding to a
//! `--kind blocker`; the Implementer's next round removes it; the following
//! Adversary round is clean; convergence → land → merged. Here:
//!
//! - the [`fake_implementer_unsafe`] worker writes the FLAWED variant (a
//!   compiling, QA-passing `unsafe { *bytes.get_unchecked(0) }`) on the first
//!   round, and the FIXED variant (safe `bytes[0]`) once the orchestrator has
//!   delivered a prior finding into its workspace flagging the flaw;
//! - the [`fake_adversary_unsafe`] worker reads the pre-rendered
//!   `_orchestrator/diff.patch` and FLAGS a finding **iff** the diff still
//!   contains the flaw's distinctive marker — a `get_unchecked` call (a specific
//!   code token, not the word `unsafe`, so an incidental mention can never
//!   re-flag a clean change). Its verdict follows the real change, not a round
//!   index.
//!
//! The finding content reaches the next Implementer THROUGH THE ORCHESTRATOR: the
//! pump posts it as a `--kind blocker`, accumulates it, and delivers it into the
//! re-implement round's Implementer workspace as
//! `_orchestrator/prior_findings.jsonl` (the pump's `render_prior_findings`, the
//! Direct-worker analogue of the live-claude `append_prior_findings` task
//! channel). There is NO fixture-to-fixture side channel — the fakes react only
//! to orchestrator-delivered inputs.
//!
//! Because the Adversary's verdict is a function of the diff, the loop only
//! converges once the code is actually fixed: content drives the whole machine.
//!
//! ## What iteration-2 now proves end-to-end (AC-15 completeness note)
//!
//! | Capability (REQ) | Proven by |
//! |---|---|
//! | Adversary role wired into the build pump (REQ-8) | [`iteration2_content_driven_flaw_flags_reimplements_converges_lands`] here; `pump_adversary_loop::adversary_clean_first_round_converges_and_lands` |
//! | Pre-rendered Adversary inputs — no `.jj/` mount (REQ-8) | `pump_adversarial.rs` render-inputs tests; the fake adversary reads `_orchestrator/diff.patch` |
//! | findings → `--kind blocker` translation, content-driven (REQ-3, REQ-8) | this test asserts one blocker whose body cites the `unsafe` block |
//! | orchestrator delivers finding content to the Implementer (REQ-8) | this test: the fixed round is triggered **only** by the pump-delivered `_orchestrator/prior_findings.jsonl`; no fixture side channel exists |
//! | re-implement on findings, keyed off real content (REQ-8, REQ-10) | this test: flawed r0 → flagged → fixed r1 |
//! | strict findings reader — absent findings ≠ converged | `pump_adversary_loop::adversary_absent_findings_does_not_converge` |
//! | N-consecutive-clean convergence detector (REQ-10) | `convergence.rs` needs-N-rounds + mid-streak reset |
//! | round-cap poison (no infinite loop) | `pump_adversary_loop::divergent_adversary_poisons_at_round_cap_and_cleans_up` |
//! | crash-recovery of the review window / prior findings (REQ-8, #1/#2) | `pump_adversary_loop::{implementer_workspace_forgotten_before_adversary_review, rehydrated_prior_findings_make_reentry_converge_without_climbing_round}` |
//! | land the converged change (local mode, REQ-17) | this test asserts `main` carries the FIXED (no-`unsafe`) code |
//!
//! ## Live-claude variant — deliberately omitted
//!
//! A two-agent live loop (Implementer AND Adversary both `kind = "claude"`)
//! reaching `Merged` is already covered by
//! `dogfood_ac11b::ac11b_live_claude_lands_say_hi`. A *content-driven* live
//! variant is NOT added: you cannot deterministically make a live Implementer
//! emit a specific seeded flaw, nor guarantee a live Adversary flags exactly it,
//! so a forced-flaw loop cannot be driven reliably against a live agent. Per the
//! A4 brief, the deterministic content-driven test below is the required
//! deliverable; the live variant is skipped for reliability.

mod common;

use std::path::Path;
use std::process::Command;

use common::{
    build_fixture, fake_adversary_unsafe, fake_implementer_unsafe, unique_session, SessionGuard,
};
use orchestrator::config::{OrchestratorConfig, WorkerConfig};
use orchestrator::events::{read_all, EventLog, ORCHESTRATOR_DIR};
use orchestrator::pump::{BuildPump, IssueOutcome};
use orchestrator::spawn::{SandboxPin, Spawner};
use orchestrator::state::{EventKind, Phase, StateDb};
use orchestrator::workspace::WorkspaceManager;
use vetinari_crosslink_api::CrosslinkRepo;

fn main_commit(cwd: &Path) -> String {
    let out = Command::new("jj")
        .args(["log", "-r", "main", "--no-graph", "-T", "commit_id"])
        .current_dir(cwd)
        .output()
        .expect("jj log for main");
    assert!(out.status.success(), "jj log must succeed");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// The contents of `src/lib.rs` on `main` (the landed baseline).
fn main_lib_rs(cwd: &Path) -> String {
    let out = Command::new("jj")
        .args(["file", "show", "-r", "main", "src/lib.rs"])
        .current_dir(cwd)
        .output()
        .expect("jj file show main:src/lib.rs");
    assert!(out.status.success(), "jj file show must succeed");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A config dispatching the content-driven Direct implementer + adversary
/// scripts, tight CI timeouts. `n_rounds = 1`: one clean Adversary round after
/// the fix converges (matching the A2 loop tests' streak expectations).
fn config_for(implementer: &Path, adversary: &Path) -> OrchestratorConfig {
    OrchestratorConfig {
        worker: WorkerConfig {
            argv: vec![
                "bash".to_owned(),
                implementer.to_string_lossy().into_owned(),
            ],
            adversary_argv: vec!["bash".to_owned(), adversary.to_string_lossy().into_owned()],
            ..WorkerConfig::default()
        },
        worker_timeout_secs: 60,
        convergence: orchestrator::config::ConvergenceConfig {
            n_rounds: 1,
            ..Default::default()
        },
        ..OrchestratorConfig::default()
    }
}

/// Build a pump over a fresh fixture with the given fake workers. Returns the
/// fixture, the pump, and the session guard (hold all three for the test).
fn pump_over(
    tag: &str,
    implementer: &Path,
    adversary: &Path,
) -> (common::Fixture, BuildPump, SessionGuard) {
    let fx = build_fixture();
    let orchestrator_dir = fx.root.join(ORCHESTRATOR_DIR);
    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("open state.db");
    let log = EventLog::open(&orchestrator_dir).expect("open events.jsonl");
    let manager = WorkspaceManager::load(&fx.root).expect("load workspace manager");
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink repo");
    let (session, guard) = unique_session(tag);
    let spawner = Spawner::new(session, &fx.root, SandboxPin::new("unused-direct"));
    let pump = BuildPump::new(
        config_for(implementer, adversary),
        state,
        log,
        manager,
        spawner,
        crosslink,
    );
    (fx, pump, guard)
}

/// The AC-15 loop, end-to-end, driven by real change content:
///
/// 1. round 0 — the Implementer writes the FLAWED variant (a compiling,
///    QA-passing `unsafe { }` block behind a safe-looking API);
/// 2. the Adversary reads the diff, sees `unsafe`, and FLAGS a finding;
/// 3. the orchestrator translates it to a `--kind blocker` (posted once) and
///    re-implements (round++, `empty_round_streak` reset to 0);
/// 4. round 1 — the Implementer, seeing the prior finding, writes the FIXED
///    variant (safe indexing, no `unsafe`);
/// 5. the Adversary reads the new diff, finds no `unsafe`, and signs off CLEAN;
/// 6. with `n_rounds = 1` that clean round converges → land → `Merged`.
///
/// Asserts the whole sequence, that `main` carries the FIXED (no-`unsafe`) code,
/// that the blocker comment cites the unsafe block, and that the events show the
/// finding → re-implement → converge → land transitions.
#[test]
fn iteration2_content_driven_flaw_flags_reimplements_converges_lands() {
    let (fx, pump, _guard) = pump_over(
        "iter2-e2e",
        &fake_implementer_unsafe(),
        &fake_adversary_unsafe(),
    );
    let orchestrator_dir = fx.root.join(ORCHESTRATOR_DIR);
    let key = fx.issue_id.to_string();
    let main_before = main_commit(&fx.root);
    assert!(
        !main_lib_rs(&fx.root).contains("greeting_head"),
        "precondition: main has no greeting_head yet"
    );

    let outcomes = pump.run_until_idle().expect("pump runs to idle");
    assert_eq!(
        outcomes,
        vec![(fx.issue_id, IssueOutcome::Merged)],
        "a content-driven flaw that is flagged then fixed must converge → Merged, got {outcomes:?}"
    );

    // --- state.db authority: Merged at round 1 (the flaw bumped the round once),
    // with the single converging clean round counted. ---
    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("reopen state.db");
    let issue = state.get_issue(&key).expect("read").expect("row");
    assert_eq!(issue.phase, Phase::Merged, "must converge to Merged");
    assert_eq!(
        issue.round, 1,
        "the flagged unsafe block must force exactly one re-implement (round 1), got {}",
        issue.round
    );
    assert_eq!(
        issue.empty_round_streak, 1,
        "the clean round after the fix converges the streak to 1, got {}",
        issue.empty_round_streak
    );

    // --- main advanced and carries the FIXED code: greeting_head present, the
    // unsafe block GONE (the whole point — content drove the loop to a fix). ---
    assert_ne!(main_commit(&fx.root), main_before, "main must advance");
    let landed = main_lib_rs(&fx.root);
    assert!(
        landed.contains("greeting_head"),
        "main must carry the greeting_head helper, got:\n{landed}"
    );
    assert!(
        landed.contains("bytes[0]"),
        "main must carry the FIXED safe-indexing variant, got:\n{landed}"
    );
    assert!(
        !landed.contains("unsafe"),
        "main must NOT carry the unsafe block — the flaw was fixed before landing, got:\n{landed}"
    );

    // --- the finding was translated to exactly one `--kind blocker`, derived
    // from findings.jsonl (content-addressed ledger, idempotent). ---
    let posted = state.list_posted_artifacts(&key).expect("list posted");
    let blockers: Vec<_> = posted.iter().filter(|p| p.finding_index >= 0).collect();
    assert_eq!(
        blockers.len(),
        1,
        "exactly one blocker must be posted for the single flagged round, got {posted:?}"
    );
    assert!(
        blockers[0].artifact_path.ends_with("findings.jsonl"),
        "the blocker derives from findings.jsonl, got {:?}",
        blockers[0]
    );

    // --- the blocker body cites the unsafe flaw (the Adversary flagged the real
    // content, and the orchestrator posted it verbatim). ---
    let crosslink = CrosslinkRepo::open(&fx.root).expect("reopen crosslink");
    let comments = crosslink.list_comments(fx.issue_id).expect("list comments");
    assert!(
        comments.iter().any(|c| c.kind == "blocker"
            && c.body.contains("[adversary]")
            && c.body.contains("unsafe")),
        "an [adversary] blocker citing the unsafe block must exist, got {comments:?}"
    );

    // --- events: a findings transition reset the streak and re-implemented; both
    // rounds' implementers ran; an adversary ran; and a convergence event fired. ---
    let events = read_all(orchestrator_dir.join("events.jsonl")).expect("read events");
    assert!(
        events.iter().any(|e| e.kind == EventKind::Transition
            && e.payload.get("to_phase").and_then(|v| v.as_str()) == Some("implementing")
            && e.payload.get("findings").and_then(|v| v.as_u64()) == Some(1)
            && e.payload.get("empty_round_streak").and_then(|v| v.as_u64()) == Some(0)),
        "a findings transition must re-implement and reset the streak to 0, got {events:?}"
    );
    let implementer_spawns = events
        .iter()
        .filter(|e| {
            e.kind == EventKind::Spawn
                && e.payload.get("role").and_then(|v| v.as_str()) == Some("implementer")
        })
        .count();
    assert!(
        implementer_spawns >= 2,
        "the flawed round and the fix round must both spawn an implementer (>= 2), got {implementer_spawns}"
    );
    assert!(
        events.iter().any(|e| e.kind == EventKind::Spawn
            && e.payload.get("role").and_then(|v| v.as_str()) == Some("adversary")),
        "an adversary must have been spawned"
    );
    assert!(
        events.iter().any(|e| e.kind == EventKind::Convergence
            && e.payload.get("converged").and_then(|v| v.as_bool()) == Some(true)),
        "a convergence event must record the clean-after-fix round converging"
    );
}
