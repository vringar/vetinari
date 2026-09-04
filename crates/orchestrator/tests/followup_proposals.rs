//! REQ-SWARM-2 — the follow-up-proposal channel, end to end (propose, never
//! commit).
//!
//! An Implementer that discovers out-of-scope follow-up work writes
//! `_orchestrator/followups.jsonl` (two proposals). This test drives the fixture
//! issue to `phase:merged` with that worker and asserts the ONLY effects a
//! worker's proposals can have:
//!
//! - exactly two follow-up comments appear on the issue (one per proposal,
//!   deduped — never four), each under the allowlisted `note` wire kind and
//!   marked as a proposal by its `**Follow-up proposal**` body header;
//! - the `followup:proposed` label is applied so the chief can find the issue;
//!
//! and, load-bearing, that a proposal can NEVER escalate:
//!
//! - **no blocker edge** is wired (the `suggested_blockers` field is comment
//!   TEXT only, never a real `crosslink issue block`);
//! - **no privileged label** is applied (`inbound-approved:land` absent);
//! - **no `phase:graphed`** is (re-)applied by the proposal path.
//!
//! "No new issue is created" holds by construction, not by assertion: the whole
//! [`CrosslinkRepo`] write surface the orchestrator has is
//! `comment_write` / `label_add` / `label_remove` / `close_issue` — there is no
//! issue-create and no issue-block method to call, so a followups artifact has
//! no reachable path to author the graph.

mod common;

use common::{build_fixture, fake_adversary_clean, fake_implementer_followups, unique_session};
use orchestrator::config::{ConvergenceConfig, OrchestratorConfig, WorkerConfig};
use orchestrator::events::EventLog;
use orchestrator::events::ORCHESTRATOR_DIR;
use orchestrator::pump::{
    BuildPump, IssueOutcome, FOLLOWUP_PROPOSED_LABEL, GRAPHED_LABEL, INBOUND_APPROVED_LABEL,
};
use orchestrator::spawn::Spawner;
use orchestrator::state::StateDb;
use orchestrator::workspace::WorkspaceManager;
use vetinari_crosslink_api::CrosslinkRepo;

#[test]
fn followup_proposals_post_comments_and_label_but_never_author_the_graph() {
    let fx = build_fixture();
    let orchestrator_dir = fx.root.join(ORCHESTRATOR_DIR);

    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("open state.db");
    let log = EventLog::open(&orchestrator_dir).expect("open events.jsonl");
    let manager = WorkspaceManager::load(&fx.root).expect("load workspace manager");
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink repo");

    let (session, _guard) = unique_session("followup");
    let spawner = Spawner::new(session, &fx.root, common::bwrap_pin());

    let config = OrchestratorConfig {
        worker: WorkerConfig {
            argv: vec![
                "bash".to_owned(),
                fake_implementer_followups().to_string_lossy().into_owned(),
            ],
            adversary_argv: vec![
                "bash".to_owned(),
                fake_adversary_clean().to_string_lossy().into_owned(),
            ],
            ..WorkerConfig::default()
        },
        worker_timeout_secs: 60,
        convergence: ConvergenceConfig {
            n_rounds: 1,
            ..Default::default()
        },
        ..OrchestratorConfig::default()
    };

    let pump = BuildPump::new(config, state, log, manager, spawner, crosslink);
    let outcomes = pump.run_until_idle().expect("pump must run to idle");

    // The proposals must NOT derail the loop — the issue still merges.
    assert_eq!(
        outcomes,
        vec![(fx.issue_id, IssueOutcome::Merged)],
        "the seed issue must still merge despite the follow-up proposals, got {outcomes:?}"
    );

    let cl = CrosslinkRepo::open(&fx.root).expect("reopen crosslink repo");

    // --- exactly two follow-up comments, one per proposal -------------------
    // Wire kind is the neutral, allowlisted `note` (crosslink rejects a
    // `followup` kind); the durable, greppable marker that a note is a proposal
    // is the `**Follow-up proposal**` body header (plus the label, below).
    // `contains` (not `starts_with`): crosslink prepends a `[role]` marker line
    // to the stored comment body, so the header is not the literal first line.
    let comments = cl.list_comments(fx.issue_id).expect("list comments");
    let followups: Vec<_> = comments
        .iter()
        .filter(|c| c.body.contains("**Follow-up proposal**"))
        .collect();
    // Every follow-up comment must ride the allowlisted `note` wire kind — the
    // whole point of the fix: `comment_write(.., "followup", ..)` was rejected.
    assert!(
        followups.iter().all(|c| c.kind == "note"),
        "follow-up comments must post under the allowlisted `note` kind, got {:?}",
        followups.iter().map(|c| &c.kind).collect::<Vec<_>>()
    );
    assert_eq!(
        followups.len(),
        2,
        "exactly two follow-up comments (one per proposal, no duplication), got {:?}",
        comments.iter().map(|c| &c.kind).collect::<Vec<_>>()
    );
    assert!(
        followups.iter().any(|c| c.body.contains("say_bye")),
        "the first proposal's title must appear in a followup comment: {followups:?}"
    );
    assert!(
        followups
            .iter()
            .any(|c| c.body.contains("Localize greetings")),
        "the second proposal's title must appear in a followup comment: {followups:?}"
    );
    // The suggested blocker is rendered as advisory TEXT, framed as not-wired.
    assert!(
        followups
            .iter()
            .any(|c| c.body.contains("advisory") && c.body.contains("#1")),
        "suggested_blockers must render as advisory comment text, not a wired edge: {followups:?}"
    );

    let info = cl.read_issue(fx.issue_id).expect("read issue");

    // --- the ONE graph-side effect: the followup:proposed label -------------
    assert!(
        info.labels.iter().any(|l| l == FOLLOWUP_PROPOSED_LABEL),
        "the issue must carry `{FOLLOWUP_PROPOSED_LABEL}` so the chief can find it, got {:?}",
        info.labels
    );

    // --- propose-don't-commit: NO escalation --------------------------------
    // No blocker edge was wired by the proposal (`suggested_blockers` is text).
    assert!(
        cl.open_blockers(fx.issue_id)
            .expect("read blockers")
            .is_empty(),
        "a follow-up proposal must NEVER wire a real blocker edge"
    );
    // No privileged trust-gate label.
    assert!(
        !info.labels.iter().any(|l| l == INBOUND_APPROVED_LABEL),
        "a proposal must never apply the `{INBOUND_APPROVED_LABEL}` privileged label, got {:?}",
        info.labels
    );
    // The proposal path never (re-)applies `phase:graphed`; the issue merged.
    assert!(
        !info.labels.iter().any(|l| l == GRAPHED_LABEL),
        "the proposal path must not (re-)graph the issue; it merged, got {:?}",
        info.labels
    );
    assert!(
        info.labels.iter().any(|l| l == "phase:merged"),
        "the issue reached phase:merged, got {:?}",
        info.labels
    );
}
