//! GAP 1 capstone — the **federated inbound loop, end to end, as ONE test**.
//!
//! Every other inbound-loop test proves a single seam in isolation:
//! `inbound_approval.rs` the park/approve/resume/land gate, `answer_back.rs` the
//! answer sweep, `dogfood.rs` the graphed→merged worker pipeline. This test is the
//! regression guard that proves they **compose** into the one flow a real inbound
//! request travels — a synthetic `xb:inbound` issue from a peer, driven through the
//! whole machine start to finish, with the security-critical trust boundary
//! (untrusted origin ⇒ never auto-land, peer labels ⇒ never trusted, source peer ⇒
//! answered exactly once) holding at every step.
//!
//! No live crossbridge peer, supervisor, or socket is involved — the sandbox has
//! none. The inbound issue is minted as a plain labeled crosslink issue (exactly
//! the shape the embedded server's `handle_submit` creates), and the answer-back
//! round-trip goes through a **fake [`AnswerTransport`]** (the same injected seam
//! `answer_back.rs` uses), so the peer-facing delivery is observed without a wire.
//! The build/land/resume half runs through the REAL pump (`tick`, the fake Direct
//! worker, the real inbound-approval gate); only the transport is faked.
//!
//! # The one flow this drives (spec §1.2/§1.3, REQ-SWARM-1)
//!
//! 1. **A hostile peer's inbound issue arrives** — `xb:inbound` + routing labels +
//!    a `kind=result` payload, carrying a peer-planted `inbound-approved:land` (the
//!    upstream `handle_submit` echoes `SubmitIssue.labels` verbatim, so a peer CAN
//!    pre-stamp its own land-approval). It arrives **unphased**.
//! 2. **A human graphs it** — the trusted section-chief applies `phase:graphed`
//!    (the enqueue signal); the gate-able `.orchestrator/static_qa.sh` is already
//!    committed in the fixture and passes. This is deliberately the human's action,
//!    NOT the peer's, so the untrusted peer's labels and the trusted enqueue signal
//!    are cleanly separated (see the "which seeded phase:graphed" note below).
//! 3. **Ingest sanitizes on first adoption** — the first `tick` that adopts the
//!    now-graphed issue strips the peer-planted `inbound-approved:land` (and every
//!    other privileged peer label), so the step-6 land gate can never misread it as
//!    a human approval.
//! 4. **The pump works it** — Direct implementer + clean adversary → QA passes →
//!    convergence (`n_rounds = 1`) → land.
//! 5. **The approval gate parks it** — at land, being inbound with NO
//!    `inbound-approved:land` (sanitized away), it parks at
//!    `awaiting-inbound-approval`. `main` does NOT advance.
//! 6. **The peer is answered once, at the park** — the terminal park arms the
//!    answer; the fake transport delivers exactly one `SubmitAnswer` back to the
//!    source peer, carrying the `kind=result` payload.
//! 7. **A human approves** — adds `inbound-approved:land`; the next `tick`'s resume
//!    sweep lands **exactly the reviewed change**. `main` advances to it.
//! 8. **No second answer** — after the merge, a further answer sweep delivers
//!    nothing: the peer was answered exactly once.
//!
//! ## Which seeded `phase:graphed`?
//!
//! **The human (step 2), not the peer.** The synthetic inbound issue is seeded
//! UNPHASED (the peer plants only the dangerous `inbound-approved:land`), and the
//! test's "human" applies `phase:graphed` as an explicit, distinct action. This is
//! the clearest telling of the trust boundary: the enqueue signal is a trusted
//! human's, the sanitize still fires (on the first adoption AFTER the human graphs),
//! and the `phase:graphed`-is-peer-preserved residual documented in
//! `inbound_approval::ingest_strips_a_peer_preset_approval_so_the_gate_still_parks`
//! is sidestepped rather than relied on.

mod common;

use std::cell::RefCell;
use std::path::Path;
use std::process::Command;

use common::{build_fixture, fake_adversary_clean, fake_implementer, unique_session, Fixture};
use orchestrator::answer::{deliver_pending, on_issue_terminal, AnswerAction, AnswerTransport};
use orchestrator::config::{OrchestratorConfig, WorkerConfig};
use orchestrator::events::{EventLog, ORCHESTRATOR_DIR};
use orchestrator::pump::{BuildPump, IssueOutcome, INBOUND_APPROVED_LABEL};
use orchestrator::spawn::Spawner;
use orchestrator::state::{IssueRow, Phase, PhaseSubstate, StateDb};
use orchestrator::workspace::WorkspaceManager;
use vetinari_crossbridge_api::{AnswerOutcome, AnswerReq, CrossbridgeError};
use vetinari_crosslink_api::CrosslinkRepo;

/// The source peer slug the inbound issue routes back to (its `xb-source:`).
const SOURCE_PEER: &str = "peerX";
/// A distinctive marker in the `kind=result` payload, so the delivered answer can
/// be proven to carry the worked result.
const RESULT_MARKER: &str = "say_hi implemented and QA-passed for peerX";

/// The commit `main` points at in the repo at `cwd` (test-support read).
fn main_commit(cwd: &Path) -> String {
    let out = Command::new("jj")
        .args(["log", "-r", "main", "--no-graph", "-T", "commit_id"])
        .current_dir(cwd)
        .output()
        .expect("jj log for main");
    assert!(out.status.success(), "jj log must succeed");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// The `say_hi` presence in the crate as `main` sees it (test-support read).
fn main_has_say_hi(cwd: &Path) -> bool {
    let out = Command::new("jj")
        .args(["file", "show", "-r", "main", "src/lib.rs"])
        .current_dir(cwd)
        .output()
        .expect("jj file show main:src/lib.rs");
    assert!(out.status.success(), "jj file show must succeed");
    String::from_utf8_lossy(&out.stdout).contains("fn say_hi")
}

/// Reopen the fixture's `state.db` and read one issue row (proves durability —
/// the pump owns its own handle for the loop).
fn read_issue(fx: &Fixture, issue_id: i64) -> IssueRow {
    let state = StateDb::open(fx.root.join(ORCHESTRATOR_DIR).join("state.db")).expect("reopen");
    state
        .get_issue(&issue_id.to_string())
        .expect("read")
        .expect("row present")
}

/// Seed one UNPHASED `xb:inbound` crosslink issue in the exact shape a hostile
/// peer's `submit` produces (the server echoes `SubmitIssue.labels` verbatim): the
/// legitimate routing labels PLUS a peer-planted `inbound-approved:land` — the
/// land-gate bypass the sanitize must strip. Deliberately NO `phase:graphed`: the
/// enqueue signal is the human's to apply (step 2). Also posts the `kind=result`
/// payload the answer-back delivers. Returns the created issue's id.
fn seed_hostile_inbound(root: &Path) -> i64 {
    let out = Command::new("crosslink")
        .args([
            "issue",
            "create",
            "inbound work from a peer",
            "-d",
            "peer-submitted, untrusted, self-approved",
            "-l",
            "xb:inbound",
            "-l",
            &format!("xb-source:{SOURCE_PEER}"),
            "-l",
            "xb-ref:uuid-fed-e2e",
            "-l",
            "xb-status:open",
            // The dangerous peer-planted label the sanitize MUST strip.
            "-l",
            INBOUND_APPROVED_LABEL,
            "--quiet",
        ])
        .current_dir(root)
        .output()
        .expect("spawn crosslink issue create");
    assert!(
        out.status.success(),
        "crosslink issue create failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let id: i64 = String::from_utf8_lossy(&out.stdout)
        .lines()
        .last()
        .and_then(|l| l.trim().parse().ok())
        .expect("parse created issue id");

    // The worked-result payload the answer-back carries back to the peer.
    let crosslink = CrosslinkRepo::open(root).expect("open crosslink to seed result");
    crosslink
        .comment_write(id, "result", RESULT_MARKER, None)
        .expect("seed the kind=result payload");
    id
}

/// A fake [`AnswerTransport`] that records every [`AnswerReq`] it is handed and
/// returns success — no socket is ever touched. The same seam `answer_back.rs`
/// uses; the sandbox has no crossbridge peer, so the peer-facing delivery is
/// observed here rather than on a wire.
struct RecordingTransport {
    calls: RefCell<Vec<AnswerReq>>,
}

impl RecordingTransport {
    fn new() -> Self {
        RecordingTransport {
            calls: RefCell::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<AnswerReq> {
        self.calls.borrow().clone()
    }
}

impl AnswerTransport for RecordingTransport {
    fn answer(&self, req: &AnswerReq) -> Result<AnswerOutcome, CrossbridgeError> {
        self.calls.borrow_mut().push(req.clone());
        Ok(AnswerOutcome {
            remote_issue_id: 9000 + req.source_uuid.len() as i64,
        })
    }
}

/// The whole federated inbound loop, driven as ONE flow. See the module docs for
/// the eight steps; the assertions below are numbered to match.
#[test]
fn federation_inbound_loop_end_to_end() {
    // --- Harness: the `hello` fixture (real jj + crosslink, committed
    //     `.orchestrator/static_qa.sh`), local landing mode, crossbridge DISABLED
    //     so the pump's own tick never touches the real transport — the answer
    //     round-trip is driven explicitly through the fake seam below. ---
    let fx = build_fixture();
    let orchestrator_dir = fx.root.join(ORCHESTRATOR_DIR);
    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("open state.db");
    let log = EventLog::open(&orchestrator_dir).expect("open events.jsonl");
    let manager = WorkspaceManager::load(&fx.root).expect("load workspace manager");
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink repo");
    let (session, _guard) = unique_session("fed-e2e");
    let spawner = Spawner::new(session, &fx.root, common::bwrap_pin());
    let config = OrchestratorConfig {
        worker: WorkerConfig {
            argv: vec![
                "bash".to_owned(),
                fake_implementer().to_string_lossy().into_owned(),
            ],
            adversary_argv: vec![
                "bash".to_owned(),
                fake_adversary_clean().to_string_lossy().into_owned(),
            ],
            ..WorkerConfig::default()
        },
        worker_timeout_secs: 60,
        convergence: orchestrator::config::ConvergenceConfig {
            n_rounds: 1,
            ..Default::default()
        },
        ..OrchestratorConfig::default()
    };
    let pump = BuildPump::new(config, state, log, manager, spawner, crosslink);

    // The fixture's own seed issue is locally-authored — neutralize its
    // `phase:graphed` so the pump only ever works the synthetic inbound issue.
    let crosslink = CrosslinkRepo::open(&fx.root).expect("reopen crosslink");
    crosslink
        .label_remove(fx.issue_id, "phase:graphed")
        .expect("neutralize the fixture seed issue");

    // === STEP 1 — a hostile peer's inbound issue arrives (unphased) ===========
    let inbound = seed_hostile_inbound(&fx.root);
    let labels_on_arrival = crosslink.read_issue(inbound).expect("read inbound").labels;
    assert!(
        labels_on_arrival
            .iter()
            .any(|l| l == INBOUND_APPROVED_LABEL),
        "precondition: the peer arrives WITH its planted land-approval, got {labels_on_arrival:?}"
    );
    assert!(
        !labels_on_arrival.iter().any(|l| l == "phase:graphed"),
        "precondition: the inbound issue arrives UNPHASED (the human graphs it), got {labels_on_arrival:?}"
    );
    let main_at_arrival = main_commit(&fx.root);
    assert!(
        !main_has_say_hi(&fx.root),
        "precondition: main carries no worker change yet"
    );

    // === STEP 2 — a human graphs it (the trusted enqueue signal) ==============
    // The peer is un-adopted until now: ingest keys off `phase:graphed`, which the
    // peer did NOT set. The human/section-chief applies it as the graph gate.
    assert!(
        pump.tick().expect("pre-graph tick").is_empty(),
        "before the human graphs, the pump adopts NOTHING (the issue is unphased)"
    );
    assert!(
        crosslink
            .read_issue(inbound)
            .expect("read")
            .labels
            .iter()
            .any(|l| l == INBOUND_APPROVED_LABEL),
        "an unadopted issue is NOT sanitized — the peer label still stands pre-graph"
    );
    crosslink
        .label_add(inbound, "phase:graphed")
        .expect("the human graphs the reviewed inbound issue");

    // === STEP 3 — first adoption sanitizes the peer-planted approval ==========
    // This first tick both ingests+sanitizes AND drives the issue synchronously; by
    // the time it returns the peer's land-approval is stripped and the issue has
    // been worked to its terminal park (asserted in steps 4-5).
    let first = pump.tick().expect("first adopting tick");
    let sanitized = crosslink.read_issue(inbound).expect("read inbound").labels;
    assert!(
        !sanitized.iter().any(|l| l == INBOUND_APPROVED_LABEL),
        "SANITIZE: the peer-planted `inbound-approved:land` MUST be stripped on first adoption, got {sanitized:?}"
    );
    // The legitimate labels survive — routing + the human's enqueue signal.
    for keep in ["xb:inbound", "xb-source:peerX", "xb-ref:uuid-fed-e2e"] {
        assert!(
            sanitized.iter().any(|l| l == keep),
            "the sanitize must preserve the legitimate label `{keep}`, got {sanitized:?}"
        );
    }

    // === STEPS 4-5 — worked to convergence, then PARKED (never auto-landed) ====
    // Drive to idle in case the park did not complete within the first tick (the
    // parked phase is terminal + non-drivable, so this is a no-op once parked).
    let mut outcomes = first;
    outcomes.extend(
        pump.run_until_idle()
            .expect("drive the inbound issue to idle"),
    );
    assert!(
        outcomes
            .iter()
            .any(|(id, o)| *id == inbound && *o == IssueOutcome::AwaitingInboundApproval),
        "an untrusted inbound issue must PARK at the gate, never auto-land, got {outcomes:?}"
    );
    assert!(
        !outcomes
            .iter()
            .any(|(id, o)| *id == inbound && *o == IssueOutcome::Merged),
        "the inbound issue must NOT have merged before human approval, got {outcomes:?}"
    );

    let parked = read_issue(&fx, inbound);
    assert_eq!(
        parked.phase,
        Phase::AwaitingInboundApproval,
        "state.db authority: the issue is parked awaiting inbound approval"
    );
    let reviewed_change = parked
        .landing_change
        .clone()
        .expect("the park must persist the reviewed change for the label-gated resume");
    // main is UNTOUCHED — untrusted work never fast-forwarded trunk.
    assert_eq!(
        main_commit(&fx.root),
        main_at_arrival,
        "the inbound gate must leave main exactly where it was (no auto-land)"
    );
    assert!(
        !main_has_say_hi(&fx.root),
        "the worker's change must NOT be on main while the issue is parked"
    );

    // === STEP 6 — the peer is answered ONCE, at the park ======================
    // The park is terminal, so the answer-back trigger arms the peer's delivery.
    // (With crossbridge disabled the pump does not run this itself; we drive the
    // real trigger + sweep explicitly through the fake transport — the sandbox has
    // no wire.) The socket_root is inert for the fake; own_slug is this node's.
    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("reopen state.db");
    let log = EventLog::open(&orchestrator_dir).expect("reopen events.jsonl");
    let armed = on_issue_terminal(&state, &crosslink, &log, inbound)
        .expect("arming a terminal inbound issue must not error");
    assert!(
        armed,
        "the parked inbound issue must arm an answer-back delivery"
    );
    assert_eq!(
        read_issue(&fx, inbound).phase_substate.as_deref(),
        Some(PhaseSubstate::AnswerPending.as_str()),
        "arming sets the answer_pending substate"
    );

    let transport = RecordingTransport::new();
    let socket_root = fx.root.join("run");
    let actions = deliver_pending(
        &state,
        &crosslink,
        &log,
        &transport,
        "localnode",
        &socket_root,
        300,
        1_000_000,
    )
    .expect("the park-time answer sweep");
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, AnswerAction::Answered { issue_id } if *issue_id == inbound)),
        "the park-time sweep must answer the source peer, got {actions:?}"
    );
    let calls = transport.calls();
    assert_eq!(
        calls.len(),
        1,
        "exactly ONE answer must reach the peer at the park"
    );
    assert_eq!(
        calls[0].peer_slug, SOURCE_PEER,
        "the answer must route to the source peer `{SOURCE_PEER}`, got `{}`",
        calls[0].peer_slug
    );
    assert!(
        calls[0]
            .comments
            .iter()
            .any(|c| c.kind == "result" && c.content.contains(RESULT_MARKER)),
        "the delivered answer must carry the kind=result payload, got {:?}",
        calls[0].comments
    );
    assert_eq!(
        read_issue(&fx, inbound).phase_substate.as_deref(),
        Some(PhaseSubstate::AnswerSent.as_str()),
        "a delivered answer moves the substate to answer_sent"
    );

    // === STEP 7 — a human approves → the resume sweep lands exactly the review ==
    let main_before_land = main_commit(&fx.root);
    crosslink
        .label_add(inbound, INBOUND_APPROVED_LABEL)
        .expect("the human approves the reviewed change");
    let resume = pump.tick().expect("tick with an approved inbound issue");
    assert!(
        resume
            .iter()
            .any(|(id, o)| *id == inbound && *o == IssueOutcome::Merged),
        "an approved inbound issue must be resumed and landed by the pump, got {resume:?}"
    );

    let merged = read_issue(&fx, inbound);
    assert_eq!(
        merged.phase,
        Phase::Merged,
        "the approved issue reached Merged"
    );
    // main advanced to EXACTLY the reviewed change (the durable handle), and now
    // carries the worker's say_hi.
    assert_ne!(
        main_commit(&fx.root),
        main_before_land,
        "after approval, main must fast-forward to the reviewed change"
    );
    assert!(
        main_has_say_hi(&fx.root),
        "main must now carry the worker's say_hi change"
    );
    // The landed change is the one that was reviewed at the park — not a fresh
    // re-implementation the human never saw.
    assert_eq!(
        merged.landing_change.as_deref(),
        Some(reviewed_change.as_str()),
        "the resume must land exactly the reviewed change, not a re-implementation"
    );

    // === STEP 8 — the peer is answered exactly ONCE (no second answer) ========
    // The merge cleared the substate; because the park answer was already
    // `answer_sent`, the resume did NOT re-arm it. A further sweep delivers nothing.
    assert_eq!(
        merged.phase_substate, None,
        "the merge clears the substate; an already-answered park must not re-arm it"
    );
    let post_merge = deliver_pending(
        &state,
        &crosslink,
        &log,
        &transport,
        "localnode",
        &socket_root,
        300,
        2_000_000,
    )
    .expect("post-merge answer sweep");
    assert!(
        post_merge.is_empty(),
        "no answer is due after the merge — the peer was already answered, got {post_merge:?}"
    );
    assert_eq!(
        transport.calls().len(),
        1,
        "the source peer must be answered EXACTLY ONCE across park → approve → merge"
    );
}
