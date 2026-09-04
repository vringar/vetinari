//! Worker → orchestrator artifact contract, DONE sentinel, and idempotent
//! translation planning (REQ-3, REQ-3b, AC-23).
//!
//! Workers (Implementer / Adversary / Merger) never mutate crosslink. They drop
//! structured files under `_orchestrator/` in their workspace; the orchestrator
//! parses those files *after* the phase ends and translates them into crosslink
//! comments. This module owns three things:
//!
//! 1. **The DONE sentinel gate.** `_orchestrator/DONE` is written LAST by the
//!    worker. Its absence means the worker crashed — *regardless* of process
//!    exit code (REQ-3b). A [`DoneSentinel`] can only be constructed by
//!    [`DoneSentinel::verify`], which reads the file, parses the JSON, and
//!    recomputes the SHA-256 of every listed artifact against the digest DONE
//!    recorded. A torn / partial DONE (bad JSON, missing artifact, sha
//!    mismatch) is a typed [`vetinari_error::ArtifactError`], never a panic —
//!    this is the AC-23 torn-write class. "A validated DONE" is unrepresentable
//!    without passing that verification.
//!
//! 2. **Artifact parsers**, each returning typed values tolerant of real worker
//!    output: [`ResultMd::read`] (freeform markdown → PR body),
//!    [`Findings::read`] (`findings.jsonl` → `Vec<`[`Finding`]`>`, one JSON
//!    object per line, malformed line → line-numbered error), and
//!    [`Progress::read`] (optional `progress.jsonl` → best-effort breadcrumbs).
//!
//! 3. **The idempotent translation plan.** [`translation_plan`] turns a parsed
//!    [`ArtifactSet`] plus a `worker_uuid` into a deterministic list of
//!    [`TranslationItem`]s — one per Implementer/Merger whole-file artifact
//!    (`finding_index = -1`), one per Adversary finding (`finding_index =` line
//!    index). The plan is *pure*: identical inputs yield an identical plan, so a
//!    crash mid-translation can be replayed safely. Each item carries the
//!    `(artifact_path, content_sha, finding_index)` key the orchestrator feeds
//!    through [`crate::state::StateDb::is_posted`] /
//!    [`crate::state::StateDb::record_posted`] (the REQ-3b idempotency LEDGER)
//!    so each comment posts at most once.
//!
//! # Why the ledger lives elsewhere
//!
//! This module does *not* dedupe. It produces the plan; the SQLite-backed
//! `posted_artifacts` table in [`crate::state`] is the source of truth for what
//! has already been posted. Keeping the plan pure and the ledger separate is
//! what makes replay-after-crash correct: the plan is recomputed identically,
//! then filtered against the ledger.
//!
//! # No shell-out (AC-24)
//!
//! SHA-256 is computed with the [`sha2`] crate; all file access is
//! [`std::fs`]. Nothing here constructs a `std::process::Command`.

// `ArtifactError` carries rich diagnostic context (a `NamedSource` for miette
// span rendering, a boxed parser source) in its `SchemaViolation` variant,
// pushing it over clippy's large-`Err` threshold. Same rationale as the `error`
// crate itself (see its crate-level allow): these errors propagate at
// human-decision rate on the post-phase translation path, not in a hot loop, so
// the variant size is the wrong axis to optimize. `state.rs`/`workspace.rs`
// don't need this only because `StateError`/`SpawnError` happen to stay under
// the threshold.
#![allow(clippy::result_large_err)]

use std::fmt::Write as _;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vetinari_error::ArtifactError;

/// The `_orchestrator/` directory a worker writes its artifacts into, relative
/// to its workspace root. Kept as a constant so the layout in
/// `.design/vdd-orchestrator.md` and the code agree.
pub const ARTIFACT_DIR: &str = "_orchestrator";

/// The DONE sentinel filename (REQ-3b), relative to [`ARTIFACT_DIR`].
pub const DONE_FILE: &str = "DONE";

/// The Implementer / Merger result artifact (freeform markdown → PR body).
pub const RESULT_FILE: &str = "result.md";

/// The Adversary findings artifact (one JSON finding per line).
pub const FINDINGS_FILE: &str = "findings.jsonl";

/// Max number of [`Finding`]s a single `findings.jsonl` may carry. An Adversary
/// driving an inbound issue is UNTRUSTED (spec §1.6): without a count cap it can
/// write a huge `findings.jsonl` whose translation posts hundreds of thousands
/// of `blocker` comments + ledger rows onto one issue (resource exhaustion /
/// issue-poisoning). The cap is deliberately GENEROUS — a real adversary round
/// posts well under ~20 findings, so no legitimate round is ever affected — yet
/// still bounds the DoS. An over-cap artifact is a misbehaving worker, so it is
/// REJECTED whole (a typed [`ArtifactError::SchemaViolation`]), never partially
/// accepted (a partial accept would silently hide the misbehavior).
const FINDINGS_MAX: usize = 256;

/// Max byte length of a `findings.jsonl` artifact, checked BEFORE the per-line
/// parse so a multi-MB file can't DoS parsing itself before the [`FINDINGS_MAX`]
/// count check runs. Generous enough for [`FINDINGS_MAX`] real findings; an
/// over-size file is a typed [`ArtifactError::SchemaViolation`]. See
/// [`FINDINGS_MAX`] for the untrusted-worker rationale.
const FINDINGS_ARTIFACT_MAX_BYTES: usize = 1024 * 1024;

/// The optional progress-breadcrumb artifact.
pub const PROGRESS_FILE: &str = "progress.jsonl";

/// The optional Implementer / Merger follow-up-proposal artifact (REQ-SWARM-2,
/// swarm-kickoff-spec §1.6): one JSON [`FollowupProposal`] per line.
///
/// # Propose, never commit — the load-bearing invariant
///
/// This artifact is the *only* channel by which a worker surfaces follow-up work
/// it discovered while driving an issue. A worker holds crosslink **read-only**
/// and MUST NEVER write the issue graph. This file is therefore deliberately
/// impotent: everything it can cause is confined to
///
/// 1. one **`--kind followup`** comment per proposal (through the same
///    idempotency ledger as every other artifact), and
/// 2. the single named [`crate::pump::FOLLOWUP_PROPOSED_LABEL`] applied to the
///    issue so the chief can find proposals awaiting review.
///
/// It is **impossible** for a proposal to create a crosslink issue, apply
/// `phase:graphed` (or any `phase:*`), wire a real blocker edge, or apply
/// `inbound-approved:land` — [`translation_plan`] maps a followups artifact to
/// nothing but [`CommentKind::Followup`] items, and the pump's translation loop
/// does nothing with those but post a comment and add that one label.
/// `suggested_blockers` is rendered as **TEXT INSIDE THE COMMENT BODY** — a
/// suggestion for the human — and is never fed to a `crosslink issue block`
/// call. Promotion of a proposal into a real graphed issue is a human/chief
/// action via the `vetinari` skill (the trusted single writer), out of scope for
/// the worker→orchestrator path this module implements.
pub const FOLLOWUPS_FILE: &str = "followups.jsonl";

/// Max byte length of a [`FollowupProposal`] title. A proposal is UNTRUSTED
/// worker output (a worker driving an inbound issue is untrusted, spec §1.6), so
/// every field is length-capped at parse time; an over-cap title is a
/// schema violation, never a truncation.
const FOLLOWUP_TITLE_MAX: usize = 200;

/// Max byte length of a [`FollowupProposal`] rationale (untrusted; see
/// [`FOLLOWUP_TITLE_MAX`]).
const FOLLOWUP_RATIONALE_MAX: usize = 4_000;

/// Max byte length of a [`FollowupProposal`] gate sketch (untrusted; see
/// [`FOLLOWUP_TITLE_MAX`]).
const FOLLOWUP_GATE_SKETCH_MAX: usize = 2_000;

/// Max number of `suggested_blockers` a single [`FollowupProposal`] may carry.
/// These are advisory issue numbers rendered into the comment TEXT for a human;
/// bounding the count keeps a hostile proposal from ballooning a comment body.
const FOLLOWUP_MAX_SUGGESTED_BLOCKERS: usize = 32;

/// Max number of [`FollowupProposal`]s a single `followups.jsonl` may carry. A
/// worker driving an inbound issue is UNTRUSTED (spec §1.6): the per-proposal
/// caps above bound each proposal's SIZE, but without a count cap a hostile
/// worker can write a multi-MB `followups.jsonl` whose translation posts
/// hundreds of thousands of `note` comments + ledger rows onto one issue
/// (resource exhaustion / issue-poisoning). This is not an escalation — still
/// only `note` comments plus the one `followup:proposed` label — but a real DoS
/// against the modeled hostile actor. An over-cap artifact is a misbehaving
/// worker, so it is REJECTED whole (a typed
/// [`ArtifactError::SchemaViolation`]), never partially accepted (a partial
/// accept would silently hide the misbehavior).
const FOLLOWUP_MAX_PROPOSALS: usize = 32;

/// Max byte length of a `followups.jsonl` artifact, checked BEFORE the per-line
/// parse so a multi-MB file can't DoS parsing itself before the
/// [`FOLLOWUP_MAX_PROPOSALS`] count check runs. Comfortably fits
/// [`FOLLOWUP_MAX_PROPOSALS`] max-size proposals (each ~6.5 KB of capped
/// fields); an over-size file is a typed [`ArtifactError::SchemaViolation`].
const FOLLOWUP_ARTIFACT_MAX_BYTES: usize = 512 * 1024;

/// Sentinel finding index for a whole-file artifact (e.g. `result.md`), per the
/// `posted_artifacts` schema in [`crate::state`]. Per-finding artifacts use the
/// finding's 0-based line index instead.
pub const WHOLE_FILE_INDEX: i64 = -1;

// ============================================================================
// Severity + ExitStatus enums
// ============================================================================

/// Severity of an Adversary [`Finding`]. A newtype over the three
/// contract-defined tokens rather than a bare string, so an unknown severity is
/// rejected at parse time instead of silently flowing into a comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// A high-severity finding — a real defect or safety issue.
    High,
    /// A medium-severity finding.
    #[serde(rename = "med")]
    Med,
    /// A low-severity finding — a nit or minor concern.
    Low,
}

impl Severity {
    /// The canonical token this severity is spelled as in `findings.jsonl`.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::High => "high",
            Severity::Med => "med",
            Severity::Low => "low",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A worker's self-reported terminal status, recorded in the DONE sentinel.
/// Advisory only: the orchestrator does not trust it to decide pass/fail
/// (REQ-9), but records it in `events.jsonl` for the narrative trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExitStatus {
    /// The worker believes it completed successfully.
    Success,
    /// The worker believes it failed.
    Error,
}

impl ExitStatus {
    /// The canonical token this status is spelled as in the DONE sentinel.
    pub fn as_str(self) -> &'static str {
        match self {
            ExitStatus::Success => "success",
            ExitStatus::Error => "error",
        }
    }
}

impl std::fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The crosslink comment kind an artifact translates to (REQ-3). Mirrors
/// crosslink's `--kind` flag; a newtype so a translation item can never carry a
/// free-form kind string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentKind {
    /// An Implementer / Merger result summary → `--kind result`.
    Result,
    /// A per-finding Adversary blocker → `--kind blocker`.
    Blocker,
    /// A summarized progress breadcrumb cluster → `--kind observation`.
    Observation,
    /// A worker-proposed unit of follow-up work (REQ-SWARM-2). Propose-only:
    /// this comment records a *suggestion* for a human/chief to promote; it
    /// never authors the graph. See [`FOLLOWUPS_FILE`].
    ///
    /// **Wire kind is `note`, not `followup`.** crosslink's
    /// `KNOWN_COMMENT_KINDS` allowlist does not include `followup`, so posting
    /// under that kind is rejected with `InvalidCommentKind`. The durable,
    /// findable marker of a proposal is instead the freeform
    /// [`FOLLOWUP_PROPOSED_LABEL`] plus the `**Follow-up proposal**` body
    /// header — see [`FollowupProposal::comment_body`]. The enum variant keeps
    /// its descriptive name as an in-code marker; only the wire token is `note`.
    Followup,
}

impl CommentKind {
    /// The crosslink `--kind` token. Every value here must be in crosslink's
    /// `KNOWN_COMMENT_KINDS` allowlist, or `comment_write` fails with
    /// `InvalidCommentKind`. In particular [`CommentKind::Followup`] maps to
    /// the neutral, always-allowed `note` (see its doc comment).
    pub fn as_str(self) -> &'static str {
        match self {
            CommentKind::Result => "result",
            CommentKind::Blocker => "blocker",
            CommentKind::Observation => "observation",
            CommentKind::Followup => "note",
        }
    }
}

impl std::fmt::Display for CommentKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ============================================================================
// Location
// ============================================================================

/// A validated `path:line` source location from a [`Finding`].
///
/// A newtype over the two components rather than a bare `"path:line"` string:
/// [`Location::parse`] guarantees a non-empty path and a parseable line number,
/// so downstream comment rendering never has to re-validate. The `path` may
/// itself contain `:` (rare, but Windows-drive-like); the split is on the
/// *last* `:` so the trailing line number is unambiguous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    /// File path the finding points at.
    path: String,
    /// 1-based line number within that file.
    line: u32,
}

impl Location {
    /// Parse a `path:line` token. Returns `None` if there is no `:`, the path is
    /// empty, or the line suffix is not a non-negative integer.
    pub fn parse(raw: &str) -> Option<Self> {
        let (path, line) = raw.rsplit_once(':')?;
        if path.is_empty() {
            return None;
        }
        let line: u32 = line.parse().ok()?;
        Some(Location {
            path: path.to_owned(),
            line,
        })
    }

    /// The file path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The 1-based line number.
    pub fn line(&self) -> u32 {
        self.line
    }
}

impl std::fmt::Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.path, self.line)
    }
}

// ============================================================================
// Finding
// ============================================================================

/// Intermediate shape a `findings.jsonl` line deserializes into before the
/// stringly-typed `location` is validated into a [`Location`]. Kept private so
/// no unvalidated finding escapes this module.
#[derive(Debug, Deserialize)]
struct RawFinding {
    severity: Severity,
    location: String,
    claim: String,
    #[serde(default)]
    evidence_files: Vec<String>,
}

/// One Adversary finding — a single line of `findings.jsonl`. Each finding
/// translates to exactly one `--kind blocker` comment (REQ-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Severity of the finding.
    pub severity: Severity,
    /// Validated `path:line` the finding points at.
    pub location: Location,
    /// The claim the Adversary is making.
    pub claim: String,
    /// Files the Adversary cites as evidence.
    pub evidence_files: Vec<String>,
}

impl Finding {
    /// Render this finding as the body of its `--kind blocker` comment. Pure and
    /// deterministic: [`translation_plan`] relies on identical findings yielding
    /// identical bodies so a replayed plan is byte-for-byte stable.
    pub fn comment_body(&self) -> String {
        let mut body = format!(
            "[{}] {}\nlocation: {}",
            self.severity, self.claim, self.location
        );
        // One evidence file per line rather than a `", "`-joined list: a
        // comma-joined list is ambiguous if a filename itself contains a comma,
        // whereas a leading `- ` per line round-trips unambiguously (a filename
        // cannot contain a newline).
        if !self.evidence_files.is_empty() {
            body.push_str("\nevidence:");
            for file in &self.evidence_files {
                body.push_str("\n- ");
                body.push_str(file);
            }
        }
        body
    }

    /// Render this finding as one `findings.jsonl` line — the wire schema the
    /// Adversary emits and the pump reuses when it delivers accumulated prior
    /// findings into a re-implement round's Implementer workspace (REQ-8). The
    /// structured [`Location`] collapses back to the flat `"path:line"` string,
    /// so the line round-trips through [`Findings::parse`].
    ///
    /// Returns the serializer error rather than unwrapping it. The fields are
    /// plain strings, so a failure is not reachable in practice, but the pump
    /// must never `unwrap`/`panic` on a non-test path (see `pump` module docs).
    pub fn to_jsonl_line(&self) -> Result<String, serde_json::Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            severity: &'a str,
            location: String,
            claim: &'a str,
            evidence_files: &'a [String],
        }
        serde_json::to_string(&Wire {
            severity: self.severity.as_str(),
            location: self.location.to_string(),
            claim: &self.claim,
            evidence_files: &self.evidence_files,
        })
    }
}

// ============================================================================
// ResultMd
// ============================================================================

/// The Implementer / Merger `result.md` artifact — freeform markdown that
/// becomes the PR body in remote mode (REQ-17). A typed wrapper over the raw
/// content rather than a bare `String`, so the translation planner takes a
/// proof-of-read value rather than an arbitrary string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultMd {
    content: String,
}

impl ResultMd {
    /// Read `result.md` from a worker's `_orchestrator/` directory.
    pub fn read(artifact_dir: &Path) -> Result<Self, ArtifactError> {
        let path = artifact_dir.join(RESULT_FILE);
        let content = read_file(&path)?;
        Ok(ResultMd { content })
    }

    /// The raw markdown body.
    pub fn content(&self) -> &str {
        &self.content
    }
}

// ============================================================================
// Findings (findings.jsonl)
// ============================================================================

/// The parsed `findings.jsonl` artifact — zero or more [`Finding`]s in file
/// order. An empty file is valid: an Adversary round that found nothing (the
/// convergence signal, REQ-10) produces zero findings, not an error.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Findings {
    findings: Vec<Finding>,
}

impl Findings {
    /// Read and parse `findings.jsonl` from a worker's `_orchestrator/`
    /// directory. One JSON object per line; blank lines are skipped. A
    /// malformed line — invalid JSON, an unknown severity, or a `location` that
    /// is not `path:line` — is rejected with a line-numbered
    /// [`ArtifactError::SchemaViolation`] (AC-23: never parse a half-written
    /// line as a comment). A missing file is treated as an empty set (an
    /// Adversary that wrote no findings), matching the design's "possibly
    /// empty" contract.
    ///
    /// This is the **lenient** reader (missing ⇒ empty). The convergence path
    /// must NOT use it — an absent file reading as "empty ⇒ converged" is the
    /// false-convergence hole. Use [`from_done`](Findings::from_done), which
    /// requires an explicitly DONE-attested `findings.jsonl`.
    pub fn read(artifact_dir: &Path) -> Result<Self, ArtifactError> {
        let path = artifact_dir.join(FINDINGS_FILE);
        // Bounded read (untrusted worker): never slurp more than the byte cap
        // (+1, so `parse` can see the overflow and reject) into memory.
        let content = read_bounded(&path, FINDINGS_ARTIFACT_MAX_BYTES)?;
        Self::parse(&path, &content)
    }

    /// Strict convergence reader (REQ-10): parse `findings.jsonl` from a
    /// **verified** [`DoneSentinel`], REQUIRING the worker to have declared it.
    ///
    /// This is the reader the Adversary/convergence path (#22/#23) must use —
    /// NOT the lenient [`read`](Findings::read), which maps an absent file to an
    /// empty set. That leniency is a false-convergence hole: a worker that wrote
    /// `DONE` but never wrote `findings.jsonl` would read as "empty ⇒ converged"
    /// and auto-land a buggy change on a crashed Adversary. Here a clean round
    /// must be an explicitly-present, DONE-attested `findings.jsonl`:
    ///
    /// - **absent/undeclared** `findings.jsonl` ⇒ [`ArtifactError::FindingsMissing`]
    ///   (an incomplete worker; the pump/recovery re-spawns, never converges),
    /// - **present-and-empty** (declared in DONE) ⇒ a valid clean round
    ///   (`Findings::is_empty`).
    ///
    /// Presence is decided by the sentinel's declared artifacts (equivalent to
    /// `done.sha_for("_orchestrator/findings.jsonl").is_some()`), and the body is
    /// parsed from the sentinel's VERIFIED bytes — hashed once at verify time —
    /// so there is no re-read and no TOCTOU (the same guarantee
    /// [`translation_plan`] relies on).
    pub fn from_done(done: &DoneSentinel) -> Result<Self, ArtifactError> {
        let artifact = done
            .artifacts()
            .iter()
            .find(|a| artifact_file_name(a.path()) == FINDINGS_FILE)
            .ok_or_else(|| ArtifactError::FindingsMissing {
                declared: done
                    .artifacts()
                    .iter()
                    .map(|a| a.path().to_owned())
                    .collect(),
            })?;
        // Parse the *verified* bytes, exactly as `translation_plan` does, so the
        // convergence decision and the posted comments come from identical bytes.
        let content = String::from_utf8_lossy(artifact.bytes());
        Self::parse(Path::new(artifact.path()), &content)
    }

    /// Parse already-read `findings.jsonl` content. Split out from [`read`] so
    /// tests and callers can validate an in-memory buffer.
    ///
    /// Whole-artifact bounds (untrusted Adversary, spec §1.6): total size ≤
    /// [`FINDINGS_ARTIFACT_MAX_BYTES`] (checked first) and at most
    /// [`FINDINGS_MAX`] findings; an over-cap file is rejected WHOLE with a
    /// typed [`ArtifactError::SchemaViolation`], never partially accepted.
    ///
    /// [`read`]: Findings::read
    pub fn parse(path: &Path, content: &str) -> Result<Self, ArtifactError> {
        // Untrusted worker (spec §1.6): bound the artifact BYTE size before the
        // per-line loop so a multi-MB file can't DoS parsing itself, then cap
        // the COUNT so a huge file can't post hundreds of thousands of blocker
        // comments + ledger rows onto one issue. Both are whole-artifact
        // rejections, never partial accepts (see FINDINGS_MAX).
        if content.len() > FINDINGS_ARTIFACT_MAX_BYTES {
            return Err(reject_oversized(path, content, FINDINGS_ARTIFACT_MAX_BYTES));
        }
        let mut findings = Vec::new();
        for (idx, line) in content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let line_no = idx + 1;
            if findings.len() >= FINDINGS_MAX {
                return Err(schema_violation(
                    path,
                    content,
                    line_no,
                    format!("more than {FINDINGS_MAX} findings — refusing to parse").into(),
                ));
            }
            let raw: RawFinding = serde_json::from_str(line)
                .map_err(|e| schema_violation(path, content, line_no, Box::new(e)))?;
            let location = Location::parse(&raw.location).ok_or_else(|| {
                schema_violation(
                    path,
                    content,
                    line_no,
                    format!("`location` is not `path:line`: {:?}", raw.location).into(),
                )
            })?;
            findings.push(Finding {
                severity: raw.severity,
                location,
                claim: raw.claim,
                evidence_files: raw.evidence_files,
            });
        }
        Ok(Findings { findings })
    }

    /// The findings in file order.
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Whether the Adversary produced no findings (a clean round).
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
}

// ============================================================================
// Followups (followups.jsonl) — REQ-SWARM-2, propose-don't-commit
// ============================================================================

/// Intermediate shape a `followups.jsonl` line deserializes into before its
/// fields are length- and content-validated into a [`FollowupProposal`]. Kept
/// private so no unvalidated proposal escapes this module. `deny_unknown_fields`
/// so a worker cannot smuggle an extra key (e.g. a fabricated `label` or
/// `phase`) past the parser in the hope some future code path honors it — the
/// schema is exactly these four fields, nothing more.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFollowup {
    title: String,
    rationale: String,
    #[serde(default)]
    suggested_blockers: Vec<i64>,
    #[serde(default)]
    gate_sketch: Option<String>,
}

/// One worker-proposed unit of follow-up work — a single line of
/// `followups.jsonl` (REQ-SWARM-2, spec §1.6). Each proposal translates to
/// exactly one comment, posted under the neutral `note` wire kind and marked
/// as a proposal by its body header + the `followup:proposed` label.
///
/// **This is a proposal, not a commitment.** Nothing a worker writes here can
/// author the issue graph; see [`FOLLOWUPS_FILE`] for the full invariant. In
/// particular [`suggested_blockers`](FollowupProposal::suggested_blockers) is
/// advisory text for a human — it is rendered into the comment body and is NEVER
/// wired as a real `crosslink issue block` edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FollowupProposal {
    /// One-line title of the proposed work (required, non-empty, single line).
    pub title: String,
    /// Why the worker believes this follow-up is needed (required).
    pub rationale: String,
    /// Issue numbers the worker *suggests* the follow-up might depend on.
    /// **Advisory only** — rendered as comment text for a human to weigh, never
    /// turned into an actual blocker edge (the propose-don't-commit invariant).
    pub suggested_blockers: Vec<i64>,
    /// An optional sketch of the verifiable gate the follow-up would need — a
    /// hint for the chief who eventually graphs it, not a machine contract.
    pub gate_sketch: Option<String>,
}

impl FollowupProposal {
    /// Render this proposal as the body of its comment. Pure and
    /// deterministic: [`translation_plan`] relies on identical proposals
    /// yielding identical bodies so a replayed plan is byte-for-byte stable.
    ///
    /// The body opens with a greppable **`**Follow-up proposal**`** header.
    /// This matters because the comment is posted under the generic `note`
    /// wire kind (crosslink's allowlist has no `followup` kind); the header —
    /// together with the [`FOLLOWUP_PROPOSED_LABEL`] — is what tells a human or
    /// the chief that the note is a proposal rather than an ordinary note.
    ///
    /// The rendered body is plainly framed as a **proposal** and states, in
    /// text, that `suggested_blockers` are advisory — so a human reading the
    /// comment is never misled into thinking an edge was actually wired.
    pub fn comment_body(&self) -> String {
        let mut body = format!(
            "**Follow-up proposal** — {}\n\n{}",
            self.title, self.rationale
        );
        if !self.suggested_blockers.is_empty() {
            body.push_str("\n\nsuggested blockers (advisory — NOT wired; a human decides):");
            for id in &self.suggested_blockers {
                let _ = write!(body, "\n- #{id}");
            }
        }
        if let Some(sketch) = &self.gate_sketch {
            body.push_str("\n\ngate sketch:\n");
            body.push_str(sketch);
        }
        body
    }
}

/// The parsed `followups.jsonl` artifact — zero or more [`FollowupProposal`]s in
/// file order. An empty or absent file is valid (the common case: most workers
/// discover no follow-up work).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Followups {
    proposals: Vec<FollowupProposal>,
}

impl Followups {
    /// Read and parse `followups.jsonl` from a worker's `_orchestrator/`
    /// directory. One JSON object per line; blank lines are skipped. A malformed
    /// line — invalid JSON, an unknown field, a missing/empty title, or an
    /// over-cap field — is rejected with a line-numbered
    /// [`ArtifactError::SchemaViolation`] (AC-23: never post a half-written or
    /// hostile line as a comment). A **missing file is treated as an empty set**
    /// — the overwhelmingly common case; a worker with no follow-ups need not
    /// write the file at all.
    pub fn read(artifact_dir: &Path) -> Result<Self, ArtifactError> {
        let path = artifact_dir.join(FOLLOWUPS_FILE);
        // Bounded read (untrusted worker): never slurp more than the byte cap
        // (+1, so `parse` can see the overflow and reject) into memory.
        let content = read_bounded(&path, FOLLOWUP_ARTIFACT_MAX_BYTES)?;
        Self::parse(&path, &content)
    }

    /// Parse already-read `followups.jsonl` content. Split out from [`read`] so
    /// tests and [`translation_plan`] can validate an in-memory buffer (the
    /// latter parses the DONE-verified bytes, never a re-read).
    ///
    /// Validation (untrusted worker output, spec §1.6):
    /// - `title` non-empty after trimming, single line (no `\r`/`\n`), ≤
    ///   [`FOLLOWUP_TITLE_MAX`] bytes,
    /// - `rationale` ≤ [`FOLLOWUP_RATIONALE_MAX`] bytes,
    /// - `gate_sketch` (if present) ≤ [`FOLLOWUP_GATE_SKETCH_MAX`] bytes,
    /// - at most [`FOLLOWUP_MAX_SUGGESTED_BLOCKERS`] `suggested_blockers`.
    ///
    /// Whole-artifact bounds (untrusted-worker DoS, spec §1.6), checked so a
    /// misbehaving worker can neither DoS the parse loop nor poison an issue:
    /// - total size ≤ [`FOLLOWUP_ARTIFACT_MAX_BYTES`] (checked first, before any
    ///   line is parsed),
    /// - at most [`FOLLOWUP_MAX_PROPOSALS`] proposals; an over-cap file is
    ///   rejected WHOLE, never partially accepted.
    ///
    /// [`read`]: Followups::read
    pub fn parse(path: &Path, content: &str) -> Result<Self, ArtifactError> {
        // Untrusted worker (spec §1.6): bound the artifact BYTE size before the
        // per-line loop so a multi-MB file can't DoS parsing itself, then cap
        // the COUNT so a huge file can't post hundreds of thousands of note
        // comments + ledger rows onto one issue. Both are whole-artifact
        // rejections, never partial accepts (see FOLLOWUP_MAX_PROPOSALS).
        if content.len() > FOLLOWUP_ARTIFACT_MAX_BYTES {
            return Err(reject_oversized(path, content, FOLLOWUP_ARTIFACT_MAX_BYTES));
        }
        let mut proposals = Vec::new();
        for (idx, line) in content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let line_no = idx + 1;

            let reject = |msg: String| schema_violation(path, content, line_no, msg.into());

            if proposals.len() >= FOLLOWUP_MAX_PROPOSALS {
                return Err(reject(format!(
                    "more than {FOLLOWUP_MAX_PROPOSALS} follow-up proposals"
                )));
            }

            let raw: RawFollowup = serde_json::from_str(line)
                .map_err(|e| schema_violation(path, content, line_no, Box::new(e)))?;

            if raw.title.trim().is_empty() {
                return Err(reject("`title` must be non-empty".to_owned()));
            }
            // A title with an embedded newline would break the single-line
            // comment header (and could smuggle a fake second "field" past a
            // human skimming the comment). Reject rather than strip.
            if raw.title.contains(['\r', '\n']) {
                return Err(reject("`title` must be a single line".to_owned()));
            }
            if raw.title.len() > FOLLOWUP_TITLE_MAX {
                return Err(reject(format!(
                    "`title` exceeds {FOLLOWUP_TITLE_MAX} bytes"
                )));
            }
            if raw.rationale.len() > FOLLOWUP_RATIONALE_MAX {
                return Err(reject(format!(
                    "`rationale` exceeds {FOLLOWUP_RATIONALE_MAX} bytes"
                )));
            }
            if let Some(sketch) = &raw.gate_sketch {
                if sketch.len() > FOLLOWUP_GATE_SKETCH_MAX {
                    return Err(reject(format!(
                        "`gate_sketch` exceeds {FOLLOWUP_GATE_SKETCH_MAX} bytes"
                    )));
                }
            }
            if raw.suggested_blockers.len() > FOLLOWUP_MAX_SUGGESTED_BLOCKERS {
                return Err(reject(format!(
                    "`suggested_blockers` exceeds {FOLLOWUP_MAX_SUGGESTED_BLOCKERS} entries"
                )));
            }

            proposals.push(FollowupProposal {
                title: raw.title,
                rationale: raw.rationale,
                suggested_blockers: raw.suggested_blockers,
                gate_sketch: raw.gate_sketch,
            });
        }
        Ok(Followups { proposals })
    }

    /// The proposals in file order.
    pub fn proposals(&self) -> &[FollowupProposal] {
        &self.proposals
    }

    /// Whether the worker proposed no follow-up work (the common case).
    pub fn is_empty(&self) -> bool {
        self.proposals.is_empty()
    }
}

// ============================================================================
// Progress (progress.jsonl) — optional, best-effort
// ============================================================================

/// One `progress.jsonl` breadcrumb. Read post-phase and summarized (REQ-14);
/// never streamed mid-phase (avoids partial-line read races per the design).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ProgressEntry {
    /// Worker-supplied timestamp string (opaque to the orchestrator).
    pub ts: String,
    /// Short operation name.
    pub op: String,
    /// Free-form detail.
    pub detail: String,
}

/// The optional `progress.jsonl` artifact — a best-effort breadcrumb log.
///
/// Unlike `findings.jsonl`, a malformed line here is *not* fatal: `progress` is
/// an optional appendable log the design reads post-phase and summarizes, and
/// its last line may be a torn half-write from a worker that crashed
/// mid-append. Unparseable lines are skipped and counted in
/// [`Progress::skipped`] rather than failing the whole phase.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Progress {
    entries: Vec<ProgressEntry>,
    skipped: usize,
}

impl Progress {
    /// Read and parse `progress.jsonl` best-effort. A missing file yields an
    /// empty log (the artifact is optional). Unparseable lines are skipped.
    pub fn read(artifact_dir: &Path) -> Result<Self, ArtifactError> {
        let path = artifact_dir.join(PROGRESS_FILE);
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Progress::default()),
            Err(source) => return Err(ArtifactError::ReadFailed { path, source }),
        };
        Ok(Self::parse(&content))
    }

    /// Parse already-read `progress.jsonl` content best-effort.
    pub fn parse(content: &str) -> Self {
        let mut entries = Vec::new();
        let mut skipped = 0;
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<ProgressEntry>(line) {
                Ok(entry) => entries.push(entry),
                Err(_) => skipped += 1,
            }
        }
        Progress { entries, skipped }
    }

    /// The successfully-parsed breadcrumbs, in file order.
    pub fn entries(&self) -> &[ProgressEntry] {
        &self.entries
    }

    /// How many lines could not be parsed (e.g. a torn final write).
    pub fn skipped(&self) -> usize {
        self.skipped
    }
}

// ============================================================================
// DoneSentinel — the crash gate (REQ-3b, AC-23)
// ============================================================================

/// One entry of the DONE sentinel's `artifacts` list: a path plus the SHA-256
/// the worker recorded for it. Deserialize-only; verification happens in
/// [`DoneSentinel::verify`].
#[derive(Debug, Clone, Deserialize)]
struct DoneArtifact {
    path: String,
    sha256: String,
}

/// The raw JSON shape of `_orchestrator/DONE`. Private: a caller can only ever
/// hold a *verified* [`DoneSentinel`], never this unvalidated form.
#[derive(Debug, Deserialize)]
struct RawDone {
    exit_status: ExitStatus,
    artifacts: Vec<DoneArtifact>,
}

/// A validated DONE sentinel (REQ-3b).
///
/// This type is the crash gate. It **cannot be constructed without
/// verification**: the only constructor is [`DoneSentinel::verify`], which
/// - reads `_orchestrator/DONE` (absence ⇒
///   [`ArtifactError::DoneSentinelMissing`], a crash regardless of exit code),
/// - parses the JSON against the REQ-3b schema (malformed ⇒
///   [`ArtifactError::DoneMalformed`]),
/// - and recomputes the SHA-256 of every listed artifact, confirming it matches
///   the digest DONE recorded (missing artifact ⇒
///   [`ArtifactError::DoneArtifactMissing`]; digest disagreement ⇒
///   [`ArtifactError::ChecksumMismatch`]).
///
/// Holding a `DoneSentinel` is therefore proof that the worker finished cleanly
/// and every artifact it listed is intact on disk. There is no `pub` field and
/// no other constructor, so "an unverified DONE" is unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoneSentinel {
    exit_status: ExitStatus,
    /// Verified artifacts: `(path relative to the workspace, sha256 hex)`.
    artifacts: Vec<VerifiedArtifact>,
}

/// A single artifact whose on-disk content has been confirmed to match the
/// digest DONE recorded. Only [`DoneSentinel::verify`] mints these.
///
/// The verified `bytes` are retained so downstream translation reads the file
/// exactly once — at verify time — closing the TOCTOU window where a separate
/// `fs::read` at translation time could observe different bytes than the ones
/// [`sha256`] was computed over. The ledger key's `content_sha` and the posted
/// comment body therefore always describe the same bytes.
///
/// [`sha256`]: VerifiedArtifact::sha256
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedArtifact {
    /// Path exactly as the DONE sentinel spelled it (relative to the workspace).
    path: String,
    /// The verified lowercase-hex SHA-256 digest of [`bytes`].
    ///
    /// [`bytes`]: VerifiedArtifact::bytes
    sha256: String,
    /// The artifact's content, read once at verify time and hashed into
    /// [`sha256`]. The single source of truth for both the ledger key and the
    /// posted comment body.
    ///
    /// [`sha256`]: VerifiedArtifact::sha256
    bytes: Vec<u8>,
}

impl VerifiedArtifact {
    /// The artifact path as recorded in DONE (relative to the workspace root).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The verified lowercase-hex SHA-256 digest.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// The verified content — the exact bytes [`sha256`] was computed over.
    ///
    /// [`sha256`]: VerifiedArtifact::sha256
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl DoneSentinel {
    /// Read and fully verify the DONE sentinel for a worker rooted at
    /// `workspace`.
    ///
    /// `workspace` is the worker's workspace root; the sentinel is expected at
    /// `<workspace>/_orchestrator/DONE`, and each artifact `path` in the
    /// sentinel is resolved relative to `<workspace>` (matching how the fake
    /// worker records `_orchestrator/result.md`). Every failure mode is a typed
    /// [`ArtifactError`], never a panic (AC-23).
    pub fn verify(workspace: &Path) -> Result<Self, ArtifactError> {
        let done_path = workspace.join(ARTIFACT_DIR).join(DONE_FILE);
        let content = match std::fs::read_to_string(&done_path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ArtifactError::DoneSentinelMissing {
                    workspace: workspace.to_path_buf(),
                });
            }
            Err(source) => {
                return Err(ArtifactError::ReadFailed {
                    path: done_path,
                    source,
                });
            }
        };

        let raw: RawDone =
            serde_json::from_str(&content).map_err(|e| ArtifactError::DoneMalformed {
                path: done_path.clone(),
                reason: e.to_string(),
            })?;

        let mut artifacts = Vec::with_capacity(raw.artifacts.len());
        for artifact in raw.artifacts {
            // `verify` runs orchestrator-side, OUTSIDE the sandbox. A garbled or
            // hostile DONE could name `/etc/passwd` or `../../x` and `join`
            // would happily resolve it against (or past) the workspace, turning
            // this into an arbitrary host-file read (AC-23). Reject anything not
            // strictly workspace-relative BEFORE touching the filesystem.
            if !is_workspace_relative(&artifact.path) {
                return Err(ArtifactError::DoneArtifactPathUnsafe {
                    artifact: PathBuf::from(&artifact.path),
                });
            }
            let abs = workspace.join(&artifact.path);
            let bytes =
                std::fs::read(&abs).map_err(|source| ArtifactError::DoneArtifactMissing {
                    artifact: PathBuf::from(&artifact.path),
                    source,
                })?;
            let actual = sha256_hex(&bytes);
            let expected = artifact.sha256.to_ascii_lowercase();
            if actual != expected {
                return Err(ArtifactError::ChecksumMismatch {
                    artifact: PathBuf::from(&artifact.path),
                    expected,
                    actual,
                });
            }
            // Retain the verified bytes so translation reads them once (here),
            // never re-reading at a later T1 that could disagree with `actual`.
            artifacts.push(VerifiedArtifact {
                path: artifact.path,
                sha256: actual,
                bytes,
            });
        }

        Ok(DoneSentinel {
            exit_status: raw.exit_status,
            artifacts,
        })
    }

    /// The worker's self-reported terminal status (advisory only, REQ-9).
    pub fn exit_status(&self) -> ExitStatus {
        self.exit_status
    }

    /// The verified artifacts the worker listed, in DONE order.
    pub fn artifacts(&self) -> &[VerifiedArtifact] {
        &self.artifacts
    }

    /// The verified SHA-256 for a listed artifact path, if present. Used by the
    /// translation planner to key the idempotency ledger by content hash
    /// without recomputing.
    pub fn sha_for(&self, path: &str) -> Option<&str> {
        self.artifacts
            .iter()
            .find(|a| a.path == path)
            .map(|a| a.sha256.as_str())
    }
}

/// The trailing filename of a DONE-recorded artifact path, used to dispatch a
/// verified artifact to its translation. Splitting on the last `/` (rather than
/// matching the full `_orchestrator/...` string) means the plan is driven by
/// what the worker actually declared, not by a hardcoded prefix.
fn artifact_file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

// ============================================================================
// Translation plan (REQ-3b idempotent translation)
// ============================================================================

/// A single worker's verified artifacts, ready for translation.
///
/// The [`DoneSentinel`] is the *sole* source: it is mandatory (the translation
/// planner only runs on a worker that finished cleanly, REQ-3b) and each of its
/// [`VerifiedArtifact`]s carries both the verified content hash that keys the
/// idempotency ledger AND the verified bytes that become the comment body. The
/// plan reads nothing else from disk, so the `(path, content_sha)` ledger key
/// and the posted body can never come from different bytes (no TOCTOU).
///
/// Roles are distinguished by which artifacts the worker declared, not by a
/// stored role field: an Implementer/Merger declares `result.md`, an Adversary
/// declares `findings.jsonl`.
#[derive(Debug, Clone)]
pub struct ArtifactSet {
    /// The verified DONE sentinel — source of every artifact's hash and bytes.
    pub done: DoneSentinel,
}

/// One planned crosslink comment. The `(artifact_path, content_sha,
/// finding_index)` triple is exactly the key the orchestrator feeds through
/// [`crate::state::StateDb::is_posted`] /
/// [`crate::state::StateDb::record_posted`] so each comment posts at most once
/// across crashes (REQ-3b).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranslationItem {
    /// Artifact path this comment derives from (relative to the workspace, as
    /// spelled in the DONE sentinel — e.g. `_orchestrator/findings.jsonl`).
    pub artifact_path: String,
    /// The verified SHA-256 of that artifact's content — the ledger's content
    /// key, so a re-run of an *unchanged* artifact maps to the same tuple.
    pub content_sha: String,
    /// Index of the finding within a multi-finding artifact (0-based line
    /// index for `findings.jsonl`); [`WHOLE_FILE_INDEX`] (`-1`) for a
    /// whole-file artifact such as `result.md`.
    pub finding_index: i64,
    /// The crosslink `--kind` this item posts as.
    pub kind: CommentKind,
    /// The rendered comment body.
    pub body: String,
}

/// Build the deterministic translation plan for one worker's artifact set
/// (REQ-3b).
///
/// The plan is a *pure function* of its inputs: the same [`ArtifactSet`] and
/// `worker_uuid` always yield the same `Vec<`[`TranslationItem`]`>`, in the
/// same order. That determinism is what makes replay-after-crash safe — the
/// orchestrator recomputes the identical plan and filters it against the
/// `posted_artifacts` ledger, so an interrupted translation resumes exactly
/// where it left off with no duplicate and no gap.
///
/// The plan is driven off `set.done.artifacts()` — the verified list — so both
/// the ledger key (`artifact_path`, `content_sha`) and the comment body come
/// from the exact bytes the worker declared and `verify` hashed. Each verified
/// artifact is dispatched by its filename:
/// - **`result.md`** → one whole-file `result` comment (`finding_index = -1`),
///   body = the verified bytes as UTF-8. **Only emitted when the worker's
///   `exit_status` is `Success`**: an `error` DONE is a failed phase (the
///   orchestrator re-spawns; see the design's error-handling section), so it
///   must not post a "work is done" result comment.
/// - **`findings.jsonl`** → one `blocker` comment per finding, keyed by the
///   finding's 0-based line index. Parsing the verified bytes can fail (a
///   malformed line), surfacing an [`ArtifactError::SchemaViolation`].
/// - **`followups.jsonl`** → one follow-up comment per proposal, keyed by the
///   proposal's 0-based line index (REQ-SWARM-2). The comment posts under the
///   neutral `note` wire kind (crosslink's allowlist has no `followup` kind);
///   [`CommentKind::Followup`] is the in-code marker for these items. Propose-
///   only: a followups artifact can produce *nothing* but
///   [`CommentKind::Followup`] items — it can never mint a `result` (a "work is
///   done" signal) or a `blocker`, and the pump translates these items into a
///   comment plus the single `followup:proposed` label and nothing else. See
///   [`FOLLOWUPS_FILE`].
/// - any other declared artifact (`DONE`, `progress.jsonl`, …) is not
///   translated to a comment and is skipped.
///
/// `worker_uuid` is threaded through for provenance (recovery records it as the
/// ledger's audit column), but does not affect item ordering or bodies and is
/// **not** part of the dedup key. The ledger's primary key is content-addressed
/// and issue-scoped — `(issue_id, artifact_path, content_sha, finding_index)` —
/// so a re-translation of identical content under a different uuid still posts at
/// most once (AC-17). Each item carries the per-artifact `(artifact_path,
/// content_sha, finding_index)` triple the orchestrator combines with the issue
/// id at post time.
pub fn translation_plan(
    worker_uuid: &str,
    set: &ArtifactSet,
) -> Result<Vec<TranslationItem>, ArtifactError> {
    let _ = worker_uuid; // provenance only; see doc comment.
    let mut items = Vec::new();
    let is_success = set.done.exit_status() == ExitStatus::Success;

    for artifact in set.done.artifacts() {
        match artifact_file_name(artifact.path()) {
            RESULT_FILE => {
                // An error DONE is a failed phase — no result comment (REQ-3b /
                // design error-handling: the orchestrator re-spawns instead).
                if !is_success {
                    continue;
                }
                items.push(TranslationItem {
                    artifact_path: artifact.path().to_owned(),
                    content_sha: artifact.sha256().to_owned(),
                    finding_index: WHOLE_FILE_INDEX,
                    kind: CommentKind::Result,
                    // Body from the verified bytes, not a re-read (no TOCTOU).
                    body: String::from_utf8_lossy(artifact.bytes()).into_owned(),
                });
            }
            FINDINGS_FILE => {
                // Parse the *verified* bytes — the same bytes `content_sha`
                // describes — so key and body agree.
                let content = String::from_utf8_lossy(artifact.bytes());
                let findings = Findings::parse(Path::new(artifact.path()), &content)?;
                for (idx, finding) in findings.findings().iter().enumerate() {
                    items.push(TranslationItem {
                        artifact_path: artifact.path().to_owned(),
                        content_sha: artifact.sha256().to_owned(),
                        finding_index: idx as i64,
                        kind: CommentKind::Blocker,
                        body: finding.comment_body(),
                    });
                }
            }
            FOLLOWUPS_FILE => {
                // Propose-don't-commit (REQ-SWARM-2): a followups artifact maps
                // to follow-up comments ONLY (wire kind `note`; the enum marks
                // them CommentKind::Followup). It can never emit a
                // `result`/`blocker`, and the pump does nothing with these items
                // but post a comment + add the `followup:proposed` label. Parse
                // the *verified* bytes, exactly like findings, so key and body
                // agree. `suggested_blockers` stays TEXT in the body — never an
                // edge.
                let content = String::from_utf8_lossy(artifact.bytes());
                let followups = Followups::parse(Path::new(artifact.path()), &content)?;
                for (idx, proposal) in followups.proposals().iter().enumerate() {
                    items.push(TranslationItem {
                        artifact_path: artifact.path().to_owned(),
                        content_sha: artifact.sha256().to_owned(),
                        finding_index: idx as i64,
                        kind: CommentKind::Followup,
                        body: proposal.comment_body(),
                    });
                }
            }
            // DONE itself, progress.jsonl, and anything else declared but not
            // comment-translated.
            _ => {}
        }
    }

    Ok(items)
}

// ============================================================================
// Helpers
// ============================================================================

/// Read a file to a `String`, mapping any I/O failure to
/// [`ArtifactError::ReadFailed`] with the path for context.
fn read_file(path: &Path) -> Result<String, ArtifactError> {
    std::fs::read_to_string(path).map_err(|source| ArtifactError::ReadFailed {
        path: path.to_path_buf(),
        source,
    })
}

/// Read an *untrusted* artifact to a `String`, reading at most `max_bytes + 1`
/// bytes so a hostile multi-GB file can never be slurped whole into memory
/// before the caller's `parse` runs its size check. A missing file yields an
/// empty string (both `findings.jsonl` and `followups.jsonl` treat absent as an
/// empty set). The `+ 1` is deliberate: it is exactly enough for `parse` to
/// observe an over-`max_bytes` length and reject with a
/// [`ArtifactError::SchemaViolation`], never enough to be a memory DoS.
fn read_bounded(path: &Path, max_bytes: usize) -> Result<String, ArtifactError> {
    use std::io::Read as _;
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(source) => {
            return Err(ArtifactError::ReadFailed {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let mut buf = String::new();
    file.take(max_bytes as u64 + 1)
        .read_to_string(&mut buf)
        .map_err(|source| ArtifactError::ReadFailed {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(buf)
}

/// Whether `path` is safe to resolve against the workspace root: relative, and
/// built only from `Normal`/`CurDir` components. Rejects absolute paths
/// (`RootDir`/`Prefix`) and any `..` (`ParentDir`) — the only components that
/// can make `workspace.join(path)` land at or above the workspace. See
/// [`DoneSentinel::verify`] for why this matters (AC-23).
fn is_workspace_relative(path: &str) -> bool {
    Path::new(path)
        .components()
        .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

/// Lowercase-hex SHA-256 of `bytes` — matching the `sha256sum` digest the fake
/// worker records in DONE. No shell-out (AC-24): the [`sha2`] crate.
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        // {:02x} is lowercase hex, matching `sha256sum`'s output. Writing into a
        // `String` is infallible, so the formatting `Result` is discarded — no
        // per-byte allocation, unlike `push_str(&format!(..))`.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Reject an over-size artifact with a typed [`ArtifactError::SchemaViolation`].
///
/// Both [`Findings::parse`] and [`Followups::parse`] call this BEFORE their
/// per-line loop: a worker driving an inbound issue is untrusted (spec §1.6),
/// and an unbounded artifact would let the parse loop itself be DoS'd (a
/// multi-MB file is millions of lines) before the per-artifact count cap can
/// fire. The offending condition is the *total* length, not any single line, so
/// the diagnostic labels line 1 and embeds only a bounded preview of the body
/// (rendering a multi-MB source just to point at line 1 would be wasteful, and
/// on the DONE-verified path the verified bytes can be larger than the cap).
fn reject_oversized(path: &Path, content: &str, max_bytes: usize) -> ArtifactError {
    let mut preview_end = content.len().min(4096);
    while !content.is_char_boundary(preview_end) {
        preview_end -= 1;
    }
    schema_violation(
        path,
        &content[..preview_end],
        1,
        format!(
            "artifact is {} bytes, exceeding the {max_bytes}-byte cap — refusing to parse",
            content.len()
        )
        .into(),
    )
}

/// Build a line-numbered [`ArtifactError::SchemaViolation`] pointing at
/// `line_no` (1-based) within `content`, with the full file as the miette
/// source so the offending line renders as a labeled span.
fn schema_violation(
    path: &Path,
    content: &str,
    line_no: usize,
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
) -> ArtifactError {
    let (offset, len) = line_span(content, line_no);
    ArtifactError::SchemaViolation {
        artifact: path.to_path_buf(),
        line_no,
        src: miette::NamedSource::new(path.to_string_lossy(), content.to_owned()),
        offending: (offset, len).into(),
        source,
    }
}

/// Byte offset and length of the 1-based `line_no` within `content`, for a
/// miette label span. Counts each line plus its terminating `\n`; the span
/// excludes the line terminator, including a CRLF `\r\n` (both `\r` and `\n` are
/// trimmed) so the label doesn't overrun onto the invisible carriage return.
fn line_span(content: &str, line_no: usize) -> (usize, usize) {
    let mut offset = 0;
    for (idx, line) in content.split_inclusive('\n').enumerate() {
        if idx + 1 == line_no {
            let len = line.trim_end_matches(['\r', '\n']).len();
            return (offset, len);
        }
        offset += line.len();
    }
    (offset, 0)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;

    use tempfile::TempDir;

    /// The `result.md` / `findings.jsonl` paths as spelled in a DONE sentinel
    /// (`_orchestrator/` prefix included). Constants here rather than in the
    /// library because production dispatches on the *filename* now, not a
    /// hardcoded full path; the tests still write realistic DONE entries.
    const RESULT_PATH: &str = "_orchestrator/result.md";
    const FINDINGS_PATH: &str = "_orchestrator/findings.jsonl";
    const FOLLOWUPS_PATH: &str = "_orchestrator/followups.jsonl";

    /// SHA-256 of `bytes` as lowercase hex, computed the same way production
    /// does — the tests assert this equals what the worker's `sha256sum` writes.
    fn sha(bytes: &[u8]) -> String {
        sha256_hex(bytes)
    }

    /// Materialize a worker workspace with an `_orchestrator/` dir, returning the
    /// tempdir (hold it) and the workspace root path.
    fn workspace() -> (TempDir, PathBuf) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().to_path_buf();
        std::fs::create_dir_all(root.join(ARTIFACT_DIR)).expect("mkdir _orchestrator");
        (tmp, root)
    }

    /// Write `content` to `<root>/_orchestrator/<name>`.
    fn write_artifact(root: &Path, name: &str, content: &str) {
        std::fs::write(root.join(ARTIFACT_DIR).join(name), content).expect("write artifact");
    }

    /// Write a DONE sentinel listing the given `(path, sha)` artifacts.
    fn write_done(root: &Path, exit: &str, artifacts: &[(&str, &str)]) {
        let arts: Vec<String> = artifacts
            .iter()
            .map(|(p, s)| format!(r#"{{"path":"{p}","sha256":"{s}"}}"#))
            .collect();
        let json = format!(
            r#"{{"exit_status":"{exit}","artifacts":[{}]}}"#,
            arts.join(",")
        );
        write_artifact(root, DONE_FILE, &json);
    }

    // --- DONE sentinel ------------------------------------------------------

    #[test]
    fn valid_done_round_trips_and_verifies() {
        let (_tmp, root) = workspace();
        let body = "Added say_hi.\n";
        write_artifact(&root, RESULT_FILE, body);
        write_done(&root, "success", &[(RESULT_PATH, &sha(body.as_bytes()))]);

        let done = DoneSentinel::verify(&root).expect("valid DONE verifies");
        assert_eq!(done.exit_status(), ExitStatus::Success);
        assert_eq!(done.artifacts().len(), 1);
        assert_eq!(done.artifacts()[0].path(), RESULT_PATH);
        assert_eq!(
            done.sha_for(RESULT_PATH),
            Some(sha(body.as_bytes()).as_str())
        );
    }

    #[test]
    fn done_uppercase_hex_digest_still_verifies() {
        // `sha256sum` is lowercase, but be tolerant: a DONE with an uppercase
        // digest must still match (we normalize to lowercase before comparing).
        let (_tmp, root) = workspace();
        let body = "x\n";
        write_artifact(&root, RESULT_FILE, body);
        let upper = sha(body.as_bytes()).to_ascii_uppercase();
        write_done(&root, "success", &[(RESULT_PATH, &upper)]);
        assert!(DoneSentinel::verify(&root).is_ok());
    }

    #[test]
    fn missing_done_is_a_crash() {
        let (_tmp, root) = workspace();
        let err = DoneSentinel::verify(&root).unwrap_err();
        assert!(
            matches!(err, ArtifactError::DoneSentinelMissing { .. }),
            "missing DONE must be a crash, got {err:?}"
        );
    }

    #[test]
    fn torn_done_bad_json_is_rejected() {
        let (_tmp, root) = workspace();
        // A half-written DONE: truncated mid-object.
        write_artifact(&root, DONE_FILE, r#"{"exit_status":"success","artif"#);
        let err = DoneSentinel::verify(&root).unwrap_err();
        assert!(
            matches!(err, ArtifactError::DoneMalformed { .. }),
            "bad JSON must be DoneMalformed, got {err:?}"
        );
    }

    #[test]
    fn done_unknown_exit_status_is_rejected() {
        let (_tmp, root) = workspace();
        write_artifact(
            &root,
            DONE_FILE,
            r#"{"exit_status":"maybe","artifacts":[]}"#,
        );
        let err = DoneSentinel::verify(&root).unwrap_err();
        assert!(matches!(err, ArtifactError::DoneMalformed { .. }));
    }

    #[test]
    fn done_missing_artifact_is_rejected() {
        let (_tmp, root) = workspace();
        // DONE lists result.md but the worker never wrote it.
        write_done(&root, "success", &[(RESULT_PATH, &sha(b"whatever"))]);
        let err = DoneSentinel::verify(&root).unwrap_err();
        assert!(
            matches!(err, ArtifactError::DoneArtifactMissing { .. }),
            "missing listed artifact must be rejected, got {err:?}"
        );
    }

    #[test]
    fn done_sha_mismatch_is_rejected() {
        let (_tmp, root) = workspace();
        write_artifact(&root, RESULT_FILE, "real content\n");
        // DONE records the digest of *different* bytes — a torn/partial write.
        write_done(&root, "success", &[(RESULT_PATH, &sha(b"stale content\n"))]);
        let err = DoneSentinel::verify(&root).unwrap_err();
        assert!(
            matches!(err, ArtifactError::ChecksumMismatch { .. }),
            "sha mismatch must be rejected, got {err:?}"
        );
    }

    #[test]
    fn done_absolute_artifact_path_is_rejected_before_read() {
        // `verify` runs OUTSIDE the sandbox. An absolute path in DONE
        // (`/etc/passwd`) must be rejected before any `fs::read`, so a garbled
        // or hostile worker can't turn `verify` into an arbitrary host-file read
        // (AC-23). The digest is irrelevant — the path is rejected first.
        let (_tmp, root) = workspace();
        write_done(&root, "success", &[("/etc/passwd", &sha(b"root:x:0:0"))]);
        let err = DoneSentinel::verify(&root).unwrap_err();
        assert!(
            matches!(err, ArtifactError::DoneArtifactPathUnsafe { .. }),
            "absolute path must be rejected as unsafe, got {err:?}"
        );
    }

    #[test]
    fn done_parent_dir_escape_is_rejected() {
        // `../../etc/passwd` would `join` its way above the workspace root.
        let (_tmp, root) = workspace();
        write_done(&root, "success", &[("../../etc/passwd", &sha(b"x"))]);
        let err = DoneSentinel::verify(&root).unwrap_err();
        assert!(
            matches!(err, ArtifactError::DoneArtifactPathUnsafe { .. }),
            "`..`-escaping path must be rejected as unsafe, got {err:?}"
        );
    }

    #[test]
    fn done_normal_relative_artifact_path_is_accepted() {
        // The confinement check must not reject the legitimate case: a plain
        // workspace-relative path like `_orchestrator/result.md` verifies fine.
        let (_tmp, root) = workspace();
        let body = "ok\n";
        write_artifact(&root, RESULT_FILE, body);
        write_done(&root, "success", &[(RESULT_PATH, &sha(body.as_bytes()))]);
        let done = DoneSentinel::verify(&root).expect("normal relative path verifies");
        assert_eq!(done.artifacts()[0].path(), RESULT_PATH);
    }

    #[test]
    fn done_matches_sha256sum_hex_shape() {
        // Guard the digest format matches `sha256sum`: 64 lowercase hex chars.
        let hex = sha(b"hello\n");
        assert_eq!(hex.len(), 64);
        assert!(hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        // Known vector: sha256("hello\n").
        assert_eq!(
            hex,
            "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
        );
    }

    // --- result.md ----------------------------------------------------------

    #[test]
    fn result_md_reads() {
        let (_tmp, root) = workspace();
        write_artifact(&root, RESULT_FILE, "# summary\nchanged things\n");
        let result = ResultMd::read(&root.join(ARTIFACT_DIR)).expect("read result.md");
        assert_eq!(result.content(), "# summary\nchanged things\n");
    }

    #[test]
    fn result_md_missing_is_read_failed() {
        let (_tmp, root) = workspace();
        let err = ResultMd::read(&root.join(ARTIFACT_DIR)).unwrap_err();
        assert!(matches!(err, ArtifactError::ReadFailed { .. }));
    }

    // --- findings.jsonl -----------------------------------------------------

    fn valid_findings_content() -> String {
        [
            r#"{"severity":"high","location":"src/lib.rs:12","claim":"unsafe block","evidence_files":["src/lib.rs"]}"#,
            r#"{"severity":"med","location":"src/main.rs:3","claim":"unwrap in prod","evidence_files":[]}"#,
            r#"{"severity":"low","location":"README.md:1","claim":"typo"}"#,
        ]
        .join("\n")
    }

    #[test]
    fn findings_parse_all_severities_and_optional_evidence() {
        let path = Path::new("findings.jsonl");
        let findings = Findings::parse(path, &valid_findings_content()).expect("parse");
        assert_eq!(findings.findings().len(), 3);
        assert_eq!(findings.findings()[0].severity, Severity::High);
        assert_eq!(findings.findings()[1].severity, Severity::Med);
        assert_eq!(findings.findings()[2].severity, Severity::Low);
        assert_eq!(findings.findings()[0].location.line(), 12);
        assert_eq!(findings.findings()[0].location.path(), "src/lib.rs");
        // The default for a missing `evidence_files`.
        assert!(findings.findings()[2].evidence_files.is_empty());
    }

    #[test]
    fn empty_findings_is_valid() {
        let path = Path::new("findings.jsonl");
        let findings = Findings::parse(path, "").expect("empty parse");
        assert!(findings.is_empty());
        // Blank / whitespace-only lines are skipped, not errors.
        let findings = Findings::parse(path, "\n   \n\n").expect("blank parse");
        assert!(findings.is_empty());
    }

    #[test]
    fn missing_findings_file_is_empty() {
        let (_tmp, root) = workspace();
        let findings = Findings::read(&root.join(ARTIFACT_DIR)).expect("missing = empty");
        assert!(findings.is_empty());
    }

    #[test]
    fn malformed_findings_line_rejected_at_line_number() {
        let path = Path::new("findings.jsonl");
        let content = [
            r#"{"severity":"high","location":"a:1","claim":"ok","evidence_files":[]}"#,
            r#"this-is-not-json"#, // line 2
            r#"{"severity":"low","location":"b:2","claim":"ok"}"#,
        ]
        .join("\n");
        let err = Findings::parse(path, &content).unwrap_err();
        match err {
            ArtifactError::SchemaViolation { line_no, .. } => assert_eq!(line_no, 2),
            other => panic!("expected line-numbered SchemaViolation, got {other:?}"),
        }
    }

    #[test]
    fn findings_unknown_severity_rejected() {
        let path = Path::new("findings.jsonl");
        let content = r#"{"severity":"critical","location":"a:1","claim":"x"}"#;
        let err = Findings::parse(path, content).unwrap_err();
        assert!(matches!(
            err,
            ArtifactError::SchemaViolation { line_no: 1, .. }
        ));
    }

    #[test]
    fn findings_bad_location_rejected_at_line() {
        let path = Path::new("findings.jsonl");
        // Missing the `:line` suffix on line 2.
        let content = [
            r#"{"severity":"high","location":"a:1","claim":"ok"}"#,
            r#"{"severity":"low","location":"no-colon","claim":"x"}"#,
        ]
        .join("\n");
        let err = Findings::parse(path, &content).unwrap_err();
        assert!(matches!(
            err,
            ArtifactError::SchemaViolation { line_no: 2, .. }
        ));
    }

    #[test]
    fn findings_over_count_cap_rejected_whole() {
        // Untrusted Adversary DoS: > FINDINGS_MAX valid findings is rejected
        // WHOLE (never partially accepted). The cap is GENEROUS — a real round
        // posts well under it — so no legitimate multi-finding round is affected.
        let path = Path::new("findings.jsonl");
        let line = r#"{"severity":"low","location":"a:1","claim":"x"}"#;
        let over = std::iter::repeat_n(line, FINDINGS_MAX + 1)
            .collect::<Vec<_>>()
            .join("\n");
        // Stays well under the byte cap, so it is the COUNT cap that fires.
        assert!(over.len() < FINDINGS_ARTIFACT_MAX_BYTES);
        assert!(matches!(
            Findings::parse(path, &over).unwrap_err(),
            ArtifactError::SchemaViolation { line_no, .. } if line_no == FINDINGS_MAX + 1
        ));
        // Exactly at the cap is accepted.
        let at_cap = std::iter::repeat_n(line, FINDINGS_MAX)
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            Findings::parse(path, &at_cap)
                .expect("cap is inclusive")
                .findings()
                .len(),
            FINDINGS_MAX
        );
    }

    #[test]
    fn findings_oversized_artifact_rejected_before_parse() {
        // A blob over the byte cap is rejected by the size check BEFORE any line
        // is parsed — parsing itself can't be DoS'd.
        let path = Path::new("findings.jsonl");
        let content = "a".repeat(FINDINGS_ARTIFACT_MAX_BYTES + 1);
        assert!(matches!(
            Findings::parse(path, &content).unwrap_err(),
            ArtifactError::SchemaViolation { line_no: 1, .. }
        ));
    }

    #[test]
    fn finding_to_jsonl_line_round_trips_through_parse() {
        // A finding serialized to a jsonl line re-parses back into the same
        // finding — the pump delivers prior findings to a re-implement round's
        // Implementer in exactly the schema the Adversary writes them (REQ-8).
        let finding = Finding {
            severity: Severity::High,
            location: Location::parse("src/lib.rs:1").expect("location"),
            claim: "greeting_head hides a get_unchecked call".to_owned(),
            evidence_files: vec!["src/lib.rs".to_owned()],
        };
        let line = finding.to_jsonl_line().expect("serialize");
        let reparsed = Findings::parse(Path::new("prior_findings.jsonl"), &line).expect("reparse");
        assert_eq!(reparsed.findings(), std::slice::from_ref(&finding));
        // A finding with no evidence still round-trips.
        let no_evidence = Finding {
            evidence_files: Vec::new(),
            ..finding
        };
        let line = no_evidence.to_jsonl_line().expect("serialize");
        let reparsed = Findings::parse(Path::new("f.jsonl"), &line).expect("reparse");
        assert_eq!(reparsed.findings()[0], no_evidence);
    }

    // --- progress.jsonl -----------------------------------------------------

    #[test]
    fn progress_best_effort_skips_torn_line() {
        let content = [
            r#"{"ts":"t1","op":"edit","detail":"lib.rs"}"#,
            r#"{"ts":"t2","op":"test","detail":"green"}"#,
            r#"{"ts":"t3","op":"des"#, // torn final write
        ]
        .join("\n");
        let progress = Progress::parse(&content);
        assert_eq!(progress.entries().len(), 2);
        assert_eq!(progress.skipped(), 1);
        assert_eq!(progress.entries()[0].op, "edit");
    }

    #[test]
    fn missing_progress_is_empty() {
        let (_tmp, root) = workspace();
        let progress = Progress::read(&root.join(ARTIFACT_DIR)).expect("optional");
        assert!(progress.entries().is_empty());
        assert_eq!(progress.skipped(), 0);
    }

    // --- Location -----------------------------------------------------------

    #[test]
    fn location_parse_edge_cases() {
        assert_eq!(Location::parse("src/a.rs:42").map(|l| l.line()), Some(42));
        // Path containing a colon: split on the last colon.
        let loc = Location::parse("C:/x.rs:7").expect("drive-like path");
        assert_eq!(loc.path(), "C:/x.rs");
        assert_eq!(loc.line(), 7);
        assert!(Location::parse("no-colon").is_none());
        assert!(Location::parse(":42").is_none(), "empty path rejected");
        assert!(Location::parse("a.rs:notnum").is_none());
    }

    // --- translation plan ---------------------------------------------------

    /// Build a realistic Implementer artifact set (result.md + DONE) on disk,
    /// with the given self-reported `exit`.
    fn implementer_set_with_exit(exit: &str) -> (TempDir, ArtifactSet) {
        let (tmp, root) = workspace();
        let body = "Implemented the thing.\n";
        write_artifact(&root, RESULT_FILE, body);
        write_done(&root, exit, &[(RESULT_PATH, &sha(body.as_bytes()))]);
        let done = DoneSentinel::verify(&root).expect("verify");
        (tmp, ArtifactSet { done })
    }

    /// A successful Implementer artifact set.
    fn implementer_set() -> (TempDir, ArtifactSet) {
        implementer_set_with_exit("success")
    }

    /// Build a realistic Adversary artifact set (findings.jsonl + DONE).
    fn adversary_set() -> (TempDir, ArtifactSet) {
        let (tmp, root) = workspace();
        let body = valid_findings_content();
        write_artifact(&root, FINDINGS_FILE, &body);
        write_done(&root, "success", &[(FINDINGS_PATH, &sha(body.as_bytes()))]);
        let done = DoneSentinel::verify(&root).expect("verify");
        (tmp, ArtifactSet { done })
    }

    #[test]
    fn plan_for_implementer_is_one_result_item() {
        let (_tmp, set) = implementer_set();
        let plan = translation_plan("w-1", &set).expect("plan");
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].kind, CommentKind::Result);
        assert_eq!(plan[0].finding_index, WHOLE_FILE_INDEX);
        assert_eq!(plan[0].artifact_path, RESULT_PATH);
        assert_eq!(plan[0].body, "Implemented the thing.\n");
    }

    #[test]
    fn plan_for_error_exit_status_emits_no_result() {
        // An `exit_status: error` DONE is a failed phase (the orchestrator
        // re-spawns); it must NOT post a "work is done" result comment.
        let (_tmp, set) = implementer_set_with_exit("error");
        let plan = translation_plan("w-err", &set).expect("plan");
        assert!(
            plan.is_empty(),
            "an error DONE must not emit a result comment, got {plan:?}"
        );
    }

    #[test]
    fn plan_for_adversary_is_one_blocker_per_finding() {
        let (_tmp, set) = adversary_set();
        let plan = translation_plan("w-2", &set).expect("plan");
        assert_eq!(plan.len(), 3);
        for (idx, item) in plan.iter().enumerate() {
            assert_eq!(item.kind, CommentKind::Blocker);
            assert_eq!(item.finding_index, idx as i64);
            assert_eq!(item.artifact_path, FINDINGS_PATH);
        }
        assert!(plan[0].body.contains("[high]"));
        assert!(plan[0].body.contains("unsafe block"));
    }

    #[test]
    fn plan_for_empty_adversary_round_is_empty() {
        let (tmp, root) = workspace();
        write_artifact(&root, FINDINGS_FILE, "");
        write_done(&root, "success", &[(FINDINGS_PATH, &sha(b""))]);
        let done = DoneSentinel::verify(&root).expect("verify");
        let set = ArtifactSet { done };
        drop(tmp);
        assert!(translation_plan("w", &set).expect("plan").is_empty());
    }

    // --- followups.jsonl (REQ-SWARM-2, propose-don't-commit) ----------------

    fn valid_followups_content() -> String {
        [
            r#"{"title":"Add say_bye()","rationale":"symmetry with say_hi","suggested_blockers":[1,2],"gate_sketch":"test say_bye() == \"bye\""}"#,
            r#"{"title":"Localize greetings","rationale":"english is hard-coded"}"#,
        ]
        .join("\n")
    }

    /// Build a realistic Implementer artifact set that ALSO declares
    /// `followups.jsonl` (result.md + followups.jsonl + DONE), for the followup
    /// translation tests.
    fn followups_set(followups_body: &str) -> (TempDir, ArtifactSet) {
        let (tmp, root) = workspace();
        let result_body = "Implemented the thing; proposed follow-ups.\n";
        write_artifact(&root, RESULT_FILE, result_body);
        write_artifact(&root, FOLLOWUPS_FILE, followups_body);
        write_done(
            &root,
            "success",
            &[
                (RESULT_PATH, &sha(result_body.as_bytes())),
                (FOLLOWUPS_PATH, &sha(followups_body.as_bytes())),
            ],
        );
        let done = DoneSentinel::verify(&root).expect("verify");
        (tmp, ArtifactSet { done })
    }

    #[test]
    fn followups_parse_required_and_optional_fields() {
        let path = Path::new("followups.jsonl");
        let f = Followups::parse(path, &valid_followups_content()).expect("parse");
        assert_eq!(f.proposals().len(), 2);
        assert_eq!(f.proposals()[0].title, "Add say_bye()");
        assert_eq!(f.proposals()[0].rationale, "symmetry with say_hi");
        assert_eq!(f.proposals()[0].suggested_blockers, vec![1, 2]);
        assert_eq!(
            f.proposals()[0].gate_sketch.as_deref(),
            Some("test say_bye() == \"bye\"")
        );
        // Second proposal omits the optionals.
        assert!(f.proposals()[1].suggested_blockers.is_empty());
        assert!(f.proposals()[1].gate_sketch.is_none());
    }

    #[test]
    fn missing_followups_file_is_empty() {
        let (_tmp, root) = workspace();
        let f = Followups::read(&root.join(ARTIFACT_DIR)).expect("missing = empty");
        assert!(
            f.is_empty(),
            "an absent followups.jsonl is the common no-op case"
        );
    }

    #[test]
    fn empty_followups_is_valid() {
        let path = Path::new("followups.jsonl");
        assert!(Followups::parse(path, "").expect("empty").is_empty());
        assert!(Followups::parse(path, "\n  \n").expect("blank").is_empty());
    }

    #[test]
    fn followups_missing_title_rejected() {
        let path = Path::new("followups.jsonl");
        let content = r#"{"rationale":"no title here"}"#;
        assert!(matches!(
            Followups::parse(path, content).unwrap_err(),
            ArtifactError::SchemaViolation { line_no: 1, .. }
        ));
    }

    #[test]
    fn followups_empty_title_rejected() {
        let path = Path::new("followups.jsonl");
        let content = r#"{"title":"   ","rationale":"blank title"}"#;
        assert!(matches!(
            Followups::parse(path, content).unwrap_err(),
            ArtifactError::SchemaViolation { line_no: 1, .. }
        ));
    }

    #[test]
    fn followups_oversized_title_rejected() {
        let path = Path::new("followups.jsonl");
        let big = "x".repeat(FOLLOWUP_TITLE_MAX + 1);
        let content = format!(r#"{{"title":"{big}","rationale":"ok"}}"#);
        assert!(matches!(
            Followups::parse(path, &content).unwrap_err(),
            ArtifactError::SchemaViolation { line_no: 1, .. }
        ));
    }

    #[test]
    fn followups_title_with_newline_rejected() {
        // A newline in the title could smuggle a fake field past a human skimming
        // the comment; reject rather than render it into the header.
        let path = Path::new("followups.jsonl");
        let content = r#"{"title":"line one\nline two","rationale":"ok"}"#;
        assert!(matches!(
            Followups::parse(path, content).unwrap_err(),
            ArtifactError::SchemaViolation { line_no: 1, .. }
        ));
    }

    #[test]
    fn followups_unknown_field_rejected() {
        // `deny_unknown_fields`: a worker cannot smuggle an extra key (e.g. a
        // fabricated label/phase) past the parser.
        let path = Path::new("followups.jsonl");
        let content = r#"{"title":"t","rationale":"r","phase":"graphed"}"#;
        assert!(matches!(
            Followups::parse(path, content).unwrap_err(),
            ArtifactError::SchemaViolation { line_no: 1, .. }
        ));
    }

    #[test]
    fn followups_too_many_suggested_blockers_rejected() {
        let path = Path::new("followups.jsonl");
        let ids: Vec<String> = (0..=FOLLOWUP_MAX_SUGGESTED_BLOCKERS)
            .map(|n| n.to_string())
            .collect();
        let content = format!(
            r#"{{"title":"t","rationale":"r","suggested_blockers":[{}]}}"#,
            ids.join(",")
        );
        assert!(matches!(
            Followups::parse(path, &content).unwrap_err(),
            ArtifactError::SchemaViolation { line_no: 1, .. }
        ));
    }

    #[test]
    fn followups_over_proposal_cap_rejected_whole() {
        // Untrusted-worker DoS: > FOLLOWUP_MAX_PROPOSALS valid proposals is a
        // misbehaving worker. The artifact is rejected WHOLE (no partial accept)
        // and the rejection points at the first over-cap line.
        let path = Path::new("followups.jsonl");
        let line = r#"{"title":"t","rationale":"r"}"#;
        let over: Vec<&str> = std::iter::repeat_n(line, FOLLOWUP_MAX_PROPOSALS + 1).collect();
        let content = over.join("\n");
        // Stays well under the byte cap, so it is the COUNT cap that fires.
        assert!(content.len() < FOLLOWUP_ARTIFACT_MAX_BYTES);
        assert!(matches!(
            Followups::parse(path, &content).unwrap_err(),
            ArtifactError::SchemaViolation {
                line_no,
                ..
            } if line_no == FOLLOWUP_MAX_PROPOSALS + 1
        ));
        // Exactly at the cap is still accepted (the bound is generous, not
        // hair-trigger).
        let at_cap = std::iter::repeat_n(line, FOLLOWUP_MAX_PROPOSALS)
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            Followups::parse(path, &at_cap)
                .expect("cap is inclusive")
                .proposals()
                .len(),
            FOLLOWUP_MAX_PROPOSALS
        );
    }

    #[test]
    fn followups_oversized_artifact_rejected_before_parse() {
        // A multi-KB blob over the byte cap is rejected by the size check BEFORE
        // any line is parsed (a single over-cap "line" so the count cap can't be
        // what fires) — parsing itself can't be DoS'd.
        let path = Path::new("followups.jsonl");
        let content = "a".repeat(FOLLOWUP_ARTIFACT_MAX_BYTES + 1);
        assert!(matches!(
            Followups::parse(path, &content).unwrap_err(),
            ArtifactError::SchemaViolation { line_no: 1, .. }
        ));
    }

    #[test]
    fn plan_rejects_over_cap_followups_no_items_posted() {
        // End to end: an over-cap followups.jsonl in a real artifact set fails
        // the plan at parse, so NO comments (and hence no `followup:proposed`
        // label) are ever produced for it.
        let line = r#"{"title":"t","rationale":"r"}"#;
        let body = std::iter::repeat_n(line, FOLLOWUP_MAX_PROPOSALS + 1)
            .collect::<Vec<_>>()
            .join("\n");
        let (_tmp, set) = followups_set(&body);
        assert!(matches!(
            translation_plan("w", &set).unwrap_err(),
            ArtifactError::SchemaViolation { .. }
        ));
    }

    #[test]
    fn followup_comment_body_frames_a_proposal_with_advisory_blockers() {
        let f = Followups::parse(Path::new("f.jsonl"), &valid_followups_content()).expect("parse");
        let body = f.proposals()[0].comment_body();
        // Greppable header — the marker that this generic `note` is a proposal.
        assert!(body.starts_with("**Follow-up proposal** — Add say_bye()"));
        assert!(body.contains("symmetry with say_hi"));
        // suggested_blockers rendered as advisory TEXT, explicitly NOT wired.
        assert!(body.contains("advisory") && body.contains("NOT wired"));
        assert!(body.contains("#1") && body.contains("#2"));
        assert!(body.contains("gate sketch:"));
    }

    #[test]
    fn plan_for_followups_is_one_followup_item_per_proposal() {
        let (_tmp, set) = followups_set(&valid_followups_content());
        let plan = translation_plan("w-f", &set).expect("plan");
        // The result.md yields a Result item; the two proposals yield two
        // Followup items. Assert the followup items precisely.
        let followups: Vec<&TranslationItem> = plan
            .iter()
            .filter(|i| i.kind == CommentKind::Followup)
            .collect();
        assert_eq!(followups.len(), 2, "one followup item per proposal");
        for (idx, item) in followups.iter().enumerate() {
            assert_eq!(item.finding_index, idx as i64);
            assert_eq!(item.artifact_path, FOLLOWUPS_PATH);
        }
        assert!(followups[0].body.contains("Add say_bye()"));
        assert!(followups[1].body.contains("Localize greetings"));
    }

    #[test]
    fn plan_for_followups_emits_only_followup_and_result_never_blocker() {
        // THE INVARIANT (propose-don't-commit): a followups artifact can produce
        // ONLY CommentKind::Followup items. It can never mint a `blocker`, and
        // the result.md (separately) is the only other kind — never a followup
        // masquerading as one. Assert no Blocker/Observation slipped in.
        let (_tmp, set) = followups_set(&valid_followups_content());
        let plan = translation_plan("w-f", &set).expect("plan");
        for item in &plan {
            assert!(
                matches!(item.kind, CommentKind::Followup | CommentKind::Result),
                "a followups+result set must never emit {:?}",
                item.kind
            );
        }
        // And every item derived from followups.jsonl is a Followup, never else.
        for item in &plan {
            if item.artifact_path == FOLLOWUPS_PATH {
                assert_eq!(
                    item.kind,
                    CommentKind::Followup,
                    "a followups.jsonl item must be a Followup, got {:?}",
                    item.kind
                );
            }
        }
    }

    #[test]
    fn plan_for_followups_is_idempotent_across_replay() {
        let (_tmp, set) = followups_set(&valid_followups_content());
        let worker = "w-f42";
        let plan = translation_plan(worker, &set).expect("plan");
        let mut ledger = HashSet::new();
        let first = simulate_post(&mut ledger, worker, &plan);
        assert_eq!(first, plan.len(), "first pass posts every item once");
        let replay = translation_plan(worker, &set).expect("plan");
        assert_eq!(plan, replay, "same inputs, same plan");
        let second = simulate_post(&mut ledger, worker, &replay);
        assert_eq!(second, 0, "replay must post nothing (ledger-deduped)");
    }

    #[test]
    fn plan_rejects_malformed_followups_line() {
        // A schema-violating followups line fails the plan at parse — a
        // half-written or hostile line is never posted (AC-23).
        let (_tmp, set) = followups_set(r#"{"rationale":"no title"}"#);
        assert!(matches!(
            translation_plan("w", &set).unwrap_err(),
            ArtifactError::SchemaViolation { .. }
        ));
    }

    // --- strict convergence reader (Findings::from_done) --------------------

    #[test]
    fn from_done_parses_declared_findings() {
        // A DONE that declares a populated findings.jsonl yields those findings.
        let (_tmp, root) = workspace();
        let body = valid_findings_content();
        write_artifact(&root, FINDINGS_FILE, &body);
        write_done(&root, "success", &[(FINDINGS_PATH, &sha(body.as_bytes()))]);
        let done = DoneSentinel::verify(&root).expect("verify");
        let findings = Findings::from_done(&done).expect("declared findings parse");
        assert_eq!(findings.findings().len(), 3);
    }

    #[test]
    fn from_done_empty_declared_findings_is_a_clean_round() {
        // A PRESENT-and-empty findings.jsonl, declared in DONE, IS a valid clean
        // (converged) round — not an error.
        let (_tmp, root) = workspace();
        write_artifact(&root, FINDINGS_FILE, "");
        write_done(&root, "success", &[(FINDINGS_PATH, &sha(b""))]);
        let done = DoneSentinel::verify(&root).expect("verify");
        let findings = Findings::from_done(&done).expect("empty-declared is clean");
        assert!(
            findings.is_empty(),
            "an empty declared findings.jsonl is a clean round"
        );
    }

    #[test]
    fn from_done_absent_findings_is_rejected_not_converged() {
        // The load-bearing case: a worker wrote DONE listing ONLY result.md and
        // never declared findings.jsonl. The lenient `read` would map the absent
        // file to empty ⇒ "converged"; the strict reader rejects it as an
        // incomplete Adversary round (FindingsMissing), so the convergence loop
        // re-spawns instead of auto-landing on a crashed worker.
        let (_tmp, root) = workspace();
        let body = "reviewed, but crashed before writing findings\n";
        write_artifact(&root, RESULT_FILE, body);
        write_done(&root, "success", &[(RESULT_PATH, &sha(body.as_bytes()))]);
        let done = DoneSentinel::verify(&root).expect("verify");

        // Sanity: the lenient reader WOULD have (wrongly) called this empty.
        assert!(
            Findings::read(&root.join(ARTIFACT_DIR))
                .expect("lenient read")
                .is_empty(),
            "lenient read maps the absent file to empty — the hole we are closing"
        );

        // The strict reader refuses it.
        let err = Findings::from_done(&done).unwrap_err();
        match err {
            ArtifactError::FindingsMissing { declared } => {
                assert_eq!(declared, vec![RESULT_PATH.to_owned()]);
            }
            other => panic!("expected FindingsMissing, got {other:?}"),
        }
    }

    #[test]
    fn plan_is_deterministic() {
        let (_tmp, set) = adversary_set();
        let a = translation_plan("w", &set).expect("plan");
        let b = translation_plan("w", &set).expect("plan");
        assert_eq!(a, b, "same inputs must yield the same plan");
    }

    /// Model the `posted_artifacts` ledger as a HashSet keyed by
    /// `(worker_uuid, artifact_path, content_sha, finding_index)`. Simulate
    /// posting a plan through it, returning how many items were newly posted.
    fn simulate_post(
        ledger: &mut HashSet<(String, String, String, i64)>,
        worker: &str,
        plan: &[TranslationItem],
    ) -> usize {
        let mut posted = 0;
        for item in plan {
            let key = (
                worker.to_owned(),
                item.artifact_path.clone(),
                item.content_sha.clone(),
                item.finding_index,
            );
            if ledger.insert(key) {
                posted += 1;
            }
        }
        posted
    }

    #[test]
    fn plan_is_idempotent_across_replay() {
        let (_tmp, set) = adversary_set();
        let worker = "w-42";
        let plan = translation_plan(worker, &set).expect("plan");
        let mut ledger = HashSet::new();

        // First pass posts every item exactly once.
        let first = simulate_post(&mut ledger, worker, &plan);
        assert_eq!(first, plan.len());

        // Crash-and-replay: recompute the identical plan, post again — the
        // ledger already holds every tuple, so nothing is re-posted.
        let replay = translation_plan(worker, &set).expect("plan");
        assert_eq!(plan, replay);
        let second = simulate_post(&mut ledger, worker, &replay);
        assert_eq!(second, 0, "replay must post nothing");
        assert_eq!(ledger.len(), plan.len());
    }
}

// ============================================================================
// Property-based tests
// ============================================================================

#[cfg(test)]
mod proptests {
    use super::*;

    use std::collections::HashSet;

    use proptest::prelude::*;

    /// A well-formed findings vector plus its serialized `findings.jsonl` body.
    #[derive(Debug, Clone)]
    struct WellFormedFindings {
        jsonl: String,
        count: usize,
    }

    prop_compose! {
        /// One well-formed finding line. Fields avoid characters that would need
        /// JSON escaping so the hand-built line is valid; the parser is what's
        /// under test, not serde's escaping.
        fn arb_finding()(
            sev in prop_oneof![Just("high"), Just("med"), Just("low")],
            path in "[a-z][a-z0-9_/]{0,15}\\.rs",
            line in 0u32..100_000,
            claim in "[a-zA-Z0-9 ]{0,40}",
            evidence in prop::collection::vec("[a-z][a-z0-9_/]{0,10}\\.rs", 0..3),
        ) -> String {
            let ev = evidence
                .iter()
                .map(|e| format!("{e:?}"))
                .collect::<Vec<_>>()
                .join(",");
            format!(
                r#"{{"severity":"{sev}","location":"{path}:{line}","claim":{claim:?},"evidence_files":[{ev}]}}"#
            )
        }
    }

    prop_compose! {
        fn arb_findings()(lines in prop::collection::vec(arb_finding(), 0..8)) -> WellFormedFindings {
            WellFormedFindings {
                count: lines.len(),
                jsonl: lines.join("\n"),
            }
        }
    }

    proptest! {
        /// Any well-formed findings body parses without error and yields exactly
        /// as many findings as lines — the parser never drops or invents a line.
        #[test]
        fn well_formed_findings_parse_round_trip(ff in arb_findings()) {
            let path = Path::new("findings.jsonl");
            let parsed = Findings::parse(path, &ff.jsonl).expect("well-formed parses");
            prop_assert_eq!(parsed.findings().len(), ff.count);
            // Every parsed finding re-renders a body deterministically.
            for f in parsed.findings() {
                prop_assert_eq!(f.comment_body(), f.comment_body());
            }
        }

        /// The plan keys the idempotency ledger on `content_sha`, so identical
        /// content is suppressed on replay while DIFFERENT content re-posts. A
        /// single-`set` replay only proves determinism; this varies the content
        /// across two rounds and asserts the actual keying behaviour:
        /// - posting round 1 posts every item,
        /// - re-posting round 1 (crash-replay) posts nothing (same sha),
        /// - posting round 2, whose body differs, posts every item AGAIN under
        ///   its new sha (a fresh ledger key), never colliding with round 1.
        #[test]
        fn plan_reposts_on_content_change_and_suppresses_identical(
            r1 in arb_findings(),
            r2 in arb_findings(),
        ) {
            // Force the two rounds to differ so round 2 has a distinct sha.
            // (Appending a comment-free extra finding keeps r2 well-formed.)
            let r2_jsonl = format!(
                "{}\n{}",
                r2.jsonl,
                r#"{"severity":"low","location":"z.rs:1","claim":"nudge","evidence_files":[]}"#
            );
            prop_assume!(r1.jsonl != r2_jsonl);
            let r2_count = r2.count + 1;

            let set1 = findings_set(&r1.jsonl);
            let set2 = findings_set(&r2_jsonl);

            let worker = "w-prop";
            let plan1 = translation_plan(worker, &set1).expect("plan");
            let plan2 = translation_plan(worker, &set2).expect("plan");
            prop_assert_eq!(plan1.len(), r1.count);
            prop_assert_eq!(plan2.len(), r2_count);
            // The two rounds carry different content shas (the whole point).
            let sha1 = set1.done.artifacts()[0].sha256();
            let sha2 = set2.done.artifacts()[0].sha256();
            prop_assert_ne!(sha1, sha2);

            let mut ledger: HashSet<(String, String, String, i64)> = HashSet::new();
            let mut post = |plan: &[TranslationItem]| -> usize {
                let mut n = 0;
                for item in plan {
                    let key = (
                        worker.to_owned(),
                        item.artifact_path.clone(),
                        item.content_sha.clone(),
                        item.finding_index,
                    );
                    if ledger.insert(key) {
                        n += 1;
                    }
                }
                n
            };

            // Round 1 posts fresh; replaying identical content posts nothing.
            prop_assert_eq!(post(&plan1), r1.count);
            let plan1_replay = translation_plan(worker, &set1).expect("plan");
            prop_assert_eq!(&plan1, &plan1_replay); // deterministic.
            prop_assert_eq!(post(&plan1_replay), 0);

            // Round 2's DIFFERENT content re-posts under its new sha — every
            // item is a fresh ledger key, none suppressed by round 1.
            prop_assert_eq!(post(&plan2), r2_count);
            // Ledger now holds both rounds' keys, no collision.
            prop_assert_eq!(ledger.len(), r1.count + r2_count);
        }
    }

    /// Build an `ArtifactSet` for a findings body purely (no disk): a DONE whose
    /// single `findings.jsonl` artifact carries `jsonl` as its verified bytes and
    /// the matching sha — exactly the invariant `verify` establishes on disk.
    fn findings_set(jsonl: &str) -> ArtifactSet {
        let done = DoneSentinel::from_parts_for_test(
            ExitStatus::Success,
            vec![(FINDINGS_PATH.to_owned(), jsonl.as_bytes().to_vec())],
        );
        ArtifactSet { done }
    }

    const FINDINGS_PATH: &str = "_orchestrator/findings.jsonl";

    // A test-only constructor for DoneSentinel that skips disk verification —
    // used purely to build ArtifactSets for the *plan* proptests, which exercise
    // planning determinism/idempotency, not sentinel verification (covered by
    // the on-disk unit tests). It lives behind cfg(test) so no non-test code can
    // fabricate an unverified sentinel. The sha is derived from `bytes` so the
    // (sha, bytes) invariant matches what `verify` guarantees.
    impl DoneSentinel {
        fn from_parts_for_test(exit_status: ExitStatus, artifacts: Vec<(String, Vec<u8>)>) -> Self {
            DoneSentinel {
                exit_status,
                artifacts: artifacts
                    .into_iter()
                    .map(|(path, bytes)| VerifiedArtifact {
                        path,
                        sha256: sha256_hex(&bytes),
                        bytes,
                    })
                    .collect(),
            }
        }
    }
}
