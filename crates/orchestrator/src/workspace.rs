//! jj workspace lifecycle for workers (REQ-5, REQ-5a, REQ-12).
//!
//! The orchestrator gives each worker its own jj *workspace* — a separate
//! working-copy directory that shares the one `.jj/` repository. This module
//! owns that lifecycle, wrapping [`vetinari_jj_api`]. It is the first thing the
//! build pump calls per spawn.
//!
//! # The `.jj/` serialization invariant (REQ-5a)
//!
//! `.jj/` is a *shared mutable namespace*: the commit graph, operation log, and
//! bookmarks are visible across every workspace. Two `.jj/`-mutating operations
//! racing (a `workspace add` in one thread, a `rebase` in another) can corrupt
//! the operation log or lose a side. This is a **correctness** invariant, not a
//! performance tuning knob: every mutation MUST be serialized through one
//! process-internal mutex.
//!
//! The type design makes an *unguarded* mutation impossible to write. The
//! single [`JjWorkspace`] handle lives *inside* a `Mutex`, held by
//! [`WorkspaceManager`]; the only way to reach a mutating op is to take the
//! lock (see [`WorkspaceManager::gate`], which yields a [`JjGate`] guard).
//! Callers cannot obtain a raw unguarded handle. The manager is `Clone` and
//! `Arc`-backed so the future landing code (rebase, bookmark-move, push) shares
//! the *same* mutex — one gate for all of `.jj/`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use vetinari_error::{LandingError, SpawnError};
use vetinari_jj_api::{CommitInfo, JjWorkspace, WorkspaceEntry};

use crate::state::Phase;

/// Directory that holds every worker's ephemeral workspace, relative to the
/// repository root. Kept as a constant so the layout in
/// `.design/vdd-orchestrator.md` and the code agree.
pub const WORKSPACE_DIR: &str = ".workspace";

/// Length of the short UUID suffix in a [`WorkspaceName`]. Eight hex chars of a
/// v4 UUID is enough entropy to make same-round spawn collisions vanishingly
/// unlikely while keeping directory names short.
const SHORT_UUID_LEN: usize = 8;

/// Sentinel issue token used when an issue id sanitizes to empty (e.g. an
/// all-punctuation id like `###`). Folding to a fixed `[a-z]` token keeps
/// [`WorkspaceName::generate`] infallible while guaranteeing its output is
/// always well-formed and re-parseable — an empty issue segment would render a
/// `--` that [`WorkspaceName::parse`] rejects.
const EMPTY_ISSUE: &str = "issue";

// ============================================================================
// WorkspaceName
// ============================================================================

/// A validated workspace name of the form `<phase>-<issue>-r<round>-<uuid>`
/// (REQ-12), e.g. `implementing-42-r3-a1b2c3d4`.
///
/// This is a newtype, never a bare `String`: it can only be built from typed
/// components ([`WorkspaceName::generate`]) or re-parsed from a name a prior run
/// wrote ([`WorkspaceName::parse`]). Both paths guarantee the value is
/// filesystem-safe — the rendered string contains only `[a-z0-9-]`, has no path
/// separators, and never starts with a `.` — so it can be used directly as a
/// directory component without escaping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceName {
    /// Phase the worker is being spawned for (the name's prefix).
    phase: Phase,
    /// Sanitized issue id (crosslink ids like `#42` or `L3` are folded to
    /// `[a-z0-9]`; an id that sanitizes to empty folds to [`EMPTY_ISSUE`]).
    issue: String,
    /// Review round (0-based).
    round: u32,
    /// Short UUID suffix that makes repeated attempts on the same round unique.
    uuid: String,
}

impl WorkspaceName {
    /// Generate a fresh, unique workspace name for `phase`/`issue_id`/`round`,
    /// minting a new short UUID suffix. Two calls with identical arguments still
    /// differ in their suffix, so repeated attempts on one round never collide.
    pub fn generate(phase: Phase, issue_id: &str, round: u32) -> Self {
        Self::from_parts(phase, issue_id, round, &short_uuid())
    }

    /// Build a name from an explicit suffix. Private so callers cannot inject an
    /// unsanitized or non-unique suffix; [`generate`](Self::generate) mints the
    /// suffix, [`parse`](Self::parse) recovers it.
    ///
    /// An `issue_id` that sanitizes to empty (e.g. all-punctuation like `###`)
    /// folds to [`EMPTY_ISSUE`] rather than the empty string, so the rendered
    /// name never contains an empty `--` segment. This keeps `generate`
    /// infallible *and* keeps every output parseable — `parse` rejects an empty
    /// issue, so an unfolded empty issue would fail its own round-trip.
    fn from_parts(phase: Phase, issue_id: &str, round: u32, uuid: &str) -> Self {
        let issue = sanitize(issue_id);
        WorkspaceName {
            phase,
            issue: if issue.is_empty() {
                EMPTY_ISSUE.to_owned()
            } else {
                issue
            },
            round,
            uuid: sanitize(uuid),
        }
    }

    /// Re-parse a name a prior run rendered (e.g. read back from an
    /// `active_workers` row) into its typed components. Returns `None` if the
    /// string is not a name this scheme could have produced — the exact
    /// left-inverse of [`as_str`](Self::as_str): `parse(x).as_str() == x` for
    /// every accepted `x`, and every [`generate`](Self::generate) output is
    /// accepted. Recovery relies on this: it re-renders the parsed name to
    /// locate the workspace directory, so accepting a string `as_str` could
    /// never emit would target the wrong path.
    pub fn parse(s: &str) -> Option<Self> {
        // Peel the fixed-shape tail off the right — `-<hex uuid>`, then
        // `-r<digits>` — leaving `<phase>-<issue>`. Both the phase token
        // (e.g. `qa-gate`, `adversary-review`) and the sanitized issue id can
        // contain `-`, so the phase/issue boundary is not a plain first-`-`
        // split: it is resolved by matching the longest leading run of dash-
        // separated tokens that forms a *known* phase (see [`match_phase`]).
        // No phase token is a dash-boundary prefix of another, so that match is
        // unambiguous.
        //
        // Every check below rejects a shape `as_str` cannot render, so the two
        // are true inverses. The uuid tail must be exactly SHORT_UUID_LEN chars
        // of *lowercase* hex (sanitize lowercases; short_uuid emits 8), and the
        // round token must be *canonical* (`r7`, never `r007`) — the only form
        // `format!("r{round}")` produces.
        let (head, uuid) = s.rsplit_once('-')?;
        if uuid.len() != SHORT_UUID_LEN || !uuid.bytes().all(is_lower_hex) {
            return None;
        }
        let (head, round_tok) = head.rsplit_once('-')?;
        let round: u32 = round_tok.strip_prefix('r')?.parse().ok()?;
        if round_tok != format!("r{round}") {
            return None;
        }
        let (phase, issue) = match_phase(head)?;
        if issue.is_empty() {
            return None;
        }
        Some(WorkspaceName {
            phase,
            issue: issue.to_owned(),
            round,
            uuid: uuid.to_owned(),
        })
    }

    /// The rendered name, as used for both the jj workspace name and its
    /// directory component. Guaranteed filesystem-safe (see the type docs).
    pub fn as_str(&self) -> String {
        format!(
            "{}-{}-r{}-{}",
            self.phase.as_str(),
            self.issue,
            self.round,
            self.uuid
        )
    }

    /// The phase this workspace was spawned for.
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// The review round this workspace was spawned for.
    pub fn round(&self) -> u32 {
        self.round
    }
}

impl std::fmt::Display for WorkspaceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_str())
    }
}

/// Split `head` (`<phase>-<issue>`) at the phase/issue boundary. Phase tokens
/// may themselves contain `-` (`qa-gate`, `pr-open`, `awaiting-human-merge`),
/// so we can't split on the first `-`: instead, test every dash-boundary prefix
/// of `head` against the known phase set and return the first that matches,
/// with the remainder as the issue. Because no phase token is a dash-boundary
/// prefix of another, the first match is the only match.
fn match_phase(head: &str) -> Option<(Phase, &str)> {
    for (idx, _) in head.match_indices('-') {
        if let Some(phase) = Phase::from_db_str(&head[..idx]) {
            return Some((phase, &head[idx + 1..]));
        }
    }
    None
}

/// Fold an arbitrary id (a crosslink issue id, a raw uuid) to `[a-z0-9]`:
/// lowercase alphanumerics pass through, everything else becomes `-`, runs of
/// `-` collapse, and leading/trailing `-` are trimmed. Guarantees the result is
/// a safe path component with no separators and no leading dot.
fn sanitize(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_dash = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    out.trim_matches('-').to_owned()
}

/// A single byte of lowercase hex (`0-9a-f`) — the alphabet [`short_uuid`]
/// emits and thus the only one [`WorkspaceName::parse`] accepts in the uuid
/// tail. `sanitize` lowercases, so uppercase hex could never appear in a
/// rendered name.
fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

/// Eight hex characters of a fresh v4 UUID.
fn short_uuid() -> String {
    let mut s = uuid::Uuid::new_v4().simple().to_string();
    s.truncate(SHORT_UUID_LEN);
    s
}

// ============================================================================
// WorkspaceManager + JjGate (the mutex-guarded gate)
// ============================================================================

/// The single source of truth for `.jj/` mutation (REQ-5a).
///
/// Holds the one [`JjWorkspace`] handle behind an `Arc<Mutex<..>>`. Cloning the
/// manager shares that same mutex, so every part of the orchestrator that
/// mutates `.jj/` — this module's workspace lifecycle today, the landing code's
/// rebase/bookmark/push tomorrow — serializes through it. There is no method
/// that hands out the inner handle unguarded; the only reach is
/// [`gate`](Self::gate), which returns a lock guard.
#[derive(Clone)]
pub struct WorkspaceManager {
    /// Repository root (the directory that owns `.jj/`).
    root: PathBuf,
    /// The lone repo handle, reachable only under the serializing lock.
    jj: Arc<Mutex<JjWorkspace>>,
}

impl WorkspaceManager {
    /// Load the repository rooted at `root` and wrap its handle in the gate.
    /// `root` must be inside a jj repository.
    pub fn load(root: impl Into<PathBuf>) -> Result<Self, SpawnError> {
        let root = root.into();
        let jj = JjWorkspace::load(&root).map_err(|source| SpawnError::WorkspacePrep {
            path: root.clone(),
            source: Box::new(source),
        })?;
        Ok(WorkspaceManager {
            root,
            jj: Arc::new(Mutex::new(jj)),
        })
    }

    /// Repository root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Prepare a fresh workspace for a worker spawn (REQ-12).
    ///
    /// Unconditionally — every time, success or not — this first *forgets* any
    /// jj workspace by `name` and *removes* its directory, then creates a fresh
    /// one whose working copy is a new empty commit on `base_revset`. Running it
    /// over an orphan left by a prior crash cleans that orphan first; running it
    /// when nothing exists is a no-op cleanup followed by a create.
    ///
    /// Returns a [`PreparedWorkspace`] — the typed proof that the directory was
    /// cleaned and (re)created, so a caller cannot spawn into a workspace that
    /// was never prepared.
    pub fn prepare(
        &self,
        name: &WorkspaceName,
        base_revset: &str,
    ) -> Result<PreparedWorkspace, SpawnError> {
        let dir = self.workspace_dir(name);
        let gate = self.gate();
        gate.cleanup(name, &dir)?;
        if let Err(e) = gate.create(name, &dir, base_revset) {
            // Make a failed prepare atomic on its own: `workspace_add` may have
            // created `dir` (and possibly a partial registration) before
            // failing. The next prepare's REQ-12 cleanup would clear it, but
            // leave the single call clean too. Best-effort — the create error is
            // the one we surface.
            let _ = remove_dir_all_idempotent(&dir);
            return Err(e);
        }
        Ok(PreparedWorkspace {
            name: name.clone(),
            path: dir,
        })
    }

    /// Idempotently tear down a workspace: forget it (if present) and remove its
    /// directory. Safe to call when nothing exists.
    pub fn forget(&self, name: &WorkspaceName) -> Result<(), SpawnError> {
        let dir = self.workspace_dir(name);
        self.gate().cleanup(name, &dir)
    }

    /// Names of every jj workspace currently registered in the repository.
    pub fn list(&self) -> Result<Vec<String>, SpawnError> {
        Ok(self.entries()?.into_iter().map(|e| e.name).collect())
    }

    /// Every jj workspace currently registered in the repository, with its
    /// working-copy commit id. Exposes [`WorkspaceEntry`] for callers (and
    /// tests) that need to observe the working copy, not just the name.
    pub fn entries(&self) -> Result<Vec<WorkspaceEntry>, SpawnError> {
        self.gate().entries(&self.root)
    }

    /// Absolute path of the directory `name` lives in: `<root>/.workspace/<name>`.
    pub fn workspace_dir(&self, name: &WorkspaceName) -> PathBuf {
        self.root.join(WORKSPACE_DIR).join(name.as_str())
    }

    // --- landing primitives (REQ-17 local path, REQ-5a) --------------------
    //
    // These mutate `.jj/` (rebase, bookmark move) or read the commit graph and
    // MUST share the same serializing gate as the workspace lifecycle above, so
    // a rebase in the landing step cannot race a `workspace add` in the build
    // pump (REQ-5a). They live on the manager — behind [`gate`](Self::gate) —
    // rather than as free functions taking a raw handle, so the "the mutex owns
    // the only handle" invariant is preserved: no raw [`JjWorkspace`] ever
    // escapes.

    /// Rebase the change `source_revset` resolves to so its parent becomes the
    /// commit `dest_revset` resolves to, under the `.jj/` gate (REQ-17, REQ-5a).
    ///
    /// A rebase that cannot apply cleanly is **not** an error — jj records the
    /// conflict in the rebased commit's tree and the operation succeeds. The
    /// returned [`CommitInfo`] carries [`CommitInfo::has_conflict`]; the caller
    /// (`land_local`) checks that flag to decide between fast-forwarding and
    /// parking for a human. Only a genuine jj-op failure (unresolvable revset,
    /// backend/transaction error) surfaces as [`LandingError::RebaseFailed`].
    pub fn rebase(
        &self,
        source_revset: &str,
        dest_revset: &str,
    ) -> Result<CommitInfo, LandingError> {
        self.gate()
            .handle
            .rebase(source_revset, dest_revset)
            .map_err(|source| LandingError::RebaseFailed {
                change_revset: source_revset.to_owned(),
                dest_revset: dest_revset.to_owned(),
                source: Box::new(source),
            })
    }

    /// The full commit id the local bookmark `name` currently points at, or
    /// `None` if there is no such bookmark (or it is conflicted).
    ///
    /// Used by the resumable landing machine to read filesystem/graph ground
    /// truth (REQ-15): after a crash in `rebase_done_bookmark_pending`, the
    /// resume path compares this against the landed change's commit id to decide
    /// whether the move already happened (advance) or still needs doing (retry).
    pub fn bookmark_target(&self, name: &str) -> Result<Option<String>, LandingError> {
        let list = self.gate().handle.bookmark_list().map_err(|source| {
            LandingError::BookmarkMoveFailed {
                bookmark: name.to_owned(),
                source: Box::new(source),
            }
        })?;
        Ok(list
            .into_iter()
            .find(|b| b.name == name)
            .and_then(|b| b.target))
    }

    /// Metadata for the single commit `revset` resolves to, under the `.jj/`
    /// gate. A convenience read used by the landing machine to fetch the landed
    /// change's commit id (for the bookmark-move idempotency check) without the
    /// caller reaching a raw handle.
    ///
    /// Uses the length-checked `resolve_single` semantics: an *ambiguous* revset
    /// (e.g. a divergent change id resolving to several commits) is an error, not
    /// a silent pick of one. Errors as [`LandingError::RebaseFailed`] (reusing
    /// its revset-context shape) if the revset does not resolve to exactly one
    /// commit.
    pub fn resolve_change(&self, revset: &str) -> Result<CommitInfo, LandingError> {
        self.gate()
            .handle
            .resolve_single_info(revset)
            .map_err(|source| LandingError::RebaseFailed {
                change_revset: revset.to_owned(),
                dest_revset: revset.to_owned(),
                source: Box::new(source),
            })
    }

    /// Whether the commit `ancestor_revset` resolves to is an ancestor of (or
    /// equal to) the commit `descendant_revset` resolves to — i.e. moving a
    /// bookmark from the former to the latter would be a true fast-forward.
    /// Read under the `.jj/` gate (REQ-5a).
    pub fn is_ancestor(
        &self,
        ancestor_revset: &str,
        descendant_revset: &str,
    ) -> Result<bool, LandingError> {
        self.gate()
            .handle
            .is_ancestor(ancestor_revset, descendant_revset)
            .map_err(|source| LandingError::RebaseFailed {
                change_revset: ancestor_revset.to_owned(),
                dest_revset: descendant_revset.to_owned(),
                source: Box::new(source),
            })
    }

    /// Whether the tree of the commit `change_revset` resolves to differs from
    /// the tree of `base_revset` — i.e. the worker's change actually carries
    /// content, rather than being an empty commit identical to its base. Read
    /// under the `.jj/` gate (REQ-5a).
    ///
    /// The empty-commit landing guard (#4): a worker that writes a valid `DONE`
    /// but never edits the tree (or never `jj describe`s a change) leaves an
    /// empty working-copy commit equal to `main`. Landing that as a
    /// fast-forward would advance `main` to a no-op commit and falsely report
    /// `phase:merged`. The pump checks this before landing and treats an empty
    /// change as a worker failure. Implemented as a rendered `diff(base ->
    /// change)` being non-empty; a genuine jj-op failure surfaces as
    /// [`LandingError::RebaseFailed`] (reusing its revset-context shape).
    pub fn change_differs_from(
        &self,
        base_revset: &str,
        change_revset: &str,
    ) -> Result<bool, LandingError> {
        self.gate()
            .handle
            .diff(base_revset, change_revset)
            .map(|patch| !patch.trim().is_empty())
            .map_err(|source| LandingError::RebaseFailed {
                change_revset: change_revset.to_owned(),
                dest_revset: base_revset.to_owned(),
                source: Box::new(source),
            })
    }

    /// Fast-forward the local bookmark `name` to the commit `target_revset`
    /// resolves to, **refusing any move that is not a true fast-forward**
    /// (REQ-17). The load-bearing safety guard for local-mode landing.
    ///
    /// The whole check-then-move runs under a single hold of the `.jj/` gate, so
    /// no concurrent lander (REQ-5a) can advance `main` between the ancestry
    /// check and the bookmark write: the guard sees a consistent view and the
    /// move is atomic with it. If the bookmark's current commit is **not** an
    /// ancestor of `target_revset`, the move is refused with
    /// [`LandingError::NotFastForward`] and the bookmark is left untouched —
    /// `main` can only ever advance, never rewind or move sideways.
    ///
    /// A bookmark already at `target_revset` is a fast-forward (equal is an
    /// ancestor), so the move is a jj no-op and this stays idempotent on resume.
    /// A missing bookmark surfaces as [`LandingError::BookmarkMoveFailed`].
    pub fn fast_forward_bookmark(
        &self,
        name: &str,
        target_revset: &str,
    ) -> Result<(), LandingError> {
        // One gate hold spans read-current → ancestry-check → move, so a
        // concurrent `.jj/` mutator cannot slip between the guard and the write.
        let gate = self.gate();
        let current = gate
            .handle
            .bookmark_list()
            .map_err(|source| LandingError::BookmarkMoveFailed {
                bookmark: name.to_owned(),
                source: Box::new(source),
            })?
            .into_iter()
            .find(|b| b.name == name)
            .and_then(|b| b.target)
            .ok_or_else(|| LandingError::BookmarkMoveFailed {
                bookmark: name.to_owned(),
                source: format!("bookmark `{name}` is absent or conflicted").into(),
            })?;
        // Fast-forward iff the current commit is an ancestor of (or equal to)
        // the target. Query by full commit id on both sides so the check can't
        // be fooled by a symbol resolving differently between reads.
        let is_ff = gate
            .handle
            .is_ancestor(&current, target_revset)
            .map_err(|source| LandingError::BookmarkMoveFailed {
                bookmark: name.to_owned(),
                source: Box::new(source),
            })?;
        if !is_ff {
            let target = gate
                .handle
                .resolve_single_info(target_revset)
                .map(|c| c.commit_id)
                .unwrap_or_else(|_| target_revset.to_owned());
            return Err(LandingError::NotFastForward {
                bookmark: name.to_owned(),
                current,
                target,
            });
        }
        gate.handle
            .bookmark_move(name, target_revset)
            .map_err(|source| LandingError::BookmarkMoveFailed {
                bookmark: name.to_owned(),
                source: Box::new(source),
            })
    }

    /// Take the serializing lock, yielding a [`JjGate`] through which — and only
    /// through which — `.jj/`-mutating operations can run.
    ///
    /// Poisoning is deliberately recovered from: a panic inside one guarded op
    /// must not permanently wedge every future `.jj/` operation. Recovering the
    /// lock is safe not because each op is atomic — `workspace_add` commits its
    /// registration txn *before* checking out the working copy, so a panic
    /// between the two leaves a workspace registered-but-not-checked-out — but
    /// because the next `prepare`'s unconditional cleanup (REQ-12) forgets and
    /// `rm -rf`s any such partial workspace before recreating it. The recovered
    /// state is thus always cleaned by the following prepare, whatever half-step
    /// the panic interrupted.
    fn gate(&self) -> JjGate<'_> {
        let handle = self
            .jj
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        JjGate { handle }
    }
}

/// A held lock on the [`WorkspaceManager`]'s `.jj/` mutex. While this guard is
/// alive the current thread is the sole mutator of `.jj/`. Every mutating
/// method lives here rather than on the manager so it is *impossible* to call
/// one without first taking the lock (REQ-5a).
struct JjGate<'a> {
    handle: MutexGuard<'a, JjWorkspace>,
}

impl JjGate<'_> {
    /// Idempotent cleanup for one workspace name + directory (REQ-12).
    ///
    /// LANDMINE (verified against `jj_api`): `workspace_forget` errors if no
    /// workspace by that name exists and never touches the directory. So we
    /// (a) forget only when the name is actually registered — checked via
    /// `workspace_list` under this same lock, so no TOCTOU with another
    /// mutator — and (b) always own the `rm -rf` ourselves, tolerating a
    /// missing directory. No `jj`/`rm` subprocess is used (AC-24): forget is a
    /// library call, removal is [`std::fs::remove_dir_all`].
    fn cleanup(&self, name: &WorkspaceName, dir: &Path) -> Result<(), SpawnError> {
        let name_str = name.as_str();
        let registered = self
            .handle
            .workspace_list()
            .map_err(|source| jj_prep_err(dir, source))?
            .into_iter()
            .any(|entry| entry.name == name_str);
        if registered {
            self.handle
                .workspace_forget(&name_str)
                .map_err(|source| jj_prep_err(dir, source))?;
        }
        remove_dir_all_idempotent(dir)?;
        Ok(())
    }

    /// Create a fresh workspace at `dir`, rooted on `base_revset`.
    fn create(
        &self,
        name: &WorkspaceName,
        dir: &Path,
        base_revset: &str,
    ) -> Result<(), SpawnError> {
        self.handle
            .workspace_add(dir, &name.as_str(), base_revset)
            .map_err(|source| jj_prep_err(dir, source))
    }

    /// Every registered workspace with its working-copy commit id. `root` is
    /// the repository root, used only for error context — a `workspace_list`
    /// failure is a repo-view read, not scoped to any one workspace directory,
    /// so the old `.workspace` relative path was a fabricated location.
    fn entries(&self, root: &Path) -> Result<Vec<WorkspaceEntry>, SpawnError> {
        self.handle
            .workspace_list()
            .map_err(|source| jj_prep_err(root, source))
    }
}

// ============================================================================
// PreparedWorkspace
// ============================================================================

/// A live, prepared workspace: the typed evidence that the directory was
/// cleaned and (re)created by [`WorkspaceManager::prepare`]. The build pump
/// takes one of these to spawn a worker, so it cannot spawn into a workspace
/// that was never prepared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedWorkspace {
    /// The workspace's validated name.
    name: WorkspaceName,
    /// Absolute path of the workspace's working-copy directory on disk.
    path: PathBuf,
}

impl PreparedWorkspace {
    /// The workspace's name.
    pub fn name(&self) -> &WorkspaceName {
        &self.name
    }

    /// Absolute path of the working-copy directory a worker is spawned into.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Remove `dir` and its contents, treating an already-absent directory as
/// success. This is the caller-owned `rm -rf` the LANDMINE requires, done via
/// `std::fs` (no `rm` subprocess — AC-24).
fn remove_dir_all_idempotent(dir: &Path) -> Result<(), SpawnError> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(SpawnError::io(dir, source)),
    }
}

/// Wrap a `jj_api` failure raised during workspace prep as a
/// [`SpawnError::WorkspacePrep`] carrying the workspace path for context.
fn jj_prep_err(path: &Path, source: impl std::error::Error + Send + Sync + 'static) -> SpawnError {
    SpawnError::WorkspacePrep {
        path: path.to_path_buf(),
        source: Box::new(source),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_round_trips_through_parse() {
        let name = WorkspaceName::generate(Phase::Implementing, "#42", 3);
        let parsed = WorkspaceName::parse(&name.as_str()).expect("round-trips");
        assert_eq!(parsed, name);
        assert_eq!(parsed.phase(), Phase::Implementing);
        assert_eq!(parsed.round(), 3);
    }

    #[test]
    fn rendered_name_is_filesystem_safe() {
        let name = WorkspaceName::generate(Phase::AdversaryReview, "L3/weird id!", 0);
        let s = name.as_str();
        assert!(
            s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "name `{s}` is not [a-z0-9-]"
        );
        assert!(!s.starts_with('.'), "name `{s}` starts with a dot");
        assert!(!s.contains('/'), "name `{s}` contains a separator");
    }

    #[test]
    fn generate_is_collision_free_for_same_inputs() {
        let a = WorkspaceName::generate(Phase::Implementing, "#1", 0);
        let b = WorkspaceName::generate(Phase::Implementing, "#1", 0);
        assert_ne!(a.as_str(), b.as_str(), "distinct spawns must not collide");
    }

    #[test]
    fn parse_rejects_malformed_names() {
        // Missing uuid tail.
        assert!(WorkspaceName::parse("implementing-42-r3").is_none());
        // Unknown phase token.
        assert!(WorkspaceName::parse("bogusphase-42-r3-a1b2c3d4").is_none());
        // Non-numeric round.
        assert!(WorkspaceName::parse("implementing-42-rX-a1b2c3d4").is_none());
        // Uuid with non-hex characters.
        assert!(WorkspaceName::parse("implementing-42-r3-zzzzzzzz").is_none());
        // Empty issue segment (the `generate`-would-never-emit `--`).
        assert!(WorkspaceName::parse("implementing--r3-a1b2c3d4").is_none());
    }

    /// The left-inverse cases finding #1 calls out: `parse` must reject any
    /// shape `as_str` can never render, else `parse(x).as_str() != x`.
    #[test]
    fn parse_rejects_shapes_generate_never_emits() {
        // Uppercase hex — `sanitize` lowercases, so a rendered name never has it.
        assert!(WorkspaceName::parse("implementing-42-r3-A1B2C3D4").is_none());
        // Wrong-length uuid (must be exactly SHORT_UUID_LEN).
        assert!(WorkspaceName::parse("implementing-42-r3-a1b2c3d4ef").is_none());
        assert!(WorkspaceName::parse("implementing-42-r3-a1b2c3").is_none());
        // Non-canonical (leading-zero) round token — `format!("r{round}")`
        // never pads, so `r007` is not a shape `as_str` emits.
        assert!(WorkspaceName::parse("implementing-42-r007-a1b2c3d4").is_none());
    }

    /// An all-punctuation issue sanitizes to empty; `generate` must still emit a
    /// well-formed, self-parseable name (folded to the `issue` sentinel).
    #[test]
    fn generate_folds_empty_issue_and_round_trips() {
        let name = WorkspaceName::generate(Phase::Implementing, "###", 0);
        let s = name.as_str();
        assert!(!s.contains("--"), "empty issue must not render `--`: {s}");
        let parsed = WorkspaceName::parse(&s).expect("folded name must round-trip");
        assert_eq!(parsed, name);
    }
}
