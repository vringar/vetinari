//! Property-based proofs for the workspace-name scheme and the idempotent
//! cleanup contract (REQ-12), using `proptest` (`kani` is unavailable).
//!
//! Two invariants are proven over arbitrary inputs:
//!
//! 1. **Name scheme.** For any phase / issue id / round / uuid, the generated
//!    [`WorkspaceName`] renders to a filesystem-safe string, round-trips through
//!    [`WorkspaceName::parse`], and distinct spawns for identical inputs never
//!    collide.
//! 2. **Cleanup idempotence.** Running `prepare` twice is observationally
//!    identical to running it once. Proven against a *pure model* of the gate's
//!    cleanup+create (a set of registered names + a per-directory
//!    presence/contents flag), so the proof is fast and deterministic — no real
//!    jj repo per case. The model mirrors the LANDMINE exactly: forget only when
//!    registered, always remove the directory.

use std::collections::BTreeSet;

use orchestrator::state::Phase;
use orchestrator::workspace::WorkspaceName;
use proptest::prelude::*;

/// Every phase, so `prop_phase` can pick one. Kept in sync with `state::Phase`.
const PHASES: &[Phase] = &[
    Phase::Graphed,
    Phase::Implementing,
    Phase::QaGate,
    Phase::AdversaryReview,
    Phase::Converged,
    Phase::Landing,
    Phase::Merged,
    Phase::PrOpen,
    Phase::AwaitingHumanMerge,
    Phase::OrchestratorError,
];

prop_compose! {
    /// An arbitrary phase.
    fn prop_phase()(idx in 0..PHASES.len()) -> Phase {
        PHASES[idx]
    }
}

// ---------------------------------------------------------------------------
// Pure model of the gate's cleanup + create (mirrors JjGate::cleanup/create).
// ---------------------------------------------------------------------------

/// A pure stand-in for the `.jj/` view plus the on-disk workspace directories.
/// `registered` is the set of jj-registered workspace names (what
/// `workspace_list` would return); `dirs` maps a workspace name to the *marker*
/// its directory currently holds (a stand-in for arbitrary directory contents).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct RepoModel {
    registered: BTreeSet<String>,
    dirs: std::collections::BTreeMap<String, u64>,
}

impl RepoModel {
    /// Model of `JjGate::cleanup`: forget only if registered (the LANDMINE),
    /// then always remove the directory (tolerating absence).
    fn cleanup(&mut self, name: &str) {
        self.registered.remove(name);
        self.dirs.remove(name);
    }

    /// Model of `JjGate::create`: register the name and materialize its
    /// directory with a fresh, distinguishable content marker.
    fn create(&mut self, name: &str, marker: u64) {
        self.registered.insert(name.to_owned());
        self.dirs.insert(name.to_owned(), marker);
    }

    /// Model of `WorkspaceManager::prepare`: cleanup then create.
    fn prepare(&mut self, name: &str, marker: u64) {
        self.cleanup(name);
        self.create(name, marker);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The rendered name is always `[a-z0-9-]`, has no path separator, and does
    /// not start with a dot — safe to use as a directory component unescaped.
    #[test]
    fn name_is_filesystem_safe(
        phase in prop_phase(),
        issue in ".{0,40}",
        round in any::<u32>(),
    ) {
        let name = WorkspaceName::generate(phase, &issue, round);
        let s = name.as_str();
        prop_assert!(
            s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "name `{s}` escaped [a-z0-9-]"
        );
        prop_assert!(!s.starts_with('.'), "name `{s}` starts with a dot");
        prop_assert!(!s.contains('/'), "name `{s}` contains a separator");
        prop_assert!(!s.contains(std::path::MAIN_SEPARATOR), "name `{s}` contains a separator");
    }

    /// Every `generate` output round-trips through `parse` back to an equal
    /// value, and the recovered phase/round match the inputs. `issue` is fully
    /// arbitrary — including all-punctuation / empty-sanitizing ids like `###`,
    /// which fold to the `issue` sentinel — so this proves `generate` never
    /// emits a name its own `parse` rejects (finding #2).
    #[test]
    fn name_round_trips(
        phase in prop_phase(),
        issue in ".{0,40}",
        round in any::<u32>(),
    ) {
        let name = WorkspaceName::generate(phase, &issue, round);
        let parsed = WorkspaceName::parse(&name.as_str()).expect("must round-trip");
        prop_assert_eq!(&parsed, &name);
        prop_assert_eq!(parsed.phase(), phase);
        prop_assert_eq!(parsed.round(), round);
    }

    /// `parse` is a true left-inverse of `as_str` on its accepted domain: for
    /// any string `parse` accepts, re-rendering it reproduces the input exactly
    /// (`parse(x).unwrap().as_str() == x`). We reach the accepted domain by
    /// assembling strings from the *only* component shapes `parse` admits — a
    /// known phase token, a non-empty `[a-z0-9]`(+`-`) issue, a canonical
    /// `r{round}`, and exactly SHORT_UUID_LEN lowercase-hex chars — then assert
    /// `parse` both accepts them and round-trips. This is the guard finding #1
    /// demands: recovery re-renders a parsed name to locate its directory, so
    /// any accepted-but-non-canonical shape would target the wrong path.
    #[test]
    fn parse_is_left_inverse_of_as_str(
        phase in prop_phase(),
        // A sanitized-style issue: lowercase alnum runs joined by single dashes,
        // no leading/trailing dash — exactly what `sanitize` can emit non-empty.
        issue in "[a-z0-9]{1,6}(-[a-z0-9]{1,6}){0,3}",
        round in any::<u32>(),
        uuid in "[0-9a-f]{8}",
    ) {
        let rendered = format!("{}-{}-r{}-{}", phase.as_str(), issue, round, uuid);
        let parsed = WorkspaceName::parse(&rendered)
            .unwrap_or_else(|| panic!("parse must accept canonical name `{rendered}`"));
        prop_assert_eq!(parsed.as_str(), rendered);
    }

    /// Two generated names for identical inputs never collide — the short-uuid
    /// suffix keeps repeated same-round attempts distinct.
    #[test]
    fn generate_is_collision_free(
        phase in prop_phase(),
        issue in "[a-zA-Z0-9]{1,20}",
        round in any::<u32>(),
    ) {
        let a = WorkspaceName::generate(phase, &issue, round);
        let b = WorkspaceName::generate(phase, &issue, round);
        prop_assert_ne!(a.as_str(), b.as_str());
    }

    /// Idempotent cleanup: preparing twice leaves the repository model in the
    /// same *shape* (registration + which directories exist) as preparing once.
    /// The two prepares carry different content markers, proving the second
    /// prepare genuinely tore down and recreated the directory rather than
    /// leaving the first attempt's contents in place.
    #[test]
    fn prepare_is_idempotent(
        names in prop::collection::vec("[a-z0-9]{1,8}", 1..6),
        marker_once in any::<u64>(),
        marker_a in any::<u64>(),
        marker_b in any::<u64>(),
    ) {
        prop_assume!(marker_a != marker_b);

        // Prepare each name once.
        let mut once = RepoModel::default();
        for n in &names {
            once.prepare(n, marker_once);
        }

        // Prepare each name twice, with distinct markers per pass.
        let mut twice = RepoModel::default();
        for n in &names {
            twice.prepare(n, marker_a);
        }
        for n in &names {
            twice.prepare(n, marker_b);
        }

        // Registration and directory presence are identical either way.
        prop_assert_eq!(&once.registered, &twice.registered);
        prop_assert_eq!(
            once.dirs.keys().collect::<Vec<_>>(),
            twice.dirs.keys().collect::<Vec<_>>()
        );
        // And the twice-prepared directory holds the *second* attempt's marker
        // for every name — the recreate is real, not a no-op skip.
        for n in &names {
            prop_assert_eq!(twice.dirs.get(n), Some(&marker_b));
        }
    }
}
