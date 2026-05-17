//! REQ-15 deterministic crash-recovery table — scaffold.
//!
//! On restart the orchestrator must, for every issue in a non-terminal phase,
//! re-derive ground truth from the filesystem (`_orchestrator/DONE`, `jj log`,
//! bookmark position, `gh pr list`) and decide whether to advance, repeat, or
//! roll back the phase. That deterministic table lands in P2 (crosslink issue
//! #16).
//!
//! This module is the scaffold for it. [`plan_recovery`] currently does the
//! one thing the table's correctness hinges on: it recognizes the eight
//! defined `phase_substate` values (REQ-2a) and rejects anything else, so an
//! issue persisted by a newer binary is never silently mis-recovered. Every
//! recognized state is reported as [`RecoveryPlan::NotImplemented`] until #16
//! fills in the real advance / repeat / roll-back logic.

use vetinari_error::RecoveryError;

use crate::state::{Phase, PhaseSubstate};

/// The recovery action decided for an issue found mid-phase on restart.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecoveryPlan {
    /// The `(phase, substate)` pair is recognized, but the deterministic
    /// recovery logic for it is not yet implemented. Lands in P2 (#16).
    NotImplemented {
        /// Phase the issue was found in.
        phase: Phase,
        /// Substate the issue was found in, if any.
        substate: Option<PhaseSubstate>,
    },
}

/// Decide how to recover an issue found mid-phase on orchestrator restart.
///
/// `substate` is the raw `phase_substate` column value (REQ-2a). An
/// unrecognized non-null value yields [`RecoveryError::UnknownSubstate`] — the
/// signal that a newer binary wrote state this one cannot interpret. A `None`
/// substate (the issue is in a single-step phase) is always valid.
///
/// The full per-substate decision table lands in P2 (#16); until then every
/// recognized state is returned as [`RecoveryPlan::NotImplemented`].
pub fn plan_recovery(phase: Phase, substate: Option<&str>) -> Result<RecoveryPlan, RecoveryError> {
    let substate =
        match substate {
            None => None,
            Some(raw) => Some(PhaseSubstate::from_db_str(raw).ok_or_else(|| {
                RecoveryError::UnknownSubstate {
                    phase: phase.to_string(),
                    substate: raw.to_string(),
                }
            })?),
        };
    Ok(RecoveryPlan::NotImplemented { phase, substate })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_substate_is_recognized() {
        let plan = plan_recovery(Phase::Implementing, None).unwrap();
        assert_eq!(
            plan,
            RecoveryPlan::NotImplemented {
                phase: Phase::Implementing,
                substate: None,
            }
        );
    }

    #[test]
    fn all_defined_substates_are_recognized() {
        for token in [
            "qa_running",
            "qa_passed_pending_transition",
            "rebase_started",
            "rebase_done_bookmark_pending",
            "bookmark_moved_complete",
            "push_started",
            "push_done_pr_pending",
            "pr_created",
        ] {
            plan_recovery(Phase::Landing, Some(token))
                .unwrap_or_else(|_| panic!("substate `{token}` should be recognized"));
        }
    }

    #[test]
    fn unknown_substate_is_rejected() {
        let err = plan_recovery(Phase::Landing, Some("frobnicate")).unwrap_err();
        match err {
            RecoveryError::UnknownSubstate { substate, .. } => {
                assert_eq!(substate, "frobnicate");
            }
            other => panic!("expected UnknownSubstate, got {other:?}"),
        }
    }
}
