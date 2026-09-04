//! The crossbridge `xb*` marker labels, as vetinari-owned plain string consts.
//!
//! crossbridge stamps these labels onto the crosslink issues it creates and
//! answers. The orchestrator's ingestion path (step 4) keys off them to
//! recognize inbound work, its source peer, and its answer status. They are
//! defined here as plain `&str` consts — the same self-contained-plain-types
//! discipline the rest of this crate follows — so the orchestrator never links
//! crossbridge just to name a label.
//!
//! These MUST stay byte-for-byte identical to crossbridge's own label strings
//! (`crossbridge_client::labels`). Because these are independent vetinari-owned
//! literals, a crossbridge rename does **not** break compilation — the crate
//! keeps building with stale strings. The drift is caught only by the
//! `#[cfg(test)]` assertion in the `tests` module below, and only when that
//! test is actually run; CI must execute this crate's tests for the guard to
//! fire.

/// Marks an issue created by the embedded server from a peer's `SubmitIssue` —
/// i.e. untrusted, inbound work. The pump never picks it up until it is graphed
/// (spec §1.2); it is also the human-gate trigger for `awaiting-inbound-approval`.
pub const XB_INBOUND: &str = "xb:inbound";

/// Marks a locally-authored issue that was submitted *out* to a peer and is
/// awaiting that peer's answer.
pub const XB_OUTBOUND: &str = "xb:outbound";

/// Prefix carrying the submitting peer's slug: `xb-source:<slug>`. Recorded so
/// the trust boundary is legible (spec §1.2 audit trail) and so an answer can
/// be routed back to the originating peer.
pub const XB_SOURCE_PREFIX: &str = "xb-source:";

/// Prefix carrying the cross-node correlation id: `xb-ref:<source_uuid>`. This
/// is the value echoed back in a `SubmitAnswer` so the source repo can match
/// the answer to its outbound issue.
pub const XB_REF_PREFIX: &str = "xb-ref:";

/// Applied to an outbound issue while its answer is still pending.
pub const XB_STATUS_PENDING: &str = "xb-status:pending";

/// Applied (as a courtesy, spec §1.3) once an inbound issue has been answered.
pub const XB_STATUS_ANSWERED: &str = "xb-status:answered";

#[cfg(test)]
mod tests {
    use super::*;

    /// Drift guard: our vetinari-owned consts must equal crossbridge's own
    /// label strings. If crossbridge renames a label, this fails to compile or
    /// assert — the intended loud signal, not a silent ingestion desync.
    #[test]
    fn consts_match_crossbridge() {
        use crossbridge_client::labels as xb;
        assert_eq!(XB_INBOUND, xb::INBOUND);
        assert_eq!(XB_OUTBOUND, xb::OUTBOUND);
        assert_eq!(XB_SOURCE_PREFIX, xb::SOURCE_PREFIX);
        assert_eq!(XB_REF_PREFIX, xb::REF_PREFIX);
        assert_eq!(XB_STATUS_PENDING, xb::STATUS_PENDING);
        assert_eq!(XB_STATUS_ANSWERED, xb::STATUS_ANSWERED);
    }
}
