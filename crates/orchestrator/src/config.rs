//! Orchestrator configuration parsed from `.orchestrator/config.toml` (REQ-13).
//!
//! The config is the orchestrator's tunable surface: the concurrency budget
//! ([`OrchestratorConfig::max_concurrent_agents`]), the poll cadence
//! ([`OrchestratorConfig::poll_interval_ms`]), the per-run timeouts, and — for
//! the AC-11a dogfood — the worker command the build pump dispatches. Every
//! field has a sane default, and an **absent** file yields the all-defaults
//! config: a fresh repo runs the pump without any config authored first.
//!
//! # Shape
//!
//! ```toml
//! poll_interval_ms   = 1000
//! max_concurrent_agents = 1
//! qa_timeout_secs    = 600
//! worker_timeout_secs = 120
//!
//! [worker]
//! # Which worker to dispatch: "direct" (fake-worker dogfood, the default) or
//! # "claude" (a real sandboxed Implementer, S7).
//! kind = "direct"
//! # The Direct worker command. argv[0] is the program; the rest are its args.
//! argv = ["bash", "tests/fixtures/fake-implementer.sh"]
//! # The Implementer turn cap when kind = "claude" (REQ-13).
//! max_turns_implementer = 80
//! ```
//!
//! The `[worker]` table is optional: absent, the pump falls back to the
//! [`WorkerConfig::default`] (`kind = "direct"`, the fake implementer, resolved
//! by the caller).
//!
//! # No shell-out (AC-24)
//!
//! Parsing is [`toml`] + [`serde`]; file access is [`std::fs`]. This module
//! constructs no `std::process::Command` — the worker *argv* it holds is data
//! handed to the spawn layer's `WorkerCommand::Direct`, which the AC-24 lint
//! already sanctions for `bash`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use miette::Diagnostic;
use serde::Deserialize;
use thiserror::Error;

/// The config file, relative to the orchestrator-private `.orchestrator/`
/// directory. Kept as a constant so the design layout and the code agree.
pub const CONFIG_FILE: &str = "config.toml";

/// Default poll interval between pump ticks, in milliseconds (REQ-13). One
/// second keeps the headless dogfood responsive; production may widen it.
pub const DEFAULT_POLL_INTERVAL_MS: u64 = 1000;

/// Default concurrency budget: one agent at a time (REQ-13, matches the MVP
/// `max_per_role.implementer = 1`).
pub const DEFAULT_MAX_CONCURRENT_AGENTS: u32 = 1;

/// Default QA-gate wall-clock budget, in seconds (mirrors `qa::DEFAULT_QA_TIMEOUT`).
pub const DEFAULT_QA_TIMEOUT_SECS: u64 = 600;

/// Default per-worker wall-clock budget, in seconds, before the pump treats a
/// still-running worker as a stall.
pub const DEFAULT_WORKER_TIMEOUT_SECS: u64 = 120;

/// The single argv position [`OrchestratorConfig::worker_argv`] resolves against
/// the repository root: `argv[1]`, the script argument that follows the
/// interpreter (`bash <script>`). Only this designated field is path-resolved;
/// every other argument passes through verbatim.
pub const SCRIPT_ARGV_INDEX: usize = 1;

/// Failure to load or parse `.orchestrator/config.toml`.
#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum ConfigError {
    /// The config file exists but could not be read.
    #[error("failed to read orchestrator config at `{path}`")]
    #[diagnostic(code(vetinari::config::read))]
    Read {
        /// Path of the config that failed to read.
        path: PathBuf,
        /// Underlying I/O cause.
        #[source]
        source: std::io::Error,
    },

    /// The config file was read but is not valid TOML for this schema.
    #[error("failed to parse orchestrator config at `{path}`")]
    #[diagnostic(
        code(vetinari::config::parse),
        help("Check the TOML syntax and field types against the documented schema.")
    )]
    Parse {
        /// Path of the config that failed to parse.
        path: PathBuf,
        /// Underlying TOML parse cause.
        #[source]
        source: toml::de::Error,
    },
}

/// Which kind of worker the build pump dispatches (S7).
///
/// A **typed** enum, never a stringly `kind` read in the pump: the pump matches
/// on this to build either a `WorkerCommand::Direct` (the fake-worker dogfood)
/// or a real Implementer `WorkerCommand::Claude`. Defaults to [`Direct`] so a
/// fresh repo — and the AC-11a dogfood — runs the fake worker unchanged.
///
/// [`Direct`]: WorkerKind::Direct
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkerKind {
    /// Run the configured [`WorkerConfig::argv`] directly in the workspace (the
    /// AC-11a tracer-bullet dogfood; no live `claude`, no sandbox).
    #[default]
    Direct,
    /// Spawn a real sandboxed `claude` Implementer (S7): the pump builds the
    /// command from [`crate::roles::implementer`] and dispatches it through the
    /// `Spawner`, which enforces the mount matrix and the `bwrap` pin.
    Claude,
}

/// The default Implementer turn cap (REQ-13 `max_turns_implementer`); mirrors
/// [`crate::roles::implementer::DEFAULT_MAX_TURNS`].
pub const DEFAULT_MAX_TURNS_IMPLEMENTER: u32 = crate::roles::implementer::DEFAULT_MAX_TURNS;

/// The default Adversary turn cap (REQ-13 `max_turns_adversary`); mirrors
/// [`crate::roles::adversary::DEFAULT_MAX_TURNS`].
pub const DEFAULT_MAX_TURNS_ADVERSARY: u32 = crate::roles::adversary::DEFAULT_MAX_TURNS;

/// The A2 placeholder convergence threshold (REQ-10): how many consecutive
/// DONE-attested clean Adversary rounds converge an issue. **Default 1** for A2
/// — the first clean round converges, so the AC-11a/AC-11b dogfoods land on
/// their first clean adversary round unchanged. A3 (#23) hardens the detector
/// (configurable n consecutive clean rounds **plus** diff-hash stability); the
/// design's eventual default is 2.
pub const DEFAULT_CONVERGENCE_N_ROUNDS: u32 = 1;

/// The worker command the build pump dispatches (REQ-13, S7).
///
/// For [`WorkerKind::Direct`] this is a closed argv, not a free-form string:
/// the pump hands it to the spawn layer's `WorkerCommand::Direct`. `argv[0]` is
/// the program (`bash`), the rest its arguments (the fake-implementer path). The
/// default resolves to the fake implementer with a **relative** path; the pump
/// resolves it against the repository root so an absolute committed path is not
/// baked into the config. For [`WorkerKind::Claude`] the argv is unused and the
/// Implementer command is built from [`crate::roles::implementer`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerConfig {
    /// Which worker kind to dispatch (S7). Default [`WorkerKind::Direct`], so
    /// the dogfood is unchanged.
    #[serde(default)]
    pub kind: WorkerKind,
    /// The Direct worker's program plus its arguments. Must be non-empty; an
    /// empty argv is rejected by [`OrchestratorConfig::worker_argv`]. Ignored
    /// when [`kind`](Self::kind) is [`WorkerKind::Claude`].
    #[serde(default = "default_worker_argv")]
    pub argv: Vec<String>,
    /// The Implementer `--max-turns` cap for [`WorkerKind::Claude`] (REQ-13).
    /// Default [`DEFAULT_MAX_TURNS_IMPLEMENTER`].
    #[serde(default = "default_max_turns_implementer")]
    pub max_turns_implementer: u32,
    /// Which Adversary worker kind to dispatch for the review phase (A2), mirror
    /// of [`kind`](Self::kind). Default [`WorkerKind::Direct`] so tests use a
    /// deterministic fake Adversary; real runs set `adversary_kind = "claude"`.
    #[serde(default)]
    pub adversary_kind: WorkerKind,
    /// The Direct Adversary's program plus arguments, resolved against the repo
    /// root like [`argv`](Self::argv). Ignored when
    /// [`adversary_kind`](Self::adversary_kind) is [`WorkerKind::Claude`].
    /// Default: the committed `fake-adversary-clean.sh` (a clean/converging
    /// round), so the dogfoods land on their first review round.
    #[serde(default = "default_adversary_argv")]
    pub adversary_argv: Vec<String>,
    /// The Adversary `--max-turns` cap for [`WorkerKind::Claude`] (REQ-13).
    /// Default [`DEFAULT_MAX_TURNS_ADVERSARY`].
    #[serde(default = "default_max_turns_adversary")]
    pub max_turns_adversary: u32,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        WorkerConfig {
            kind: WorkerKind::default(),
            argv: default_worker_argv(),
            max_turns_implementer: default_max_turns_implementer(),
            adversary_kind: WorkerKind::default(),
            adversary_argv: default_adversary_argv(),
            max_turns_adversary: default_max_turns_adversary(),
        }
    }
}

fn default_max_turns_implementer() -> u32 {
    DEFAULT_MAX_TURNS_IMPLEMENTER
}

fn default_max_turns_adversary() -> u32 {
    DEFAULT_MAX_TURNS_ADVERSARY
}

/// The default dogfood worker argv: `bash tests/fixtures/fake-implementer.sh`.
/// The path is relative to the repository root; the pump joins it against the
/// root before dispatch.
fn default_worker_argv() -> Vec<String> {
    vec![
        "bash".to_owned(),
        "tests/fixtures/fake-implementer.sh".to_owned(),
    ]
}

/// The default dogfood Adversary argv: `bash tests/fixtures/fake-adversary-clean.sh`
/// (a clean/converging round). Relative to the repo root like
/// [`default_worker_argv`]; the pump joins it against the root before dispatch.
fn default_adversary_argv() -> Vec<String> {
    vec![
        "bash".to_owned(),
        "tests/fixtures/fake-adversary-clean.sh".to_owned(),
    ]
}

/// The orchestrator's parsed configuration (REQ-13).
///
/// Built by [`OrchestratorConfig::load`] (from `.orchestrator/config.toml`, or
/// all-defaults when absent) or [`OrchestratorConfig::default`]. Every field is
/// defaulted, so a partial config file overrides only what it names.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrchestratorConfig {
    /// Milliseconds between pump ticks (REQ-13). Default
    /// [`DEFAULT_POLL_INTERVAL_MS`].
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
    /// The concurrency budget: how many agents may run at once (REQ-13).
    /// Default [`DEFAULT_MAX_CONCURRENT_AGENTS`].
    #[serde(default = "default_max_concurrent_agents")]
    pub max_concurrent_agents: u32,
    /// QA-gate wall-clock budget in seconds. Default
    /// [`DEFAULT_QA_TIMEOUT_SECS`].
    #[serde(default = "default_qa_timeout_secs")]
    pub qa_timeout_secs: u64,
    /// Per-worker wall-clock budget in seconds. Default
    /// [`DEFAULT_WORKER_TIMEOUT_SECS`].
    #[serde(default = "default_worker_timeout_secs")]
    pub worker_timeout_secs: u64,
    /// The dogfood worker command (REQ-13). Default: the fake implementer.
    #[serde(default)]
    pub worker: WorkerConfig,
    /// The A2 placeholder convergence threshold (REQ-10): how many consecutive
    /// DONE-attested clean Adversary rounds converge an issue. Default
    /// [`DEFAULT_CONVERGENCE_N_ROUNDS`] (**1** for A2). A3 (#23) replaces the
    /// pump's `converged` detector with the full n-rounds + diff-hash-stability
    /// rule reading this same field.
    #[serde(default = "default_convergence_n_rounds")]
    pub convergence_n_rounds: u32,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        OrchestratorConfig {
            poll_interval_ms: DEFAULT_POLL_INTERVAL_MS,
            max_concurrent_agents: DEFAULT_MAX_CONCURRENT_AGENTS,
            qa_timeout_secs: DEFAULT_QA_TIMEOUT_SECS,
            worker_timeout_secs: DEFAULT_WORKER_TIMEOUT_SECS,
            worker: WorkerConfig::default(),
            convergence_n_rounds: DEFAULT_CONVERGENCE_N_ROUNDS,
        }
    }
}

fn default_convergence_n_rounds() -> u32 {
    DEFAULT_CONVERGENCE_N_ROUNDS
}

impl OrchestratorConfig {
    /// Load the config from `<orchestrator_dir>/config.toml`.
    ///
    /// An **absent** file is not an error — it yields the all-defaults config
    /// (REQ-13: a fresh repo runs the pump with no config authored). A file
    /// that exists but cannot be read or parsed is a typed [`ConfigError`].
    pub fn load(orchestrator_dir: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = orchestrator_dir.as_ref().join(CONFIG_FILE);
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(OrchestratorConfig::default());
            }
            Err(source) => return Err(ConfigError::Read { path, source }),
        };
        toml::from_str(&content).map_err(|source| ConfigError::Parse { path, source })
    }

    /// The poll interval as a [`Duration`].
    pub fn poll_interval(&self) -> Duration {
        Duration::from_millis(self.poll_interval_ms)
    }

    /// The QA-gate timeout as a [`Duration`].
    pub fn qa_timeout(&self) -> Duration {
        Duration::from_secs(self.qa_timeout_secs)
    }

    /// The per-worker timeout as a [`Duration`].
    pub fn worker_timeout(&self) -> Duration {
        Duration::from_secs(self.worker_timeout_secs)
    }

    /// The worker argv with **only the designated script-path field** resolved
    /// against `root` when it is a relative path, so a config-relative fixture
    /// path works regardless of the cwd the pump runs under. Returns `None` if
    /// the argv is empty (a misconfiguration the pump reports rather than
    /// spawning nothing).
    ///
    /// The designated script field is [`SCRIPT_ARGV_INDEX`] — `argv[1]`, the
    /// argument immediately after the interpreter (`bash <script>`). Only that
    /// one position is rewritten, and only when it is a relative path that
    /// exists under `root`. Every other position — the program name (`argv[0]`,
    /// e.g. `bash`) and any trailing script arguments (`argv[2..]`) — passes
    /// through verbatim, so an incidental argument that merely happens to name an
    /// existing file (e.g. a `--config foo.toml` value) is never silently
    /// rewritten into a path.
    pub fn worker_argv(&self, root: &Path) -> Option<Vec<String>> {
        resolve_script_argv(&self.worker.argv, root)
    }

    /// The Direct Adversary argv with its designated script field resolved
    /// against `root`, mirroring [`worker_argv`](Self::worker_argv). Returns
    /// `None` for an empty argv (a misconfiguration the pump reports rather than
    /// spawning nothing).
    pub fn adversary_argv(&self, root: &Path) -> Option<Vec<String>> {
        resolve_script_argv(&self.worker.adversary_argv, root)
    }
}

/// Resolve the [`SCRIPT_ARGV_INDEX`] script field of `argv` against `root` when
/// it is an existing relative path, leaving every other position verbatim (see
/// [`OrchestratorConfig::worker_argv`] for the rationale). Returns `None` for an
/// empty argv. Shared by the Implementer and Adversary Direct argv resolvers.
fn resolve_script_argv(argv: &[String], root: &Path) -> Option<Vec<String>> {
    if argv.is_empty() {
        return None;
    }
    let mut resolved = argv.to_vec();
    if let Some(script) = resolved.get_mut(SCRIPT_ARGV_INDEX) {
        let candidate = Path::new(script.as_str());
        if candidate.is_relative() && root.join(candidate).exists() {
            *script = root.join(candidate).to_string_lossy().into_owned();
        }
    }
    Some(resolved)
}

fn default_poll_interval_ms() -> u64 {
    DEFAULT_POLL_INTERVAL_MS
}

fn default_max_concurrent_agents() -> u32 {
    DEFAULT_MAX_CONCURRENT_AGENTS
}

fn default_qa_timeout_secs() -> u64 {
    DEFAULT_QA_TIMEOUT_SECS
}

fn default_worker_timeout_secs() -> u64 {
    DEFAULT_WORKER_TIMEOUT_SECS
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_file_is_all_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = OrchestratorConfig::load(dir.path()).expect("absent = defaults");
        assert_eq!(cfg, OrchestratorConfig::default());
        assert_eq!(cfg.poll_interval_ms, DEFAULT_POLL_INTERVAL_MS);
        assert_eq!(cfg.max_concurrent_agents, DEFAULT_MAX_CONCURRENT_AGENTS);
        assert_eq!(cfg.worker.argv[0], "bash");
    }

    #[test]
    fn partial_file_overrides_only_named_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join(CONFIG_FILE),
            "poll_interval_ms = 250\nmax_concurrent_agents = 3\n",
        )
        .expect("write config");
        let cfg = OrchestratorConfig::load(dir.path()).expect("parse partial");
        assert_eq!(cfg.poll_interval_ms, 250);
        assert_eq!(cfg.max_concurrent_agents, 3);
        // Unnamed fields keep their defaults.
        assert_eq!(cfg.qa_timeout_secs, DEFAULT_QA_TIMEOUT_SECS);
        assert_eq!(cfg.worker, WorkerConfig::default());
    }

    #[test]
    fn worker_kind_defaults_to_direct() {
        // Absent config, and a `[worker]` table that names only argv, both keep
        // the dogfood on the Direct path (so AC-11a is unchanged).
        assert_eq!(WorkerConfig::default().kind, WorkerKind::Direct);
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join(CONFIG_FILE),
            "[worker]\nargv = [\"bash\"]\n",
        )
        .expect("write config");
        let cfg = OrchestratorConfig::load(dir.path()).expect("parse");
        assert_eq!(cfg.worker.kind, WorkerKind::Direct);
        assert_eq!(
            cfg.worker.max_turns_implementer,
            DEFAULT_MAX_TURNS_IMPLEMENTER
        );
    }

    #[test]
    fn worker_kind_claude_is_selected_and_turns_override() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join(CONFIG_FILE),
            "[worker]\nkind = \"claude\"\nmax_turns_implementer = 42\n",
        )
        .expect("write config");
        let cfg = OrchestratorConfig::load(dir.path()).expect("parse");
        assert_eq!(cfg.worker.kind, WorkerKind::Claude);
        assert_eq!(cfg.worker.max_turns_implementer, 42);
    }

    #[test]
    fn worker_kind_rejects_unknown_variant() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(CONFIG_FILE), "[worker]\nkind = \"bogus\"\n")
            .expect("write config");
        let err = OrchestratorConfig::load(dir.path()).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn worker_table_overrides_argv() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join(CONFIG_FILE),
            "[worker]\nargv = [\"sh\", \"-c\", \"true\"]\n",
        )
        .expect("write config");
        let cfg = OrchestratorConfig::load(dir.path()).expect("parse worker");
        assert_eq!(cfg.worker.argv, vec!["sh", "-c", "true"]);
    }

    #[test]
    fn malformed_toml_is_a_typed_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join(CONFIG_FILE),
            "poll_interval_ms = \"not a number\"",
        )
        .expect("write config");
        let err = OrchestratorConfig::load(dir.path()).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn unknown_field_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(CONFIG_FILE), "bogus_field = 1\n").expect("write");
        let err = OrchestratorConfig::load(dir.path()).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn worker_argv_resolves_relative_path_under_root() {
        let root = tempfile::tempdir().expect("root");
        std::fs::create_dir_all(root.path().join("tests/fixtures")).expect("mkdir");
        let script = root.path().join("tests/fixtures/fake-implementer.sh");
        std::fs::write(&script, "#!/usr/bin/env bash\n").expect("write script");

        let cfg = OrchestratorConfig::default();
        let argv = cfg.worker_argv(root.path()).expect("non-empty");
        assert_eq!(argv[0], "bash", "program name passes through");
        assert_eq!(
            argv[1],
            script.to_string_lossy(),
            "relative existing path is resolved against root"
        );
    }

    #[test]
    fn worker_argv_only_resolves_designated_script_field() {
        let root = tempfile::tempdir().expect("root");
        // An incidental argument that happens to name an existing file under
        // root — NOT the script field. It must pass through untouched (#6).
        std::fs::write(root.path().join("config.toml"), "x = 1\n").expect("write config.toml");
        // The real script at the designated argv[1] position.
        std::fs::create_dir_all(root.path().join("tests")).expect("mkdir");
        std::fs::write(root.path().join("tests/w.sh"), "#!/bin/sh\n").expect("write script");

        let cfg = OrchestratorConfig {
            worker: WorkerConfig {
                argv: vec![
                    "bash".to_owned(),
                    "tests/w.sh".to_owned(),
                    "--config".to_owned(),
                    "config.toml".to_owned(),
                ],
                ..WorkerConfig::default()
            },
            ..OrchestratorConfig::default()
        };
        let argv = cfg.worker_argv(root.path()).expect("non-empty");
        assert_eq!(argv[0], "bash", "program name untouched");
        assert_eq!(
            argv[1],
            root.path().join("tests/w.sh").to_string_lossy(),
            "the designated script field is resolved against root"
        );
        assert_eq!(argv[2], "--config", "flag passes through");
        assert_eq!(
            argv[3], "config.toml",
            "an incidental existing-file argument must NOT be rewritten (#6)"
        );
    }

    #[test]
    fn empty_worker_argv_is_none() {
        let cfg = OrchestratorConfig {
            worker: WorkerConfig {
                argv: Vec::new(),
                ..WorkerConfig::default()
            },
            ..OrchestratorConfig::default()
        };
        assert!(cfg.worker_argv(Path::new("/repo")).is_none());
    }
}
