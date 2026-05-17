//! The [`CrosslinkRepo`] handle and every adapter operation.
//!
//! crosslink's library API is synchronous and `anyhow`-based; this module is
//! the only place that names crosslink types. Each operation opens a fresh
//! `crosslink::db::Database` (cheap, and what crosslink's own CLI does) so the
//! handle itself holds no database connection and stays `Send + Sync`.

use std::path::{Path, PathBuf};

use crosslink::db::Database;
use crosslink::shared_writer::SharedWriter;

use crate::error::{CrosslinkError, Result};

/// Adapter-owned snapshot of a crosslink issue.
///
/// A plain data type with no crosslink types in it, so the orchestrator can
/// hold issues without linking crosslink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueInfo {
    /// Numeric issue id.
    pub id: i64,
    /// Issue title.
    pub title: String,
    /// Issue description / body, if any.
    pub description: Option<String>,
    /// Status — `open`, `closed`, or `archived`.
    pub status: String,
    /// Priority — `low`, `medium`, `high`, or `critical`.
    pub priority: String,
    /// Parent issue id, if this issue has one.
    pub parent_id: Option<i64>,
    /// Labels attached to the issue.
    pub labels: Vec<String>,
}

/// A handle to a crosslink-tracked repository.
///
/// Construct with [`CrosslinkRepo::discover`] or [`CrosslinkRepo::open`], then
/// call the adapter operations. The handle is just the path to the repo's
/// `.crosslink/` directory.
#[derive(Debug, Clone)]
pub struct CrosslinkRepo {
    /// Absolute path to the repository's `.crosslink/` directory.
    crosslink_dir: PathBuf,
}

impl CrosslinkRepo {
    /// Locate the crosslink repository containing the current directory.
    ///
    /// Walks up from the current directory looking for a `.crosslink/`
    /// directory, falling back to the main-repo root for git worktrees.
    pub fn discover() -> Result<Self> {
        let start = std::env::current_dir().map_err(|source| CrosslinkError::Read {
            operation: "determine current directory".to_owned(),
            source: Box::new(source),
        })?;
        let mut cursor: &Path = &start;
        loop {
            let candidate = cursor.join(".crosslink");
            if candidate.is_dir() {
                return Ok(Self {
                    crosslink_dir: candidate,
                });
            }
            match cursor.parent() {
                Some(parent) => cursor = parent,
                None => break,
            }
        }
        // git-worktree case: the `.crosslink/` lives in the main repo root.
        if let Some(main_root) = crosslink::utils::resolve_main_repo_root(&start) {
            let candidate = main_root.join(".crosslink");
            if candidate.is_dir() {
                return Ok(Self {
                    crosslink_dir: candidate,
                });
            }
        }
        Err(CrosslinkError::NotARepository)
    }

    /// Open the crosslink repository rooted at `repo_root` (the directory that
    /// directly contains `.crosslink/`).
    pub fn open(repo_root: impl AsRef<Path>) -> Result<Self> {
        let crosslink_dir = repo_root.as_ref().join(".crosslink");
        if !crosslink_dir.is_dir() {
            return Err(CrosslinkError::NotARepository);
        }
        Ok(Self { crosslink_dir })
    }

    /// Read issue `id`, including its labels.
    pub fn read_issue(&self, id: i64) -> Result<IssueInfo> {
        let db = self.db()?;
        let issue = self.require_issue(&db, id)?;
        let labels = db.get_labels(id).map_err(|source| CrosslinkError::Read {
            operation: format!("read labels of issue #{id}"),
            source: source.into(),
        })?;
        Ok(IssueInfo {
            id: issue.id,
            title: issue.title,
            description: issue.description,
            status: issue.status.as_str().to_owned(),
            priority: issue.priority.as_str().to_owned(),
            parent_id: issue.parent_id,
            labels,
        })
    }

    /// Add a comment to issue `issue_id` and return the new comment's id.
    ///
    /// `kind` must be a crosslink comment kind (note, plan, decision,
    /// observation, blocker, resolution, result, handoff, human, intervention,
    /// system); an unknown kind is rejected with
    /// [`CrosslinkError::InvalidCommentKind`].
    ///
    /// crosslink's comment table has no role/author column on the direct-write
    /// path, so `role_metadata` — when given — is recorded as a leading marker
    /// line (`[role]`) in the comment body rather than a structured field.
    ///
    /// The write goes through crosslink's `SharedWriter` when the repository is
    /// in multi-agent (hub) mode and directly to the database otherwise, which
    /// is exactly the branch crosslink's own `comment` command takes — a direct
    /// write in hub mode would be lost to the next hydration.
    pub fn comment_write(
        &self,
        issue_id: i64,
        kind: &str,
        body: &str,
        role_metadata: Option<&str>,
    ) -> Result<i64> {
        if !crosslink::issue_file::validate_comment_kind(kind) {
            return Err(CrosslinkError::InvalidCommentKind {
                kind: kind.to_owned(),
            });
        }
        let db = self.db()?;
        self.require_issue(&db, issue_id)?;
        let content = match role_metadata {
            Some(role) => format!("[{role}]\n\n{body}"),
            None => body.to_owned(),
        };
        let writer = self.shared_writer()?;
        let outcome = match &writer {
            Some(writer) => writer.add_comment(&db, issue_id, &content, kind),
            None => db.add_comment(issue_id, &content, kind),
        };
        outcome.map_err(|source| CrosslinkError::Write {
            operation: format!("add `{kind}` comment to issue #{issue_id}"),
            source: source.into(),
        })
    }

    /// Attach label `name` to issue `id`. Returns `true` if the label was
    /// newly added, `false` if it was already present.
    pub fn label_add(&self, id: i64, name: &str) -> Result<bool> {
        let db = self.db()?;
        self.require_issue(&db, id)?;
        let writer = self.shared_writer()?;
        let outcome = match &writer {
            Some(writer) => writer.add_label(&db, id, name),
            None => db.add_label(id, name),
        };
        outcome.map_err(|source| CrosslinkError::Write {
            operation: format!("add label `{name}` to issue #{id}"),
            source: source.into(),
        })
    }

    /// Remove label `name` from issue `id`. Returns `true` if the label was
    /// present and removed, `false` if it was not attached.
    pub fn label_remove(&self, id: i64, name: &str) -> Result<bool> {
        let db = self.db()?;
        self.require_issue(&db, id)?;
        let writer = self.shared_writer()?;
        let outcome = match &writer {
            Some(writer) => writer.remove_label(&db, id, name),
            None => db.remove_label(id, name),
        };
        outcome.map_err(|source| CrosslinkError::Write {
            operation: format!("remove label `{name}` from issue #{id}"),
            source: source.into(),
        })
    }

    /// Sign `payload` (a set of key/value fields) under `namespace`, returning
    /// the base64 signature.
    ///
    /// The fields are canonicalized (sorted, `key=value` lines) before signing,
    /// matching crosslink's own signing scheme. Note that crosslink performs
    /// the signature with an `ssh-keygen` subprocess internally — this adapter
    /// itself shells out to nothing.
    pub fn sign(&self, payload: &[(&str, &str)], namespace: &str) -> Result<String> {
        let (key_path, _fingerprint) = self.signing_key()?;
        let canonical = crosslink::signing::canonicalize_for_signing(payload);
        crosslink::signing::sign_content(&key_path, &canonical, namespace).map_err(|source| {
            CrosslinkError::Sign {
                source: source.into(),
            }
        })
    }

    /// Verify that a usable signing key is configured and present, returning
    /// its fingerprint.
    ///
    /// This does **not** generate a key — provisioning an agent identity is a
    /// deliberate `crosslink` setup step, not a side effect of an orchestrator
    /// call. It fails with [`CrosslinkError::IdentityUnavailable`] when the
    /// agent identity or its key file is missing.
    pub fn key_ensure_loaded(&self) -> Result<String> {
        let (_key_path, fingerprint) = self.signing_key()?;
        Ok(fingerprint)
    }

    /// Open a fresh database handle on `.crosslink/issues.db`.
    fn db(&self) -> Result<Database> {
        let path = self.crosslink_dir.join("issues.db");
        Database::open(&path).map_err(|source| CrosslinkError::DatabaseOpen {
            path,
            source: source.into(),
        })
    }

    /// Fetch an issue, mapping a "not found" failure to the dedicated
    /// [`CrosslinkError::IssueNotFound`] so callers can branch on it.
    fn require_issue(&self, db: &Database, id: i64) -> Result<crosslink::models::Issue> {
        db.require_issue(id).map_err(|source| {
            if source.to_string().contains("not found") {
                CrosslinkError::IssueNotFound { id }
            } else {
                CrosslinkError::Read {
                    operation: format!("read issue #{id}"),
                    source: source.into(),
                }
            }
        })
    }

    /// Build the `SharedWriter` for this repository — `Some` in multi-agent
    /// (hub) mode, `None` for a single-agent / local-only repository.
    fn shared_writer(&self) -> Result<Option<SharedWriter>> {
        SharedWriter::new(&self.crosslink_dir).map_err(|source| CrosslinkError::Write {
            operation: "initialize crosslink shared writer".to_owned(),
            source: source.into(),
        })
    }

    /// Resolve the agent's ssh signing key to `(absolute path, fingerprint)`.
    fn signing_key(&self) -> Result<(PathBuf, String)> {
        let agent = crosslink::identity::AgentConfig::load(&self.crosslink_dir)
            .map_err(|source| CrosslinkError::Read {
                operation: "load crosslink agent identity".to_owned(),
                source: source.into(),
            })?
            .ok_or_else(|| CrosslinkError::IdentityUnavailable {
                detail: "no `.crosslink/agent.json` — the repository has no agent identity"
                    .to_owned(),
            })?;
        let key_relative =
            agent
                .ssh_key_path
                .ok_or_else(|| CrosslinkError::IdentityUnavailable {
                    detail: "the agent identity records no `ssh_key_path`".to_owned(),
                })?;
        let key_path = self.crosslink_dir.join(&key_relative);
        if !key_path.is_file() {
            return Err(CrosslinkError::IdentityUnavailable {
                detail: format!("ssh signing key `{}` is missing", key_path.display()),
            });
        }
        let fingerprint = agent
            .ssh_fingerprint
            .unwrap_or_else(|| "unknown".to_owned());
        Ok((key_path, fingerprint))
    }
}
