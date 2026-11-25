//! Session, result, and metadata wire types.

use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::code_domain::CodeScanDomain;
use crate::code_scan::CodeIssue;
use crate::manifest::ManifestDigest;
use crate::score::{CategoryScore, ScoreSnapshot};
use crate::sync::wire::CheckId;
use crate::vocab::{Category, CheckResult, IssueConfidence, Severity};

pub use super::fixes::{
    BriefTarget, BriefTargetLocation, FixPlan, FixTarget, FixTextTarget, FixUnavailable, FixerInfo,
    Patch,
};
use super::frame::BodyRef;
use super::local_site_wire::{category_scores, check_results, ScoreSnapshotWire};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathError;

impl std::fmt::Display for PathError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid relative path")
    }
}

impl std::error::Error for PathError {}

/// Slash-separated path relative to the listing root.
/// The host's listing check handles Windows reserved names and trailing dots.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct RelPath(String);

impl RelPath {
    pub fn parse(raw: &str) -> Result<RelPath, PathError> {
        Self::validate(raw)?;
        Ok(Self(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(raw: &str) -> Result<(), PathError> {
        if raw.contains(['\\', ':'])
            || raw.as_bytes().iter().any(u8::is_ascii_control)
            || raw.split('/').any(|part| matches!(part, "" | "." | ".."))
        {
            return Err(PathError);
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for RelPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::validate(&raw).map_err(serde::de::Error::custom)?;
        Ok(Self(raw))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Dir,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListingEntry {
    pub path: RelPath,
    pub size: u64,
    pub kind: EntryKind,
    pub ignored: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Listing {
    /// Entries sorted by path, with each path occurring once.
    pub entries: Vec<ListingEntry>,
    /// Entries omitted because their paths cannot be represented uniquely.
    pub skipped_paths: u64,
}

impl Listing {
    pub fn get(&self, p: &RelPath) -> Option<&ListingEntry> {
        self.entries
            .binary_search_by(|entry| entry.path.cmp(p))
            .ok()
            .map(|index| &self.entries[index])
    }

    pub fn is_file(&self, p: &RelPath) -> bool {
        self.get(p)
            .is_some_and(|entry| entry.kind == EntryKind::File)
    }

    pub fn is_dir(&self, p: &RelPath) -> bool {
        self.get(p)
            .is_some_and(|entry| entry.kind == EntryKind::Dir)
    }
}

impl<'de> Deserialize<'de> for Listing {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ListingWire {
            entries: Vec<ListingEntry>,
            skipped_paths: u64,
        }

        let ListingWire {
            entries,
            skipped_paths,
        } = ListingWire::deserialize(deserializer)?;
        if entries.windows(2).any(|pair| pair[0].path >= pair[1].path) {
            return Err(serde::de::Error::custom(
                "listing paths must be sorted and unique",
            ));
        }
        Ok(Self {
            entries,
            skipped_paths,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseEngine {
    Postgres,
    Sqlite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseTargetOffer {
    pub id: String,
    pub engine: DatabaseEngine,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaSnapshot {
    pub tables: Vec<String>,
    pub columns: Vec<SchemaColumn>,
    pub indexes: Vec<SchemaIndex>,
    pub foreign_keys: Vec<SchemaForeignKey>,
    pub migration_names: SchemaMigrationNames,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Box<SchemaSource>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaSource {
    /// Display location of a local database artifact or its configuration file.
    pub relative_path: String,
    pub absolute_path: String,
    /// Connection labels without a username, password, or connection string.
    pub database_name: Option<String>,
    pub host: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaMigrationNames {
    /// Applied names when the Prisma migration table exists.
    pub prisma: Option<Vec<String>>,
    /// Applied row count when the Drizzle migration table exists.
    pub drizzle_count: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaColumn {
    pub table: String,
    pub name: String,
    pub not_null: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaIndex {
    pub table: String,
    pub columns: Vec<String>,
    pub unique: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaForeignKey {
    pub table: String,
    pub column: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditOptions {
    pub inspect_local_databases: bool,
    pub databases: Vec<DatabaseTargetOffer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Task {
    Audit {},
    FixPlan { target: FixTarget },
    FixCatalog {},
    FixText { targets: Vec<FixTextTarget> },
    Brief { target: BriefTarget },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionBegin {
    /// Operation the module should perform.
    pub task: Task,
    /// Sorted project inventory, including sizes and ignore state.
    pub listing: Listing,
    /// Opt-ins and opaque database targets available to the module.
    pub options: AuditOptions,
    /// Evaluation time in Unix milliseconds.
    pub now_ms: i64,
    /// Cumulative retained source and configuration byte limit.
    pub text_budget: u64,
    /// Observations that cannot be represented by the listing.
    pub host: AuditHostFacts,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditHostFacts {
    /// Canonical root used for resolving project-relative locations.
    pub root: String,
    /// Host order used by the source-file cap, nearest the root then lexical.
    pub file_order: Vec<RelPath>,
    /// Pruned directory counts and samples.
    pub skipped_scopes: SkippedScopes,
    /// File offers indexed by ID, with the corresponding paths kept by the host.
    pub files: Vec<AuditFileOffer>,
    /// Non-listed path observations used by bounded project metadata probes.
    pub paths: Vec<AuditPathFact>,
    /// Direct child paths in lexical order within each metadata probe directory.
    pub probe_order: Vec<DisplayPath>,
    /// Candidate ancestor directories in nearest-first order, through the Git boundary.
    pub npm_ancestors: Vec<AuditNpmAncestor>,
    /// Whether Git metadata exists at the root.
    pub has_git_entry: bool,
    /// Hook installation state from local Git metadata excluded from the listing.
    pub hooks: AuditHooks,
    /// Key and debug metadata from opted-in dotenv files, whose raw text can contain credentials.
    pub local_env: Vec<AuditEnvFile>,
    /// Redacted target summary from opted-in dotenv values.
    pub remote_database: Option<AuditRemoteDatabase>,
}

/// A display-only path which may contain characters excluded from listing keys.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct DisplayPath(String);

impl DisplayPath {
    pub fn parse(raw: &str) -> Result<Self, PathError> {
        if raw.len() > 4_096 || raw.contains('\0') {
            return Err(PathError);
        }
        Ok(Self(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for DisplayPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Opaque file offer ID, equal to its index in the host's offer list.
pub type FileOfferId = u32;

/// A validated listing key or an opaque reference to an offered file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum FileLocation {
    /// Project-relative listing path.
    Listed(RelPath),
    /// Index into the host's file offers.
    Offer {
        /// ID of the offered file.
        id: FileOfferId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditFileOffer {
    /// Index into the offer list.
    pub id: FileOfferId,
    /// Path for analysis only, relative to the project root.
    pub path: DisplayPath,
    /// File class controlling how the host serves the input.
    pub kind: AuditFileKind,
    /// Observed file size in bytes.
    pub size: u64,
}

impl AuditFileOffer {
    /// Whether the host can check this project file in the Git index.
    pub fn is_trackable(&self) -> bool {
        !matches!(self.kind, AuditFileKind::DatabaseLocation {})
            && !self.path.as_str().starts_with("../")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuditFileKind {
    /// Walked file whose native name has no unique listing key.
    Inventory {
        /// Position among listed and unlisted files in host order.
        walk_index: usize,
        /// Whether Git's ignore rules exclude the file from source analysis.
        ignored: bool,
    },
    /// A fixed dependency file probe under a pruned path or above the root.
    Dependency {},
    /// A bounded project metadata probe under a pruned path.
    Metadata {},
    /// Location of an opted-in database finding outside the listing.
    DatabaseLocation {},
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditPathKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// A symbolic link with an unavailable target or a target outside the project.
    Symlink,
    /// Another present filesystem entry.
    Other,
    /// An entry beneath a symbolic link whose target could not be observed.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPathFact {
    /// Project-relative display path observed by the host.
    pub path: DisplayPath,
    /// Observed filesystem kind.
    pub kind: AuditPathKind,
    /// Whether a directory is safe for in-project metadata discovery.
    pub safe_directory: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditNpmAncestor {
    /// Number of parents above the project root.
    pub levels: u8,
    /// Present dependency names, including lockfiles whose contents are unsupported.
    pub present: Vec<RelPath>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditHooks {
    /// Whether a native Git hooks directory is available.
    pub git_dir: bool,
    /// Names of installed native hook files.
    pub native_hooks: Vec<String>,
    /// Whether Husky's runtime is present.
    pub husky_runtime: bool,
    /// Whether Git has a configured hooks path.
    pub hooks_path_configured: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEnvFile {
    /// Listed dotenv path.
    pub path: RelPath,
    /// Retained bytes charged to the shared text budget.
    pub retained_bytes: u64,
    /// Variable names observed without their values.
    pub keys: Vec<String>,
    /// Whether APP_DEBUG enables debug mode.
    pub app_debug: bool,
    /// One-based line of the APP_DEBUG assignment, when available.
    pub app_debug_line: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRemoteDatabase {
    /// Listed dotenv file which declared the remote target.
    pub path: RelPath,
    /// Redacted human-readable target summary.
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileAnalysisSource {
    pub location: FileLocation,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileAnalysisInput {
    pub path: String,
    pub body: BodyRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalyzeFilesRequest {
    pub files: Vec<FileAnalysisInput>,
    pub context: FileAnalysisContext,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileAnalysisContext {
    /// Controller status keyed by lowercased class basename.
    pub laravel_controllers: BTreeMap<String, LaravelControllerStatus>,
    /// Lowercased paths of route files protected by framework middleware.
    pub laravel_auth_routes: BTreeSet<String>,
    /// Lowercased paths of route manifests parsed by the session.
    pub laravel_parsed_routes: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaravelControllerStatus {
    /// Every reference to the controller requires auth-granting middleware.
    pub auth_protected: bool,
    /// Every unauthenticated reference is throttled.
    pub throttled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileAnalysisResult {
    pub path: String,
    pub issues: Vec<CodeIssue>,
    pub summary: FileSignalSummary,
}

/// Per-file predicates reused during operations analysis.
/// Raw pattern fields remain distinct from combined signals.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSignalSummary {
    pub pattern_registry: bool,
    pub scanner_rule_impl: bool,
    pub route_like: bool,
    pub server_action_like: bool,
    pub uses_env: bool,
    pub uses_llm: bool,
    pub touches_db: bool,
    pub background_jobs: bool,
    pub frontend_supabase: bool,
    pub client_auth: bool,
    pub healthcheck: bool,
    pub error_reporting: bool,
    pub structured_logging: bool,
    pub ai_observability: bool,
    pub feature_flags: bool,
    pub error_boundary: bool,
    pub job_visibility: bool,
    pub job_marker_words: bool,
    pub auth_enforcement: bool,
    pub ai_heavy_marker: bool,
    pub shared_data_layer: bool,
    pub sensitive_handler: bool,
    pub write_handler: bool,
    pub inline_rust_tests: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Want {
    AnalyzeFiles {
        files: Vec<FileAnalysisSource>,
        context: FileAnalysisContext,
    },
    File {
        path: RelPath,
    },
    /// Read a host-offered file by its opaque ID.
    OfferedFile {
        /// Index of the offered file.
        id: FileOfferId,
    },
    GitTracked {
        paths: Vec<RelPath>,
    },
    /// Query Git index membership for offered project files.
    GitTrackedOffers {
        /// IDs of inventory files whose tracking status is needed.
        ids: Vec<FileOfferId>,
    },
    /// Query presence of declared Rust targets under the project root.
    PathPresence {
        /// Validated project-relative paths to probe.
        paths: Vec<RelPath>,
    },
    DatabaseSchema {
        target: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    NotListed,
    TooLarge,
    NotText,
    BudgetSpent,
    /// This input was already requested in the current session.
    AlreadyAnswered,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WantAnswer {
    AnalyzeFiles {
        files: Vec<FileAnalysisResult>,
    },
    File {
        body: BodyRef,
    },
    GitTracked {
        tracked: Vec<RelPath>,
    },
    /// The offered project files found in the Git index.
    GitTrackedOffers {
        /// Tracked file IDs drawn from the request.
        ids: Vec<FileOfferId>,
    },
    /// Presence observations for declared Rust targets.
    PathPresence {
        /// Present project-relative paths drawn from the request.
        present: Vec<RelPath>,
        /// Requested paths with a symbolic link at any component.
        symlinks: Vec<RelPath>,
    },
    DatabaseSchema {
        snapshot: SchemaSnapshot,
    },
    Refused {
        reason: Refusal,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionContinue {
    pub answers: Vec<WantAnswer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Step {
    Wants { wants: Vec<Want> },
    Done { done: Done },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Done {
    Audit(AuditReport),
    /// The audit ended without a report, with the reason preserved.
    AuditFailed(AuditFailure),
    FixPlan(FixPlan),
    FixUnavailable(FixUnavailable),
    FixCatalog(Vec<FixerInfo>),
    FixText(Vec<String>),
    Brief(Brief),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditIssue {
    pub rule_id: String,
    /// Finding ID with any offered path omitted.
    pub id: String,
    /// UTF-8 byte offset in the finding ID where the host inserts the offered path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_path_offset: Option<u32>,
    pub check_id: String,
    pub category: String,
    pub title: String,
    pub description: String,
    /// Validated location or opaque file offer resolved by the host.
    pub path: FileLocation,
    pub line: Option<u32>,
    pub severity: Severity,
    pub confidence: IssueConfidence,
    pub why_now: Option<String>,
    pub likely_fix: Option<String>,
    pub verify_hint: Option<String>,
    pub confidence_reason: Option<String>,
    pub fix_prompt: Option<String>,
    /// Redacted by the module, provider keys included, before it answers. The host adds the public log redactor on top.
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditReport {
    pub checked_at: String,
    pub framework: Option<String>,
    pub issue_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub issues: Vec<AuditIssue>,
    pub skipped_scopes: SkippedScopes,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coverage: Vec<AuditFileRefusal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditFileRefusal {
    /// File for which the audit could not obtain text.
    pub path: FileLocation,
    /// Closed reason why the file was skipped.
    pub reason: Refusal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AuditFailure {
    /// The input or an answer did not conform to the session contract.
    InvalidInput,
    /// The caller cancelled the scan.
    Cancelled,
    /// No retained source or project root marker was found.
    NoProject,
    /// Retained configuration exceeded the cumulative budget, in bytes.
    TextBudget(u64),
    /// An analysis failure carrying the same message as the native audit.
    AnalysisFailed(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkippedScopes {
    pub nested_repositories: usize,
    pub gitignored_directories: usize,
    pub sample_names: Vec<String>,
    /// Rules constructs the module omitted by analysis bounds or unsupported syntax.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_blocks_skipped: Option<usize>,
    /// A bounded sample of the omitted rules constructs, worded by the host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_samples: Option<Vec<RuleSkip>>,
}

/// One rules construct the module omitted from analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSkip {
    /// Rules file holding the construct.
    pub path: FileLocation,
    pub line: u32,
    pub column: u32,
    pub reason: RuleSkipReason,
}

/// Closed reason a rules construct was omitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleSkipReason {
    /// Open scopes, including the service and root blocks, passed the limit.
    ScopeLimit {
        limit: u32,
    },
    /// A match path passed the segment limit below the service root.
    PathSegmentLimit {
        limit: u32,
    },
    /// JSON objects, including the document and rules objects, passed the limit.
    JsonNestingLimit {
        limit: u32,
    },
    UnsupportedMatch,
    UnsupportedGrant,
    UnsupportedService,
    AdditionalService,
    UnsupportedBlock,
    UnreadableJson,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Brief {
    pub title: String,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeRuleInfo {
    pub id: String,
    pub title: String,
    pub domain: CodeScanDomain,
    pub default_severity: Option<Severity>,
    /// Canonical check id, as `canonical_code_check_id(id)` gives it.
    pub check_id: String,
    /// The product category the engine's table assigns the rule.
    pub category: Category,
    /// The published description, or None for the default sentence.
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineInfo {
    pub module_version: String,
    pub abi_version: u32,
    pub manifest_digest: ManifestDigest,
    pub code_rules: Vec<CodeRuleInfo>,
    pub local_checks: Vec<CheckId>,
}

impl EngineInfo {
    pub fn code_rule(&self, id: &str) -> Option<&CodeRuleInfo> {
        self.code_rules.iter().find(|rule| rule.id == id)
    }
}

/// One response header name and value, in arrival order.
pub type HeaderLine = (String, String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalSiteRequest {
    pub requested_url: String,
    pub final_url: String,
    pub status: u16,
    pub header_lines: Vec<HeaderLine>,
    pub body: BodyRef,
    pub now_ms: i64,
    /// The Polish scan profile skips the local predeploy registry.
    #[serde(default)]
    pub polish_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub categories: Option<Vec<Category>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalSiteAnswer {
    #[serde(with = "check_results")]
    pub results: Vec<CheckResult>,
    #[serde(with = "ScoreSnapshotWire")]
    pub score: ScoreSnapshot,
    /// `display_category_scores(results, score)`; None when the score can't be shown per category.
    #[serde(with = "category_scores")]
    pub categories: Option<Vec<CategoryScore>>,
    /// Gains calculated in fix rank order and aligned to uncovered failures and warnings in input order.
    pub fix_points: Vec<u32>,
}

/// The entire JSON answer to malformed input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorAnswer {
    pub error: ErrorCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidFrame,
    InvalidRequest,
    InvalidBodyReference,
    Unsupported,
}
