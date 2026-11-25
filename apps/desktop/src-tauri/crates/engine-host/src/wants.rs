//! Answers to module requests for project data.

use sitecmd_protocol::database_env::is_private_dotenv;
use sitecmd_protocol::engine_abi::{
    AuditFileKind, AuditFileOffer, BodyRef, DatabaseTargetOffer, EntryKind, FileLocation,
    FileOfferId, Listing, Refusal, RelPath, SchemaSnapshot, SessionBegin, Want, WantAnswer,
    AUDIT_MAX_FILES,
};
use std::{
    collections::{HashMap, HashSet},
    fmt, io,
};

/// Maximum dependency manifest or lockfile size accepted by Updates and Code Scan.
pub const MAX_DEPENDENCY_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Exact basenames read by Code Scan's npm workspace and lockfile readers at any depth.
/// These reads use the dependency cap and do not spend the host's source text budget.
const DEPENDENCY_FILE_NAMES: &[&str] = &[
    ".npmrc",
    "package.json",
    "pnpm-workspace.yaml",
    "pnpm-workspace.yml",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
];

pub trait HostIo {
    /// Read up to one byte beyond the limit to detect oversized files.
    fn read(&self, path: &RelPath, limit: u64) -> io::Result<Vec<u8>>;
    /// Read an offer using the host's saved native path.
    fn read_offer(&self, _id: FileOfferId, _limit: u64) -> io::Result<Vec<u8>> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Resolve index membership using the native names behind the offers.
    fn git_tracked_offers(&self, _ids: &[FileOfferId]) -> io::Result<Vec<FileOfferId>> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Return present paths from a metadata-only probe under the selected root.
    fn path_presence(&self, _path: &RelPath) -> PathPresence {
        PathPresence::Absent
    }

    fn git_tracked(&self, paths: &[RelPath]) -> io::Result<Vec<RelPath>>;
    fn database_schema(&self, offer: &DatabaseTargetOffer) -> Option<SchemaSnapshot>;
}

pub enum PathPresence {
    Absent,
    Present,
    Symlink,
}

pub struct ReadBudget {
    remaining: u64,
    per_file: u64,
    answered: HashSet<FileLocation>,
    presence: HashSet<RelPath>,
    tracked: HashSet<RelPath>,
    tracked_offers: HashSet<FileOfferId>,
    databases: HashSet<String>,
    analysis_reads: Option<HashMap<FileLocation, Vec<u8>>>,
}

impl ReadBudget {
    pub fn new(total: u64, per_file: u64) -> Self {
        Self {
            remaining: total,
            per_file: per_file.min(u64::from(u32::MAX)),
            answered: HashSet::new(),
            presence: HashSet::new(),
            tracked: HashSet::new(),
            tracked_offers: HashSet::new(),
            databases: HashSet::new(),
            analysis_reads: None,
        }
    }

    /// Keep the bytes from reads charged to this audit for the file analysis workers.
    pub fn retain_analysis_reads(&mut self) {
        self.analysis_reads = Some(HashMap::new());
    }

    /// Move the existing read snapshots to the workers without opening any file again.
    pub fn take_analysis_reads(&mut self) -> HashMap<FileLocation, Vec<u8>> {
        self.analysis_reads.take().unwrap_or_default()
    }

    /// First answers and refusals of eligible inputs both advance the session.
    pub fn completed_requests(&self) -> usize {
        self.answered.len()
            + self.presence.len()
            + self.tracked.len()
            + self.tracked_offers.len()
            + self.databases.len()
    }
}

pub struct HostAnswer(WantAnswer, Vec<u8>);

impl HostAnswer {
    pub fn into_parts(self) -> (WantAnswer, Vec<u8>) {
        (self.0, self.1)
    }
}

impl fmt::Debug for HostAnswer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.0 {
            WantAnswer::File { .. } => "file",
            WantAnswer::AnalyzeFiles { .. } => "analyze_files",
            WantAnswer::GitTracked { .. } => "git_tracked",
            WantAnswer::GitTrackedOffers { .. } => "git_tracked_offers",
            WantAnswer::PathPresence { .. } => "path_presence",
            WantAnswer::DatabaseSchema { .. } => "database_schema",
            WantAnswer::Refused { .. } => "refused",
        };
        formatter
            .debug_struct("HostAnswer")
            .field("kind", &kind)
            .field("body_len", &self.1.len())
            .finish()
    }
}

/// Reject components that can resolve to a different name or a device on Windows.
pub fn is_portable_path(path: &RelPath) -> bool {
    path.as_str().split('/').all(|part| {
        if part.ends_with(['.', ' ']) || part.contains(['<', '>', '"', '|', '?', '*']) {
            return false;
        }
        let stem = part.split('.').next().unwrap_or(part).trim_end_matches(' ');
        let name = stem.to_ascii_uppercase();
        !matches!(
            name.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) && !name
            .strip_prefix("COM")
            .or_else(|| name.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                matches!(
                    suffix,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
    })
}

pub fn answer(
    request: &SessionBegin,
    budget: &mut ReadBudget,
    io: &dyn HostIo,
    want: &Want,
) -> HostAnswer {
    let databases = if request.options.inspect_local_databases {
        request.options.databases.as_slice()
    } else {
        &[]
    };
    answer_for_inventory(
        &request.listing,
        &request.host.files,
        databases,
        budget,
        io,
        want,
    )
}

fn answer_for_inventory(
    listing: &Listing,
    files: &[AuditFileOffer],
    databases: &[DatabaseTargetOffer],
    budget: &mut ReadBudget,
    io: &dyn HostIo,
    want: &Want,
) -> HostAnswer {
    match answer_want(listing, files, databases, budget, io, want) {
        Ok(answer) => answer,
        Err(reason) => HostAnswer(WantAnswer::Refused { reason }, Vec::new()),
    }
}

fn answer_want(
    listing: &Listing,
    files: &[AuditFileOffer],
    databases: &[DatabaseTargetOffer],
    budget: &mut ReadBudget,
    io: &dyn HostIo,
    want: &Want,
) -> Result<HostAnswer, Refusal> {
    let metadata = match want {
        Want::AnalyzeFiles { .. } => return Err(Refusal::Unavailable),
        Want::File { path } => {
            if is_private_dotenv(file_name(path.as_str()))
                || (cfg!(windows) && !is_portable_path(path))
            {
                return Err(Refusal::NotListed);
            }
            let entry = listing
                .get(path)
                .filter(|entry| entry.kind == EntryKind::File)
                .ok_or(Refusal::NotListed)?;
            let location = FileLocation::Listed(path.clone());
            first_request(&mut budget.answered, location.clone())?;
            return answer_file(
                location,
                path.as_str(),
                entry.size,
                false,
                budget,
                |limit| io.read(path, limit),
            );
        }
        Want::OfferedFile { id } => {
            let offer = file_offer(files, *id).ok_or(Refusal::NotListed)?;
            if is_private_dotenv(file_name(offer.path.as_str())) {
                return Err(Refusal::NotListed);
            }
            let location = FileLocation::Offer { id: *id };
            first_request(&mut budget.answered, location.clone())?;
            if offer.kind == (AuditFileKind::DatabaseLocation {}) {
                return Err(Refusal::Unavailable);
            }
            return answer_file(
                location,
                offer.path.as_str(),
                offer.size,
                offer.kind == (AuditFileKind::Dependency {}),
                budget,
                |limit| io.read_offer(*id, limit),
            );
        }
        Want::GitTracked { paths } => {
            let available = listing
                .entries
                .iter()
                .filter(|entry| entry.kind == EntryKind::File)
                .take(paths.len())
                .count();
            if paths.len() > available {
                return Err(Refusal::NotListed);
            }
            let mut requested = HashSet::new();
            let mut unique = Vec::new();
            for path in paths {
                if (cfg!(windows) && !is_portable_path(path)) || !listing.is_file(path) {
                    return Err(Refusal::NotListed);
                }
                if requested.insert(path) {
                    unique.push(path.clone());
                }
            }
            unique.retain(|path| budget.tracked.insert(path.clone()));
            if unique.is_empty() {
                return Err(Refusal::AlreadyAnswered);
            }
            let mut requested: HashSet<_> = unique.iter().collect();
            let mut tracked = io.git_tracked(&unique).map_err(|_| Refusal::Unavailable)?;
            tracked.retain(|path| requested.remove(path));
            WantAnswer::GitTracked { tracked }
        }
        Want::GitTrackedOffers { ids } => {
            if ids.len() > files.len() {
                return Err(Refusal::NotListed);
            }
            let mut requested = HashSet::new();
            let mut unique = Vec::new();
            for &id in ids {
                if !file_offer(files, id).is_some_and(AuditFileOffer::is_trackable) {
                    return Err(Refusal::NotListed);
                }
                if requested.insert(id) {
                    unique.push(id);
                }
            }
            unique.retain(|id| budget.tracked_offers.insert(*id));
            if unique.is_empty() {
                return Err(Refusal::AlreadyAnswered);
            }
            let mut requested: HashSet<_> = unique.iter().copied().collect();
            let mut ids = io
                .git_tracked_offers(&unique)
                .map_err(|_| Refusal::Unavailable)?;
            ids.retain(|id| requested.remove(id));
            WantAnswer::GitTrackedOffers { ids }
        }
        Want::PathPresence { paths } => {
            if cfg!(windows) && paths.iter().any(|path| !is_portable_path(path)) {
                return Err(Refusal::NotListed);
            }
            if paths.iter().any(|path| budget.presence.contains(path)) {
                return Err(Refusal::AlreadyAnswered);
            }
            if paths.len() > AUDIT_MAX_FILES - budget.presence.len() {
                return Err(Refusal::BudgetSpent);
            }
            let unique: HashSet<_> = paths.iter().collect();
            if unique.len() != paths.len() || paths.is_empty() {
                return Err(Refusal::AlreadyAnswered);
            }
            let mut present = Vec::new();
            let mut symlinks = Vec::new();
            for path in paths {
                budget.presence.insert(path.clone());
                match io.path_presence(path) {
                    PathPresence::Absent => {}
                    PathPresence::Present => present.push(path.clone()),
                    PathPresence::Symlink => symlinks.push(path.clone()),
                }
            }
            WantAnswer::PathPresence { present, symlinks }
        }
        Want::DatabaseSchema { target } => {
            let offer = databases
                .iter()
                .find(|offer| !target.is_empty() && offer.id == *target)
                .ok_or(Refusal::NotListed)?;
            first_request(&mut budget.databases, target.clone())?;
            let snapshot = io.database_schema(offer).ok_or(Refusal::Unavailable)?;
            WantAnswer::DatabaseSchema { snapshot }
        }
    };
    Ok(HostAnswer(metadata, Vec::new()))
}

fn first_request<T: Eq + std::hash::Hash>(
    answered: &mut HashSet<T>,
    key: T,
) -> Result<(), Refusal> {
    if answered.insert(key) {
        Ok(())
    } else {
        Err(Refusal::AlreadyAnswered)
    }
}

fn file_offer(files: &[AuditFileOffer], id: FileOfferId) -> Option<&AuditFileOffer> {
    files.get(id as usize).filter(|offer| offer.id == id)
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn answer_file(
    location: FileLocation,
    path: &str,
    size: u64,
    dependency_offer: bool,
    budget: &mut ReadBudget,
    read: impl FnOnce(u64) -> io::Result<Vec<u8>>,
) -> Result<HostAnswer, Refusal> {
    let name = file_name(path);
    let dependency = dependency_offer || DEPENDENCY_FILE_NAMES.contains(&name);
    let cap = if dependency {
        MAX_DEPENDENCY_FILE_BYTES
    } else {
        budget.per_file
    };
    if size > cap {
        return Err(Refusal::TooLarge);
    }
    if !dependency && (budget.remaining == 0 || size > budget.remaining) {
        return Err(Refusal::BudgetSpent);
    }

    let limit = if dependency {
        cap
    } else {
        cap.min(budget.remaining)
    };
    let bytes = read(limit).map_err(|_| Refusal::Unavailable)?;
    let len = bytes.len() as u64;
    if len > cap {
        return Err(Refusal::TooLarge);
    }
    if len != size {
        return Err(Refusal::Unavailable);
    }
    if std::str::from_utf8(&bytes).is_err() {
        return Err(Refusal::NotText);
    }
    if !dependency {
        budget.remaining -= len;
        if let Some(reads) = &mut budget.analysis_reads {
            reads.insert(location, bytes.clone());
        }
    }
    Ok(HostAnswer(
        WantAnswer::File {
            body: BodyRef {
                at: 0,
                len: len as u32,
            },
        },
        bytes,
    ))
}

#[cfg(test)]
#[path = "wants_tests.rs"]
mod tests;
