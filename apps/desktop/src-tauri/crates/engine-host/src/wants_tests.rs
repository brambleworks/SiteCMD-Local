use super::*;
use sitecmd_protocol::engine_abi::{BodyRef, DatabaseEngine, EntryKind, ListingEntry, Refusal};
use std::cell::RefCell;

const BODY: &[u8] = b"private source marker";

#[derive(Debug, PartialEq, Eq)]
enum Call {
    Read(RelPath, u64),
    Offer(FileOfferId, u64),
    Git(Vec<RelPath>),
    Database(String),
    Presence(RelPath),
}

#[derive(Default)]
struct RecordingIo {
    calls: RefCell<Vec<Call>>,
    bytes: Option<Vec<u8>>,
}

impl HostIo for RecordingIo {
    fn read(&self, path: &RelPath, limit: u64) -> io::Result<Vec<u8>> {
        self.calls
            .borrow_mut()
            .push(Call::Read(path.clone(), limit));
        self.bytes
            .clone()
            .ok_or_else(|| io::Error::other("private source marker: /outside/project"))
    }

    fn read_offer(&self, id: FileOfferId, limit: u64) -> io::Result<Vec<u8>> {
        self.calls.borrow_mut().push(Call::Offer(id, limit));
        self.bytes.clone().ok_or(io::ErrorKind::NotFound.into())
    }

    fn git_tracked(&self, paths: &[RelPath]) -> io::Result<Vec<RelPath>> {
        self.calls.borrow_mut().push(Call::Git(paths.to_vec()));
        Ok(paths.to_vec())
    }

    fn path_presence(&self, path: &RelPath) -> PathPresence {
        self.calls.borrow_mut().push(Call::Presence(path.clone()));
        PathPresence::Absent
    }

    fn database_schema(&self, offer: &DatabaseTargetOffer) -> Option<SchemaSnapshot> {
        self.calls
            .borrow_mut()
            .push(Call::Database(offer.id.clone()));
        Some(SchemaSnapshot::default())
    }
}

fn rel(path: &str) -> RelPath {
    RelPath::parse(path).unwrap()
}

fn file_want(path: &str) -> Want {
    Want::File { path: rel(path) }
}

fn listing(path: &str, size: u64, kind: EntryKind) -> Listing {
    Listing {
        entries: vec![ListingEntry {
            path: rel(path),
            size,
            kind,
            ignored: false,
        }],
        skipped_paths: 0,
    }
}

fn refuse(answer: HostAnswer, reason: Refusal) {
    assert_eq!(
        answer.into_parts(),
        (WantAnswer::Refused { reason }, vec![])
    );
}

fn assert_pre_read_refusal(
    listing: &Listing,
    budget: &mut ReadBudget,
    want: &Want,
    reason: Refusal,
) {
    let io = RecordingIo::default();
    refuse(
        answer_for_inventory(listing, &[], &[], budget, &io, want),
        reason,
    );
    assert!(io.calls.into_inner().is_empty());
}

fn assert_invalid_wire_path(io: &RecordingIo, wire: &str) {
    let listing = Listing::default();
    let mut budget = ReadBudget::new(100, 50);
    let decoded = serde_json::from_str::<Want>(wire)
        .map(|want| answer_for_inventory(&listing, &[], &[], &mut budget, io, &want));
    assert!(decoded.is_err());
    assert!(io.calls.borrow().is_empty());
}

#[test]
fn a_parent_path_want_never_reads() {
    // The module reading outside the project.
    let io = RecordingIo::default();
    assert_invalid_wire_path(&io, r#"{"kind":"file","path":"../x"}"#);
}

#[test]
fn an_absolute_path_want_never_reads() {
    // The module reading outside the project.
    let io = RecordingIo::default();
    assert_invalid_wire_path(&io, r#"{"kind":"file","path":"/x"}"#);
}

#[test]
fn an_unlisted_path_answers_not_listed() {
    // The module reading outside the project.
    assert_pre_read_refusal(
        &Listing::default(),
        &mut ReadBudget::new(0, 0),
        &file_want("private.txt"),
        Refusal::NotListed,
    );
}

#[test]
fn a_directory_want_never_reads() {
    // The module reading outside the project.
    assert_pre_read_refusal(
        &listing("src", 100, EntryKind::Dir),
        &mut ReadBudget::new(0, 0),
        &file_want("src"),
        Refusal::NotListed,
    );
}

#[cfg(windows)]
#[test]
fn device_names_and_normalized_paths_never_read_even_if_listed() {
    // The module reading outside the project.
    for path in [
        "a/NUL.txt",
        "CONIN$",
        "a/lpt¹.md",
        "safe.",
        "dir /file",
        "a?",
    ] {
        assert_pre_read_refusal(
            &listing(path, 0, EntryKind::File),
            &mut ReadBudget::new(10, 10),
            &file_want(path),
            Refusal::NotListed,
        );
    }
}

#[test]
fn a_file_over_the_cap_answers_too_large() {
    // The module reading outside the project.
    assert_pre_read_refusal(
        &listing("app.rs", 51, EntryKind::File),
        &mut ReadBudget::new(0, 50),
        &file_want("app.rs"),
        Refusal::TooLarge,
    );
}

#[test]
fn a_large_package_lock_is_answered_without_spending_the_text_budget() {
    // Bug: The source file cap or spent text budget can hide a readable lockfile.
    let bytes = vec![b' '; 1_500_000];
    let io = RecordingIo {
        bytes: Some(bytes.clone()),
        ..Default::default()
    };
    let mut budget = ReadBudget::new(0, 1_000_000);
    let path = "package-lock.json";
    let size = bytes.len() as u32;
    let answer = answer_for_inventory(
        &listing(path, u64::from(size), EntryKind::File),
        &[],
        &[],
        &mut budget,
        &io,
        &file_want(path),
    );
    let (answer, body) = answer.into_parts();
    assert_eq!(
        answer,
        WantAnswer::File {
            body: BodyRef { at: 0, len: size }
        }
    );
    assert!(body == bytes);
    assert_eq!(
        io.calls.into_inner(),
        [Call::Read(rel(path), 16 * 1024 * 1024)]
    );
}

#[test]
fn a_large_source_file_still_answers_too_large() {
    // Bug: Extending the lockfile cap to source lets an oversized source file through.
    let path = "src/package-lock.json.ts";
    assert_pre_read_refusal(
        &listing(path, 1_000_001, EntryKind::File),
        &mut ReadBudget::new(64_000_000, 1_000_000),
        &file_want(path),
        Refusal::TooLarge,
    );
}

#[test]
fn a_dependency_file_over_16_mib_answers_too_large() {
    // Bug: Exempting lockfiles from the text budget can drop their per-file cap.
    let path = "package-lock.json";
    assert_pre_read_refusal(
        &listing(path, 16 * 1024 * 1024 + 1, EntryKind::File),
        &mut ReadBudget::new(64_000_000, 1_000_000),
        &file_want(path),
        Refusal::TooLarge,
    );
}

#[test]
fn a_nested_lockfile_uses_the_basename_and_leaves_the_text_budget_intact() {
    // Bug: Checking the whole path can reject a lockfile beside a nested manifest.
    let path = "src/package-lock.json";
    let size = 1_500_000;
    let io = RecordingIo {
        bytes: Some(vec![b' '; size as usize]),
        ..Default::default()
    };
    let mut budget = ReadBudget::new(100, 1_000_000);
    let (answer, bytes) = answer_for_inventory(
        &listing(path, u64::from(size), EntryKind::File),
        &[],
        &[],
        &mut budget,
        &io,
        &file_want(path),
    )
    .into_parts();
    assert_eq!(
        answer,
        WantAnswer::File {
            body: BodyRef { at: 0, len: size }
        }
    );
    assert_eq!(bytes.len(), size as usize);
    assert_eq!(budget.remaining, 100);
    assert_eq!(
        io.calls.into_inner(),
        [Call::Read(rel(path), 16 * 1024 * 1024)]
    );
}

#[test]
fn a_spent_budget_answers_budget_spent() {
    // The module reading outside the project.
    assert_pre_read_refusal(
        &listing("app.rs", 1, EntryKind::File),
        &mut ReadBudget::new(0, 50),
        &file_want("app.rs"),
        Refusal::BudgetSpent,
    );
    assert_pre_read_refusal(
        &listing("empty.rs", 0, EntryKind::File),
        &mut ReadBudget::new(0, 50),
        &file_want("empty.rs"),
        Refusal::BudgetSpent,
    );
}

#[test]
fn an_unoffered_database_answers_not_listed() {
    // The module reading outside the project.
    assert_pre_read_refusal(
        &Listing::default(),
        &mut ReadBudget::new(100, 50),
        &Want::DatabaseSchema {
            target: "unknown".into(),
        },
        Refusal::NotListed,
    );
}

#[test]
fn database_wants_are_refused_when_inspection_is_disabled() {
    // A stale offer can bypass the local database opt-in at answer time.
    let request = SessionBegin {
        task: sitecmd_protocol::engine_abi::Task::Audit {},
        listing: Listing::default(),
        options: sitecmd_protocol::engine_abi::AuditOptions {
            inspect_local_databases: false,
            databases: vec![DatabaseTargetOffer {
                id: "db-1".into(),
                engine: DatabaseEngine::Sqlite,
            }],
        },
        now_ms: 0,
        text_budget: 0,
        host: Default::default(),
    };
    let io = RecordingIo::default();
    refuse(
        answer(
            &request,
            &mut ReadBudget::new(0, 0),
            &io,
            &Want::DatabaseSchema {
                target: "db-1".into(),
            },
        ),
        Refusal::NotListed,
    );
    assert!(io.calls.into_inner().is_empty());
}

#[test]
fn offered_local_dotenv_files_cannot_return_credentials() {
    // A native file offer can bypass the listed dotenv read restriction.
    let files = [AuditFileOffer {
        id: 0,
        path: sitecmd_protocol::engine_abi::DisplayPath::parse("with:colon/.env.local").unwrap(),
        kind: AuditFileKind::Inventory {
            walk_index: 0,
            ignored: false,
        },
        size: BODY.len() as u64,
    }];
    let io = RecordingIo {
        bytes: Some(BODY.to_vec()),
        ..Default::default()
    };
    refuse(
        answer_for_inventory(
            &Listing::default(),
            &files,
            &[],
            &mut ReadBudget::new(100, 50),
            &io,
            &Want::OfferedFile { id: 0 },
        ),
        Refusal::NotListed,
    );
    assert!(io.calls.into_inner().is_empty());
}

#[test]
fn an_unlisted_git_path_refuses_the_batch() {
    // The module reading outside the project.
    let mut listing = listing("app.rs", 10, EntryKind::File);
    listing.entries.push(ListingEntry {
        path: rel("other.rs"),
        size: 1,
        kind: EntryKind::File,
        ignored: false,
    });
    assert_pre_read_refusal(
        &listing,
        &mut ReadBudget::new(100, 50),
        &Want::GitTracked {
            paths: vec![rel("app.rs"), rel("unlisted.rs")],
        },
        Refusal::NotListed,
    );
}

#[test]
fn git_batches_cannot_exceed_the_listed_file_count() {
    // The module reading outside the project.
    let mut listing = listing("app.rs", 10, EntryKind::File);
    listing.entries.push(ListingEntry {
        path: rel("src"),
        size: 0,
        kind: EntryKind::Dir,
        ignored: false,
    });
    assert_pre_read_refusal(
        &listing,
        &mut ReadBudget::new(100, 50),
        &Want::GitTracked {
            paths: vec![rel("app.rs"), rel("app.rs")],
        },
        Refusal::NotListed,
    );
}

#[test]
fn git_batches_send_each_listed_path_once() {
    // The module reading outside the project.
    let mut listing = listing("app.rs", 10, EntryKind::File);
    listing.entries.push(ListingEntry {
        path: rel("other.rs"),
        size: 1,
        kind: EntryKind::File,
        ignored: false,
    });
    let io = RecordingIo::default();
    let paths = vec![rel("app.rs"), rel("app.rs")];
    let result = answer_for_inventory(
        &listing,
        &[],
        &[],
        &mut ReadBudget::new(100, 50),
        &io,
        &Want::GitTracked { paths },
    );
    let unique = vec![rel("app.rs")];
    assert_eq!(
        result.into_parts(),
        (
            WantAnswer::GitTracked {
                tracked: unique.clone()
            },
            vec![]
        )
    );
    assert_eq!(io.calls.into_inner(), [Call::Git(unique)]);
}

#[test]
fn listed_git_files_and_database_offers_reach_the_adapter() {
    // The module reading outside the project.
    let path = rel("a.db");
    let listing = listing(path.as_str(), 1, EntryKind::File);
    let offer = DatabaseTargetOffer {
        id: "local".into(),
        engine: DatabaseEngine::Sqlite,
    };
    let io = RecordingIo::default();
    let mut budget = ReadBudget::new(1, 1);
    let results = [
        answer_for_inventory(
            &listing,
            &[],
            &[],
            &mut budget,
            &io,
            &Want::GitTracked {
                paths: vec![path.clone()],
            },
        )
        .into_parts(),
        answer_for_inventory(
            &listing,
            &[],
            &[offer],
            &mut budget,
            &io,
            &Want::DatabaseSchema {
                target: "local".into(),
            },
        )
        .into_parts(),
    ];
    assert_eq!(
        results,
        [
            (
                WantAnswer::GitTracked {
                    tracked: vec![path.clone()]
                },
                vec![]
            ),
            (
                WantAnswer::DatabaseSchema {
                    snapshot: SchemaSnapshot::default()
                },
                vec![]
            ),
        ]
    );
    assert_eq!(
        io.calls.into_inner(),
        [Call::Git(vec![path]), Call::Database("local".into())]
    );
}

fn read(io: &RecordingIo, budget: &mut ReadBudget, listed_size: u64) -> HostAnswer {
    answer_for_inventory(
        &listing("app.rs", listed_size, EntryKind::File),
        &[],
        &[],
        budget,
        io,
        &file_want("app.rs"),
    )
}

#[test]
fn binary_bytes_answer_not_text() {
    // The module reading outside the project.
    let io = RecordingIo {
        bytes: Some(vec![0xff]),
        ..RecordingIo::default()
    };
    let mut budget = ReadBudget::new(1, 50);
    refuse(read(&io, &mut budget, 1), Refusal::NotText);
    refuse(read(&io, &mut budget, 1), Refusal::AlreadyAnswered);
    assert_eq!(io.calls.into_inner(), [Call::Read(rel("app.rs"), 1)]);
}

#[test]
fn a_file_deleted_after_listing_answers_unavailable() {
    // The module reading outside the project.
    let io = RecordingIo::default();
    refuse(
        read(&io, &mut ReadBudget::new(100, 50), 10),
        Refusal::Unavailable,
    );
    assert_eq!(io.calls.into_inner(), [Call::Read(rel("app.rs"), 50)]);
}

#[test]
fn a_file_grown_past_the_cap_answers_too_large() {
    // The module reading outside the project.
    let io = RecordingIo {
        bytes: Some(vec![b'x'; 51]),
        ..RecordingIo::default()
    };
    let mut budget = ReadBudget::new(70, 50);
    refuse(read(&io, &mut budget, 10), Refusal::TooLarge);
    assert_eq!(budget.remaining, 70);
    refuse(read(&io, &mut budget, 10), Refusal::AlreadyAnswered);
    assert_eq!(io.calls.into_inner(), [Call::Read(rel("app.rs"), 50)]);
}

#[test]
fn a_changed_size_within_the_cap_answers_unavailable() {
    // The module reading outside the project.
    let io = RecordingIo {
        bytes: Some(vec![b'x'; 30]),
        ..RecordingIo::default()
    };
    let mut budget = ReadBudget::new(45, 50);
    refuse(read(&io, &mut budget, 10), Refusal::Unavailable);
    assert_eq!(budget.remaining, 45);
    refuse(read(&io, &mut budget, 10), Refusal::AlreadyAnswered);
    assert_eq!(io.calls.into_inner(), [Call::Read(rel("app.rs"), 45)]);
}

#[test]
fn a_file_exactly_at_the_cap_answers_with_its_body() {
    // The module reading outside the project.
    let size = BODY.len() as u64;
    let io = RecordingIo {
        bytes: Some(BODY.to_vec()),
        ..RecordingIo::default()
    };
    let mut budget = ReadBudget::new(size, size);
    assert_eq!(
        read(&io, &mut budget, size).into_parts(),
        (
            WantAnswer::File {
                body: BodyRef {
                    at: 0,
                    len: size as u32
                }
            },
            BODY.to_vec()
        ),
    );
    refuse(read(&io, &mut budget, size), Refusal::AlreadyAnswered);
    refuse(
        answer_for_inventory(
            &listing("next.rs", size, EntryKind::File),
            &[],
            &[],
            &mut budget,
            &io,
            &file_want("next.rs"),
        ),
        Refusal::BudgetSpent,
    );
    assert_eq!(io.calls.into_inner(), [Call::Read(rel("app.rs"), size)]);
}

#[test]
fn host_answer_debug_shows_lengths_only() {
    // User code in a log line
    let io = RecordingIo {
        bytes: Some(BODY.to_vec()),
        ..RecordingIo::default()
    };
    let size = BODY.len() as u64;
    let answer = read(&io, &mut ReadBudget::new(100, 50), size);
    assert_eq!(
        format!("{answer:?}"),
        format!("HostAnswer {{ kind: \"file\", body_len: {size} }}")
    );
    assert_eq!(io.calls.into_inner(), [Call::Read(rel("app.rs"), 50)]);
}

#[test]
fn refusal_error_text_holds_no_body_bytes() {
    // User code in a log line
    let io = RecordingIo::default();
    let answer = read(&io, &mut ReadBudget::new(100, 50), 10);
    assert_eq!(
        format!("{answer:?}"),
        "HostAnswer { kind: \"refused\", body_len: 0 }"
    );
    let (wire, bytes) = answer.into_parts();
    assert_eq!(
        serde_json::to_string(&wire).unwrap(),
        r#"{"kind":"refused","reason":"unavailable"}"#
    );
    assert!(bytes.is_empty());
    assert_eq!(io.calls.into_inner(), [Call::Read(rel("app.rs"), 50)]);
}

fn offer(path: &str, kind: AuditFileKind, size: u64) -> AuditFileOffer {
    AuditFileOffer {
        id: 0,
        path: sitecmd_protocol::engine_abi::DisplayPath::parse(path).unwrap(),
        kind,
        size,
    }
}

#[test]
fn refused_offers_never_read_before_id_cap_and_budget_checks() {
    // Bug: An offered file can bypass qualification and consume unbounded I/O.
    let listing = Listing::default();
    let files = [offer("app/sign:in.ts", AuditFileKind::Metadata {}, 5)];
    let io = RecordingIo::default();
    for (id, bytes, cap, reason) in [
        (1, 0, 0, Refusal::NotListed),
        (0, 0, 4, Refusal::TooLarge),
        (0, 4, 5, Refusal::BudgetSpent),
    ] {
        let mut budget = ReadBudget::new(bytes, cap);
        refuse(
            answer_for_inventory(
                &listing,
                &files,
                &[],
                &mut budget,
                &io,
                &Want::OfferedFile { id },
            ),
            reason,
        );
    }
    assert!(io.calls.borrow().is_empty());
}

#[test]
fn listed_and_offered_dependencies_are_answered_only_once() {
    // Bug: A module can repeatedly request dependency bodies across batches.
    let size = 1_500_000;
    let listed = listing(".npmrc", size, EntryKind::File);
    let files = [offer(
        "packages/sign:in/.npmrc",
        AuditFileKind::Dependency {},
        size,
    )];
    let io = RecordingIo {
        bytes: Some(vec![b'a'; size as usize]),
        ..Default::default()
    };
    let mut budget = ReadBudget::new(0, 1_000_000);
    let wants = [file_want(".npmrc"), Want::OfferedFile { id: 0 }];
    for want in &wants {
        let (answer, bytes) =
            answer_for_inventory(&listed, &files, &[], &mut budget, &io, want).into_parts();
        assert_eq!(
            answer,
            WantAnswer::File {
                body: BodyRef {
                    at: 0,
                    len: size as u32
                }
            }
        );
        assert_eq!(bytes.len() as u64, size);
    }
    for want in &wants {
        refuse(
            answer_for_inventory(&listed, &files, &[], &mut budget, &io, want),
            Refusal::AlreadyAnswered,
        );
    }
    assert_eq!(
        *io.calls.borrow(),
        [
            Call::Read(rel(".npmrc"), MAX_DEPENDENCY_FILE_BYTES),
            Call::Offer(0, MAX_DEPENDENCY_FILE_BYTES),
        ]
    );
}

#[test]
fn non_utf8_refusals_leave_the_budget_available() {
    // Bug: Bytes rejected as non-text can leave no allowance for the next valid source.
    let io = RecordingIo {
        bytes: Some(vec![0xff]),
        ..Default::default()
    };
    let mut budget = ReadBudget::new(1, 1);
    refuse(read(&io, &mut budget, 1), Refusal::NotText);
    let io = RecordingIo {
        bytes: Some(vec![b'x']),
        ..Default::default()
    };
    let (answer, body) = answer_for_inventory(
        &listing("z.rs", 1, EntryKind::File),
        &[],
        &[],
        &mut budget,
        &io,
        &file_want("z.rs"),
    )
    .into_parts();
    assert_eq!(
        answer,
        WantAnswer::File {
            body: BodyRef { at: 0, len: 1 }
        }
    );
    assert_eq!(body, b"x");
}

#[test]
fn presence_paths_are_answered_once_and_capped_across_batches() {
    let listing = Listing::default();
    let io = RecordingIo::default();
    let mut budget = ReadBudget::new(0, 0);
    let paths: Vec<_> = (0..AUDIT_MAX_FILES)
        .map(|index| rel(&format!("src/{index}.rs")))
        .collect();
    let mut answer = |paths| {
        answer_for_inventory(
            &listing,
            &[],
            &[],
            &mut budget,
            &io,
            &Want::PathPresence { paths },
        )
    };
    refuse(answer(vec![paths[0].clone(); 2]), Refusal::AlreadyAnswered);
    for round in [&paths[..1], &paths[1..]] {
        assert_eq!(
            answer(round.to_vec()).into_parts(),
            (
                WantAnswer::PathPresence {
                    present: Vec::new(),
                    symlinks: Vec::new()
                },
                Vec::new()
            ),
        );
    }
    refuse(answer(vec![paths[0].clone()]), Refusal::AlreadyAnswered);
    refuse(answer(vec![rel("src/overflow.rs")]), Refusal::BudgetSpent);
    assert_eq!(
        io.calls.into_inner(),
        paths.into_iter().map(Call::Presence).collect::<Vec<_>>()
    );
}
