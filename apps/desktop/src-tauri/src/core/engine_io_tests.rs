use super::*;
use crate::core::project_listing::list_project;
use sitecmd_engine_host::wants::{answer, ReadBudget};
use sitecmd_protocol::engine_abi::{Refusal, Want, WantAnswer};
use std::fs;
use tempfile::tempdir;

fn database_offers(content: &str, enabled: bool) -> Vec<DatabaseTargetOffer> {
    let root = tempdir().unwrap();
    fs::write(root.path().join(".env"), content).unwrap();
    let listing = list_project(root.path()).unwrap();
    crate::core::engine_facts::session_request(&listing, enabled, 0, &|| false, root.path(), 100)
        .unwrap()
        .request
        .options
        .databases
}

#[test]
fn offers_carry_no_url_or_credential() {
    // A database offer can expose credentials or a connection URL.
    let offers = database_offers(
        "DATABASE_URL=postgres://user:pw@localhost/db\n\nSHADOW_DATABASE_URL=postgres://user:pw@localhost/shadow\n",
        true,
    );
    let wire = serde_json::to_string(&offers).unwrap();
    for secret in ["postgres://", "user", "pw"] {
        assert!(!wire.contains(secret));
    }
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&wire).unwrap(),
        serde_json::json!([{"id": "db-1", "engine": "postgres"}, {"id": "db-2", "engine": "postgres"}]),
    );
}

#[test]
fn no_offers_without_the_flag() {
    // Database targets can be offered without explicit inspection consent.
    assert!(database_offers("DATABASE_URL=postgres://user:pw@localhost/db\n", false).is_empty());
}

#[test]
fn a_public_database_host_is_never_offered() {
    // A hosted database can be offered to the local database inspector.
    assert!(
        database_offers("DATABASE_URL=postgres://user:pw@db.example.com/db\n", true).is_empty()
    );
}

#[test]
fn tracked_files_answer_from_git() {
    // A Git want can miss indexed files or report untracked files as indexed.
    let root = tempdir().unwrap();
    for file in ["tracked.rs", "untracked.rs", "another.rs"] {
        fs::write(root.path().join(file), "content").unwrap();
    }
    for args in [&["init"][..], &["add", "tracked.rs"]] {
        let output = std::process::Command::new("git")
            .current_dir(root.path())
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
    }
    let listing = list_project(root.path()).unwrap();
    let io = ProjectIo::new(&listing);
    let request = test_session(&listing, vec![]);
    let tracked = RelPath::parse("tracked.rs").unwrap();
    let untracked = RelPath::parse("untracked.rs").unwrap();
    let mut budget = ReadBudget::new(0, 0);
    assert_eq!(
        answer(
            &request,
            &mut budget,
            &io,
            &Want::GitTracked {
                paths: vec![untracked, tracked.clone(), tracked.clone()],
            },
        )
        .into_parts(),
        (
            WantAnswer::GitTracked {
                tracked: vec![tracked.clone()]
            },
            vec![]
        ),
    );
    for (path, reason) in [
        (tracked, Refusal::AlreadyAnswered),
        (RelPath::parse("missing.rs").unwrap(), Refusal::NotListed),
    ] {
        assert_eq!(
            answer(
                &request,
                &mut budget,
                &io,
                &Want::GitTracked { paths: vec![path] }
            )
            .into_parts(),
            (WantAnswer::Refused { reason }, vec![]),
        );
    }
}

#[test]
fn a_deleted_or_grown_file_is_refused_after_listing() {
    // Stale file metadata can permit an oversized or missing file read.
    let temp = tempdir().unwrap();
    let file = temp.path().join("app.rs");
    fs::write(&file, b"small").unwrap();
    let listing = list_project(temp.path()).unwrap();
    let io = ProjectIo::new(&listing);
    let path = RelPath::parse("app.rs").unwrap();
    let want = Want::File { path: path.clone() };
    let mut budget = ReadBudget::new(100, 5);

    assert_eq!(io.read(&path, 5).unwrap(), b"small");
    fs::write(&file, b"this file has grown").unwrap();
    assert_eq!(io.read(&path, 5).unwrap(), b"this f");
    assert_eq!(
        answer(
            &crate::core::engine_io::test_session(&listing, vec![]),
            &mut budget,
            &io,
            &want
        )
        .into_parts(),
        (
            WantAnswer::Refused {
                reason: Refusal::TooLarge
            },
            vec![]
        ),
    );
    fs::remove_file(file).unwrap();
    let mut budget = ReadBudget::new(100, 5);
    assert_eq!(
        answer(
            &crate::core::engine_io::test_session(&listing, vec![]),
            &mut budget,
            &io,
            &want
        )
        .into_parts(),
        (
            WantAnswer::Refused {
                reason: Refusal::Unavailable
            },
            vec![]
        ),
    );
}

#[cfg(unix)]
#[test]
fn project_io_refuses_replaced_directories_and_in_root_symlinks() {
    // A directory or file swapped after listing can redirect a read through a symlink.
    use std::os::unix::fs::symlink;

    let temp = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let src = temp.path().join("src");
    let outside_src = temp.path().join("outside_src");
    let file = temp.path().join("app.rs");
    fs::create_dir(&outside_src).unwrap();
    fs::write(outside_src.join("lib.rs"), b"normal").unwrap();
    fs::create_dir(&src).unwrap();
    fs::write(src.join("lib.rs"), b"normal").unwrap();
    fs::write(outside.path().join("lib.rs"), b"secret").unwrap();
    fs::write(&file, b"local!").unwrap();
    let listing = list_project(temp.path()).unwrap();
    let io = ProjectIo::new(&listing);

    fs::rename(&src, temp.path().join("moved")).unwrap();
    symlink("moved", &src).unwrap();
    fs::remove_dir_all(&outside_src).unwrap();
    symlink(outside.path(), &outside_src).unwrap();
    fs::remove_file(&file).unwrap();
    symlink("moved/lib.rs", &file).unwrap();

    let mut budget = ReadBudget::new(100, 50);
    for path in ["src/lib.rs", "outside_src/lib.rs", "app.rs"] {
        let want = Want::File {
            path: RelPath::parse(path).unwrap(),
        };
        assert_eq!(
            answer(
                &crate::core::engine_io::test_session(&listing, vec![]),
                &mut budget,
                &io,
                &want
            )
            .into_parts(),
            (
                WantAnswer::Refused {
                    reason: Refusal::Unavailable
                },
                vec![]
            ),
        );
    }
}

#[test]
fn database_offer_from_an_ignored_env_file_is_answered() {
    // Dropping ignored files makes their database offers unreachable.
    use sitecmd_protocol::engine_abi::DatabaseEngine;

    let temp = tempdir().unwrap();
    fs::write(temp.path().join(".gitignore"), ".env\n").unwrap();
    let content = b"DATABASE_URL=sqlite:local.db\n";
    fs::write(temp.path().join(".env"), content).unwrap();
    let database = rusqlite::Connection::open(temp.path().join("local.db")).unwrap();
    database
        .execute("CREATE TABLE example (id INTEGER PRIMARY KEY)", [])
        .unwrap();
    drop(database);
    let listing = list_project(temp.path()).unwrap();
    let inputs = crate::core::engine_facts::session_request(
        &listing,
        true,
        0,
        &|| false,
        listing.root(),
        100,
    )
    .unwrap();
    let io = ProjectIo::with_offers(&listing, &inputs.files, &inputs.databases);
    let path = RelPath::parse(".env").unwrap();
    assert!(listing.wire().get(&path).unwrap().ignored);
    assert_eq!(
        inputs.request.options.databases,
        [DatabaseTargetOffer {
            id: "db-1".into(),
            engine: DatabaseEngine::Sqlite
        }],
    );
    let mut budget = ReadBudget::new(100, 50);
    assert_eq!(listing.read_file(&path, 50).unwrap(), content);
    let want = Want::File { path };
    assert_eq!(
        answer(
            &crate::core::engine_io::test_session(&listing, vec![]),
            &mut budget,
            &io,
            &want
        )
        .into_parts(),
        (
            WantAnswer::Refused {
                reason: Refusal::NotListed
            },
            vec![]
        ),
    );
    let want = Want::DatabaseSchema {
        target: "db-1".into(),
    };
    let (answer_metadata, answer_bytes) =
        answer(&inputs.request, &mut budget, &io, &want).into_parts();
    let WantAnswer::DatabaseSchema { snapshot } = answer_metadata else {
        panic!("expected a schema snapshot, received {answer_metadata:?}");
    };
    assert!(answer_bytes.is_empty());
    assert_eq!(snapshot.tables, ["example"]);
    assert_eq!(snapshot.columns.len(), 1);
    assert_eq!(snapshot.columns[0].name, "id");
    assert_eq!(snapshot.source.unwrap().relative_path, "local.db");
}

#[test]
fn database_ids_follow_discovery_order_across_engines() {
    // Grouping offers by engine can renumber targets found earlier in the dotenv file.
    use sitecmd_protocol::engine_abi::DatabaseEngine;

    let root = tempdir().unwrap();
    drop(rusqlite::Connection::open(root.path().join("local.db")).unwrap());
    fs::write(
        root.path().join(".env"),
        "DATABASE_URL=postgres://user:pw@localhost/db\nDIRECT_URL=sqlite:local.db\nSHADOW_DATABASE_URL=sqlite:local.db\n",
    )
    .unwrap();
    let listing = list_project(root.path()).unwrap();
    let inputs = crate::core::engine_facts::session_request(
        &listing,
        true,
        0,
        &|| false,
        listing.root(),
        100,
    )
    .unwrap();
    assert_eq!(
        inputs.request.options.databases,
        [
            DatabaseTargetOffer {
                id: "db-1".into(),
                engine: DatabaseEngine::Postgres
            },
            DatabaseTargetOffer {
                id: "db-2".into(),
                engine: DatabaseEngine::Sqlite
            },
        ],
    );
}

#[test]
#[ignore = "requires SITECMD_POSTGRES_TEST_URL pointing at a localhost Postgres maintenance database"]
fn postgres_live_host_answers_an_opaque_schema_request() {
    // Bug: Local Postgres inspection can lose the target or schema between listing and the host answer.
    use crate::core::{
        engine_facts::session_request, postgres_test_support::with_live_postgres_test_db,
    };
    use sitecmd_protocol::engine_abi::{DatabaseEngine, Want, WantAnswer};

    with_live_postgres_test_db("host_answer", |temp, database_url, client| {
        client
            .batch_execute("CREATE TABLE fixture_items (id BIGINT PRIMARY KEY, name TEXT NOT NULL)")
            .unwrap();
        let project = crate::core::project_listing::list_project(temp.path()).unwrap();
        let inputs = session_request(&project, true, 0, &|| false, project.root(), 1024).unwrap();
        let [offer] = inputs.request.options.databases.as_slice() else {
            panic!("expected one opted-in database target");
        };
        assert_eq!(offer.engine, DatabaseEngine::Postgres);
        assert!(!serde_json::to_string(&inputs.request)
            .unwrap()
            .contains(database_url));

        let io = super::ProjectIo::with_offers(&project, &inputs.files, &inputs.databases);
        let want = Want::DatabaseSchema {
            target: offer.id.clone(),
        };
        let response = sitecmd_engine_host::wants::answer(
            &inputs.request,
            &mut sitecmd_engine_host::wants::ReadBudget::new(0, 0),
            &io,
            &want,
        );
        let (WantAnswer::DatabaseSchema { snapshot }, bytes) = response.into_parts() else {
            panic!("expected a Postgres schema snapshot");
        };
        assert!(bytes.is_empty());
        assert!(snapshot.tables.iter().any(|table| table == "fixture_items"));
        assert!(snapshot.columns.iter().any(|column| {
            column.table == "fixture_items" && column.name == "name" && column.not_null
        }));
        assert!(!serde_json::to_string(&snapshot)
            .unwrap()
            .contains(database_url));
    })
    .expect("run the localhost Postgres fixture");
}
