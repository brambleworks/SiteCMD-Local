use super::*;
use std::fs;
use tempfile::tempdir;

fn paths(listing: &ProjectListing) -> Vec<&str> {
    listing
        .wire()
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect()
}

#[test]
fn host_file_order_prefers_the_project_root_then_lexical_paths() {
    let root = tempdir().unwrap();
    let expected = ["b.ts", "z.ts", "a/deep.ts"];
    for order in [["z.ts", "a/deep.ts", "b.ts"], ["b.ts", "a/deep.ts", "z.ts"]] {
        let mut walker = Walker {
            root: root.path(),
            max_files: MAX_PROJECT_FILES,
            max_depth: MAX_PROJECT_DEPTH,
            files: order
                .map(|path| NativeFile {
                    relative: path.into(),
                    size: 1,
                    ignored: false,
                })
                .into(),
            skipped_paths: 0,
            skipped_scopes: SkippedScopes::default(),
            entries: Vec::new(),
            omitted: HashSet::new(),
        };
        walker.record(PendingEntry::Dir("a".into()));
        for index in 0..order.len() {
            walker.record(PendingEntry::File(index));
        }
        let listing = walker.into_listing(open_project_dir(root.path()).unwrap());
        let paths = listing.file_order();
        let actual: Vec<_> = paths.iter().map(RelPath::as_str).collect();
        assert_eq!(actual, expected);
        let children = listing.observed_children(listing.root());
        let names: Vec<_> = children
            .iter()
            .map(|child| child.file_name().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(names, ["a", "b.ts", "z.ts"]);
        let unsorted = [listing.root().join("z.ts"), listing.root().join("a")];
        let mut candidates = unsorted.clone();
        listing.order_children(listing.root(), &mut candidates);
        assert_eq!(candidates, unsorted);
    }
}

#[test]
fn omitted_children_are_indexed_by_their_immediate_parent() {
    // Bug: Finding one directory's omitted children walks omissions from unrelated directories.
    let temp = tempdir().unwrap();
    for relative in [
        "apps/web/node_modules",
        "apps/api/node_modules",
        "apps/api/dist",
    ] {
        fs::create_dir_all(temp.path().join(relative)).unwrap();
    }
    let listing = list_project(temp.path()).unwrap();
    let parent = Path::new("apps/web");

    assert_eq!(
        listing.omitted.get(parent),
        Some(&HashSet::from([OsString::from("node_modules")]))
    );
    assert_eq!(
        OmittedPaths::children(&listing, &listing.root().join(parent)),
        [listing.root().join(parent).join("node_modules")]
    );
    assert!(listing.is_omitted(&listing.root().join("apps/web/node_modules/a")));
}

#[cfg(unix)]
#[test]
fn symlink_out_of_root_is_not_listed() {
    // A symlink can expose entries from outside the listing root.
    use std::os::unix::fs::symlink;

    let root = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let target = outside.path().join("secret.txt");
    fs::write(&target, "private").unwrap();
    symlink(&target, root.path().join("file.txt")).unwrap();
    symlink(outside.path(), root.path().join("dir")).unwrap();
    fs::write(root.path().join("real.txt"), "real").unwrap();

    assert_eq!(paths(&list_project(root.path()).unwrap()), ["real.txt"]);
}

#[cfg(unix)]
#[test]
fn symlink_loop_ends() {
    // A symlink cycle can send the walker back to the project root.
    use std::os::unix::fs::symlink;

    let root = tempdir().unwrap();
    let src = root.path().join("src");
    fs::create_dir(&src).unwrap();
    symlink(root.path(), src.join("loop")).unwrap();
    fs::write(src.join("real.txt"), "real").unwrap();

    assert_eq!(
        paths(&list_project(root.path()).unwrap()),
        ["src", "src/real.txt"]
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_name_is_treated_as_today() {
    // A lossy filename can alias a different file in the module listing.
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let raw = Path::new(OsStr::from_bytes(b"bad\xff.js"));
    let valid = Path::new("bad�.js");
    assert_eq!(listing_path(raw), listing_path(valid));
    assert_eq!(listing_path(raw).unwrap().as_str(), "bad�.js");
}

#[cfg(target_os = "linux")]
#[test]
fn a_non_utf8_file_is_read_through_the_listed_disk_path() {
    // Bug: Reconstructing the lossy filename can read a different file on disk.
    use crate::core::engine_io::ProjectIo;
    use sitecmd_engine_host::wants::{answer, ReadBudget};
    use sitecmd_protocol::engine_abi::{Want, WantAnswer};
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let root = tempdir().unwrap();
    let raw = root.path().join(OsStr::from_bytes(b"bad\x80.js"));
    let alias = root.path().join("bad�.js");
    let content = "let invalid = 1;";
    fs::write(&alias, "let valid = 12; ").unwrap();
    fs::write(&raw, content).unwrap();

    let listing = list_project(root.path()).unwrap();
    assert_eq!(paths(&listing), ["bad�.js"]);
    assert_eq!(listing.wire().entries[0].size, content.len() as u64);
    assert_eq!(listing.wire().skipped_paths, 1);
    let want = Want::File {
        path: RelPath::parse("bad�.js").unwrap(),
    };
    let io = ProjectIo::new(&listing);
    let mut budget = ReadBudget::new(100, 50);
    let (metadata, bytes) = answer(
        &crate::core::engine_io::test_session(&listing, vec![]),
        &mut budget,
        &io,
        &want,
    )
    .into_parts();
    assert!(matches!(metadata, WantAnswer::File { .. }));
    assert_eq!(bytes, content.as_bytes());
}

#[cfg(unix)]
#[test]
fn a_losing_directory_cannot_list_children_under_the_winning_file() {
    // Bug: a losing directory's children were listed under the winning file's name.
    use sitecmd_protocol::project_paths::ProjectPaths;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let root = tempdir().unwrap();
    let loser = PathBuf::from(OsStr::from_bytes(b"x\xff"));
    let nested = loser.join("nested");
    let entries = [
        PendingEntry::File(1),
        PendingEntry::Dir(nested.clone()),
        PendingEntry::Dir(loser.clone()),
        PendingEntry::File(0),
    ];
    // Exercise wire selection without creating non-UTF-8 names on disk.
    let mut walker = Walker {
        root: root.path(),
        max_files: MAX_PROJECT_FILES,
        max_depth: MAX_PROJECT_DEPTH,
        files: vec![
            NativeFile {
                relative: PathBuf::from("x�"),
                size: 1,
                ignored: false,
            },
            NativeFile {
                relative: nested.join("a.js"),
                size: 3,
                ignored: false,
            },
        ],
        skipped_paths: 0,
        skipped_scopes: SkippedScopes::default(),
        omitted: HashSet::new(),
        entries: Vec::new(),
    };
    for entry in entries {
        walker.record(entry);
    }
    let listing = walker.into_listing(open_project_dir(root.path()).unwrap());
    assert_eq!(paths(&listing), ["x�"]);
    assert_eq!(listing.wire().entries[0].kind, EntryKind::File);
    assert_eq!(listing.wire().skipped_paths, 3);
    assert_eq!(listing.paths().kind(&listing.root().join(loser)), None);
    let [(index, unlisted)] = listing.unlisted_files().collect::<Vec<_>>()[..] else {
        panic!("expected the child of the losing directory");
    };
    assert_eq!(index, 1);
    assert_eq!(unlisted.relative, nested.join("a.js"));
    let child = RelPath::parse("x�/nested/a.js").unwrap();
    assert_eq!(
        listing.read_file(&child, 10).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_listing_keeps_native_files_under_a_losing_directory() {
    // Files under a directory with a colliding display name can disappear from inventory.
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let root = tempdir().unwrap();
    let loser = Path::new(OsStr::from_bytes(b"x\xff"));
    let contents = b"export {};";
    fs::write(root.path().join("x�"), "winner").unwrap();
    fs::create_dir(root.path().join(loser)).unwrap();
    fs::write(root.path().join(loser).join("a.js"), contents).unwrap();

    let listing = list_project(root.path()).unwrap();
    assert_eq!(paths(&listing), ["x�"]);
    assert_eq!(listing.wire().entries[0].kind, EntryKind::File);
    assert_eq!(listing.wire().skipped_paths, 2);
    let [(_, child)] = listing.unlisted_files().collect::<Vec<_>>()[..] else {
        panic!("expected the child of the losing directory");
    };
    assert_eq!(child.relative, loser.join("a.js"));
    assert_eq!(
        listing.read_native_file(child, 100).unwrap(),
        contents.as_slice()
    );
}

#[cfg(unix)]
#[test]
fn unix_listing_keeps_ordinary_names_and_counts_unrepresentable_paths() {
    // A Windows device-name rule can discard ordinary Unix files.
    use crate::core::engine_io::ProjectIo;
    use sitecmd_engine_host::wants::{answer, ReadBudget};
    use sitecmd_protocol::engine_abi::Want;

    let root = tempdir().unwrap();
    fs::create_dir_all(root.path().join("src/aux")).unwrap();
    for name in [
        "aux.js",
        "nul.rs",
        "src/aux/lib.rs",
        "bad:name.rs",
        "bad\\name.rs",
        "bad\tname.rs",
    ] {
        fs::write(root.path().join(name), "local").unwrap();
    }
    let listing = list_project(root.path()).unwrap();
    assert_eq!(
        paths(&listing),
        ["aux.js", "nul.rs", "src", "src/aux", "src/aux/lib.rs"]
    );
    assert_eq!(listing.wire().skipped_paths, 3);
    let want = Want::File {
        path: RelPath::parse("aux.js").unwrap(),
    };
    let io = ProjectIo::new(&listing);
    assert_eq!(
        answer(
            &crate::core::engine_io::test_session(&listing, vec![]),
            &mut ReadBudget::new(10, 10),
            &io,
            &want
        )
        .into_parts()
        .1,
        b"local",
    );
}

#[test]
fn directories_do_not_consume_the_project_file_limit() {
    // Directory entries can exhaust a budget that only counts files.
    let root = tempdir().unwrap();
    fs::create_dir_all(root.path().join("src/empty")).unwrap();
    fs::write(root.path().join("src/app.rs"), "local").unwrap();
    let listing = list_project_with_limits(root.path(), 1, 8).unwrap();
    assert_eq!(paths(&listing), ["src", "src/app.rs", "src/empty"]);
}

#[test]
fn invalid_project_root_keeps_the_resolution_error() {
    // Listing failures can replace the existing root error shown to users.
    let temp = tempdir().unwrap();
    let missing = temp.path().join("missing");
    let source = fs::canonicalize(&missing).unwrap_err();
    let Err(error) = list_project(&missing) else {
        panic!("missing project root accepted");
    };
    assert_eq!(
        error.to_string(),
        format!(
            "Could not resolve project root {}: {source}",
            missing.display()
        )
    );
}

#[test]
fn listing_is_sorted_and_keeps_the_existing_scope() {
    // Walking ignored directories or nested repositories can expose excluded files.
    let root = tempdir().unwrap();
    let path = root.path();
    fs::write(
        path.join(".gitignore"),
        "ignored/\nprivate.txt\n.env\n!keep.txt\n",
    )
    .unwrap();
    for dir in ["src", "node_modules", "ignored", "nested/.git"] {
        fs::create_dir_all(path.join(dir)).unwrap();
    }
    for file in [
        "src/z.rs",
        "src/a.rs",
        "node_modules/hidden.rs",
        "ignored/hidden.rs",
        "nested/hidden.rs",
        "private.txt",
        ".env",
        "keep.txt",
    ] {
        fs::write(path.join(file), "x").unwrap();
    }

    let listing = list_project(path).unwrap();
    assert_eq!(
        paths(&listing),
        [
            ".env",
            ".gitignore",
            "keep.txt",
            "private.txt",
            "src",
            "src/a.rs",
            "src/z.rs"
        ]
    );
    assert_eq!(listing.wire().entries[4].size, 0);
    assert_eq!(listing.wire().entries[5].size, 1);
    assert!(
        listing
            .wire()
            .get(&RelPath::parse(".env").unwrap())
            .unwrap()
            .ignored
    );
    assert!(
        listing
            .wire()
            .get(&RelPath::parse("private.txt").unwrap())
            .unwrap()
            .ignored
    );
    assert!(
        !listing
            .wire()
            .get(&RelPath::parse("keep.txt").unwrap())
            .unwrap()
            .ignored
    );
    assert!(listing
        .wire()
        .get(&RelPath::parse("ignored").unwrap())
        .is_none());
}

#[cfg(unix)]
#[test]
fn the_listing_does_not_follow_a_symlinked_gitignore() {
    // An in-project symlink can make the walker read an unlisted ignore file.
    use std::os::unix::fs::symlink;

    let root = tempdir().unwrap();
    let rules = root.path().join("rules");
    fs::write(&rules, "file.js\n").unwrap();
    fs::write(root.path().join("file.js"), "export {};").unwrap();
    symlink(&rules, root.path().join(".gitignore")).unwrap();

    assert_eq!(
        paths(&list_project(root.path()).unwrap()),
        ["file.js", "rules"]
    );
}

#[cfg(unix)]
#[test]
fn security_regression_inventory_read_rejects_file_replaced_by_symlink() {
    use std::os::unix::fs::symlink;

    let project = tempdir().expect("temp dir");
    let outside = tempdir().expect("temp dir");
    let manifest = project.path().join("package.json");
    let secret = outside.path().join("secret.json");
    fs::write(&manifest, "{\"name\":\"safe\"}\n").expect("write manifest");
    fs::write(&secret, "{\"token\":\"outside-secret\"}\n").expect("write secret");

    let listing = list_project(project.path()).expect("list project");
    let recorded = RelPath::parse("package.json").unwrap();
    assert!(listing.wire().is_file(&recorded));

    fs::remove_file(&manifest).expect("remove original manifest");
    symlink(&secret, &manifest).expect("replace manifest with symlink");

    assert!(
        listing.read_file(&recorded, 250_000).is_err(),
        "inventory-backed reads must reject files replaced by symlinks"
    );
}

// Guards fixed-path reads against symlink escape and unbounded files.
#[cfg(unix)]
#[test]
fn security_regression_read_text_under_root_rejects_symlink_escape() {
    use crate::core::filesystem::{read_text_under_root, read_under_root, MAX_FILE_BYTES};
    use std::os::unix::fs::symlink;

    let project = tempdir().expect("temp dir");
    let outside = tempdir().expect("temp dir");
    let secret = outside.path().join("id_rsa");
    fs::write(&secret, "SECRET_MARKER\n").expect("write secret");

    // A real instruction file under the root reads normally.
    let real = project.path().join("AGENTS.md");
    fs::write(&real, "# Agents\nreal guidance\n").expect("write real");
    assert_eq!(
        read_text_under_root(project.path(), &real).as_deref(),
        Some("# Agents\nreal guidance\n"),
    );

    // A symlinked instruction file pointing outside the root is refused.
    let linked = project.path().join("CLAUDE.md");
    symlink(&secret, &linked).expect("symlink");
    assert!(
        read_text_under_root(project.path(), &linked).is_none(),
        "fixed-path reads must not follow a symlink out of the project"
    );

    // An oversized file is refused (a link to /dev/zero would otherwise OOM).
    let big = project.path().join("BIG.md");
    fs::write(&big, vec![b'a'; (MAX_FILE_BYTES + 1) as usize]).expect("write big");
    assert!(
        read_under_root(project.path(), &big, MAX_FILE_BYTES).is_none(),
        "fixed-path reads must enforce the size budget"
    );
}

#[test]
fn project_listing_rejects_a_second_file_over_its_budget() {
    // A second source file can pass a listing cap and enter the audit.
    let root = tempdir().unwrap();
    for path in ["one.rs", "two.rs"] {
        fs::write(root.path().join(path), "fn main() {}").unwrap();
    }
    let Err(error) = list_project_with_limits(root.path(), 1, 8) else {
        panic!("the second source file must exceed the limit");
    };
    assert!(error.to_string().contains("project-file budget"));
}
