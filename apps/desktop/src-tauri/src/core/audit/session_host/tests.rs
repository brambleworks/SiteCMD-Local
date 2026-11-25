use super::{answer_batch, resume_round, ReadBudget};
use crate::core::engine_facts::session_request;
use crate::core::engine_io::ProjectIo;
use crate::core::project_listing::{list_project, ProjectListing};
use sitecmd_protocol::engine_abi::{
    AuditFailure, BodyRef, Done, Refusal, RelPath, SessionBegin, Step, Want, WantAnswer,
};
use std::fs;

fn request(listing: &ProjectListing) -> SessionBegin {
    session_request(
        listing,
        false,
        0,
        &|| false,
        listing.root(),
        crate::constants::CODE_SCAN_MAX_TEXT_BYTES,
    )
    .unwrap()
    .request
}

fn file(path: &str) -> Want {
    Want::File {
        path: RelPath::parse(path).unwrap(),
    }
}

#[test]
fn host_text_budget_is_shared_across_rounds() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("app.rs"), "abc").unwrap();
    fs::write(root.path().join("lib.rs"), "def").unwrap();
    let listing = list_project(root.path()).unwrap();
    let request = request(&listing);
    let io = ProjectIo::new(&listing);
    let mut budget = ReadBudget::new(5, 5);

    assert_eq!(
        answer_batch(&request, &mut budget, &io, vec![file("app.rs")], &|| false).unwrap(),
        (
            vec![WantAnswer::File {
                body: BodyRef { at: 0, len: 3 }
            }],
            b"abc".to_vec()
        ),
    );
    assert_eq!(
        answer_batch(&request, &mut budget, &io, vec![file("lib.rs")], &|| false).unwrap(),
        (
            vec![WantAnswer::Refused {
                reason: Refusal::BudgetSpent
            }],
            Vec::new()
        ),
    );
}

#[test]
fn a_round_without_new_answers_finishes_with_audit_failed() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("app.rs"), "abc").unwrap();
    let listing = list_project(root.path()).unwrap();
    let request = request(&listing);
    let io = ProjectIo::new(&listing);
    let mut budget = ReadBudget::new(5, 5);
    answer_batch(&request, &mut budget, &io, vec![file("app.rs")], &|| false).unwrap();

    for wants in [vec![file("app.rs")], vec![file("unlisted.rs")], Vec::new()] {
        let step = resume_round(&request, &mut budget, &io, wants, &|| false, |_, _| {
            panic!("a stalled batch must terminate before resuming the module")
        });
        assert_eq!(
            step,
            Step::Done {
                done: Done::AuditFailed(AuditFailure::InvalidInput)
            }
        );
    }
}

#[cfg(unix)]
#[test]
fn presence_does_not_observe_paths_beneath_an_outside_link() {
    use sitecmd_protocol::engine_abi::AuditPathKind;
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let marker = "web/core/lib/Drupal.php";
    fs::create_dir_all(outside.path().join("core/lib")).unwrap();
    fs::write(outside.path().join("core/lib/Drupal.php"), "<?php").unwrap();
    symlink(outside.path(), root.path().join("web")).unwrap();
    symlink("missing", root.path().join("dangling")).unwrap();
    let listing = list_project(root.path()).unwrap();
    let request = request(&listing);
    let fact = request
        .host
        .paths
        .iter()
        .find(|fact| fact.path.as_str() == "web")
        .expect("root-level link fact");
    assert_eq!(fact.kind, AuditPathKind::Symlink);
    assert!(!fact.safe_directory);
    let marker_fact = request
        .host
        .paths
        .iter()
        .find(|fact| fact.path.as_str() == marker)
        .expect("Drupal marker presence probe");
    assert_eq!(marker_fact.kind, AuditPathKind::Unknown);
    assert!(!marker_fact.safe_directory);
    assert!(listing
        .observed_children(&listing.root().join("web"))
        .is_empty());
    let io = ProjectIo::new(&listing);
    let paths =
        ["web", marker, "web/missing", "dangling"].map(|path| RelPath::parse(path).unwrap());
    let mut budget = ReadBudget::new(0, 0);

    assert_eq!(
        answer_batch(
            &request,
            &mut budget,
            &io,
            vec![Want::PathPresence {
                paths: paths.to_vec()
            }],
            &|| false
        )
        .unwrap(),
        (
            vec![WantAnswer::PathPresence {
                present: Vec::new(),
                symlinks: vec![paths[0].clone(), paths[3].clone()]
            }],
            Vec::new()
        ),
    );
}
