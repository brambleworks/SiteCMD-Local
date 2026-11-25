use crate::constants::CODE_SCAN_MAX_TEXT_BYTES;
use crate::core::engine_facts::{session_request, SessionInputs};
use crate::core::engine_io::ProjectIo;
use crate::core::project_listing::{list_project, ProjectListing};
use sitecmd_engine_host::wants::answer;
use sitecmd_protocol::engine_abi::{AuditFileKind, Refusal, RelPath, Want, WantAnswer};
use std::fs;
use std::os::unix::fs::symlink;

fn project_inputs(listing: &ProjectListing) -> SessionInputs<'_> {
    session_request(
        listing,
        false,
        0,
        &|| false,
        listing.root(),
        CODE_SCAN_MAX_TEXT_BYTES,
    )
    .unwrap()
}

#[test]
fn a_metadata_offer_reads_from_the_open_root_after_rename() {
    // Reopening a project by path can read metadata from its replacement.
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("project");
    let original = b"# Original instructions\n";
    fs::create_dir(&root).unwrap();
    fs::write(root.join("guide.md"), original).unwrap();
    symlink("guide.md", root.join("AGENTS.md")).unwrap();

    let listing = list_project(&root).unwrap();
    let inputs = project_inputs(&listing);
    let offer = inputs
        .request
        .host
        .files
        .iter()
        .find(|offer| offer.path.as_str() == "AGENTS.md")
        .unwrap();
    assert_eq!(offer.kind, AuditFileKind::Metadata {});

    fs::rename(&root, parent.path().join("original")).unwrap();
    fs::create_dir(&root).unwrap();
    fs::write(root.join("guide.md"), b"# Replacement instructions\n").unwrap();
    symlink("guide.md", root.join("AGENTS.md")).unwrap();

    assert_eq!(
        inputs.files[offer.id as usize]
            .read(&listing, 1_000)
            .unwrap(),
        original
    );
}

#[test]
fn committed_metadata_links_to_private_dotenv_are_not_offered() {
    // A tracked metadata link can disguise a private dotenv as engine input.
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    fs::write(root.join(".env.local"), b"PRIVATE_VALUE=fixture-secret\n").unwrap();
    symlink(".env.local", root.join("AGENTS.md")).unwrap();
    symlink(".env.local", root.join("example.info.yml")).unwrap();
    for args in [
        &["init", "--quiet"][..],
        &["add", "--", "AGENTS.md", "example.info.yml"],
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.test",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "Add metadata links",
        ],
    ] {
        let output = std::process::Command::new("git")
            .current_dir(root)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let listing = list_project(root).unwrap();
    let inputs = project_inputs(&listing);
    let io = ProjectIo::with_offers(&listing, &inputs.files, &inputs.databases);
    let mut budget = super::session_host::read_budget();
    for path in ["AGENTS.md", "example.info.yml", ".env.local"] {
        assert!(inputs
            .request
            .host
            .files
            .iter()
            .all(|offer| offer.path.as_str() != path));
        let want = Want::File {
            path: RelPath::parse(path).unwrap(),
        };
        assert_eq!(
            answer(&inputs.request, &mut budget, &io, &want).into_parts(),
            (
                WantAnswer::Refused {
                    reason: Refusal::NotListed
                },
                vec![]
            ),
        );
    }
}

#[test]
fn a_metadata_offer_retargeted_to_private_dotenv_is_refused() {
    // An existing metadata offer can be retargeted to a private dotenv before the engine reads it.
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let dotenv = b"PRIVATE_VALUE=fixture-secret\n";
    let guide = format!("# {}\n", "x".repeat(dotenv.len() - 3));
    fs::write(root.join("guide.md"), guide).unwrap();
    fs::write(root.join(".ENV.local"), dotenv).unwrap();
    let instructions = root.join("AGENTS.md");
    symlink("guide.md", &instructions).unwrap();
    let listing = list_project(root).unwrap();
    let inputs = project_inputs(&listing);
    let offer = inputs
        .request
        .host
        .files
        .iter()
        .find(|offer| offer.path.as_str() == "AGENTS.md")
        .unwrap();
    let want = Want::OfferedFile { id: offer.id };
    let io = ProjectIo::with_offers(&listing, &inputs.files, &inputs.databases);

    fs::remove_file(&instructions).unwrap();
    symlink(".ENV.local", &instructions).unwrap();
    let mut budget = super::session_host::read_budget();
    assert_eq!(
        answer(&inputs.request, &mut budget, &io, &want).into_parts(),
        (
            WantAnswer::Refused {
                reason: Refusal::Unavailable
            },
            vec![]
        ),
    );
}
