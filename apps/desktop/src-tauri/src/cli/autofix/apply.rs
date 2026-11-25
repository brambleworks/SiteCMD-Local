//! `sitecmd autofix apply`: every fixer whose prerequisites hold, on every
//! host the checkout declares, with `--dry-run` to see the plan first.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use sitecmd_protocol::engine_abi::{FixPlan, FixTarget, FixUnavailable, Listing, Patch, RelPath};

use super::template_plan::{self, TemplateFix};

use crate::core::fix_templates;
use crate::core::project_listing::list_project;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyArgs {
    pub path: PathBuf,
    pub only: Vec<String>,
    pub dry_run: bool,
}

pub(super) fn parse(mut args: impl Iterator<Item = String>) -> Result<ApplyArgs, String> {
    let mut parsed = ApplyArgs {
        dry_run: false,
        only: Vec::new(),
        path: PathBuf::from("."),
    };
    while let Some(token) = args.next() {
        match token.as_str() {
            // The flag repeats to name more than one check, so naming the
            // same one twice is a typo and never a request to run it twice.
            "--only" => {
                let check_id = super::next_value(&mut args, "--only")?;
                if !parsed.only.contains(&check_id) {
                    parsed.only.push(check_id);
                }
            }
            "--dry-run" => parsed.dry_run = true,
            "--path" => parsed.path = PathBuf::from(super::next_value(&mut args, "--path")?),
            other => return Err(format!("Unknown option: {other}")),
        }
    }
    Ok(parsed)
}

#[derive(Debug, PartialEq, Eq)]
pub struct PatchRefusal {
    pub path: RelPath,
    pub reason: String,
}

pub fn accept_patches(
    listing: &Listing,
    root: &Path,
    plan: FixPlan,
) -> (Vec<Patch>, Vec<PatchRefusal>) {
    let mut prepared = Vec::new();
    let mut refused = Vec::new();
    let mut paths = HashSet::new();
    for patch in plan.patches {
        let path = patch.path.clone();
        let result = if !listing.is_file(&path) {
            Err(format!("{} is not a listed file", path.as_str()))
        } else if !paths.insert(path.clone()) {
            const DUPLICATE_PATH: &str = "appears more than once in the patch plan";
            Err(format!("{} {DUPLICATE_PATH}", path.as_str()))
        } else {
            fix_templates::prepare(root, patch)
        };
        match result {
            Ok(patch) => prepared.push((path, patch)),
            Err(reason) => refused.push(PatchRefusal { path, reason }),
        }
    }
    let mut written = Vec::new();
    if refused.is_empty() {
        for (path, patch) in prepared {
            match fix_templates::apply(patch) {
                Ok(patch) => written.push(patch),
                Err(reason) => {
                    refused.push(PatchRefusal { path, reason });
                    break;
                }
            }
        }
    }
    (written, refused)
}

/// A path outside the allowed set is a violation, and so is anything under
/// `.github/workflows/` whatever the set says: a fix must never rewrite the
/// workflow that runs it.
pub(super) fn check_write_set(
    patches: &[Patch],
    allowed: impl Fn(&RelPath) -> bool,
) -> Result<(), String> {
    if let Some(patch) = patches.iter().find(|patch| {
        !allowed(&patch.path) || patch.path.as_str().starts_with(".github/workflows/")
    }) {
        return Err(format!(
            "{}: template reaches outside the fixer's write set",
            patch.path.as_str()
        ));
    }
    Ok(())
}

pub(super) fn write_patches(
    listing: &Listing,
    root: &Path,
    patches: Vec<Patch>,
    allowed: impl Fn(&RelPath) -> bool,
) -> Result<Vec<Patch>, String> {
    check_write_set(&patches, allowed)?;
    let (accepted, refused) = accept_patches(listing, root, FixPlan { patches });
    match refused.into_iter().next() {
        Some(refusal) => Err(refusal.reason),
        None => Ok(accepted),
    }
}

pub fn run(args: &ApplyArgs) -> Result<(u8, String), String> {
    let root = std::fs::canonicalize(&args.path)
        .map_err(|error| format!("cannot resolve {}: {error}", args.path.display()))?;
    let catalog = template_plan::catalog()?;
    let selected: Vec<_> = if args.only.is_empty() {
        catalog.iter().collect()
    } else {
        args.only
            .iter()
            .map(|id| {
                catalog
                    .iter()
                    .find(|fixer| &fixer.check_id == id)
                    .ok_or_else(|| format!("no template fixer exists for {id}"))
            })
            .collect::<Result<_, _>>()?
    };
    let project = list_project(&root).map_err(|error| error.to_string())?;
    let mut lines = Vec::new();
    let mut patches = Vec::new();
    let mut host_found = false;
    let mut write_set = HashSet::new();
    for fixer in selected {
        let target = FixTarget {
            check_id: fixer.check_id.clone(),
            identity: "/".into(),
        };
        let check_id = &fixer.check_id;
        match template_plan::plan_finding(&project, target, fixer)? {
            TemplateFix::Patches(entries) => {
                host_found = true;
                write_set.extend(fixer.write_set.iter());
                for patch in entries {
                    let verb = if args.dry_run {
                        "would write"
                    } else {
                        "will write"
                    };
                    lines.push(format!("{check_id}: {verb} {}", patch.path.as_str()));
                    patches.push(patch);
                }
            }
            TemplateFix::Unavailable(FixUnavailable::AlreadySatisfied { path }) => {
                host_found = true;
                lines.push(format!(
                    "{check_id}: already satisfied in {}",
                    path.as_str()
                ));
            }
            TemplateFix::Unavailable(FixUnavailable::Unsupported { reason }) => {
                host_found = true;
                lines.push(format!("{check_id}: unsupported, {reason}"));
            }
            TemplateFix::Unavailable(FixUnavailable::NoHost) => {}
            TemplateFix::Unavailable(FixUnavailable::NoTemplate) => {
                return Err(format!("no template fixer exists for {check_id}"));
            }
        }
    }
    if !host_found {
        return Ok((
            0,
            "no recognized host configuration in this checkout (vercel.json); nothing to apply"
                .into(),
        ));
    }
    if !args.dry_run {
        for patch in write_patches(project.wire(), &root, patches, |path| {
            write_set.contains(path)
        })? {
            lines.push(format!("wrote {}", patch.path.as_str()));
        }
    }
    Ok((0, lines.join("\n")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patch(path: &str, before: &str) -> Patch {
        Patch {
            path: RelPath::parse(path).unwrap(),
            base_sha256: Patch::hash_base(before.as_bytes()),
            content: "module replacement".into(),
        }
    }

    #[test]
    fn a_patch_outside_the_listing_is_refused() {
        // Bug: A module can overwrite a file it was never offered.
        let root = tempfile::tempdir().unwrap();
        let project = crate::core::project_listing::list_project(root.path()).unwrap();
        let path = root.path().join("unlisted.json");
        std::fs::write(&path, "original").unwrap();
        let plan = FixPlan {
            patches: vec![patch("unlisted.json", "original")],
        };

        let (accepted, refused) = accept_patches(project.wire(), root.path(), plan);

        assert!(accepted.is_empty());
        assert_eq!(refused.len(), 1);
        assert_eq!(refused[0].path.as_str(), "unlisted.json");
        assert!(refused[0].reason.contains("not a listed file"));
        assert_eq!(std::fs::read_to_string(path).unwrap(), "original");
    }

    #[test]
    fn a_patch_whose_base_changed_is_refused_and_nothing_is_written() {
        // Bug: A module patch overwrites an intervening user edit.
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("vercel.json");
        std::fs::write(&path, "original").unwrap();
        let project = crate::core::project_listing::list_project(root.path()).unwrap();
        let plan = FixPlan {
            patches: vec![patch("vercel.json", "original")],
        };
        std::fs::write(&path, "edited").unwrap();

        let (accepted, refused) = accept_patches(project.wire(), root.path(), plan);

        assert!(accepted.is_empty());
        assert_eq!(refused.len(), 1);
        assert_eq!(refused[0].path.as_str(), "vercel.json");
        assert!(refused[0].reason.contains("changed"));
        assert_eq!(std::fs::read_to_string(path).unwrap(), "edited");
    }

    #[test]
    fn a_changed_second_patch_leaves_the_first_file_untouched() {
        // Bug: A refused patch leaves an earlier patch written to disk.
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("vercel.json");
        let second = root.path().join("other.json");
        std::fs::write(&first, "{}").unwrap();
        std::fs::write(&second, "{}").unwrap();
        let project = list_project(root.path()).unwrap();
        let patches = vec![patch("vercel.json", "{}"), patch("other.json", "{}")];
        std::fs::write(&second, "edited").unwrap();

        let error = write_patches(project.wire(), root.path(), patches, |path| {
            matches!(path.as_str(), "vercel.json" | "other.json")
        })
        .unwrap_err();

        assert!(error.contains("other.json changed"), "{error}");
        assert_eq!(std::fs::read_to_string(first).unwrap(), "{}");
        assert_eq!(std::fs::read_to_string(second).unwrap(), "edited");
    }

    #[test]
    fn a_second_patch_outside_the_write_set_leaves_both_files_untouched() {
        // Bug: A valid earlier patch is written before a later write-set violation.
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("vercel.json");
        let second = root.path().join("other.json");
        std::fs::write(&first, "{}").unwrap();
        std::fs::write(&second, "{}").unwrap();
        let project = list_project(root.path()).unwrap();
        let patches = vec![patch("vercel.json", "{}"), patch("other.json", "{}")];

        let error = write_patches(project.wire(), root.path(), patches, |path| {
            path.as_str() == "vercel.json"
        })
        .unwrap_err();

        assert!(error.contains("other.json"), "{error}");
        assert!(error.contains("outside the fixer's write set"), "{error}");
        assert_eq!(std::fs::read_to_string(first).unwrap(), "{}");
        assert_eq!(std::fs::read_to_string(second).unwrap(), "{}");
    }

    #[test]
    fn a_repeated_only_names_the_check_once() {
        let parsed = parse(
            [
                "--only",
                "security.headers.x_content_type_options",
                "--only",
                "security.headers.x_content_type_options",
            ]
            .map(String::from)
            .into_iter(),
        )
        .unwrap();
        assert_eq!(
            parsed.only,
            vec!["security.headers.x_content_type_options".to_string()]
        );
    }

    #[test]
    fn dry_run_reports_the_planned_file_without_writing() {
        // Dry run can write the patch it is only supposed to display.
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("vercel.json"), "{\"example\":false}\n").unwrap();
        let (code, summary) = run(&ApplyArgs {
            dry_run: true,
            only: vec![],
            path: temp.path().to_path_buf(),
        })
        .unwrap();
        assert_eq!(code, 0);
        assert!(summary.contains("would write vercel.json"), "{summary}");
        assert_eq!(
            std::fs::read_to_string(temp.path().join("vercel.json")).unwrap(),
            "{\"example\":false}\n"
        );
    }

    #[test]
    fn an_unknown_check_is_a_usage_error() {
        let temp = tempfile::tempdir().unwrap();
        let error = run(&ApplyArgs {
            dry_run: true,
            only: vec!["security.headers.hsts".into()],
            path: temp.path().to_path_buf(),
        })
        .unwrap_err();
        assert!(error.contains("no template fixer"), "{error}");
    }

    #[test]
    fn a_checkout_without_a_host_declines() {
        let temp = tempfile::tempdir().unwrap();
        let (code, summary) = run(&ApplyArgs {
            dry_run: true,
            only: vec![],
            path: temp.path().to_path_buf(),
        })
        .unwrap();
        assert_eq!(code, 0);
        assert!(summary.contains("no recognized host"), "{summary}");
    }

    #[test]
    fn applies_a_module_patch_and_reports_its_path() {
        // Apply can report an edit without writing its accepted module patch.
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("vercel.json"), "{}\n").unwrap();
        let (code, summary) = run(&ApplyArgs {
            dry_run: false,
            only: vec!["standin.rule".into()],
            path: temp.path().to_path_buf(),
        })
        .unwrap();
        assert_eq!(code, 0);
        assert!(summary.contains("wrote vercel.json"), "{summary}");
        assert!(std::fs::read_to_string(temp.path().join("vercel.json"))
            .unwrap()
            .contains("\"example\":true"));
    }
}
