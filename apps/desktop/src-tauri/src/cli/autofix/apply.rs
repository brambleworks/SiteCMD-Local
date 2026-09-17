//! `sitecmd autofix apply`: every fixer whose prerequisites hold, on every
//! host the checkout declares, with `--dry-run` to see the plan first.

use std::path::PathBuf;

use crate::core::fix_templates::{all_fixers, apply, fixer_for, hosts, Finding, Fixer, Patch};

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
            "--only" => parsed.only.push(super::next_value(&mut args, "--only")?),
            "--dry-run" => parsed.dry_run = true,
            "--path" => parsed.path = PathBuf::from(super::next_value(&mut args, "--path")?),
            other => return Err(format!("Unknown option: {other}")),
        }
    }
    Ok(parsed)
}

fn selected_fixers(only: &[String]) -> Result<Vec<&'static dyn Fixer>, String> {
    if only.is_empty() {
        return Ok(all_fixers().to_vec());
    }
    only.iter()
        .map(|check_id| {
            fixer_for(check_id).ok_or_else(|| format!("no template fixer exists for {check_id}"))
        })
        .collect()
}

pub fn run(args: &ApplyArgs) -> Result<(u8, String), String> {
    let root = std::fs::canonicalize(&args.path)
        .map_err(|error| format!("cannot resolve {}: {error}", args.path.display()))?;
    let fixers = selected_fixers(&args.only)?;
    let targets = hosts::detect(&root);
    if targets.is_empty() {
        return Ok((
            0,
            "no recognized host configuration in this checkout (vercel.json); nothing to apply"
                .into(),
        ));
    }
    let mut lines = Vec::new();
    let mut patches: Vec<Patch> = Vec::new();
    for fixer in fixers {
        let finding = Finding {
            check_id: fixer.check_id().to_string(),
            identity: "/".into(),
        };
        for target in &targets {
            match fixer.plan(&finding, target, &root) {
                Ok(Some(patch)) => {
                    lines.push(format!(
                        "{}: {} {}",
                        fixer.check_id(),
                        if args.dry_run {
                            "would write"
                        } else {
                            "will write"
                        },
                        patch.path.display()
                    ));
                    patches.push(patch);
                }
                Ok(None) => lines.push(format!(
                    "{}: already satisfied in {}",
                    fixer.check_id(),
                    target.config_path.display()
                )),
                Err(unsupported) => lines.push(format!(
                    "{}: unsupported, {}",
                    fixer.check_id(),
                    unsupported.reason
                )),
            }
        }
    }
    if !args.dry_run && !patches.is_empty() {
        let applied = apply(&patches, &root)?;
        for path in applied.written {
            lines.push(format!("wrote {}", path.display()));
        }
    }
    Ok((0, lines.join("\n")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dry_run_reports_the_planned_file_without_writing() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("vercel.json"),
            "{\n  \"cleanUrls\": true\n}\n",
        )
        .unwrap();
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
            "{\n  \"cleanUrls\": true\n}\n"
        );
    }

    #[test]
    fn apply_writes_the_patch_and_names_the_check() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("vercel.json"), "{}\n").unwrap();
        let (code, summary) = run(&ApplyArgs {
            dry_run: false,
            only: vec!["security.headers.x_content_type_options".into()],
            path: temp.path().to_path_buf(),
        })
        .unwrap();
        assert_eq!(code, 0);
        assert!(summary.contains("wrote vercel.json"), "{summary}");
        assert!(std::fs::read_to_string(temp.path().join("vercel.json"))
            .unwrap()
            .contains("nosniff"));
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
}
