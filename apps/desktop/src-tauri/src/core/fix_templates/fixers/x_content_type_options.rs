//! `security.headers.x_content_type_options`: set `nosniff` on every route
//! through the host's platform file. Catalog class template, host-dependent.

use std::path::{Path, PathBuf};

use crate::core::fix_templates::writers::json::{add_vercel_header, is_catch_all_source};
use crate::core::fix_templates::{Finding, Fixer, HostKind, HostTarget, Patch, Unsupported};

pub struct XContentTypeOptions;

const HEADER: &str = "X-Content-Type-Options";
const VALUE: &str = "nosniff";

/// True when a catch-all rule already sets the header to something else: the
/// fixer refuses rather than append a second rule over a deliberate choice.
/// A rule with a narrower source answers for its own routes and not the site
/// root, so it is neither the deliberate choice nor a conflict.
fn sets_another_value(document: &serde_json::Value) -> bool {
    document["headers"].as_array().is_some_and(|rules| {
        rules
            .iter()
            .filter(|rule| is_catch_all_source(rule))
            .any(|rule| {
                rule["headers"].as_array().is_some_and(|headers| {
                    headers.iter().any(|header| {
                        header["key"]
                            .as_str()
                            .is_some_and(|key| key.eq_ignore_ascii_case(HEADER))
                            && !header["value"]
                                .as_str()
                                .is_some_and(|value| value.eq_ignore_ascii_case(VALUE))
                    })
                })
            })
    })
}

impl Fixer for XContentTypeOptions {
    fn check_id(&self) -> &'static str {
        "security.headers.x_content_type_options"
    }

    fn title(&self) -> &'static str {
        "Add the X-Content-Type-Options header"
    }

    fn write_set(&self, target: &HostTarget) -> Vec<PathBuf> {
        vec![target.config_path.clone()]
    }

    fn prerequisites(
        &self,
        _finding: &Finding,
        target: &HostTarget,
        root: &Path,
    ) -> Result<(), Unsupported> {
        match target.kind {
            HostKind::Vercel => {
                let path = root.join(&target.config_path);
                if !path.is_file() {
                    return Err(Unsupported {
                        reason: format!("{} is not a file", target.config_path.display()),
                    });
                }
                // A config that cannot be read or parsed passes here; the
                // writer names what it cannot edit.
                let conflicts = std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|source| serde_json::from_str::<serde_json::Value>(&source).ok())
                    .is_some_and(|document| sets_another_value(&document));
                if conflicts {
                    return Err(Unsupported {
                        reason: format!("{HEADER} is already set to a different value"),
                    });
                }
                Ok(())
            }
        }
    }

    fn plan(
        &self,
        finding: &Finding,
        target: &HostTarget,
        root: &Path,
    ) -> Result<Option<Patch>, Unsupported> {
        self.prerequisites(finding, target, root)?;
        let path = root.join(&target.config_path);
        let before = std::fs::read_to_string(&path).map_err(|error| Unsupported {
            reason: format!(
                "{} could not be read: {error}",
                target.config_path.display()
            ),
        })?;
        Ok(
            add_vercel_header(&before, HEADER, VALUE)?.map(|after| Patch {
                after,
                before: Some(before),
                path: target.config_path.clone(),
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::fix_templates::{hosts, Finding};

    fn finding() -> Finding {
        Finding {
            check_id: "security.headers.x_content_type_options".into(),
            identity: "/".into(),
        }
    }

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/fix_templates/vercel/x-content-type-options")
    }

    /// Copies a fixture checkout into a temporary directory so no test can
    /// write into the tracked tree.
    fn checkout(fixture: &str) -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        for entry in std::fs::read_dir(fixture_root().join(fixture)).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), temp.path().join(entry.file_name())).unwrap();
        }
        temp
    }

    #[test]
    fn plans_a_patch_for_a_vercel_config_without_the_header() {
        let temp = checkout("basic");
        let target = hosts::detect(temp.path()).remove(0);
        XContentTypeOptions
            .prerequisites(&finding(), &target, temp.path())
            .unwrap();
        let patch = XContentTypeOptions
            .plan(&finding(), &target, temp.path())
            .unwrap()
            .unwrap();
        assert_eq!(patch.path, PathBuf::from("vercel.json"));
        assert!(patch
            .after
            .contains("\"key\": \"X-Content-Type-Options\", \"value\": \"nosniff\""));
        assert_eq!(
            patch.after,
            std::fs::read_to_string(fixture_root().join("basic/expected.json")).unwrap()
        );
        assert_eq!(
            patch.before.as_deref(),
            Some("{\n  \"cleanUrls\": true\n}\n")
        );
        assert_eq!(
            XContentTypeOptions.write_set(&target),
            vec![PathBuf::from("vercel.json")]
        );
    }

    #[test]
    fn plans_nothing_when_the_header_is_present() {
        let temp = checkout("already-set");
        let target = hosts::detect(temp.path()).remove(0);
        assert_eq!(
            XContentTypeOptions
                .plan(&finding(), &target, temp.path())
                .unwrap(),
            None
        );
    }

    #[test]
    fn declines_a_config_it_cannot_edit() {
        let temp = checkout("unmet");
        let target = hosts::detect(temp.path()).remove(0);
        let refused = XContentTypeOptions
            .plan(&finding(), &target, temp.path())
            .unwrap_err();
        assert!(refused.reason.contains("headers"), "{}", refused.reason);
    }

    #[test]
    fn refuses_a_config_that_sets_another_value() {
        let temp = checkout("conflicting-value");
        let target = hosts::detect(temp.path()).remove(0);
        let refused = XContentTypeOptions
            .prerequisites(&finding(), &target, temp.path())
            .unwrap_err();
        assert!(
            refused.reason.contains("different value"),
            "{}",
            refused.reason
        );
        assert!(XContentTypeOptions
            .plan(&finding(), &target, temp.path())
            .is_err());
    }

    #[test]
    fn a_narrower_source_neither_satisfies_nor_blocks_the_root_rule() {
        let temp = checkout("narrower-source");
        let target = hosts::detect(temp.path()).remove(0);
        // The narrow rule sets another value, but only for its own routes, so
        // it is not the deliberate choice the refusal protects.
        XContentTypeOptions
            .prerequisites(&finding(), &target, temp.path())
            .unwrap();
        let patch = XContentTypeOptions
            .plan(&finding(), &target, temp.path())
            .unwrap()
            .unwrap();
        assert_eq!(
            patch.after,
            std::fs::read_to_string(fixture_root().join("narrower-source/expected.json")).unwrap()
        );
        let parsed: serde_json::Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(parsed["headers"].as_array().unwrap().len(), 2);
        assert_eq!(parsed["headers"][1]["source"], "/(.*)");
    }

    #[test]
    fn is_registered_under_its_check_id() {
        let fixer =
            crate::core::fix_templates::fixer_for("security.headers.x_content_type_options")
                .unwrap();
        assert_eq!(fixer.title(), "Add the X-Content-Type-Options header");
        assert!(crate::core::fix_templates::fixer_for("security.headers.hsts").is_none());
    }
}
