//! Repository-config host detection: the platform file decides, the live
//! detected stack is only a hint. Vercel is the launch host.

use std::path::Path;

use super::{HostKind, HostTarget};

const VERCEL_CONFIG: &str = "vercel.json";

pub fn detect(root: &Path) -> Vec<HostTarget> {
    let mut targets = Vec::new();
    if let Ok(source) = std::fs::read_to_string(root.join(VERCEL_CONFIG)) {
        if serde_json::from_str::<serde_json::Value>(&source).is_ok_and(|value| value.is_object()) {
            targets.push(HostTarget {
                config_path: VERCEL_CONFIG.into(),
                kind: HostKind::Vercel,
            });
        }
    }
    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_vercel_from_a_json_object_config() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/fix_templates/vercel/host");
        let targets = detect(&root);
        assert_eq!(
            targets,
            vec![HostTarget {
                config_path: "vercel.json".into(),
                kind: HostKind::Vercel
            }]
        );
    }

    #[test]
    fn ignores_a_vercel_config_that_is_not_an_object() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("vercel.json"), "[]").unwrap();
        assert!(detect(temp.path()).is_empty());
    }

    #[test]
    fn detects_nothing_in_an_empty_checkout() {
        let temp = tempfile::tempdir().unwrap();
        assert!(detect(temp.path()).is_empty());
    }
}
