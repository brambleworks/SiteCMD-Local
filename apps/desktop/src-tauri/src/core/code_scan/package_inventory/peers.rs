//! Peer requirements recorded in a lockfile, so a package declared only to
//! satisfy another package's peer range is not reported as unused.

use super::registry::normalize_pnpm_package_key;
use super::*;

/// Peer dependency names per directly installed package, keyed by lowercase
/// package name. npm lockfile v2/v3 and pnpm record them; Yarn Classic does not.
///
/// `lockfile_dir` is the directory of the lockfile that covers the manifest,
/// which for a workspace member is the workspace root, not the member.
pub(in crate::core::code_scan) fn collect_lockfile_peer_dependencies(
    lockfile_dir: &Path,
) -> HashMap<String, HashSet<String>> {
    if let Some(peers) = parse_package_lock_peer_dependencies(lockfile_dir) {
        return peers;
    }
    parse_pnpm_lock_peer_dependencies(lockfile_dir).unwrap_or_default()
}

fn parse_package_lock_peer_dependencies(dir: &Path) -> Option<HashMap<String, HashSet<String>>> {
    let content = crate::updates::read_dependency_file(&dir.join("package-lock.json"))?;
    let lock: Value = serde_json::from_str(&content).ok()?;
    let packages = lock.get("packages")?.as_object()?;
    let mut peers = HashMap::new();
    for (key, info) in packages {
        let Some(name) = key.strip_prefix("node_modules/") else {
            continue;
        };
        // Only hoisted top-level installs describe the manifest's own
        // declarations; nested copies belong to other packages.
        let slash_count = name.matches('/').count();
        let is_scoped = name.starts_with('@');
        if (is_scoped && slash_count > 1) || (!is_scoped && slash_count > 0) {
            continue;
        }
        let Some(table) = info.get("peerDependencies").and_then(Value::as_object) else {
            continue;
        };
        let names = table
            .keys()
            .map(|peer| peer.to_ascii_lowercase())
            .collect::<HashSet<_>>();
        if !names.is_empty() {
            peers.insert(name.to_ascii_lowercase(), names);
        }
    }
    Some(peers)
}

fn parse_pnpm_lock_peer_dependencies(dir: &Path) -> Option<HashMap<String, HashSet<String>>> {
    let content = crate::updates::read_dependency_file(&dir.join("pnpm-lock.yaml"))?;
    let mut peers: HashMap<String, HashSet<String>> = HashMap::new();
    let mut current_package: Option<String> = None;
    let mut in_peers = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        match indent {
            0 => {
                current_package = None;
                in_peers = false;
            }
            2 if trimmed.ends_with(':') => {
                let key = trimmed
                    .trim_end_matches(':')
                    .trim_matches('"')
                    .trim_matches('\'');
                current_package = (key.starts_with('/') || key.contains('@'))
                    .then(|| normalize_pnpm_package_key(key))
                    .flatten();
                in_peers = false;
            }
            4 => in_peers = trimmed == "peerDependencies:",
            6 if in_peers => {
                let (Some(package), Some((peer, _))) =
                    (current_package.as_ref(), trimmed.split_once(':'))
                else {
                    continue;
                };
                let peer = peer
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_ascii_lowercase();
                if !peer.is_empty() {
                    peers.entry(package.clone()).or_default().insert(peer);
                }
            }
            _ => {}
        }
    }
    if peers.is_empty() {
        None
    } else {
        Some(peers)
    }
}

#[cfg(test)]
mod tests {
    use super::collect_lockfile_peer_dependencies;
    use tempfile::TempDir;

    #[test]
    fn npm_lockfile_peer_dependencies_are_read_per_top_level_package() {
        let temp = TempDir::new().unwrap();
        std::fs::write(
            temp.path().join("package-lock.json"),
            r#"{
              "lockfileVersion": 3,
              "packages": {
                "": {},
                "node_modules/bootstrap": {
                  "version": "5.3.8",
                  "peerDependencies": { "@popperjs/core": "^2.11.8" }
                },
                "node_modules/@popperjs/core": { "version": "2.11.8" },
                "node_modules/widget/node_modules/nested": {
                  "version": "1.0.0",
                  "peerDependencies": { "react": "^19.0.0" }
                }
              }
            }"#,
        )
        .unwrap();

        let peers = collect_lockfile_peer_dependencies(temp.path());
        assert!(peers["bootstrap"].contains("@popperjs/core"));
        assert!(
            !peers.contains_key("nested"),
            "nested installs are not the manifest's own"
        );
        assert!(!peers.contains_key("@popperjs/core"));
    }

    #[test]
    fn pnpm_lockfile_peer_dependencies_are_read_from_package_blocks() {
        let temp = TempDir::new().unwrap();
        std::fs::write(
            temp.path().join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n\npackages:\n\n  '@popperjs/core@2.11.8':\n    resolution: {integrity: sha512-x}\n\n  bootstrap@5.3.8:\n    resolution: {integrity: sha512-y}\n    peerDependencies:\n      '@popperjs/core': ^2.11.8\n\n  lodash@4.17.21:\n    resolution: {integrity: sha512-z}\n",
        )
        .unwrap();

        let peers = collect_lockfile_peer_dependencies(temp.path());
        assert!(peers["bootstrap"].contains("@popperjs/core"));
        assert!(!peers.contains_key("lodash"));
    }

    #[test]
    fn missing_lockfiles_yield_no_peer_dependencies() {
        let temp = TempDir::new().unwrap();
        assert!(collect_lockfile_peer_dependencies(temp.path()).is_empty());
    }
}
