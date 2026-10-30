//! Incomplete Rust module resolution disables project-wide env filtering.

use super::super::super::ProjectFile;
use super::*;

impl RustModuleGraph {
    fn nearest_package(&self, path: &Path) -> Option<&PathBuf> {
        self.cargo_packages
            .iter()
            .filter(|package| path.starts_with(package))
            .max_by_key(|package| package.components().count())
    }

    pub(in crate::core::code_scan) fn finish(&mut self, root: &Path, files: &[ProjectFile]) {
        self.existing_files = files
            .iter()
            .map(|file| normalize(Path::new(&file.relative_path)))
            .collect();
        for path in self.target_roots.keys() {
            if !self.existing_files.contains(path) && root.join(path).exists() {
                self.fallback_reasons.push(format!(
                    "{}: Cargo target root was not inventoried",
                    path.display()
                ));
            }
        }
        for path in &self.existing_files {
            let Some(package) = self.nearest_package(path).cloned() else {
                continue;
            };
            let Ok(relative) = path.strip_prefix(&package) else {
                continue;
            };
            if is_conventional_root(relative) {
                self.target_roots
                    .entry(path.clone())
                    .or_default()
                    .insert(package.clone());
            }
        }
        let (incoming, unresolved) = self.resolve();
        self.fallback_reasons
            .extend(unresolved.into_values().flatten());
        for (path, parents) in &incoming {
            if !self.files.contains_key(path) && parents.iter().any(|(_, test_only)| !test_only) {
                self.fallback_reasons.push(format!(
                    "{}: resolved Rust target was not parsed",
                    path.display()
                ));
            }
        }
        for path in &self.existing_files {
            if path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
                && !self.files.contains_key(path)
                && !super::super::super::is_test_like_path(path)
                && !super::super::super::is_example_like_path(path)
            {
                self.fallback_reasons
                    .push(format!("{}: Rust source was not parsed", path.display()));
            }
        }
        self.fallback_reasons.sort();
        self.fallback_reasons.dedup();
        self.incoming_edges = incoming;
    }
}

fn is_conventional_root(relative: &Path) -> bool {
    relative == Path::new("src/lib.rs")
        || relative == Path::new("src/main.rs")
        || (relative
            .extension()
            .is_some_and(|extension| extension == "rs")
            && relative.parent() == Some(Path::new("src/bin")))
        || (relative.file_name().is_some_and(|name| name == "main.rs")
            && relative.parent().and_then(Path::parent) == Some(Path::new("src/bin")))
}
