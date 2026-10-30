//! Rust module facts for environment inventory and inline test sanitization.

use super::{is_rust_test_only_file, Path};
use std::collections::{HashMap, HashSet};
use std::path::{Component, PathBuf};
mod attributes;
mod declarations;
use declarations::{modules, Module};
mod includes;
mod macros;

mod resolution;

type IncomingEdges = HashMap<PathBuf, Vec<(PathBuf, bool)>>;
type UnresolvedModules = HashMap<PathBuf, Vec<String>>;

struct DeclarationResolution {
    name: String,
    resolved: bool,
    uncertainty: Option<&'static str>,
}

pub(in crate::core::code_scan) fn strip_rust_test_modules(content: &str) -> Option<String> {
    let modules = modules(content);
    let mut result = String::new();
    let mut offset = 0;
    for module in modules
        .iter()
        .filter(|module| module.inline && module.test_only)
    {
        if module.start < offset {
            continue;
        }
        result.push_str(&content[offset..module.start]);
        offset = module.end;
        if !content[offset..].trim().is_empty() {
            result.extend(
                content[module.start..offset]
                    .chars()
                    .filter(|value| *value == '\n'),
            );
        } else {
            offset = content.len();
        }
    }
    if offset == 0 {
        return None;
    }
    result.push_str(&content[offset..]);
    result.shrink_to_fit();
    Some(result)
}

#[derive(Clone, Default, Debug)]
pub(in crate::core::code_scan) struct RustModuleGraph {
    files: HashMap<PathBuf, Vec<Module>>,
    test_files: HashSet<PathBuf>,
    cargo_packages: HashSet<PathBuf>,
    target_roots: HashMap<PathBuf, HashSet<PathBuf>>,
    existing_files: HashSet<PathBuf>,
    incoming_edges: IncomingEdges,
    fallback_reasons: Vec<String>,
}

impl RustModuleGraph {
    pub(in crate::core::code_scan) fn add_cargo_manifest(
        &mut self,
        path: &Path,
        content: Option<&str>,
    ) {
        let package = path.parent().unwrap_or(Path::new(""));
        self.cargo_packages.insert(package.to_path_buf());
        let Some(content) = content else {
            self.fallback_reasons.push(format!(
                "{}: Cargo manifest could not be read",
                path.display()
            ));
            return;
        };
        if let Ok(document) = content.parse::<toml_edit::DocumentMut>() {
            if let Some(path) = document
                .get("lib")
                .and_then(|lib| lib.get("path"))
                .and_then(|path| path.as_str())
            {
                self.target_roots
                    .entry(normalize(&package.join(path)))
                    .or_default()
                    .insert(package.to_path_buf());
            }
            if let Some(bins) = document
                .get("bin")
                .and_then(|bins| bins.as_array_of_tables())
            {
                for bin in bins {
                    if let Some(path) = bin.get("path").and_then(|path| path.as_str()) {
                        self.target_roots
                            .entry(normalize(&package.join(path)))
                            .or_default()
                            .insert(package.to_path_buf());
                    }
                }
            }
            if let Some(bins) = document.get("bin").and_then(|bins| bins.as_array()) {
                for bin in bins {
                    if let Some(path) = bin
                        .as_inline_table()
                        .and_then(|bin| bin.get("path"))
                        .and_then(|path| path.as_str())
                    {
                        self.target_roots
                            .entry(normalize(&package.join(path)))
                            .or_default()
                            .insert(package.to_path_buf());
                    }
                }
            }
        } else {
            self.fallback_reasons.push(format!(
                "{}: Cargo manifest could not be parsed",
                path.display()
            ));
        }
        if let Some(script) = super::cargo_build_script(content) {
            self.target_roots
                .entry(normalize(&package.join(script)))
                .or_default()
                .insert(package.to_path_buf());
        }
    }

    fn is_cargo_target_root(&self, path: &Path) -> bool {
        self.target_roots.contains_key(path)
    }

    pub(in crate::core::code_scan) fn add_file(&mut self, path: &Path, content: &str) {
        if !path
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
        {
            return;
        }
        let path = normalize(path);
        if super::super::is_test_like_path(&path) || is_rust_test_only_file(&path, content) {
            self.test_files.insert(path.clone());
        }
        self.files.insert(path, modules(content));
    }

    fn targets(
        &self,
        path: &Path,
        module: &Module,
        path_loaded: &HashSet<PathBuf>,
        named_loaded: &HashSet<PathBuf>,
    ) -> Vec<PathBuf> {
        let parent = path.parent().unwrap_or(Path::new(""));
        let stem = path
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        let crate_or_mod = stem == "mod" || self.is_cargo_target_root(path);
        let mut directories = Vec::new();
        if crate_or_mod || path_loaded.contains(path) {
            directories.push(parent.to_path_buf());
        }
        if !crate_or_mod && (!path_loaded.contains(path) || named_loaded.contains(path)) {
            directories.push(parent.join(stem));
        }
        directories
            .into_iter()
            .flat_map(|mut base| {
                for name in &module.parents {
                    base.push(name);
                }
                if let Some(override_path) = &module.path {
                    let base = if module.parents.is_empty() {
                        parent
                    } else {
                        &base
                    };
                    vec![base.join(override_path)]
                } else {
                    vec![
                        base.join(format!("{}.rs", module.name)),
                        base.join(&module.name).join("mod.rs"),
                    ]
                }
            })
            .map(|target| normalize(&target))
            .collect()
    }

    fn resolve(&self) -> (IncomingEdges, UnresolvedModules) {
        let mut path_loaded = HashSet::new();
        let mut named_loaded = HashSet::new();
        loop {
            let mut next_paths = HashSet::new();
            let mut next_names = HashSet::new();
            for (path, modules) in &self.files {
                for module in modules.iter().filter(|module| !module.inline) {
                    let next = if module.path.is_some() {
                        &mut next_paths
                    } else {
                        &mut next_names
                    };
                    next.extend(
                        self.targets(path, module, &path_loaded, &named_loaded)
                            .into_iter()
                            .filter(|path| self.existing_files.contains(path)),
                    );
                }
            }
            let count = path_loaded.len() + named_loaded.len();
            path_loaded.extend(next_paths);
            named_loaded.extend(next_names);
            if count == path_loaded.len() + named_loaded.len() {
                break;
            }
        }
        let mut incoming: HashMap<PathBuf, Vec<(PathBuf, bool)>> = HashMap::new();
        let mut unresolved: HashMap<PathBuf, Vec<String>> = HashMap::new();
        for (path, modules) in &self.files {
            let mut declarations: HashMap<usize, DeclarationResolution> = HashMap::new();
            for module in modules {
                let declaration =
                    declarations
                        .entry(module.start)
                        .or_insert_with(|| DeclarationResolution {
                            name: module.name.clone(),
                            resolved: module.inline,
                            uncertainty: None,
                        });
                declaration.uncertainty = declaration.uncertainty.or(module.uncertainty);
                if module.inline {
                    continue;
                }
                for target in self.targets(path, module, &path_loaded, &named_loaded) {
                    if self.existing_files.contains(&target) {
                        declaration.resolved = true;
                        incoming
                            .entry(target)
                            .or_default()
                            .push((path.clone(), module.test_only));
                    }
                }
            }
            for (_, declaration) in declarations {
                let reason = if let Some(reason) = declaration.uncertainty {
                    reason
                } else if !declaration.resolved {
                    "no existing module file"
                } else {
                    continue;
                };
                unresolved.entry(path.clone()).or_default().push(format!(
                    "{}: mod {}: {reason}",
                    path.display(),
                    declaration.name
                ));
            }
        }
        (incoming, unresolved)
    }

    pub(in crate::core::code_scan) fn test_only_paths(&self) -> HashSet<PathBuf> {
        self.tests_from(&self.incoming_edges)
    }

    fn tests_from(&self, incoming: &HashMap<PathBuf, Vec<(PathBuf, bool)>>) -> HashSet<PathBuf> {
        // The graph sees only edges written in the scanned text, so a module loaded by a
        // dependency's macro, or a package outside the scan root that loads a file inside
        // it, cannot be seen.
        if !self.fallback_reasons.is_empty() {
            return HashSet::new();
        }
        let mut tests = self.test_files.clone();
        loop {
            let next = incoming
                .iter()
                .filter(|(path, parents)| {
                    !tests.contains(*path)
                        && !self.is_cargo_target_root(path)
                        && parents
                            .iter()
                            .all(|(parent, test_only)| *test_only || tests.contains(parent))
                })
                .map(|(path, _)| path.clone())
                .collect::<Vec<_>>();
            if next.is_empty() {
                return tests;
            }
            tests.extend(next);
        }
    }

    pub(in crate::core::code_scan) fn runtime_module_paths(&self, root: &Path) -> HashSet<PathBuf> {
        let root = normalize(root);
        let incoming = &self.incoming_edges;
        let tests = self.tests_from(incoming);
        let mut paths = HashSet::from([root]);
        loop {
            let next = incoming
                .iter()
                .filter(|(path, parents)| {
                    !paths.contains(*path)
                        && !tests.contains(*path)
                        && parents
                            .iter()
                            .any(|(parent, test_only)| !test_only && paths.contains(parent))
                })
                .map(|(path, _)| path.clone())
                .collect::<Vec<_>>();
            if next.is_empty() {
                return paths;
            }
            paths.extend(next);
        }
    }
}

pub(in crate::core::code_scan) fn normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => match normalized.components().next_back() {
                Some(Component::Normal(_)) => {
                    normalized.pop();
                }
                Some(Component::RootDir) => {}
                _ => normalized.push(component.as_os_str()),
            },
            Component::CurDir => {}
            value => normalized.push(value.as_os_str()),
        }
    }
    normalized
}
