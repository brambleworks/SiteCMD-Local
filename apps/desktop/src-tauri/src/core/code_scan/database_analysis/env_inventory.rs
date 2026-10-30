//! Developer configuration inventory from collected source and Cargo build provenance.

use super::*;
use std::sync::LazyLock;

static BUILD_ENV: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"\bprintln!\s*\(\s*"cargo::?rustc-env=([A-Z][A-Z0-9_]*)="#)
        .expect("static Cargo environment emission pattern") // allow-expect: compile-time literal regex
});

pub(in crate::core::code_scan) struct SourceEnvInventory {
    pub(in crate::core::code_scan) keys_by_file: Vec<HashSet<String>>,
    pub(in crate::core::code_scan) all_keys: HashSet<String>,
}

impl SourceEnvInventory {
    pub(in crate::core::code_scan) fn new(
        files: &[SourceFile],
        project_files: &[ProjectFile],
        modules: &scan_scope::RustModuleGraph,
        text_budget: &mut ScanTextBudget<'_>,
    ) -> Result<Self, CodeScanError> {
        let mut packages = HashSet::new();
        let mut scripts = Vec::new();
        for manifest in project_files.iter().filter(|file| {
            Path::new(&file.relative_path)
                .file_name()
                .is_some_and(|name| name == "Cargo.toml")
        }) {
            let package = Path::new(&manifest.relative_path)
                .parent()
                .unwrap_or(Path::new(""));
            packages.insert(package.to_path_buf());
            let Some(content) =
                text_budget.read_project_file(manifest, scan_scope::CARGO_MANIFEST_MAX_BYTES)?
            else {
                continue;
            };
            let Some(script) = scan_scope::cargo_build_script(&content) else {
                continue;
            };
            scripts.push((
                package.to_path_buf(),
                scan_scope::normalize_rust_module_path(&package.join(script)),
            ));
        }
        let by_path = files
            .iter()
            .map(|file| (Path::new(&file.relative_path), file))
            .collect::<HashMap<_, _>>();
        let mut build_keys = HashMap::new();
        for (package, path) in scripts {
            let keys = modules
                .runtime_module_paths(&path)
                .iter()
                .filter_map(|path| by_path.get(path.as_path()))
                .flat_map(|file| emitted_build_keys(file))
                .collect::<HashSet<_>>();
            build_keys.insert(package, keys);
        }
        let test_paths = modules.test_only_paths();
        let keys_by_file = files
            .iter()
            .map(|file| {
                let path = Path::new(&file.relative_path);
                if test_paths.contains(path) {
                    return HashSet::new();
                }
                let package = packages
                    .iter()
                    .filter(|package| path.starts_with(package))
                    .max_by_key(|package| package.components().count());
                let injected = package.and_then(|package| build_keys.get(package));
                if let Some(injected) = injected {
                    env_files::collect_source_env_keys_with_build(file, Some(injected))
                } else {
                    env_files::collect_source_env_keys_from_file(file)
                }
            })
            .collect::<Vec<_>>();
        let all_keys = keys_by_file.iter().flatten().cloned().collect();
        Ok(Self {
            keys_by_file,
            all_keys,
        })
    }
}

fn emitted_build_keys(file: &SourceFile) -> HashSet<String> {
    let content = &file.content;
    let structure = file_analysis::blank_rust_non_code(content);
    BUILD_ENV
        .captures_iter(content)
        .filter(|capture| {
            capture
                .get(0)
                .is_some_and(|whole| !structure.as_bytes()[whole.start()].is_ascii_whitespace())
        })
        .map(|capture| capture[1].to_string())
        .collect()
}
