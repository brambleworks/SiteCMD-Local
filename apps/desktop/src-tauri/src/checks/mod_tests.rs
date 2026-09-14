// Coverage floor for Web Scan check implementations. Every file that
// implements a check must carry an inline test module or have its check
// structs exercised from a dedicated test file under `src/checks`.
#[test]
fn every_check_file_has_test_coverage() {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("readable checks dir") {
            let path = entry.expect("readable dir entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    // Both check trees: the desktop's and the engine crate's, which check
    // modules move into as the connected-service extraction proceeds.
    let checks_dir = std::path::Path::new(env!("SITECMD_SOURCE_ROOT")).join("src/checks");
    let mut files = Vec::new();
    walk(&checks_dir, &mut files);
    walk(
        &std::path::Path::new(env!("SITECMD_SOURCE_ROOT")).join("crates/engine/src/checks"),
        &mut files,
    );

    let impl_re = regex::Regex::new(r"impl (?:AsyncCheck|Check) for ([A-Za-z0-9_]+)")
        .expect("valid impl regex");

    let mut corpus = String::new();
    let mut untested: Vec<String> = Vec::new();
    let mut impl_files = 0usize;

    for path in &files {
        let content = std::fs::read_to_string(path).expect("readable check source");
        if let Some(offset) = content.find("#[cfg(test)]") {
            corpus.push_str(&content[offset..]);
        }
        if path.components().any(|c| c.as_os_str() == "tests")
            || path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().contains("tests"))
        {
            corpus.push_str(&content);
        }
    }

    for path in &files {
        let content = std::fs::read_to_string(path).expect("readable check source");
        let production = content.split("#[cfg(test)]").next().unwrap_or("");
        let structs: Vec<&str> = impl_re
            .captures_iter(production)
            .map(|capture| capture.get(1).expect("impl capture").as_str())
            .collect();
        if structs.is_empty() {
            continue;
        }
        impl_files += 1;
        if content.contains("#[cfg(test)]") {
            continue;
        }
        for name in structs {
            if !corpus.contains(name) {
                untested.push(format!(
                    "{}: {name}",
                    path.strip_prefix(&checks_dir).unwrap_or(path).display()
                ));
            }
        }
    }

    assert!(
        impl_files >= 60,
        "check file walk collapsed ({impl_files} impl files) - the scan is broken"
    );
    assert!(
        untested.is_empty(),
        "check files with no test coverage (add an inline test module or exercise the check from a tests file): {untested:?}"
    );
}
