//! The fix job's build check: install with the lockfile's package manager,
//! then run the repository's `build` script, both through the allowlisted
//! subprocess. A failing build means no publish.

use std::io::Write;
use std::path::Path;

use super::subprocess::{allowlisted_command, run_captured};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    Npm,
    Pnpm,
    Yarn,
}

/// The lockfile decides; a lone `package.json` means npm.
pub fn detect_package_manager(root: &Path) -> Option<PackageManager> {
    if root.join("pnpm-lock.yaml").is_file() {
        Some(PackageManager::Pnpm)
    } else if root.join("yarn.lock").is_file() {
        Some(PackageManager::Yarn)
    } else if root.join("package-lock.json").is_file() || root.join("package.json").is_file() {
        Some(PackageManager::Npm)
    } else {
        None
    }
}

pub fn package_json(root: &Path) -> Option<serde_json::Value> {
    read_manifest(root).ok().flatten()
}

/// A missing manifest and an unparsable one are different answers: the first
/// means there is nothing to build, the second means the checkout is broken
/// and must not pass the gate. Serde names the line and column, not the path.
fn read_manifest(root: &Path) -> Result<Option<serde_json::Value>, String> {
    let Ok(text) = std::fs::read_to_string(root.join("package.json")) else {
        return Ok(None);
    };
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|error| format!("package.json is not valid JSON: {error}"))
}

pub fn needs_install(manifest: &serde_json::Value) -> bool {
    ["dependencies", "devDependencies"].iter().any(|key| {
        manifest[key]
            .as_object()
            .is_some_and(|deps| !deps.is_empty())
    })
}

pub fn build_script(manifest: &serde_json::Value) -> Option<String> {
    manifest["scripts"]["build"]
        .as_str()
        .filter(|script| !script.trim().is_empty())
        .map(str::to_string)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildOutcome {
    pub ran: bool,
    pub success: bool,
    pub log: String,
}

fn install_args(manager: PackageManager) -> (&'static str, &'static [&'static str]) {
    match manager {
        PackageManager::Npm => ("npm", &["ci", "--no-audit", "--no-fund"]),
        PackageManager::Pnpm => ("pnpm", &["install", "--frozen-lockfile"]),
        PackageManager::Yarn => ("yarn", &["install", "--frozen-lockfile"]),
    }
}

fn build_args(manager: PackageManager) -> (&'static str, &'static [&'static str]) {
    match manager {
        PackageManager::Npm => ("npm", &["run", "build"]),
        PackageManager::Pnpm => ("pnpm", &["run", "build"]),
        PackageManager::Yarn => ("yarn", &["run", "build"]),
    }
}

/// Streams a finished step to the job log. A closed log must not fail a build
/// that otherwise succeeded, so the write result is deliberately dropped.
fn emit(out: &mut dyn Write, step: &str) {
    let _ = out.write_all(step.as_bytes());
    let _ = out.flush();
}

/// The build check with its step log going to the fix job's stdout, which is
/// the workflow log a maintainer reads after a failure.
pub fn run_build_check(root: &Path) -> Result<BuildOutcome, String> {
    run_build_check_with_output(root, &mut std::io::stdout().lock())
}

/// Each step's command line and captured output reach `out` as the step
/// finishes; the same text accumulates in the returned outcome.
pub fn run_build_check_with_output(
    root: &Path,
    out: &mut dyn Write,
) -> Result<BuildOutcome, String> {
    let manifest = match read_manifest(root) {
        Ok(Some(manifest)) => manifest,
        Ok(None) => {
            return Ok(BuildOutcome {
                log: "no package.json; no build to run".into(),
                ran: false,
                success: true,
            })
        }
        Err(reason) => {
            return Ok(BuildOutcome {
                log: reason,
                ran: false,
                success: false,
            })
        }
    };
    let Some(script) = build_script(&manifest) else {
        return Ok(BuildOutcome {
            log: "package.json has no build script; no build to run".into(),
            ran: false,
            success: true,
        });
    };
    let manager = detect_package_manager(root).unwrap_or(PackageManager::Npm);
    let mut log = String::new();
    if needs_install(&manifest) {
        // `npm ci` requires a lockfile; a checkout without one installs instead.
        let install = if manager == PackageManager::Npm && !root.join("package-lock.json").is_file()
        {
            ("npm", &["install", "--no-audit", "--no-fund"][..])
        } else {
            install_args(manager)
        };
        let captured = run_captured(
            allowlisted_command(install.0, install.1, root),
            crate::constants::AUTOFIX_INSTALL_TIMEOUT,
        )?;
        let step = format!("$ {} {}\n{}", install.0, install.1.join(" "), captured.log);
        emit(out, &step);
        log.push_str(&step);
        if captured.status != Some(0) {
            return Ok(BuildOutcome {
                log,
                ran: true,
                success: false,
            });
        }
    }
    let build = build_args(manager);
    let captured = run_captured(
        allowlisted_command(build.0, build.1, root),
        crate::constants::AUTOFIX_BUILD_TIMEOUT,
    )?;
    let step = format!(
        "$ {} {} ({script})\n{}",
        build.0,
        build.1.join(" "),
        captured.log
    );
    emit(out, &step);
    log.push_str(&step);
    Ok(BuildOutcome {
        log,
        ran: true,
        success: captured.status == Some(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &std::path::Path, name: &str, content: &str) {
        std::fs::write(root.join(name), content).unwrap();
    }

    #[test]
    fn detects_the_package_manager_from_the_lockfile() {
        let temp = tempfile::tempdir().unwrap();
        assert_eq!(detect_package_manager(temp.path()), None);
        write(temp.path(), "package.json", "{}");
        assert_eq!(
            detect_package_manager(temp.path()),
            Some(PackageManager::Npm)
        );
        write(temp.path(), "pnpm-lock.yaml", "");
        assert_eq!(
            detect_package_manager(temp.path()),
            Some(PackageManager::Pnpm)
        );
        write(temp.path(), "yarn.lock", "");
        assert_eq!(
            detect_package_manager(temp.path()),
            Some(PackageManager::Pnpm)
        );
        std::fs::remove_file(temp.path().join("pnpm-lock.yaml")).unwrap();
        assert_eq!(
            detect_package_manager(temp.path()),
            Some(PackageManager::Yarn)
        );
    }

    #[test]
    fn reads_the_build_script_and_whether_an_install_is_needed() {
        let manifest: serde_json::Value = serde_json::from_str(
            "{\"scripts\":{\"build\":\"next build\"},\"devDependencies\":{\"next\":\"15\"}}",
        )
        .unwrap();
        assert_eq!(build_script(&manifest).as_deref(), Some("next build"));
        assert!(needs_install(&manifest));
        let bare: serde_json::Value =
            serde_json::from_str("{\"scripts\":{\"build\":\"node build.mjs\"}}").unwrap();
        assert!(!needs_install(&bare));
    }

    #[test]
    fn a_checkout_without_a_build_script_runs_nothing() {
        let temp = tempfile::tempdir().unwrap();
        write(temp.path(), "package.json", "{\"name\":\"x\"}");
        let mut sink = Vec::new();
        let outcome = run_build_check_with_output(temp.path(), &mut sink).unwrap();
        assert_eq!((outcome.ran, outcome.success), (false, true));
        assert!(sink.is_empty());
    }

    #[test]
    fn an_unparsable_manifest_fails_the_build_check() {
        let temp = tempfile::tempdir().unwrap();
        write(
            temp.path(),
            "package.json",
            "{ \"scripts\": { \"build\": \"x\", }",
        );
        let mut sink = Vec::new();
        let outcome = run_build_check_with_output(temp.path(), &mut sink).unwrap();
        assert!(!outcome.ran);
        assert!(!outcome.success);
        assert!(outcome.log.contains("JSON"), "{}", outcome.log);
    }

    #[cfg(unix)]
    #[test]
    fn a_failing_build_script_is_reported_with_its_log() {
        let temp = tempfile::tempdir().unwrap();
        write(
            temp.path(),
            "package.json",
            "{\"scripts\":{\"build\":\"node -e \\\"console.error('boom'); process.exit(2)\\\"\"}}",
        );
        let mut sink = Vec::new();
        let outcome = run_build_check_with_output(temp.path(), &mut sink).unwrap();
        assert!(outcome.ran);
        assert!(!outcome.success);
        assert!(outcome.log.contains("boom"), "{}", outcome.log);
        let streamed = String::from_utf8_lossy(&sink).into_owned();
        assert!(streamed.contains("$ npm run build"), "{streamed}");
        assert!(streamed.contains("boom"), "{streamed}");
    }
}
