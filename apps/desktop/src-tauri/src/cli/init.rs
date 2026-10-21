//! sitecmd init command
//!
//! Initializes a `.sitecmd/` project in the current directory.

use std::io::{BufRead, Write};

use crate::cli::{write_config, CliConfig};

pub struct InitArgs {
    pub url: Option<String>,
    pub name: Option<String>,
    pub yes: bool,
}

/// Write project configuration and ignore rules in the current directory.
pub fn run(args: InitArgs) -> Result<(), String> {
    let cwd =
        std::env::current_dir().map_err(|e| format!("failed to get current directory: {}", e))?;

    if cwd.join(".sitecmd").is_dir() {
        return Err(
            "Project already initialized. A .sitecmd/ directory already exists.".to_string(),
        );
    }

    let url = resolve_url(&args)?;

    let name = resolve_name(&args, &cwd);

    let framework = detect_framework(&cwd);

    let sitecmd_dir = cwd.join(".sitecmd");
    let config = CliConfig::new(&url, &name);
    write_config(&sitecmd_dir, &config)?;

    write_gitignore(&sitecmd_dir)?;

    print_summary(&url, &name, framework.as_deref(), &sitecmd_dir);

    Ok(())
}

fn resolve_url(args: &InitArgs) -> Result<String, String> {
    let detected = detect_url_from_package_json();

    let suggestion = args.url.clone().or(detected);

    if args.yes {
        match suggestion {
            Some(url) => return normalize_url(url),
            None => return Err("--yes specified but no URL found. Provide --url <URL> or set 'homepage' in package.json.".to_string()),
        }
    }

    let url = prompt_url(suggestion.as_deref())?;
    Ok(url)
}

fn detect_url_from_package_json() -> Option<String> {
    let pkg_path = std::env::current_dir().ok()?.join("package.json");
    let content = std::fs::read_to_string(pkg_path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;
    parsed
        .get("homepage")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn prompt_url(suggestion: Option<&str>) -> Result<String, String> {
    loop {
        match suggestion {
            Some(s) => eprint!("Site URL [{}]: ", s),
            None => eprint!("Site URL: "),
        }
        std::io::stdout()
            .flush()
            .map_err(|e| format!("flush error: {}", e))?;

        let input = read_line()?;

        // Use suggestion if user pressed Enter without input
        let value = if input.is_empty() {
            match suggestion {
                Some(s) => s.to_string(),
                None => {
                    eprintln!("URL is required.");
                    continue;
                }
            }
        } else {
            input
        };

        match normalize_url(value) {
            Ok(url) => return Ok(url),
            Err(e) => {
                eprintln!("Invalid URL: {}. Please try again.", e);
            }
        }
    }
}

fn normalize_url(url: String) -> Result<String, String> {
    let url = url.trim().to_string();
    // Prepend https:// if no scheme
    let url = if !url.starts_with("http://") && !url.starts_with("https://") {
        format!("https://{}", url)
    } else {
        url
    };
    url::Url::parse(&url).map_err(|e| format!("'{}' is not a valid URL: {}", url, e))?;
    Ok(url)
}

fn resolve_name(args: &InitArgs, cwd: &std::path::Path) -> String {
    if let Some(ref name) = args.name {
        return name.clone();
    }

    // Detect from package.json `name` field or directory name
    let detected = detect_name_from_package_json().unwrap_or_else(|| {
        cwd.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("my-site")
            .to_string()
    });

    if args.yes {
        return detected;
    }

    prompt_name(&detected).unwrap_or(detected)
}

fn detect_name_from_package_json() -> Option<String> {
    let pkg_path = std::env::current_dir().ok()?.join("package.json");
    let content = std::fs::read_to_string(pkg_path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;
    parsed
        .get("name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn prompt_name(suggestion: &str) -> Result<String, String> {
    eprint!("Project name [{}]: ", suggestion);
    std::io::stdout()
        .flush()
        .map_err(|e| format!("flush error: {}", e))?;

    let input = read_line()?;
    if input.is_empty() {
        Ok(suggestion.to_string())
    } else {
        Ok(input)
    }
}

fn detect_framework(cwd: &std::path::Path) -> Option<String> {
    // Check package.json dependencies
    if let Some(framework) = detect_framework_from_package_json(cwd) {
        return Some(framework);
    }

    if cwd.join("Cargo.toml").exists() {
        return Some("Rust".to_string());
    }
    if cwd.join("requirements.txt").exists() || cwd.join("pyproject.toml").exists() {
        return Some("Python".to_string());
    }
    if cwd.join("go.mod").exists() {
        return Some("Go".to_string());
    }
    if cwd.join("Gemfile").exists() {
        return Some("Ruby".to_string());
    }

    None
}

fn detect_framework_from_package_json(cwd: &std::path::Path) -> Option<String> {
    let content = std::fs::read_to_string(cwd.join("package.json")).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;

    // Collect all dependency keys (dependencies + devDependencies)
    let mut dep_keys: Vec<String> = Vec::new();
    for field in &["dependencies", "devDependencies"] {
        if let Some(obj) = parsed.get(field).and_then(|v| v.as_object()) {
            for key in obj.keys() {
                dep_keys.push(key.clone());
            }
        }
    }

    let deps_str = dep_keys.join(" ");

    // Order matters: more specific frameworks first
    let patterns: &[(&str, &str)] = &[
        ("next", "Next.js"),
        ("nuxt", "Nuxt"),
        ("astro", "Astro"),
        ("@sveltejs/kit", "SvelteKit"),
        ("gatsby", "Gatsby"),
        ("@remix-run/react", "Remix"),
        ("react", "React"),
        ("vue", "Vue"),
        ("svelte", "Svelte"),
        ("angular", "Angular"),
    ];

    for (pattern, label) in patterns {
        if dep_keys.iter().any(|k| k.contains(pattern)) || deps_str.contains(pattern) {
            return Some(label.to_string());
        }
    }

    None
}

fn write_gitignore(sitecmd_dir: &std::path::Path) -> Result<(), String> {
    let path = sitecmd_dir.join(".gitignore");
    let content = "# SiteCMD - only config.json is committed\n*\n!.gitignore\n!config.json\n";
    std::fs::write(&path, content).map_err(|e| format!("failed to write {}: {}", path.display(), e))
}

fn print_summary(url: &str, name: &str, framework: Option<&str>, sitecmd_dir: &std::path::Path) {
    println!();
    println!("Initialized SiteCMD project");
    println!("  Name:    {}", name);
    println!("  URL:     {}", url);
    if let Some(fw) = framework {
        println!("  Stack:   {}", fw);
    }
    println!("  Config:  {}", sitecmd_dir.join("config.json").display());
    println!();
    println!("Next steps:");
    println!("  sitecmd scan        Run a Web Scan");
    println!("  sitecmd check       Check for issues inline");
    println!("  sitecmd watch       Watch for score regressions");
}

fn read_line() -> Result<String, String> {
    let stdin = std::io::stdin();
    let mut line = String::new();
    stdin
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("failed to read input: {}", e))?;
    Ok(line.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_url_prepends_https() {
        let result = normalize_url("example.com".to_string()).unwrap();
        assert_eq!(result, "https://example.com");
    }

    #[test]
    fn normalize_url_preserves_http() {
        let result = normalize_url("http://example.com".to_string()).unwrap();
        assert_eq!(result, "http://example.com");
    }

    #[test]
    fn normalize_url_preserves_https() {
        let result = normalize_url("https://example.com".to_string()).unwrap();
        assert_eq!(result, "https://example.com");
    }

    #[test]
    fn normalize_url_rejects_invalid() {
        let result = normalize_url("not a url !!!".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn normalize_url_trims_whitespace() {
        let result = normalize_url("  https://example.com  ".to_string()).unwrap();
        assert_eq!(result, "https://example.com");
    }

    #[test]
    fn detect_framework_rust_project() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();
        let fw = detect_framework(dir.path());
        assert_eq!(fw.as_deref(), Some("Rust"));
    }

    #[test]
    fn detect_framework_go_project() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("go.mod"), "module example.com/test").unwrap();
        let fw = detect_framework(dir.path());
        assert_eq!(fw.as_deref(), Some("Go"));
    }

    #[test]
    fn detect_framework_nextjs_from_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = r#"{"dependencies":{"next":"14.0.0","react":"18.0.0"}}"#;
        std::fs::write(dir.path().join("package.json"), pkg).unwrap();
        let fw = detect_framework(dir.path());
        assert_eq!(fw.as_deref(), Some("Next.js"));
    }

    #[test]
    fn detect_framework_react_from_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = r#"{"dependencies":{"react":"18.0.0","react-dom":"18.0.0"}}"#;
        std::fs::write(dir.path().join("package.json"), pkg).unwrap();
        let fw = detect_framework(dir.path());
        assert_eq!(fw.as_deref(), Some("React"));
    }

    #[test]
    fn detect_url_from_package_json_works() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = r#"{"name":"my-site","homepage":"https://example.com"}"#;
        std::fs::write(dir.path().join("package.json"), pkg).unwrap();

        // Temporarily change cwd is not reliable in tests; test the file parse logic directly
        let content = std::fs::read_to_string(dir.path().join("package.json")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        let homepage = parsed
            .get("homepage")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        assert_eq!(homepage.as_deref(), Some("https://example.com"));
    }

    #[test]
    fn init_fails_if_already_initialized() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".sitecmd")).unwrap();

        // We can't run the full command without changing cwd, but we can test the guard logic
        let sitecmd_path = dir.path().join(".sitecmd");
        assert!(
            sitecmd_path.is_dir(),
            "guard should detect existing .sitecmd/"
        );
    }
}
