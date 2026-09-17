use std::fs;

use serde_json::json;
use tempfile::tempdir;

use super::{
    inspect_watch_files, matches_watch_pattern, parse_project_command, resolve_existing_path,
    resolve_existing_watch_paths, resolve_registered_project_target, validate_external_browser_url,
    validate_project_command_policy, ActionableDesktopNotificationRequest, DesktopWatchRequest,
    MAX_EXTERNAL_BROWSER_URL_CHARS,
};

#[test]
fn external_browser_urls_accept_product_and_third_party_sites() {
    for value in [
        "https://sitecmd.com/docs",
        "https://www.bing.com/webmasters/",
        "https://github.com/brambleworks/SiteCMD-Local",
        "http://localhost:4321/",
    ] {
        let parsed = validate_external_browser_url(&format!(" {value} "))
            .expect("ordinary web links should be allowed");
        assert_eq!(parsed.as_str(), value);
    }
}

#[test]
fn external_browser_urls_require_http_without_embedded_credentials() {
    for unsafe_url in [
        "",
        "not a URL",
        "https://",
        "file:///Users/dev/private.txt",
        "javascript:alert(1)",
        "data:text/html,hello",
        "mailto:hello@example.com",
        "https://user@example.com/private",
        "https://user:token@example.com/private",
        "https://example.com/\nsecond-line",
        "https://example.com/\u{0}control",
    ] {
        assert!(
            validate_external_browser_url(unsafe_url).is_err(),
            "{unsafe_url} should be rejected"
        );
    }
}

#[test]
fn external_browser_urls_enforce_the_length_limit() {
    let prefix = "https://example.com/";
    let at_limit = format!(
        "{prefix}{}",
        "a".repeat(MAX_EXTERNAL_BROWSER_URL_CHARS - prefix.len())
    );
    assert!(validate_external_browser_url(&at_limit).is_ok());
    assert!(validate_external_browser_url(&format!("{at_limit}a")).is_err());
}

#[test]
fn parse_project_command_splits_quoted_args() {
    let (program, args) =
        parse_project_command(r#"npm install "react dom""#).expect("command should parse");

    assert_eq!(program, "npm");
    assert_eq!(args, vec!["install".to_string(), "react dom".to_string()]);
}

#[test]
fn parse_project_command_rejects_shell_chaining() {
    let error = parse_project_command("npm install && npm run build")
        .expect_err("shell chaining should be rejected");

    assert!(error.contains("Shell chaining"));
}

#[test]
fn validate_project_command_policy_rejects_interpreters_and_git() {
    for executable in ["node", "python", "npx", "git", "docker"] {
        let error = validate_project_command_policy(executable, &[])
            .expect_err("dangerous executable should be blocked");
        assert!(error.contains("allowed list"));
    }
}

#[test]
fn validate_project_command_policy_rejects_package_manager_script_escape_hatches() {
    let args = vec!["run".to_string(), "postinstall".to_string()];
    let error = validate_project_command_policy("npm", &args)
        .expect_err("script execution should be blocked");

    assert!(error.contains("not allowed"));
}

#[test]
fn validate_project_command_policy_rejects_package_manager_lifecycle_and_script_aliases() {
    let blocked = [
        ("npm", vec!["test"]),
        ("npm", vec!["start"]),
        ("npm", vec!["build"]),
        ("npm", vec!["rebuild"]),
        ("npm", vec!["remove", "react"]),
        ("npm", vec!["explore", "react", "--", "sh"]),
        // npm aliases and abbreviations resolve to the same script runners.
        ("npm", vec!["run-script", "postinstall"]),
        ("npm", vec!["rum", "postinstall"]),
        ("npm", vec!["urn", "postinstall"]),
        ("npm", vec!["ru", "postinstall"]),
        ("npm", vec!["t"]),
        ("npm", vec!["tst"]),
        ("npm", vec!["rb"]),
        ("npm", vec!["un", "react"]),
        ("npm", vec!["rm", "react"]),
        ("npm", vec!["r", "react"]),
        ("npm", vec!["unlink", "react"]),
        ("npm", vec!["it"]),
        ("npm", vec!["install-test"]),
        ("npm", vec!["cit"]),
        ("npm", vec!["sit"]),
        ("npm", vec!["clean-install-test"]),
        // install aliases that would dodge the --ignore-scripts requirement.
        ("npm", vec!["ic"]),
        ("npm", vec!["clean-install"]),
        ("npm", vec!["u"]),
        ("npm", vec!["upgrade"]),
        // commands that run lifecycle scripts or fetch and execute packages.
        ("npm", vec!["init", "vite"]),
        ("npm", vec!["create", "vite"]),
        ("npm", vec!["version", "patch"]),
        ("npm", vec!["pack"]),
        ("npm", vec!["publish"]),
        ("npm", vec!["link"]),
        ("pnpm", vec!["build"]),
        ("pnpm", vec!["remove", "react"]),
        ("pnpm", vec!["rebuild"]),
        ("pnpm", vec!["approve-builds"]),
        ("yarn", vec!["build"]),
        ("yarn", vec!["remove", "react"]),
        ("yarn", vec!["rebuild"]),
        ("bun", vec!["test"]),
        ("bun", vec!["remove", "react"]),
        ("bun", vec!["pm", "trust", "react"]),
    ];

    for (executable, raw_args) in blocked {
        let args = raw_args
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>();
        let error = validate_project_command_policy(executable, &args)
            .expect_err("package-manager script aliases should require terminal review");
        assert!(
            error.contains("not allowed"),
            "{executable} {raw_args:?} should explain script alias risk: {error}"
        );
    }
}

#[test]
fn validate_project_command_policy_rejects_installs_that_can_run_lifecycle_scripts() {
    let args = vec!["install".to_string(), "react@19.0.0".to_string()];

    let error = validate_project_command_policy("npm", &args)
        .expect_err("dependency installs should require lifecycle script opt-out");

    assert!(error.contains("lifecycle scripts"));
    assert!(error.contains("--ignore-scripts"));
}

#[test]
fn validate_project_command_policy_allows_installs_with_script_opt_out() {
    let args = vec![
        "install".to_string(),
        "react@19.0.0".to_string(),
        "--ignore-scripts".to_string(),
    ];

    validate_project_command_policy("npm", &args)
        .expect("curated dependency install with script opt-out should be allowed");
}

#[test]
fn validate_project_command_policy_rejects_false_script_opt_out_values() {
    let args = vec![
        "install".to_string(),
        "react@19.0.0".to_string(),
        "--ignore-scripts=false".to_string(),
    ];

    let error = validate_project_command_policy("npm", &args)
        .expect_err("false script opt-out values should not count as safe");

    assert!(error.contains("lifecycle scripts"));
}

#[test]
fn validate_project_command_policy_rejects_leading_flags_that_hide_the_command() {
    let args = vec![
        "--ignore-scripts".to_string(),
        "run".to_string(),
        "postinstall".to_string(),
    ];

    let error = validate_project_command_policy("npm", &args)
        .expect_err("leading flags should not hide the command from policy checks");

    assert!(error.contains("command name before flags"));
}

#[test]
fn validate_project_command_policy_blocks_installers_without_safe_script_opt_outs() {
    let blocked = [
        (
            "composer",
            vec!["require".to_string(), "vendor/package".to_string()],
        ),
        ("gem", vec!["install".to_string(), "somegem".to_string()]),
        (
            "cargo",
            vec!["install".to_string(), "some-crate".to_string()],
        ),
    ];

    for (executable, args) in blocked {
        let error = validate_project_command_policy(executable, &args)
            .expect_err("installer should require terminal review or script opt-out");
        assert!(
            error.contains("lifecycle scripts")
                || error.contains("third-party build/install code")
                || error.contains("Composer plugins"),
            "{executable} should explain installer risk: {error}"
        );
    }
}

#[test]
fn validate_project_command_policy_requires_composer_script_and_plugin_opt_outs() {
    let scripts_only = vec![
        "require".to_string(),
        "vendor/package".to_string(),
        "--no-scripts".to_string(),
    ];
    let error = validate_project_command_policy("composer", &scripts_only)
        .expect_err("Composer plugins can execute code even when scripts are disabled");
    assert!(error.contains("--no-plugins"));

    let args = vec![
        "require".to_string(),
        "vendor/package".to_string(),
        "--no-scripts".to_string(),
        "--no-plugins".to_string(),
    ];

    validate_project_command_policy("composer", &args)
        .expect("Composer dependency command with scripts and plugins disabled should be allowed");
}

#[test]
fn resolve_registered_project_target_allows_files_inside_registered_projects() {
    let dir = tempdir().expect("tempdir");
    let project_dir = dir.path().join("project");
    let nested_file = project_dir.join("src").join("index.ts");
    fs::create_dir_all(nested_file.parent().expect("parent")).expect("create tree");
    fs::write(&nested_file, "export {}").expect("write file");

    let projects = vec![crate::db::ProjectRecord {
        id: 1,
        name: "Example".to_string(),
        path: project_dir.to_string_lossy().to_string(),
        framework: None,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        secret_namespace: "desktop-test".to_string(),
        environments: vec![],
    }];

    let resolved =
        resolve_registered_project_target(&projects, nested_file.to_str().expect("utf8 path"))
            .expect("path should be accepted");

    assert_eq!(
        resolved,
        nested_file.canonicalize().expect("canonical file")
    );
}

#[test]
fn resolve_registered_project_target_rejects_files_outside_registered_projects() {
    let dir = tempdir().expect("tempdir");
    let project_dir = dir.path().join("project");
    let outside_file = dir.path().join("notes.txt");
    fs::create_dir_all(&project_dir).expect("create project");
    fs::write(&outside_file, "hello").expect("write file");

    let projects = vec![crate::db::ProjectRecord {
        id: 1,
        name: "Example".to_string(),
        path: project_dir.to_string_lossy().to_string(),
        framework: None,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        secret_namespace: "desktop-test".to_string(),
        environments: vec![],
    }];

    let error =
        resolve_registered_project_target(&projects, outside_file.to_str().expect("utf8 path"))
            .expect_err("outside path should be rejected");

    assert!(error.contains("registered project"));
}

#[test]
fn parse_project_command_rejects_multiline_input() {
    let error = parse_project_command("npm install\nnpm run build")
        .expect_err("multiline command should be rejected");

    assert!(error.contains("Multi-line"));
}

#[test]
fn resolve_existing_path_rejects_traversal_outside_project() {
    let dir = tempdir().expect("tempdir");
    let project_dir = dir.path().join("project");
    fs::create_dir_all(&project_dir).expect("create project");
    let outside_file = dir.path().join("secret.txt");
    fs::write(&outside_file, "secret").expect("write outside file");

    let resolved = resolve_existing_path(&project_dir, "../secret.txt");

    assert!(resolved.is_none());
}

#[test]
fn actionable_notification_request_preserves_exact_scan_targets() {
    let request: ActionableDesktopNotificationRequest = serde_json::from_value(json!({
        "id": "scan:1",
        "title": "Scan Complete",
        "body": "Open exact results",
        "clickTarget": {
            "page": "scans",
            "projectId": 42,
            "url": "https://example.com/",
            "scanId": 88,
            "sessionId": 12,
            "scanKind": "site",
            "focus": "seo",
            "itemId": "issue-1",
            "promptId": "prompt-1",
            "lane": "pending-verification",
            "reason": "fresh-scan",
            "filePath": "/tmp/report.json",
            "restoreScan": true
        },
        "actions": [
            {
                "id": "open-results",
                "label": "Open Results",
                "target": {
                    "page": "scans",
                    "projectId": 42,
                    "url": "https://example.com/",
                    "scanId": 88,
                    "sessionId": 12,
                    "scanKind": "code"
                }
            }
        ]
    }))
    .expect("request should deserialize");

    let click_target = request.click_target.expect("click target");
    assert_eq!(click_target.page, "scans");
    assert_eq!(click_target.project_id, Some(42));
    assert_eq!(click_target.url.as_deref(), Some("https://example.com/"));
    assert_eq!(click_target.scan_id, Some(88));
    assert_eq!(click_target.session_id, Some(12));
    assert_eq!(click_target.scan_kind.as_deref(), Some("site"));
    assert_eq!(click_target.focus.as_deref(), Some("seo"));
    assert_eq!(click_target.item_id.as_deref(), Some("issue-1"));
    assert_eq!(click_target.prompt_id.as_deref(), Some("prompt-1"));
    assert_eq!(click_target.lane.as_deref(), Some("pending-verification"));
    assert_eq!(click_target.reason.as_deref(), Some("fresh-scan"));
    assert_eq!(click_target.file_path.as_deref(), Some("/tmp/report.json"));
    assert!(click_target.restore_scan);

    let action_target = request
        .actions
        .first()
        .and_then(|action| action.target.as_ref())
        .expect("action target");
    assert_eq!(action_target.scan_id, Some(88));
    assert_eq!(action_target.session_id, Some(12));
    assert_eq!(action_target.scan_kind.as_deref(), Some("code"));
}

#[test]
fn matches_watch_pattern_supports_simple_filename_globs() {
    assert!(matches_watch_pattern("robots.txt.tsx", "robots.txt.*"));
    assert!(matches_watch_pattern("serverless.yaml", "serverless.y*ml"));
    assert!(matches_watch_pattern("next.config.mjs", "next.config.*"));
    assert!(!matches_watch_pattern("robots.ts", "robots.txt.*"));
}

#[test]
fn resolve_existing_watch_paths_returns_matching_files_for_globs() {
    let dir = tempdir().expect("tempdir");
    let app_dir = dir.path().join("app");
    fs::create_dir_all(&app_dir).expect("create app dir");
    fs::write(app_dir.join("robots.ts"), "export default {};").expect("write robots ts");
    fs::write(app_dir.join("robots.js"), "export default {};").expect("write robots js");
    fs::write(app_dir.join("other.ts"), "export default {};").expect("write unrelated file");

    let matches = resolve_existing_watch_paths(dir.path(), "app/robots.*");
    let relative_paths = matches
        .iter()
        .map(|(relative_path, path)| {
            assert!(path.is_file());
            relative_path.clone()
        })
        .collect::<Vec<_>>();

    assert_eq!(
        relative_paths,
        vec!["app/robots.js".to_string(), "app/robots.ts".to_string(),]
    );
}

#[test]
fn inspect_watch_files_detects_next_app_robots_routes() {
    let dir = tempdir().expect("tempdir");
    let app_dir = dir.path().join("src/app");
    fs::create_dir_all(&app_dir).expect("create app dir");
    fs::write(
        app_dir.join("robots.ts"),
        "export default function robots() {}",
    )
    .expect("write robots route");

    let signals = inspect_watch_files(&[DesktopWatchRequest {
        project_id: 7,
        project_path: dir.path().to_string_lossy().to_string(),
        primary_url: Some("https://example.com".to_string()),
    }]);

    let robots_signal = signals
        .iter()
        .find(|signal| signal.relative_path == "src/app/robots.ts")
        .expect("robots signal");

    assert_eq!(robots_signal.page, "search-console");
    assert_eq!(robots_signal.kind, "robots");
    assert_eq!(robots_signal.focus.as_deref(), Some("seo.robots"));
    assert_eq!(robots_signal.url.as_deref(), Some("https://example.com"));
}

#[test]
fn inspect_watch_files_detects_astro_robots_routes() {
    let dir = tempdir().expect("tempdir");
    let pages_dir = dir.path().join("src/pages");
    fs::create_dir_all(&pages_dir).expect("create pages dir");
    fs::write(
        pages_dir.join("robots.txt.ts"),
        "export async function GET() { return new Response(\"User-agent: *\"); }",
    )
    .expect("write astro robots route");

    let signals = inspect_watch_files(&[DesktopWatchRequest {
        project_id: 11,
        project_path: dir.path().to_string_lossy().to_string(),
        primary_url: Some("https://example.com".to_string()),
    }]);

    let robots_signal = signals
        .iter()
        .find(|signal| signal.relative_path == "src/pages/robots.txt.ts")
        .expect("astro robots signal");

    assert_eq!(robots_signal.page, "search-console");
    assert_eq!(robots_signal.kind, "robots");
    assert_eq!(robots_signal.focus.as_deref(), Some("seo.robots"));
    assert_eq!(robots_signal.url.as_deref(), Some("https://example.com"));
}

#[test]
fn inspect_watch_files_detects_remix_robots_routes() {
    let dir = tempdir().expect("tempdir");
    let routes_dir = dir.path().join("app/routes");
    fs::create_dir_all(&routes_dir).expect("create routes dir");
    fs::write(
        routes_dir.join("robots.txt.tsx"),
        "export function loader() { return new Response(\"User-agent: *\"); }",
    )
    .expect("write remix robots route");

    let signals = inspect_watch_files(&[DesktopWatchRequest {
        project_id: 15,
        project_path: dir.path().to_string_lossy().to_string(),
        primary_url: Some("https://example.com".to_string()),
    }]);

    let robots_signal = signals
        .iter()
        .find(|signal| signal.relative_path == "app/routes/robots.txt.tsx")
        .expect("remix robots signal");

    assert_eq!(robots_signal.page, "search-console");
    assert_eq!(robots_signal.kind, "robots");
    assert_eq!(robots_signal.focus.as_deref(), Some("seo.robots"));
    assert_eq!(robots_signal.url.as_deref(), Some("https://example.com"));
}

#[test]
fn inspect_watch_files_detects_remix_sitemap_routes() {
    let dir = tempdir().expect("tempdir");
    let routes_dir = dir.path().join("app/routes");
    fs::create_dir_all(&routes_dir).expect("create routes dir");
    fs::write(
        routes_dir.join("sitemap.xml.ts"),
        "export function loader() { return new Response(\"<urlset />\"); }",
    )
    .expect("write remix sitemap route");

    let signals = inspect_watch_files(&[DesktopWatchRequest {
        project_id: 28,
        project_path: dir.path().to_string_lossy().to_string(),
        primary_url: Some("https://example.com".to_string()),
    }]);

    let sitemap_signal = signals
        .iter()
        .find(|signal| signal.relative_path == "app/routes/sitemap.xml.ts")
        .expect("remix sitemap signal");

    assert_eq!(sitemap_signal.page, "search-console");
    assert_eq!(sitemap_signal.kind, "sitemap");
    assert_eq!(sitemap_signal.focus.as_deref(), Some("seo.sitemap"));
    assert_eq!(sitemap_signal.url.as_deref(), Some("https://example.com"));
}

#[test]
fn inspect_watch_files_detects_next_sitemap_config() {
    let dir = tempdir().expect("tempdir");
    fs::write(
        dir.path().join("next-sitemap.config.ts"),
        "export default { siteUrl: \"https://example.com\" };",
    )
    .expect("write sitemap config");

    let signals = inspect_watch_files(&[DesktopWatchRequest {
        project_id: 8,
        project_path: dir.path().to_string_lossy().to_string(),
        primary_url: Some("https://example.com".to_string()),
    }]);

    let sitemap_signal = signals
        .iter()
        .find(|signal| signal.relative_path == "next-sitemap.config.ts")
        .expect("sitemap signal");

    assert_eq!(sitemap_signal.page, "search-console");
    assert_eq!(sitemap_signal.kind, "sitemap");
    assert_eq!(sitemap_signal.focus.as_deref(), Some("seo.sitemap"));
    assert_eq!(sitemap_signal.url.as_deref(), Some("https://example.com"));
}

#[test]
fn inspect_watch_files_detects_nuxt_server_sitemap_routes() {
    let dir = tempdir().expect("tempdir");
    let routes_dir = dir.path().join("server/routes");
    fs::create_dir_all(&routes_dir).expect("create routes dir");
    fs::write(
        routes_dir.join("sitemap.xml.ts"),
        "export default defineEventHandler(() => '<urlset />');",
    )
    .expect("write nuxt sitemap route");

    let signals = inspect_watch_files(&[DesktopWatchRequest {
        project_id: 16,
        project_path: dir.path().to_string_lossy().to_string(),
        primary_url: Some("https://example.com".to_string()),
    }]);

    let sitemap_signal = signals
        .iter()
        .find(|signal| signal.relative_path == "server/routes/sitemap.xml.ts")
        .expect("nuxt sitemap signal");

    assert_eq!(sitemap_signal.page, "search-console");
    assert_eq!(sitemap_signal.kind, "sitemap");
    assert_eq!(sitemap_signal.focus.as_deref(), Some("seo.sitemap"));
    assert_eq!(sitemap_signal.url.as_deref(), Some("https://example.com"));
}

#[test]
fn inspect_watch_files_detects_sveltekit_sitemap_routes() {
    let dir = tempdir().expect("tempdir");
    let routes_dir = dir.path().join("src/routes/sitemap.xml");
    fs::create_dir_all(&routes_dir).expect("create routes dir");
    fs::write(
        routes_dir.join("+server.ts"),
        "export async function GET() { return new Response(\"<urlset />\"); }",
    )
    .expect("write sveltekit sitemap route");

    let signals = inspect_watch_files(&[DesktopWatchRequest {
        project_id: 12,
        project_path: dir.path().to_string_lossy().to_string(),
        primary_url: Some("https://example.com".to_string()),
    }]);

    let sitemap_signal = signals
        .iter()
        .find(|signal| signal.relative_path == "src/routes/sitemap.xml/+server.ts")
        .expect("sveltekit sitemap signal");

    assert_eq!(sitemap_signal.page, "search-console");
    assert_eq!(sitemap_signal.kind, "sitemap");
    assert_eq!(sitemap_signal.focus.as_deref(), Some("seo.sitemap"));
    assert_eq!(sitemap_signal.url.as_deref(), Some("https://example.com"));
}

#[test]
fn inspect_watch_files_detects_next_middleware_as_security_header_work() {
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("create src dir");
    fs::write(
        dir.path().join("src/middleware.ts"),
        "import { NextResponse } from \"next/server\";\nexport function middleware() { return NextResponse.next(); }",
    )
    .expect("write middleware file");

    let signals = inspect_watch_files(&[DesktopWatchRequest {
        project_id: 9,
        project_path: dir.path().to_string_lossy().to_string(),
        primary_url: Some("https://example.com".to_string()),
    }]);

    let middleware_signal = signals
        .iter()
        .find(|signal| signal.relative_path == "src/middleware.ts")
        .expect("middleware signal");

    assert_eq!(middleware_signal.page, "issues");
    assert_eq!(middleware_signal.kind, "security-headers");
    assert_eq!(middleware_signal.focus.as_deref(), Some("sec.headers"));
    assert_eq!(
        middleware_signal.url.as_deref(),
        Some("https://example.com")
    );
}

#[test]
fn inspect_watch_files_detects_sveltekit_hooks_as_security_header_work() {
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("create src dir");
    fs::write(
        dir.path().join("src/hooks.server.ts"),
        "export const handle = async ({ event, resolve }) => resolve(event);",
    )
    .expect("write hooks file");

    let signals = inspect_watch_files(&[DesktopWatchRequest {
        project_id: 13,
        project_path: dir.path().to_string_lossy().to_string(),
        primary_url: Some("https://example.com".to_string()),
    }]);

    let hooks_signal = signals
        .iter()
        .find(|signal| signal.relative_path == "src/hooks.server.ts")
        .expect("hooks signal");

    assert_eq!(hooks_signal.page, "issues");
    assert_eq!(hooks_signal.kind, "security-headers");
    assert_eq!(hooks_signal.focus.as_deref(), Some("sec.headers"));
    assert_eq!(hooks_signal.url.as_deref(), Some("https://example.com"));
}

#[test]
fn inspect_watch_files_detects_traefik_config_as_security_header_work() {
    let dir = tempdir().expect("tempdir");
    fs::write(
        dir.path().join("traefik.yml"),
        "http:\n  middlewares:\n    secure-headers:\n      headers:\n        stsSeconds: 31536000",
    )
    .expect("write traefik config");

    let signals = inspect_watch_files(&[DesktopWatchRequest {
        project_id: 18,
        project_path: dir.path().to_string_lossy().to_string(),
        primary_url: Some("https://example.com".to_string()),
    }]);

    let traefik_signal = signals
        .iter()
        .find(|signal| signal.relative_path == "traefik.yml")
        .expect("traefik signal");

    assert_eq!(traefik_signal.page, "issues");
    assert_eq!(traefik_signal.kind, "security-headers");
    assert_eq!(traefik_signal.focus.as_deref(), Some("sec.headers"));
    assert_eq!(traefik_signal.url.as_deref(), Some("https://example.com"));
}

#[test]
fn inspect_watch_files_detects_auth_config_as_security_cookie_work() {
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("create src dir");
    fs::write(
        dir.path().join("src/auth.ts"),
        "export const authOptions = { session: { strategy: 'jwt' } };",
    )
    .expect("write auth config");

    let signals = inspect_watch_files(&[DesktopWatchRequest {
        project_id: 20,
        project_path: dir.path().to_string_lossy().to_string(),
        primary_url: Some("https://example.com".to_string()),
    }]);

    let auth_signal = signals
        .iter()
        .find(|signal| signal.relative_path == "src/auth.ts")
        .expect("auth signal");

    assert_eq!(auth_signal.page, "issues");
    assert_eq!(auth_signal.kind, "auth-session");
    assert_eq!(auth_signal.focus.as_deref(), Some("sec.cookies"));
    assert_eq!(auth_signal.url.as_deref(), Some("https://example.com"));
}

#[test]
fn inspect_watch_files_detects_nextauth_route_as_security_cookie_work() {
    let dir = tempdir().expect("tempdir");
    let auth_dir = dir.path().join("src/app/api/auth/[...nextauth]");
    fs::create_dir_all(&auth_dir).expect("create auth dir");
    fs::write(
        auth_dir.join("route.ts"),
        "export { GET, POST } from '@/auth';",
    )
    .expect("write nextauth route");

    let signals = inspect_watch_files(&[DesktopWatchRequest {
        project_id: 21,
        project_path: dir.path().to_string_lossy().to_string(),
        primary_url: Some("https://example.com".to_string()),
    }]);

    let auth_signal = signals
        .iter()
        .find(|signal| signal.relative_path == "src/app/api/auth/[...nextauth]/route.ts")
        .expect("nextauth signal");

    assert_eq!(auth_signal.page, "issues");
    assert_eq!(auth_signal.kind, "auth-session");
    assert_eq!(auth_signal.focus.as_deref(), Some("sec.cookies"));
    assert_eq!(auth_signal.url.as_deref(), Some("https://example.com"));
}

#[test]
fn inspect_watch_files_detects_auth_guard_middleware_as_security_auth_work() {
    let dir = tempdir().expect("tempdir");
    let middleware_dir = dir.path().join("server/middleware");
    fs::create_dir_all(&middleware_dir).expect("create middleware dir");
    fs::write(
        middleware_dir.join("auth.ts"),
        "export function requireUser() { throw new Error('todo'); }",
    )
    .expect("write auth middleware");

    let signals = inspect_watch_files(&[DesktopWatchRequest {
        project_id: 24,
        project_path: dir.path().to_string_lossy().to_string(),
        primary_url: Some("https://example.com".to_string()),
    }]);

    let guard_signal = signals
        .iter()
        .find(|signal| signal.relative_path == "server/middleware/auth.ts")
        .expect("guard signal");

    assert_eq!(guard_signal.page, "issues");
    assert_eq!(guard_signal.kind, "auth-guard");
    assert_eq!(guard_signal.focus.as_deref(), Some("sec.auth"));
    assert_eq!(guard_signal.url.as_deref(), Some("https://example.com"));
}

#[test]
fn inspect_watch_files_detects_guard_library_as_security_auth_work() {
    let dir = tempdir().expect("tempdir");
    let lib_dir = dir.path().join("src/lib");
    fs::create_dir_all(&lib_dir).expect("create lib dir");
    fs::write(
        lib_dir.join("guard.ts"),
        "export function ensureAuthorized() { return true; }",
    )
    .expect("write guard library");

    let signals = inspect_watch_files(&[DesktopWatchRequest {
        project_id: 25,
        project_path: dir.path().to_string_lossy().to_string(),
        primary_url: Some("https://example.com".to_string()),
    }]);

    let guard_signal = signals
        .iter()
        .find(|signal| signal.relative_path == "src/lib/guard.ts")
        .expect("guard library signal");

    assert_eq!(guard_signal.page, "issues");
    assert_eq!(guard_signal.kind, "auth-guard");
    assert_eq!(guard_signal.focus.as_deref(), Some("sec.auth"));
    assert_eq!(guard_signal.url.as_deref(), Some("https://example.com"));
}

#[test]
fn inspect_watch_files_detects_server_cors_config_as_security_cors_work() {
    let dir = tempdir().expect("tempdir");
    let server_dir = dir.path().join("src/server");
    fs::create_dir_all(&server_dir).expect("create server dir");
    fs::write(
        server_dir.join("cors.ts"),
        "export const cors = { origin: ['https://app.example.com'], credentials: true };",
    )
    .expect("write cors config");

    let signals = inspect_watch_files(&[DesktopWatchRequest {
        project_id: 26,
        project_path: dir.path().to_string_lossy().to_string(),
        primary_url: Some("https://example.com".to_string()),
    }]);

    let cors_signal = signals
        .iter()
        .find(|signal| signal.relative_path == "src/server/cors.ts")
        .expect("cors signal");

    assert_eq!(cors_signal.page, "issues");
    assert_eq!(cors_signal.kind, "cors-config");
    assert_eq!(cors_signal.focus.as_deref(), Some("sec.cors"));
    assert_eq!(cors_signal.url.as_deref(), Some("https://example.com"));
}

#[test]
fn inspect_watch_files_detects_proxy_library_as_security_cors_work() {
    let dir = tempdir().expect("tempdir");
    let lib_dir = dir.path().join("src/lib");
    fs::create_dir_all(&lib_dir).expect("create lib dir");
    fs::write(
        lib_dir.join("proxy.ts"),
        "export async function proxy(request: Request) { return fetch(request); }",
    )
    .expect("write proxy helper");

    let signals = inspect_watch_files(&[DesktopWatchRequest {
        project_id: 27,
        project_path: dir.path().to_string_lossy().to_string(),
        primary_url: Some("https://example.com".to_string()),
    }]);

    let proxy_signal = signals
        .iter()
        .find(|signal| signal.relative_path == "src/lib/proxy.ts")
        .expect("proxy signal");

    assert_eq!(proxy_signal.page, "issues");
    assert_eq!(proxy_signal.kind, "cors-config");
    assert_eq!(proxy_signal.focus.as_deref(), Some("sec.cors"));
    assert_eq!(proxy_signal.url.as_deref(), Some("https://example.com"));
}

#[test]
fn inspect_watch_files_detects_remix_session_config_as_security_cookie_work() {
    let dir = tempdir().expect("tempdir");
    let app_dir = dir.path().join("app");
    fs::create_dir_all(&app_dir).expect("create app dir");
    fs::write(
        app_dir.join("session.server.ts"),
        "export async function getSession() { return null; }",
    )
    .expect("write session config");

    let signals = inspect_watch_files(&[DesktopWatchRequest {
        project_id: 22,
        project_path: dir.path().to_string_lossy().to_string(),
        primary_url: Some("https://example.com".to_string()),
    }]);

    let session_signal = signals
        .iter()
        .find(|signal| signal.relative_path == "app/session.server.ts")
        .expect("session signal");

    assert_eq!(session_signal.page, "issues");
    assert_eq!(session_signal.kind, "auth-session");
    assert_eq!(session_signal.focus.as_deref(), Some("sec.cookies"));
    assert_eq!(session_signal.url.as_deref(), Some("https://example.com"));
}

#[test]
fn inspect_watch_files_detects_laravel_session_config_as_security_cookie_work() {
    let dir = tempdir().expect("tempdir");
    let config_dir = dir.path().join("config");
    fs::create_dir_all(&config_dir).expect("create config dir");
    fs::write(
        config_dir.join("session.php"),
        "<?php return ['http_only' => true, 'same_site' => 'lax'];",
    )
    .expect("write laravel session config");

    let signals = inspect_watch_files(&[DesktopWatchRequest {
        project_id: 23,
        project_path: dir.path().to_string_lossy().to_string(),
        primary_url: Some("https://example.com".to_string()),
    }]);

    let session_signal = signals
        .iter()
        .find(|signal| signal.relative_path == "config/session.php")
        .expect("laravel session signal");

    assert_eq!(session_signal.page, "issues");
    assert_eq!(session_signal.kind, "auth-session");
    assert_eq!(session_signal.focus.as_deref(), Some("sec.cookies"));
    assert_eq!(session_signal.url.as_deref(), Some("https://example.com"));
}

#[test]
fn inspect_watch_files_detects_edge_launch_config() {
    let dir = tempdir().expect("tempdir");
    fs::write(
        dir.path().join("wrangler.toml"),
        "name = \"example\"\nmain = \"src/index.ts\"",
    )
    .expect("write wrangler config");

    let signals = inspect_watch_files(&[DesktopWatchRequest {
        project_id: 10,
        project_path: dir.path().to_string_lossy().to_string(),
        primary_url: Some("https://example.com".to_string()),
    }]);

    let launch_signal = signals
        .iter()
        .find(|signal| signal.relative_path == "wrangler.toml")
        .expect("launch config signal");

    assert_eq!(launch_signal.page, "checklist");
    assert_eq!(launch_signal.kind, "launch-config");
    assert_eq!(launch_signal.focus, None);
    assert_eq!(launch_signal.url.as_deref(), Some("https://example.com"));
}

#[test]
fn inspect_watch_files_detects_serverless_launch_config() {
    let dir = tempdir().expect("tempdir");
    fs::write(
        dir.path().join("serverless.yml"),
        "service: example\nprovider:\n  name: aws\n",
    )
    .expect("write serverless config");

    let signals = inspect_watch_files(&[DesktopWatchRequest {
        project_id: 19,
        project_path: dir.path().to_string_lossy().to_string(),
        primary_url: Some("https://example.com".to_string()),
    }]);

    let launch_signal = signals
        .iter()
        .find(|signal| signal.relative_path == "serverless.yml")
        .expect("serverless launch signal");

    assert_eq!(launch_signal.page, "checklist");
    assert_eq!(launch_signal.kind, "launch-config");
    assert_eq!(launch_signal.focus, None);
    assert_eq!(launch_signal.url.as_deref(), Some("https://example.com"));
}

#[test]
fn inspect_watch_files_detects_nuxt_launch_config() {
    let dir = tempdir().expect("tempdir");
    fs::write(
        dir.path().join("nuxt.config.ts"),
        "export default defineNuxtConfig({});",
    )
    .expect("write nuxt config");

    let signals = inspect_watch_files(&[DesktopWatchRequest {
        project_id: 17,
        project_path: dir.path().to_string_lossy().to_string(),
        primary_url: Some("https://example.com".to_string()),
    }]);

    let launch_signal = signals
        .iter()
        .find(|signal| signal.relative_path == "nuxt.config.ts")
        .expect("nuxt launch signal");

    assert_eq!(launch_signal.page, "checklist");
    assert_eq!(launch_signal.kind, "launch-config");
    assert_eq!(launch_signal.focus, None);
    assert_eq!(launch_signal.url.as_deref(), Some("https://example.com"));
}

#[test]
fn inspect_watch_files_detects_astro_launch_config() {
    let dir = tempdir().expect("tempdir");
    fs::write(
        dir.path().join("astro.config.mjs"),
        "import { defineConfig } from 'astro/config';\nexport default defineConfig({});",
    )
    .expect("write astro config");

    let signals = inspect_watch_files(&[DesktopWatchRequest {
        project_id: 14,
        project_path: dir.path().to_string_lossy().to_string(),
        primary_url: Some("https://example.com".to_string()),
    }]);

    let launch_signal = signals
        .iter()
        .find(|signal| signal.relative_path == "astro.config.mjs")
        .expect("astro launch signal");

    assert_eq!(launch_signal.page, "checklist");
    assert_eq!(launch_signal.kind, "launch-config");
    assert_eq!(launch_signal.focus, None);
    assert_eq!(launch_signal.url.as_deref(), Some("https://example.com"));
}
