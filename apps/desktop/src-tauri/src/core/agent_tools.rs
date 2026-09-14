//! MCP server discovery and registration for supported coding agents.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Instant;

use crate::constants::{
    AGENT_CLI_OUTPUT_DRAIN_TIMEOUT, AGENT_CLI_POLL_INTERVAL, AGENT_CLI_TIMEOUT,
};

#[derive(Debug, Clone, serde::Serialize, ts_rs::TS)]
#[ts(export_to = "ipc-bindings.ts")]
pub struct McpServerSpec {
    pub command: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
}

/// What a user pastes when SiteCMD cannot write the editor config itself.
#[derive(Debug, Clone, serde::Serialize, ts_rs::TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct McpManualConfig {
    pub tool: AgentTool,
    pub config_path: String,
    pub spec: McpServerSpec,
    /// The exact file fragment: JSON for mcpServers-style configs, TOML for Codex.
    pub snippet: String,
    /// Claude Code registers through its CLI; other editors have no command.
    pub cli_command: Option<String>,
}

#[path = "agent_tools/config.rs"]
mod config;
#[path = "agent_tools/discovery.rs"]
mod discovery;
#[cfg(feature = "desktop")]
#[path = "agent_tools/health.rs"]
mod health;
pub use config::{
    codex_config_has_sitecmd, codex_config_matches_sitecmd_spec, cursor_config_has_sitecmd,
    cursor_config_matches_sitecmd_spec, remove_codex_config, remove_cursor_config,
    upsert_codex_config, upsert_cursor_config,
};
#[cfg(all(test, not(windows)))]
use discovery::fallback_binary_dirs_for;
pub use discovery::node_available;
#[cfg(feature = "desktop")]
use discovery::{binary_available, binary_paths};
use discovery::{binary_on_path, home_dir};
#[cfg(feature = "desktop")]
use health::run_server_health_check;

#[cfg(feature = "desktop")]
const MCP_MINIMUM_NODE_VERSION: (u64, u64, u64) = (22, 22, 1);
#[cfg(feature = "desktop")]
const MCP_MINIMUM_NODE_VERSION_LABEL: &str = "22.22.1";

/// Build the MCP launch specification from resolved runtime paths.
#[cfg(feature = "desktop")]
pub(crate) fn build_server_spec(
    node_path: &Path,
    script_path: &Path,
    db_path: &Path,
) -> McpServerSpec {
    let args = vec![
        "--disable-warning=ExperimentalWarning".to_string(),
        script_path.to_string_lossy().into_owned(),
    ];
    let env = BTreeMap::from([(
        "SITECMD_DB_PATH".to_string(),
        db_path.to_string_lossy().into_owned(),
    )]);
    McpServerSpec {
        command: node_path.to_string_lossy().into_owned(),
        args,
        env,
    }
}

#[cfg(feature = "desktop")]
fn node_version_supported(raw: &str) -> bool {
    let version = raw.trim().strip_prefix('v').unwrap_or(raw.trim());
    let mut parts = version.split('.');
    let parsed = (
        parts.next().and_then(|part| part.parse::<u64>().ok()),
        parts.next().and_then(|part| part.parse::<u64>().ok()),
        parts
            .next()
            .and_then(|part| part.split('-').next())
            .and_then(|part| part.parse::<u64>().ok()),
    );

    matches!(parsed, (Some(major), Some(minor), Some(patch)) if (major, minor, patch) >= MCP_MINIMUM_NODE_VERSION)
}

#[cfg(feature = "desktop")]
fn unsupported_node_error() -> String {
    format!(
        "SiteCMD's MCP server needs Node {MCP_MINIMUM_NODE_VERSION_LABEL}+ with the built-in node:sqlite module. Please update Node and try again."
    )
}

/// Verify the resolved runtime once per session.
#[cfg(feature = "desktop")]
fn probe_node_runtime(node_path: &Path) -> Result<(), String> {
    static CACHE: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);
    if let Ok(guard) = CACHE.lock() {
        if let Some(cached) = guard.as_ref() {
            if cached == node_path {
                return Ok(());
            }
        }
    }

    let version = Command::new(node_path)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .map_err(|_| unsupported_node_error())?;
    if !version.status.success()
        || !node_version_supported(&String::from_utf8_lossy(&version.stdout))
    {
        return Err(unsupported_node_error());
    }

    let sqlite_works = matches!(
        Command::new(node_path)
            .args([
                "-e",
                "const { DatabaseSync } = require('node:sqlite'); const db = new DatabaseSync(':memory:'); db.exec('SELECT 1'); db.close();",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
        Ok(status) if status.success()
    );
    if !sqlite_works {
        return Err(unsupported_node_error());
    }

    if let Ok(mut guard) = CACHE.lock() {
        *guard = Some(node_path.to_path_buf());
    }
    Ok(())
}

/// Resolve node, persistent script, and exact database path into a launch spec.
#[cfg(feature = "desktop")]
pub fn sitecmd_server_spec(_app: &tauri::AppHandle) -> Result<McpServerSpec, String> {
    let node = find_compatible_node(binary_paths("node"), probe_node_runtime)?;
    let script = crate::core::agent_tools_bundle::installed_script_path()?;
    let db_path = crate::app_identity::default_app_db_path()
        .ok_or_else(|| "could not resolve the SiteCMD database path".to_string())?;
    Ok(build_server_spec(&node, &script, &db_path))
}

#[cfg(feature = "desktop")]
fn find_compatible_node(
    candidates: impl IntoIterator<Item = PathBuf>,
    mut probe: impl FnMut(&Path) -> Result<(), String>,
) -> Result<PathBuf, String> {
    let mut found_node = false;
    let mut last_error = None;
    for candidate in candidates {
        found_node = true;
        match probe(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) => last_error = Some(error),
        }
    }
    if found_node {
        Err(last_error.unwrap_or_else(unsupported_node_error))
    } else {
        Err(format!(
            "Node is not installed or not on PATH. Install Node {MCP_MINIMUM_NODE_VERSION_LABEL}+ to use the SiteCMD MCP server."
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, ts_rs::TS)]
#[serde(rename_all = "kebab-case")]
#[ts(export_to = "ipc-bindings.ts")]
pub enum AgentTool {
    ClaudeCode,
    Codex,
    Cursor,
    Windsurf,
}

impl AgentTool {
    /// The canonical kebab-case token stored in `fix_attempts.agent_tool`.
    /// Must stay in lockstep with the serde representation above; a test in
    /// agent_tools_tests.rs enforces the parity.
    pub fn as_str(&self) -> &'static str {
        match self {
            AgentTool::ClaudeCode => "claude-code",
            AgentTool::Codex => "codex",
            AgentTool::Cursor => "cursor",
            AgentTool::Windsurf => "windsurf",
        }
    }

    /// Human display name for confirmation-dialog copy and toasts.
    pub fn display_name(&self) -> &'static str {
        match self {
            AgentTool::ClaudeCode => "Claude Code",
            AgentTool::Codex => "Codex",
            AgentTool::Cursor => "Cursor",
            AgentTool::Windsurf => "Windsurf",
        }
    }
}

/// Return a friendly label for known tool tokens and the raw token otherwise.
pub fn agent_tool_display_name(token: &str) -> &str {
    match token {
        "claude-code" => AgentTool::ClaudeCode.display_name(),
        "codex" => AgentTool::Codex.display_name(),
        "cursor" => AgentTool::Cursor.display_name(),
        "windsurf" => AgentTool::Windsurf.display_name(),
        other => other,
    }
}

/// Build a vendor deep link with the prompt staged but not executed.
/// Query values are percent-encoded so issue content cannot add parameters.
pub fn handoff_deep_link(
    tool: AgentTool,
    kickoff_prompt: &str,
    project_path: Option<&str>,
) -> Option<String> {
    let prompt = urlencoding::encode(kickoff_prompt);
    let folder = project_path
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(urlencoding::encode);
    match tool {
        AgentTool::ClaudeCode => Some(match folder {
            Some(folder) => format!("claude://code/new?q={prompt}&folder={folder}"),
            None => format!("claude://code/new?q={prompt}"),
        }),
        // Cursor's prompt deep link has no folder/workspace parameter; the
        // prompt lands in whichever workspace Cursor has focused.
        AgentTool::Cursor => Some(format!(
            "cursor://anysphere.cursor-deeplink/prompt?text={prompt}"
        )),
        AgentTool::Codex => Some(match folder {
            Some(path) => format!("codex://threads/new?prompt={prompt}&path={path}"),
            None => format!("codex://threads/new?prompt={prompt}"),
        }),
        // Windsurf publishes no prompt deep link; the kickoff prompt is on the clipboard.
        AgentTool::Windsurf => None,
    }
}

#[derive(Debug, serde::Serialize, ts_rs::TS)]
#[serde(rename_all = "camelCase")]
#[ts(export_to = "ipc-bindings.ts")]
pub struct AgentToolStatus {
    pub tool: AgentTool,
    pub installed: bool,
    /// Whether the tool's config contains a SiteCMD entry, even if stale.
    pub registered: bool,
    /// True only when the entry matches today's launch spec and that exact
    /// server process successfully opens the SiteCMD database read-only.
    pub healthy: bool,
    pub needs_repair: bool,
    pub repair_reason: Option<String>,
    pub node_available: bool,
    pub config_path: String,
    /// Human-readable description of exactly what register will change,
    /// shown in the UI before any file is touched.
    pub planned_change: String,
}

pub fn cursor_config_path() -> Result<PathBuf, String> {
    Ok(home_dir()?.join(".cursor").join("mcp.json"))
}

pub fn codex_config_path() -> Result<PathBuf, String> {
    Ok(home_dir()?.join(".codex").join("config.toml"))
}

pub fn claude_config_path() -> Result<PathBuf, String> {
    Ok(home_dir()?.join(".claude.json"))
}

pub fn windsurf_config_path() -> Result<PathBuf, String> {
    Ok(home_dir()?
        .join(".codeium")
        .join("windsurf")
        .join("mcp_config.json"))
}

pub fn manual_config_path(tool: AgentTool) -> Result<PathBuf, String> {
    match tool {
        AgentTool::ClaudeCode => claude_config_path(),
        AgentTool::Codex => codex_config_path(),
        AgentTool::Cursor => cursor_config_path(),
        AgentTool::Windsurf => windsurf_config_path(),
    }
}

pub fn manual_config_snippet(tool: AgentTool, spec: &McpServerSpec) -> Result<String, String> {
    match tool {
        AgentTool::Codex => upsert_codex_config("", spec),
        AgentTool::ClaudeCode | AgentTool::Cursor | AgentTool::Windsurf => {
            upsert_cursor_config("", spec)
        }
    }
}

/// Quotes a token for a POSIX shell so a pasted command survives paths that
/// contain spaces or single quotes.
fn shell_quote(token: &str) -> String {
    let readable = !token.is_empty()
        && token
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "_./:=@%+-".contains(ch));
    if readable {
        return token.to_string();
    }
    format!("'{}'", token.replace('\'', r"'\''"))
}

pub fn manual_config_cli_command(tool: AgentTool, spec: &McpServerSpec) -> Option<String> {
    if tool != AgentTool::ClaudeCode {
        return None;
    }
    let mut parts = vec![
        "claude".to_string(),
        "mcp".into(),
        "add".into(),
        "--scope".into(),
        "user".into(),
        "sitecmd".into(),
    ];
    for (key, value) in &spec.env {
        parts.push("--env".into());
        parts.push(format!("{key}={value}"));
    }
    parts.push("--".into());
    parts.push(spec.command.clone());
    parts.extend(spec.args.iter().cloned());
    Some(
        parts
            .iter()
            .map(|part| shell_quote(part))
            .collect::<Vec<_>>()
            .join(" "),
    )
}

#[cfg(feature = "desktop")]
pub fn manual_config(app: &tauri::AppHandle, tool: AgentTool) -> Result<McpManualConfig, String> {
    let spec = sitecmd_server_spec(app)?;
    Ok(McpManualConfig {
        tool,
        config_path: manual_config_path(tool)?.display().to_string(),
        snippet: manual_config_snippet(tool, &spec)?,
        cli_command: manual_config_cli_command(tool, &spec),
        spec,
    })
}

#[cfg(feature = "desktop")]
fn read_config_or_empty(path: &Result<PathBuf, String>) -> String {
    path.as_ref()
        .ok()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .unwrap_or_default()
}

#[cfg(feature = "desktop")]
fn display_config_path(path: &Result<PathBuf, String>) -> String {
    path.as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_default()
}

#[cfg(feature = "desktop")]
fn cursor_installed() -> bool {
    #[cfg(target_os = "macos")]
    if Path::new("/Applications/Cursor.app").exists() {
        return true;
    }
    binary_available("cursor")
}

#[cfg(feature = "desktop")]
fn codex_installed() -> bool {
    binary_available("codex")
        || home_dir()
            .map(|home| home.join(".codex").is_dir())
            .unwrap_or(false)
}

#[cfg(feature = "desktop")]
fn windsurf_installed() -> bool {
    #[cfg(target_os = "macos")]
    if Path::new("/Applications/Windsurf.app").exists() {
        return true;
    }
    binary_available("windsurf")
}

#[cfg(feature = "desktop")]
fn detect_with_probe(
    tool: AgentTool,
    spec: &Result<McpServerSpec, String>,
    health: &Result<(), String>,
) -> AgentToolStatus {
    let node_ok = spec.is_ok();
    let invocation = match spec {
        Ok(s) => format!("{} {}", s.command, s.args.join(" ")),
        Err(_) => {
            format!("node (with node:sqlite) - update Node to {MCP_MINIMUM_NODE_VERSION_LABEL}+")
        }
    };
    let (installed, registered, config_matches, config_path, planned_change) = match tool {
        AgentTool::ClaudeCode => {
            let path = claude_config_path();
            let config = read_config_or_empty(&path);
            (
                binary_available("claude"),
                cursor_config_has_sitecmd(&config),
                spec.as_ref()
                    .is_ok_and(|spec| cursor_config_matches_sitecmd_spec(&config, spec)),
                display_config_path(&path),
                format!("Runs: claude mcp add --scope user sitecmd -- {invocation}"),
            )
        }
        AgentTool::Codex => {
            let path = codex_config_path();
            let config_path = display_config_path(&path);
            let config = read_config_or_empty(&path);
            (
                codex_installed(),
                codex_config_has_sitecmd(&config),
                spec.as_ref()
                    .is_ok_and(|spec| codex_config_matches_sitecmd_spec(&config, spec)),
                config_path.clone(),
                format!("Adds [mcp_servers.sitecmd] (command: {invocation}) to {config_path}"),
            )
        }
        AgentTool::Cursor => {
            let path = cursor_config_path();
            let config_path = display_config_path(&path);
            let config = read_config_or_empty(&path);
            (
                cursor_installed(),
                cursor_config_has_sitecmd(&config),
                spec.as_ref()
                    .is_ok_and(|spec| cursor_config_matches_sitecmd_spec(&config, spec)),
                config_path.clone(),
                format!("Adds mcpServers.sitecmd (command: {invocation}) to {config_path}"),
            )
        }
        AgentTool::Windsurf => {
            let path = windsurf_config_path();
            let config_path = display_config_path(&path);
            let config = read_config_or_empty(&path);
            (
                windsurf_installed(),
                cursor_config_has_sitecmd(&config),
                spec.as_ref()
                    .is_ok_and(|spec| cursor_config_matches_sitecmd_spec(&config, spec)),
                config_path.clone(),
                format!("Adds mcpServers.sitecmd (command: {invocation}) to {config_path}"),
            )
        }
    };
    let healthy = registered && config_matches && health.is_ok();
    let repair_reason = if !registered {
        None
    } else if !node_ok {
        spec.as_ref().err().cloned()
    } else if !config_matches {
        Some("The saved SiteCMD MCP command, arguments, or database path is stale".to_string())
    } else {
        health.as_ref().err().cloned()
    };
    AgentToolStatus {
        tool,
        installed,
        registered,
        healthy,
        needs_repair: registered && !healthy,
        repair_reason,
        node_available: node_ok,
        config_path,
        planned_change,
    }
}

#[cfg(feature = "desktop")]
pub fn detect_one(app: &tauri::AppHandle, tool: AgentTool) -> AgentToolStatus {
    let spec = sitecmd_server_spec(app);
    let health = spec
        .as_ref()
        .map_or_else(|error| Err(error.clone()), run_server_health_check);
    detect_with_probe(tool, &spec, &health)
}

#[cfg(feature = "desktop")]
pub fn detect_all(app: &tauri::AppHandle) -> Vec<AgentToolStatus> {
    let spec = sitecmd_server_spec(app);
    let health = spec
        .as_ref()
        .map_or_else(|error| Err(error.clone()), run_server_health_check);
    [
        AgentTool::ClaudeCode,
        AgentTool::Codex,
        AgentTool::Cursor,
        AgentTool::Windsurf,
    ]
    .into_iter()
    .map(|tool| detect_with_probe(tool, &spec, &health))
    .collect()
}

/// Build the spawn command for a resolved `claude` binary. On Windows, npm
/// installs `claude.cmd`, which `Command::new` cannot spawn directly.
/// The `.cmd` and `.bat` shims must go through `cmd /C`.
fn claude_command(binary: &Path) -> Command {
    #[cfg(windows)]
    {
        let extension = binary
            .extension()
            .map(|ext| ext.to_string_lossy().to_ascii_lowercase());
        if matches!(extension.as_deref(), Some("cmd") | Some("bat")) {
            let mut command = Command::new("cmd");
            command.arg("/C").arg(binary);
            return command;
        }
    }
    Command::new(binary)
}

/// Drain a child pipe on a background thread so the child never blocks on a
/// full pipe buffer while we poll `try_wait` (same pattern as core/git.rs).
fn drain_pipe<R: Read + Send + 'static>(pipe: Option<R>) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut output = String::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_string(&mut output);
        }
        let _ = tx.send(output);
    });
    rx
}

fn recv_drained(rx: &mpsc::Receiver<String>) -> String {
    rx.recv_timeout(AGENT_CLI_OUTPUT_DRAIN_TIMEOUT)
        .unwrap_or_default()
}

/// Run the `claude` CLI with fixed arguments. The binary is resolved through
/// the same lookup detection uses, stdin is closed so first-run prompts cannot
/// hang us, and the whole invocation is bounded by `AGENT_CLI_TIMEOUT`.
fn run_claude_cli(args: &[&str]) -> Result<(), String> {
    let binary = binary_on_path("claude").ok_or_else(|| {
        "could not find the claude CLI; install Claude Code and try again".to_string()
    })?;
    let mut child = claude_command(&binary)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not run the claude CLI: {e}"))?;

    let stdout_rx = drain_pipe(child.stdout.take());
    let stderr_rx = drain_pipe(child.stderr.take());

    let started_at = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if started_at.elapsed() >= AGENT_CLI_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("the claude CLI did not respond within 30 seconds; run it \
                                once in a terminal to complete any first-time setup, then \
                                try again"
                        .to_string());
                }
                std::thread::sleep(AGENT_CLI_POLL_INTERVAL);
            }
            Err(e) => return Err(format!("could not run the claude CLI: {e}")),
        }
    };

    if status.success() {
        return Ok(());
    }
    let stderr = recv_drained(&stderr_rx);
    let stdout = recv_drained(&stdout_rx);
    let detail = if stderr.trim().is_empty() {
        stdout.trim().to_string()
    } else {
        stderr.trim().to_string()
    };
    Err(format!(
        "claude mcp {} failed: {detail}",
        args.get(1).copied().unwrap_or_default(),
    ))
}

/// Treat only a missing config as empty; preserve every other read failure.
fn read_config_for_rewrite(path: &Path) -> Result<String, String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(contents),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(format!("could not read {}: {e}", path.display())),
    }
}

/// Atomically replace a config through a same-directory temporary file.
/// Canonicalize symlinks so the target is replaced without destroying the link.
fn rewrite_config(
    path: &Path,
    edit: impl FnOnce(&str) -> Result<String, String>,
) -> Result<(), String> {
    let existing = read_config_for_rewrite(path)?;
    let updated = edit(&existing)?;

    let target = if path.exists() {
        std::fs::canonicalize(path)
            .map_err(|e| format!("could not resolve {}: {e}", path.display()))?
    } else {
        path.to_path_buf()
    };
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("could not create {}: {e}", parent.display()))?;
    }

    let file_name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "config".to_string());
    let temp_path =
        target.with_file_name(format!("{file_name}.sitecmd-tmp-{}", std::process::id()));
    if let Err(e) = std::fs::write(&temp_path, updated) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(format!("could not write {}: {e}", temp_path.display()));
    }
    if let Err(e) = std::fs::rename(&temp_path, &target) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(format!("could not write {}: {e}", target.display()));
    }
    Ok(())
}

#[cfg(feature = "desktop")]
pub fn register(app: &tauri::AppHandle, tool: AgentTool) -> Result<(), String> {
    crate::core::agent_tools_bundle::refresh_bundled_server(app)?;
    let spec = sitecmd_server_spec(app)?;
    match tool {
        AgentTool::ClaudeCode => {
            let config_path = claude_config_path()?;
            let original = read_config_for_rewrite(&config_path)?;
            let replacing = cursor_config_has_sitecmd(&original);
            if replacing {
                run_claude_cli(&["mcp", "remove", "--scope", "user", "sitecmd"])?;
            }
            let mut cli_args: Vec<&str> = vec!["mcp", "add", "--scope", "user", "sitecmd"];
            let env_args = spec
                .env
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>();
            for env_arg in &env_args {
                cli_args.push("--env");
                cli_args.push(env_arg.as_str());
            }
            cli_args.push("--");
            cli_args.push(spec.command.as_str());
            for arg in &spec.args {
                cli_args.push(arg.as_str());
            }
            if let Err(add_error) = run_claude_cli(&cli_args) {
                if replacing {
                    if let Err(restore_error) = rewrite_config(&config_path, |_| Ok(original)) {
                        return Err(format!(
                            "{add_error}; the previous Claude Code MCP entry also could not be restored: {restore_error}"
                        ));
                    }
                }
                return Err(add_error);
            }
            Ok(())
        }
        AgentTool::Codex => rewrite_config(&codex_config_path()?, |existing| {
            upsert_codex_config(existing, &spec)
        }),
        AgentTool::Cursor => rewrite_config(&cursor_config_path()?, |existing| {
            upsert_cursor_config(existing, &spec)
        }),
        AgentTool::Windsurf => rewrite_config(&windsurf_config_path()?, |existing| {
            upsert_cursor_config(existing, &spec)
        }),
    }
}

pub fn unregister(tool: AgentTool) -> Result<(), String> {
    match tool {
        AgentTool::ClaudeCode => run_claude_cli(&["mcp", "remove", "--scope", "user", "sitecmd"]),
        AgentTool::Codex => unregister_via_config(&codex_config_path()?, remove_codex_config),
        AgentTool::Cursor => unregister_via_config(&cursor_config_path()?, remove_cursor_config),
        AgentTool::Windsurf => {
            unregister_via_config(&windsurf_config_path()?, remove_cursor_config)
        }
    }
}

/// Unregister against a config file; a missing file already means
/// "unregistered", so it is an Ok no-op.
fn unregister_via_config(
    path: &Path,
    edit: impl FnOnce(&str) -> Result<String, String>,
) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    rewrite_config(path, edit)
}

#[cfg(test)]
#[path = "agent_tools_tests.rs"]
mod tests;
