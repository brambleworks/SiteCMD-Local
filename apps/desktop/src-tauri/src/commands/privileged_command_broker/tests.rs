use super::token_state::TokenStore;
use super::{
    arg_i64, arg_string, privileged_action_argument_summary, privileged_action_prompt,
    privileged_action_sentence, privileged_token_issue_requires_user_intent, BrokerScope,
    PrivilegedCommandRequest, PrivilegedCommandTokenState, SensitiveActionTone,
    DATA_ADMIN_COMMANDS, FILESYSTEM_ACCESS_COMMANDS, FILESYSTEM_EXPORT_COMMANDS,
    PRIVILEGED_ACTION_PROMPTS, PROJECT_EXECUTION_COMMANDS, SCOPES, SENSITIVE_CONNECTOR_COMMANDS,
    SENSITIVE_FILESYSTEM_ACCESS_COMMANDS,
};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::time::Duration;

#[test]
fn every_scope_admits_only_allowlisted_commands_with_live_tokens() {
    let tokens = TokenStore::new(Duration::from_secs(15));
    assert_eq!(SCOPES.len(), 5);
    for scope in SCOPES {
        let unknown = PrivilegedCommandRequest {
            command: "not_a_command".into(),
            args: json!({}),
            token: None,
            response_event: None,
        };
        assert_eq!(
            scope.admit(&tokens, &unknown).unwrap_err(),
            format!("Unsupported {} command.", scope.label)
        );

        let stale = PrivilegedCommandRequest {
            command: scope.allowlist[0].into(),
            args: json!({}),
            token: Some("0000000000000000000000000000000000000000000000000000000000000000".into()),
            response_event: None,
        };
        assert!(scope
            .admit(&tokens, &stale)
            .unwrap_err()
            .contains("invalid or expired"));

        for command in scope.allowlist {
            let token = tokens
                .issue(scope.broker_command, command, &json!({}))
                .unwrap();
            let live = PrivilegedCommandRequest {
                command: (*command).into(),
                args: json!({}),
                token: Some(token),
                response_event: None,
            };
            assert!(
                scope.admit(&tokens, &live).is_ok(),
                "{} {command}",
                scope.broker_command
            );
            assert!(
                scope.admit(&tokens, &live).is_err(),
                "tokens are single-use: {} {command}",
                scope.broker_command
            );
        }
        assert_eq!(
            BrokerScope::by_broker(scope.broker_command).map(|found| found.label),
            Some(scope.label)
        );
    }
}

#[test]
fn every_run_entry_point_admits_through_the_scope_table() {
    for (file, source) in [
        ("data_admin.rs", include_str!("data_admin.rs")),
        (
            "external_connectors.rs",
            include_str!("external_connectors.rs"),
        ),
        ("filesystem_access.rs", include_str!("filesystem_access.rs")),
        ("filesystem_export.rs", include_str!("filesystem_export.rs")),
        ("project_execution.rs", include_str!("project_execution.rs")),
    ] {
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert_eq!(
            production.matches(".admit(").count(),
            1,
            "{file} must admit exactly once"
        );
        assert!(
            !production.contains("token_state.consume("),
            "{file} must not consume tokens outside admit"
        );
        assert!(
            !production.contains("Unsupported {SCOPE_LABEL} command."),
            "{file} must not format its own refusal"
        );
    }
}

/// The four flat-match dispatchers (external_connectors.rs nests its own
/// sub-dispatchers and is covered separately by
/// `public_allowlist_matches_domain_dispatchers`) end their match on
/// `unreachable!()` because `BrokerScope::admit` already checked the command
/// against the same allowlist. That is only sound while every allowlisted
/// command has a matching dispatch arm and vice versa; if the two drift, an
/// allowlisted command with no arm panics the async command in production
/// instead of returning an error. This proves they cannot drift silently.
#[test]
fn every_dispatch_arm_matches_its_scope_allowlist() {
    let arm_pattern =
        regex::Regex::new(r#"(?m)^ {8}"([a-z_]+)" => \{"#).expect("dispatch arm pattern");
    for (file, source, allowlist) in [
        (
            "data_admin.rs",
            include_str!("data_admin.rs"),
            DATA_ADMIN_COMMANDS,
        ),
        (
            "filesystem_access.rs",
            include_str!("filesystem_access.rs"),
            FILESYSTEM_ACCESS_COMMANDS,
        ),
        (
            "filesystem_export.rs",
            include_str!("filesystem_export.rs"),
            FILESYSTEM_EXPORT_COMMANDS,
        ),
        (
            "project_execution.rs",
            include_str!("project_execution.rs"),
            PROJECT_EXECUTION_COMMANDS,
        ),
    ] {
        let production = source.split("#[cfg(test)]").next().unwrap();
        let mut dispatched: Vec<&str> = arm_pattern
            .captures_iter(production)
            .map(|caps| caps.get(1).expect("captured command name").as_str())
            .collect();
        let mut allowed: Vec<&str> = allowlist.to_vec();
        dispatched.sort_unstable();
        dispatched.dedup();
        allowed.sort_unstable();
        assert_eq!(
            dispatched, allowed,
            "{file}: dispatch arms and the allowlist must match exactly, or a drifted command hits the dispatcher's unreachable!()"
        );
    }
}

#[test]
fn issued_token_rejects_after_ttl() {
    let store = TokenStore::new(Duration::from_millis(50));
    let token = store
        .issue(
            "run_filesystem_access_command",
            "run_scan_execution",
            &json!({}),
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(60));
    assert!(store
        .consume(
            Some(&token),
            "run_filesystem_access_command",
            "run_scan_execution",
            &json!({})
        )
        .is_err());
}

#[test]
fn issued_token_rejects_mismatched_args() {
    let store = TokenStore::new(Duration::from_secs(15));
    let token = store
        .issue(
            "run_filesystem_access_command",
            "run_scan_execution",
            &json!({"a": 1}),
        )
        .unwrap();
    let result = store.consume(
        Some(&token),
        "run_filesystem_access_command",
        "run_scan_execution",
        &json!({"a": 2}),
    );
    assert!(result.is_err());
}

#[test]
fn issued_token_rejects_double_consume() {
    let store = TokenStore::new(Duration::from_secs(15));
    let token = store
        .issue(
            "run_filesystem_access_command",
            "run_scan_execution",
            &json!({}),
        )
        .unwrap();
    assert!(store
        .consume(
            Some(&token),
            "run_filesystem_access_command",
            "run_scan_execution",
            &json!({})
        )
        .is_ok());
    assert!(store
        .consume(
            Some(&token),
            "run_filesystem_access_command",
            "run_scan_execution",
            &json!({})
        )
        .is_err());
}

#[test]
fn issued_token_rejects_command_outside_broker_allowlist() {
    let store = TokenStore::new(Duration::from_secs(15));
    let result = store.issue(
        "run_filesystem_access_command",
        "run_data_admin_command_secret",
        &json!({}),
    );
    assert!(result.is_err());
}

// Pre-existing tests preserved verbatim from the original single-file
// implementation (`commands/privileged_command_broker.rs`).

#[test]
fn reads_camel_case_arguments_from_frontend_payloads() {
    let args = json!({ "projectId": 42, "itemId": "custom.launch" });

    assert_eq!(arg_i64(&args, "projectId", "project_id").unwrap(), 42);
    assert_eq!(
        arg_string(&args, "itemId", "item_id").unwrap(),
        "custom.launch"
    );
}

#[test]
fn reads_snake_case_arguments_for_native_callers() {
    let args = json!({ "project_id": 42, "item_id": "custom.launch" });

    assert_eq!(arg_i64(&args, "projectId", "project_id").unwrap(), 42);
    assert_eq!(
        arg_string(&args, "itemId", "item_id").unwrap(),
        "custom.launch"
    );
}

#[test]
fn sensitive_confirmation_summarizes_destinations_without_secrets() {
    let summary = privileged_action_argument_summary(&json!({
        "projectPath": "/Users/test/project",
        "url": "https://hooks.example.test/ingest",
        "command": "pnpm test",
        "secret": "do-not-display",
        "content": "private export body"
    }));

    assert!(summary.contains("/Users/test/project"));
    assert!(summary.contains("https://hooks.example.test/ingest"));
    assert!(summary.contains("pnpm test"));
    assert!(!summary.contains("do-not-display"));
    assert!(!summary.contains("private export body"));
}

#[test]
fn privileged_command_tokens_are_bound_to_broker_and_command() {
    let tokens = PrivilegedCommandTokenState::default();
    let args = json!({ "projectId": 7 });
    let token = tokens
        .issue("run_data_admin_command", "delete_project", &args)
        .expect("token");

    assert!(tokens
        .consume(
            Some(&token),
            "run_filesystem_access_command",
            "delete_project",
            &args
        )
        .is_err());
    assert!(tokens
        .consume(
            Some(&token),
            "run_data_admin_command",
            "delete_project",
            &args
        )
        .is_err());
}

#[test]
fn privileged_command_tokens_are_one_time_use() {
    let tokens = PrivilegedCommandTokenState::default();
    let args = json!({ "projectId": 7 });
    let token = tokens
        .issue("run_data_admin_command", "delete_project", &args)
        .expect("token");

    assert!(tokens
        .consume(
            Some(&token),
            "run_data_admin_command",
            "delete_project",
            &args
        )
        .is_ok());
    assert!(tokens
        .consume(
            Some(&token),
            "run_data_admin_command",
            "delete_project",
            &args
        )
        .is_err());
}

#[test]
fn privileged_command_tokens_only_issue_for_registered_brokers() {
    let tokens = PrivilegedCommandTokenState::default();
    let args = Value::Null;

    assert!(tokens
        .issue("run_data_admin_command", "detect_updates", &args)
        .is_err());
    assert!(tokens
        .issue("run_unknown_command", "delete_project", &args)
        .is_err());
}

#[test]
fn launching_a_coding_agent_handoff_needs_no_native_intent() {
    // The handoff only opens the agent's app with a prompt staged in its
    // composer; nothing runs until the person sends it there. A system
    // dialog here was pure friction, so the command must stay off the
    // sensitive list and out of the native-intent manifest.
    assert!(!privileged_token_issue_requires_user_intent(
        "run_filesystem_access_command",
        "launch_agent_handoff",
    ));
    assert!(privileged_action_sentence("launch_agent_handoff", &json!({})).is_none());
}

#[test]
fn sensitive_privileged_token_issuance_requires_user_intent() {
    for command in SENSITIVE_CONNECTOR_COMMANDS {
        assert!(
            privileged_token_issue_requires_user_intent("run_external_connector_command", command),
            "connector mutation {command} should require native user intent",
        );
    }
    for command in SENSITIVE_FILESYSTEM_ACCESS_COMMANDS {
        assert!(
            privileged_token_issue_requires_user_intent("run_filesystem_access_command", command),
            "filesystem action {command} should require native user intent",
        );
    }

    for command in DATA_ADMIN_COMMANDS {
        assert!(
            !privileged_token_issue_requires_user_intent("run_data_admin_command", command),
            "data admin command {command} confirms in-handler; no token-issue prompt",
        );
    }
    for command in FILESYSTEM_EXPORT_COMMANDS {
        assert!(
            !privileged_token_issue_requires_user_intent("run_filesystem_export_command", command),
            "filesystem export command {command} confirms in-handler; no token-issue prompt",
        );
    }
    for command in PROJECT_EXECUTION_COMMANDS {
        assert!(
            !privileged_token_issue_requires_user_intent("run_project_execution_command", command),
            "project execution command {command} confirms in-handler; no token-issue prompt",
        );
    }

    // Background-safe connector reads must remain usable without prompts.
    for command in [
        "fetch_analytics",
        "check_app_update",
        "fetch_integration_data",
        "github_latest_release",
        "get_pagespeed_report",
        "validate_license",
    ] {
        assert!(
            !privileged_token_issue_requires_user_intent("run_external_connector_command", command),
            "connector read {command} should keep its scoped token flow",
        );
    }

    for command in [
        "connect_google",
        "complete_google_oauth",
        "save_google_integration",
        "connect_github",
        "complete_github_oauth",
        "save_github_integration",
        "delete_integration",
        "activate_license",
        "create_issue_link",
    ] {
        assert!(
            !privileged_token_issue_requires_user_intent("run_external_connector_command", command),
            "connector setup/OAuth command {command} must not show an extra native prompt",
        );
    }

    assert_eq!(
        SENSITIVE_CONNECTOR_COMMANDS,
        [
            "save_integration",
            "save_webhook_config",
            "test_webhook",
            "sync_connected_site",
            "import_connected_connection",
            "export_connected_connection",
            "unlink_connected_site",
            "disconnect_connected_site",
            "erase_connected_site",
            "create_connected_alert_webhook",
            "test_connected_alert_webhook",
            "delete_connected_alert_webhook",
            "create_connected_destination",
            "resend_connected_destination_verification",
            "delete_connected_destination",
            "revoke_connected_site_credential",
            "revoke_connected_provider_connection",
            "revoke_connected_report"
        ],
        "connector confirmations cover credential saves, caller-chosen egress, and destructive remote mutations; create_issue_link is excluded because its destination is the stored integration config",
    );

    for command in [
        "list_connected_destinations",
        "update_connected_destination_policy",
        "get_connected_notification_settings",
        "put_connected_notification_settings",
    ] {
        assert!(
            !privileged_token_issue_requires_user_intent("run_external_connector_command", command),
            "{command} reaches only already-confirmed destinations and must not add a prompt",
        );
    }

    assert!(
        !privileged_token_issue_requires_user_intent(
            "run_filesystem_access_command",
            "run_scan_execution"
        ),
        "canonical scan execution should keep its scoped token flow without an extra prompt",
    );
}

#[test]
fn updating_a_project_path_requires_native_confirmation() {
    // Repointing a project chooses which folder every non-sensitive read
    // (run_code_scan_audit, resolve_project_files, get_git_status,
    // read_recent_logs) exposes next. Without this gate a compromised main
    // renderer could silently aim a project at ~/.ssh and read it back.
    assert!(
        privileged_token_issue_requires_user_intent(
            "run_filesystem_access_command",
            "update_project_path",
        ),
        "update_project_path decides what the non-sensitive reads expose and must prompt",
    );
}

#[test]
fn native_intent_lists_match_the_security_manifest() {
    let manifest: Value =
        serde_json::from_str(include_str!("../../../permissions/command-security.json"))
            .expect("valid command-security.json");
    let listed = |broker: &str| -> BTreeSet<String> {
        manifest["nativeIntentBrokerCommands"][broker]
            .as_array()
            .unwrap_or_else(|| panic!("native-intent commands missing for {broker}"))
            .iter()
            .map(|command| {
                command
                    .as_str()
                    .unwrap_or_else(|| panic!("native-intent command must be a string"))
                    .to_string()
            })
            .collect()
    };
    let connector_commands = SENSITIVE_CONNECTOR_COMMANDS
        .iter()
        .map(|command| (*command).to_string())
        .collect();
    let filesystem_commands = SENSITIVE_FILESYSTEM_ACCESS_COMMANDS
        .iter()
        .map(|command| (*command).to_string())
        .collect();

    assert_eq!(listed("run_external_connector_command"), connector_commands);
    assert_eq!(listed("run_filesystem_access_command"), filesystem_commands);
}

#[test]
fn every_token_issue_prompted_command_has_purpose_written_copy() {
    for command in SENSITIVE_CONNECTOR_COMMANDS
        .iter()
        .chain(SENSITIVE_FILESYSTEM_ACCESS_COMMANDS)
    {
        assert!(
            privileged_action_sentence(command, &json!({})).is_some(),
            "{command} needs purpose-written confirmation copy (no-args fallback)",
        );
        assert!(
            privileged_action_sentence(
                command,
                &json!({
                    "url": "https://hooks.example.test",
                    "path": "/tmp/x",
                    "projectPath": "/tmp/x",
                    "tool": "cursor",
                    "provider": "github",
                    "address": "ops@example.com",
                    "checkId": "security.csp",
                    "config": {
                        "integrationType": "github",
                        "siteId": "brambleworks/SiteCMD-Local"
                    }
                })
            )
            .is_some(),
            "{command} needs purpose-written confirmation copy (with args)",
        );
    }
}

/// Commands whose confirmation carries the warning icon. Kept separate from
/// `PRIVILEGED_ACTION_PROMPTS` on purpose: the table is copy, this is the
/// policy the copy has to obey, so adding a row cannot quietly widen the set
/// of dialogs that shout at people.
const DESTRUCTIVE_PRIVILEGED_ACTIONS: &[&str] = &[
    "export_connected_connection",
    "unlink_connected_site",
    "disconnect_connected_site",
    "erase_connected_site",
    "delete_connected_alert_webhook",
    "delete_connected_destination",
    "revoke_connected_site_credential",
    "revoke_connected_provider_connection",
    "revoke_connected_report",
];

#[test]
fn every_token_issue_prompted_command_has_a_written_heading() {
    for command in SENSITIVE_CONNECTOR_COMMANDS
        .iter()
        .chain(SENSITIVE_FILESYSTEM_ACCESS_COMMANDS)
    {
        let (title, _) = privileged_action_prompt(command)
            .unwrap_or_else(|| panic!("{command} needs a heading in PRIVILEGED_ACTION_PROMPTS"));
        assert!(
            !title.trim().is_empty(),
            "{command} has an empty confirmation heading",
        );
        assert_ne!(
            title, "Allow Protected Action",
            "{command} still uses the generic fallback heading",
        );
    }
}

#[test]
fn only_destructive_privileged_actions_carry_the_warning_icon() {
    for command in SENSITIVE_CONNECTOR_COMMANDS
        .iter()
        .chain(SENSITIVE_FILESYSTEM_ACCESS_COMMANDS)
    {
        let (_, tone) = privileged_action_prompt(command)
            .unwrap_or_else(|| panic!("{command} needs a heading in PRIVILEGED_ACTION_PROMPTS"));
        let expected = if DESTRUCTIVE_PRIVILEGED_ACTIONS.contains(command) {
            SensitiveActionTone::Warning
        } else {
            SensitiveActionTone::Notice
        };
        assert_eq!(
            tone, expected,
            "{command} has the wrong confirmation tone; the warning icon is for actions that destroy data, revoke access, or disclose a secret",
        );
    }
}

#[test]
fn the_prompt_table_holds_no_rows_for_commands_that_never_prompt() {
    for (command, _, _) in PRIVILEGED_ACTION_PROMPTS {
        assert!(
            SENSITIVE_CONNECTOR_COMMANDS.contains(command)
                || SENSITIVE_FILESYSTEM_ACCESS_COMMANDS.contains(command),
            "{command} has confirmation copy but never reaches a confirmation",
        );
    }
}

#[test]
fn privileged_action_sentence_sanitizes_and_binds_display_arguments() {
    let sentence = privileged_action_sentence(
        "open_path_in_editor",
        &json!({ "path": "/Users/test/proj\u{7}ect/file.ts" }),
    )
    .expect("sentence");
    assert!(sentence.contains("/Users/test/proj ect/file.ts"));
    assert!(!sentence.contains('\u{7}'));

    let webhook = privileged_action_sentence(
        "save_webhook_config",
        &json!({ "url": "https://hooks.example.test/ingest" }),
    )
    .expect("sentence");
    assert!(webhook.contains("https://hooks.example.test/ingest"));
}

#[test]
fn agent_tool_confirmation_sentences_use_display_names_not_raw_tokens() {
    let unregister =
        privileged_action_sentence("unregister_agent_tool", &json!({ "tool": "codex" }))
            .expect("sentence");
    assert_eq!(unregister, "Stop SiteCMD from launching Codex for fixes?");

    let register =
        privileged_action_sentence("register_agent_tool", &json!({ "tool": "claude-code" }))
            .expect("sentence");
    assert_eq!(register, "Let SiteCMD launch Claude Code to work on fixes?");
    // The bare kebab token must never surface in the dialog copy.
    assert!(!register.contains("claude-code"));
}

#[test]
fn privileged_command_tokens_are_bound_to_argument_payload() {
    let tokens = PrivilegedCommandTokenState::default();
    let token = tokens
        .issue(
            "run_filesystem_export_command",
            "write_export_file",
            &json!({ "path": "/Users/dev/report.md", "content": "safe" }),
        )
        .expect("token");

    assert!(tokens
        .consume(
            Some(&token),
            "run_filesystem_export_command",
            "write_export_file",
            &json!({ "path": "/Users/dev/.ssh/config", "content": "changed" }),
        )
        .is_err());
}

#[test]
fn privileged_command_token_argument_binding_is_stable_for_object_key_order() {
    let tokens = PrivilegedCommandTokenState::default();
    let token = tokens
        .issue(
            "run_data_admin_command",
            "delete_project",
            &json!({ "reason": "test", "projectId": 7 }),
        )
        .expect("token");

    assert!(tokens
        .consume(
            Some(&token),
            "run_data_admin_command",
            "delete_project",
            &json!({ "projectId": 7, "reason": "test" }),
        )
        .is_ok());
}

#[test]
fn privileged_command_token_argument_signature_does_not_store_raw_payload() {
    let tokens = PrivilegedCommandTokenState::default();
    let token = tokens
        .issue(
            "run_filesystem_export_command",
            "write_export_bytes",
            &json!({ "path": "/Users/dev/report.pdf", "bytes": vec![42_u8; 4096] }),
        )
        .expect("token");
    let stored_tokens = tokens.tokens.lock().expect("token lock");
    let record = stored_tokens.get(&token).expect("stored token");

    assert_eq!(record.args_signature.len(), 64);
    assert!(record
        .args_signature
        .chars()
        .all(|ch| ch.is_ascii_hexdigit()));
    assert!(!record.args_signature.contains("bytes"));
    assert!(!record.args_signature.contains("report.pdf"));
}
