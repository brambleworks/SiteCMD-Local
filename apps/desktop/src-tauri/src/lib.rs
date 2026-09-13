//! SiteCMD desktop backend and shared scanner library.
//!
//! Tauri commands connect the React frontend to local scanning, persistence,
//! integrations, reporting, and background workflows.

pub mod ai;
pub mod api_cache;
pub mod app_identity;
pub mod audit_log;
#[cfg(feature = "desktop")]
pub mod background;
#[cfg(feature = "browser")]
pub mod browser;
pub mod catalog;
pub mod checks;
pub mod cli;
#[cfg(feature = "desktop")]
pub mod commands;
pub mod connected_alerts;
pub mod connected_baseline;
pub mod connected_ci;
pub mod connected_credentials;
pub mod connected_delivery;
pub mod connected_export;
pub mod connected_notifications;
pub mod connected_providers;
pub mod connected_recovery;
pub mod connected_rotation;
pub mod connected_service;
pub mod connected_workflow;
pub mod constants;
pub mod core;
pub mod db;
#[cfg(feature = "desktop")]
pub mod desktop_deep_links;
#[cfg(feature = "desktop")]
pub mod desktop_tray;
pub mod dns_cache;
pub mod http_client;
pub mod integrations;
pub mod ipc_bindings;
#[cfg(feature = "desktop")]
pub mod keyring;
// Headless builds expose only the shared SQLite keyring placeholder, not the
// desktop OS-keychain implementation.
#[cfg(not(feature = "desktop"))]
pub mod keyring {
    pub use crate::constants::KEYRING_PLACEHOLDER;
}
pub mod licensing;
pub use sitecmd_engine::log_sanitizer;
pub mod network_policy;
pub mod project_paths;
#[cfg(feature = "desktop")]
pub mod report;
pub mod scan_runtime;
pub mod scoring;
pub mod ssl_probe;
pub mod updates;
#[cfg(feature = "desktop")]
pub mod webhooks;
#[cfg(feature = "desktop")]
pub mod webview;

#[cfg(feature = "desktop")]
use std::sync::Arc;
#[cfg(feature = "desktop")]
use std::{error::Error, io};
#[cfg(feature = "desktop")]
use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};

#[cfg(feature = "desktop")]
pub use desktop_tray::TrayState;

#[cfg(feature = "desktop")]
fn startup_error(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::other(message.into()))
}

#[cfg(feature = "desktop")]
fn initialize_persistent_state(app: &mut tauri::App<tauri::Wry>) -> Result<(), Box<dyn Error>> {
    // Restrict Unix-created files, including SQLite journals and backups, to the
    // current user. Windows relies on the storage directory's inherited ACL.
    #[cfg(unix)]
    {
        // SAFETY: `umask` has no preconditions; it swaps the process file-mode
        // creation mask and returns the previous value, which we discard.
        unsafe {
            libc::umask(0o077);
        }
    }

    let app_data_dir = crate::app_identity::default_storage_dir()
        .ok_or_else(|| startup_error("Failed to resolve app data directory"))?;
    crate::app_identity::ensure_private_directory(&app_data_dir)?;

    let telemetry_consent =
        commands::TelemetryConsentState::load(&app_data_dir).map_err(startup_error)?;
    app.manage(telemetry_consent);

    if let Err(error) = crate::core::agent_tools_bundle::refresh_bundled_server(app.handle()) {
        tracing::warn!("Could not refresh the persistent MCP bundle: {error}");
    }

    let db_path = app_data_dir.join(crate::app_identity::APP_DB_FILENAME);
    tracing::info!("Database path resolved");

    crate::app_identity::validate_private_file_target(&db_path)?;
    let database = db::Database::open(db_path.clone()).map_err(startup_error)?;
    crate::app_identity::restrict_private_file(&db_path)?;
    app.manage(Arc::new(database));

    app.manage(commands::scan::ScanControlState::default());
    app.manage(commands::PrivilegedCommandTokenState::default());

    // Migrate plaintext and legacy-named credentials to the OS keychain.
    {
        let db_ref = app.state::<Arc<db::Database>>();
        match keyring::migrate_credentials(app.handle(), &db_ref) {
            Ok(n) if n > 0 => tracing::info!("Keyring migration complete: {} credentials moved", n),
            Ok(_) => {}
            Err(e) => tracing::error!(
                "Keyring migration failed; unmigrated plaintext credentials are refused at read time: {}",
                e
            ),
        }
    }

    Ok(())
}

#[cfg(feature = "desktop")]
fn create_privileged_bridge_windows(
    app: &mut tauri::App<tauri::Wry>,
) -> Result<(), Box<dyn Error>> {
    let app_handle = app.handle().clone();
    for scope in [
        "data-admin",
        "external-connectors",
        "filesystem-access",
        "filesystem-export",
        "project-execution",
    ] {
        if app.get_webview_window(scope).is_some() {
            continue;
        }

        let url = WebviewUrl::App(format!("index.html?sitecmd_privileged_bridge={scope}").into());
        let window = WebviewWindowBuilder::new(&app_handle, scope, url)
            .title(format!("SiteCMD {scope} bridge"))
            .inner_size(1.0, 1.0)
            .focused(false)
            .visible(false)
            .decorations(false)
            .skip_taskbar(true)
            .build()
            .map_err(|error| {
                startup_error(format!(
                    "Failed to create privileged {scope} bridge window: {error}"
                ))
            })?;
        let _ = window.hide();
    }

    Ok(())
}

#[cfg(feature = "desktop")]
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let run_result = tauri::Builder::default()
        .plugin(tauri_plugin_window_state::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_os::init())
        .plugin(
            tauri_plugin_prevent_default::Builder::new()
                .with_flags(
                    tauri_plugin_prevent_default::Flags::all()
                        .difference(tauri_plugin_prevent_default::Flags::DEV_TOOLS),
                )
                .build(),
        )
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .plugin(tauri_plugin_autostart::Builder::new().build())
        .plugin(tauri_plugin_deep_link::init())
        .plugin(
            tauri_plugin_single_instance::Builder::new()
                .callback(|app, _args, _cwd| {
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.unminimize();
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                })
                .build(),
        )
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_keyring::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            {
                use tauri_plugin_log::{
                    Builder as LogBuilder, RotationStrategy, Target, TargetKind,
                };

                let log_dir = app.path().app_log_dir()?;
                crate::app_identity::ensure_private_directory(&log_dir)?;

                #[cfg(debug_assertions)]
                let level = if std::env::var_os("SITECMD_VERBOSE_LOGS").is_some() {
                    log::LevelFilter::Info
                } else {
                    log::LevelFilter::Warn
                };
                #[cfg(not(debug_assertions))]
                let level = log::LevelFilter::Info;

                let mut targets = vec![Target::new(TargetKind::LogDir {
                    file_name: Some("sitecmd.log".into()),
                })];

                // Default dev logs to stdout so a busy renderer cannot stall IPC;
                // browser-console mirroring remains opt-in.
                if cfg!(debug_assertions) {
                    targets.push(Target::new(TargetKind::Stdout));
                    if std::env::var_os("SITECMD_WEBVIEW_LOGS").is_some() {
                        targets.push(Target::new(TargetKind::Webview));
                    }
                }

                app.handle().plugin(
                    LogBuilder::new()
                        .level(level)
                        .targets(targets)
                        .max_file_size(5_000_000) // 5 MB per file
                        .rotation_strategy(RotationStrategy::KeepSome(3)) // keep 3 old + current
                        .build(),
                )?;
            }

            let default_hook = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                let location = info
                    .location()
                    .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
                    .unwrap_or_else(|| "unknown".into());
                let payload = if let Some(s) = info.payload().downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = info.payload().downcast_ref::<String>() {
                    s.clone()
                } else {
                    "unknown panic payload".into()
                };
                let safe_payload = crate::log_sanitizer::bounded_issue_evidence(&payload);
                tracing::error!("PANIC at {}: {}", location, safe_payload);
                crate::audit_log::record(
                    "panic",
                    serde_json::json!({
                        "location": location,
                        "has_message": payload != "unknown panic payload"
                    }),
                    "error",
                );
                default_hook(info);
            }));

            initialize_persistent_state(app)?;
            create_privileged_bridge_windows(app)?;

            desktop_tray::setup(app)?;

            // Spawn background scan scheduler under the panic-recovery harness.
            {
                let db_arc = app.state::<Arc<db::Database>>().inner().clone();
                // Fetch the managed cancellation registry once here (like db) so
                // scheduled scans join the same registry cancel_scan mutates.
                let scan_control = app
                    .state::<crate::core::scan_control::ScanControlState>()
                    .inner()
                    .clone();
                let app_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    crate::core::supervised_loop::supervised_loop_async(
                        "scan_scheduler",
                        move || {
                            let db_arc = db_arc.clone();
                            let app_handle = app_handle.clone();
                            let scan_control = scan_control.clone();
                            async move {
                                crate::background::scan_scheduler::run(
                                    db_arc,
                                    app_handle,
                                    scan_control,
                                )
                                .await;
                            }
                        },
                    )
                    .await;
                });
                // The agent-request watcher fulfils MCP start_fix and run_scan
                // rows, so it joins the same cancellation registry.
                let db_arc = app.state::<Arc<db::Database>>().inner().clone();
                let scan_control = app
                    .state::<crate::core::scan_control::ScanControlState>()
                    .inner()
                    .clone();
                let app_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    crate::core::supervised_loop::supervised_loop_async(
                        "agent_request_watcher",
                        move || {
                            let db_arc = db_arc.clone();
                            let app_handle = app_handle.clone();
                            let scan_control = scan_control.clone();
                            async move {
                                crate::background::agent_request_watcher::run(
                                    db_arc,
                                    app_handle,
                                    scan_control,
                                )
                                .await;
                            }
                        },
                    )
                    .await;
                });
            }

            // Spawn the fix-attempt watcher: settles agent fix attempts by
            // re-running verification and deciding verified/verify_failed.
            {
                let db_arc = app.state::<Arc<db::Database>>().inner().clone();
                let app_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    crate::core::supervised_loop::supervised_loop_async(
                        "fix_attempt_watcher",
                        move || {
                            let db_arc = db_arc.clone();
                            let app_handle = app_handle.clone();
                            async move {
                                crate::background::fix_attempt_watcher::run(db_arc, app_handle)
                                    .await;
                            }
                        },
                    )
                    .await;
                });
            }

            // Deliver locally committed connected-scope edits once at startup
            // and periodically thereafter. The local revision watermark keeps
            // failures durable across restarts.
            {
                let db_arc = app.state::<Arc<db::Database>>().inner().clone();
                let app_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    crate::core::supervised_loop::supervised_loop_async(
                        "connected_scope_sync",
                        move || {
                            let db_arc = db_arc.clone();
                            let app_handle = app_handle.clone();
                            async move {
                                crate::background::connected_scope_sync::run(app_handle, db_arc)
                                    .await;
                            }
                        },
                    )
                    .await;
                });
            }

            // Spawn the daily data-retention sweep: prunes the stores no
            // scan-retention path covers, once at startup, then daily.
            {
                let db_arc = app.state::<Arc<db::Database>>().inner().clone();
                tauri::async_runtime::spawn(async move {
                    crate::core::supervised_loop::supervised_loop_async(
                        "retention_sweep",
                        move || {
                            let db_arc = db_arc.clone();
                            async move {
                                crate::background::retention_sweep::run(db_arc).await;
                            }
                        },
                    )
                    .await;
                });
            }

            // Spawn the catalog refresh loop: keeps the intelligence catalog
            // current for entitled installs. Development builds have no
            // catalog endpoint, so every tick is a quiet no-op there.
            {
                let db_arc = app.state::<Arc<db::Database>>().inner().clone();
                let app_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    crate::core::supervised_loop::supervised_loop_async(
                        "catalog_refresh",
                        move || {
                            let db_arc = db_arc.clone();
                            let app_handle = app_handle.clone();
                            async move {
                                crate::background::catalog_refresh::run(app_handle, db_arc).await;
                            }
                        },
                    )
                    .await;
                });
            }

            // PageSpeed stays on-demand because background polling would send
            // project URLs to Google without a per-project opt-in.
            {
                use crate::core::integration_scheduler::{
                    set_immediate_sender, IntegrationScheduler,
                };
                use crate::integrations::adapters::{
                    cloudflare_adapter::CloudflareAdapter, ga4_adapter::Ga4Adapter,
                    gsc_adapter::GscAdapter, plausible_adapter::PlausibleAdapter,
                    updates_adapter::UpdatesAdapter, uptimerobot_adapter::UptimeRobotAdapter,
                    IntegrationAdapter,
                };

                let db_arc = app.state::<Arc<db::Database>>().inner().clone();
                let adapters: Vec<Arc<dyn IntegrationAdapter>> = vec![
                    Arc::new(Ga4Adapter::new()),
                    Arc::new(GscAdapter::new(db_arc.clone())),
                    Arc::new(UpdatesAdapter::new(db_arc.clone())),
                    Arc::new(UptimeRobotAdapter::new(db_arc.clone())),
                    Arc::new(PlausibleAdapter::new(db_arc.clone())),
                    Arc::new(CloudflareAdapter::new(db_arc.clone())),
                ];
                let scheduler = IntegrationScheduler::new(adapters);
                set_immediate_sender(scheduler.immediate_sender());

                let app_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    crate::core::supervised_loop::supervised_loop_async(
                        "integration_scheduler",
                        move || {
                            let scheduler = scheduler.clone();
                            let db_arc = db_arc.clone();
                            let app_handle = app_handle.clone();
                            async move {
                                scheduler.run(db_arc, app_handle).await;
                            }
                        },
                    )
                    .await;
                });
            }

            desktop_deep_links::register_cli_import_handler(app);

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // Hide window instead of quitting - app stays in tray
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::ping,
            commands::get_app_setting,
            commands::set_app_setting,
            commands::add_project,
            commands::add_project_by_url,
            commands::rename_project,
            commands::get_projects,
            commands::get_all_projects_summary,
            commands::get_all_projects_work_summary,
            commands::get_project_signal_snapshot,
            commands::get_project_nav_badge_snapshot,
            commands::get_dashboard_snapshot,
            commands::get_dashboard_reference_signals,
            commands::invalidate_project_signal_snapshot,
            commands::dismiss_first_scan_banner,
            commands::get_connected_status,
            commands::inspect_connected_sync,
            commands::issue_data_admin_command_token,
            commands::issue_external_connector_command_token,
            commands::issue_filesystem_access_command_token,
            commands::issue_filesystem_export_command_token,
            commands::issue_project_execution_command_token,
            commands::issue_sensitive_privileged_command_token,
            commands::run_data_admin_command,
            commands::run_filesystem_export_command,
            commands::run_external_connector_command,
            commands::run_filesystem_access_command,
            commands::run_project_execution_command,
            commands::add_environment_url,
            commands::get_integrations,
            commands::get_telemetry_consent,
            commands::set_telemetry_consent,
            commands::send_telemetry_request,
            commands::get_telemetry_delete_proof_hash,
            commands::clear_telemetry_delete_secret,
            commands::get_db_size,
            commands::scan::tools::run_webview_analysis,
            commands::scan::tools::verify_scan_checks,
            commands::scan::history::get_scan_executions,
            commands::scan::history::get_scan_execution_detail,
            commands::scan::history::get_score_trend,
            commands::scan::history::get_resolved_issues,
            commands::scan::tools::build_prompt,
            commands::scan::tools::export_scan_markdown,
            commands::discover_sitemap,
            commands::fetch_sitemap_manual,
            commands::save_site_pages,
            commands::get_site_pages,
            commands::get_scan_scope,
            commands::get_scan_scope_revision,
            commands::set_scan_scope,
            commands::refresh_sitemap,
            commands::set_site_sitemap_url,
            commands::get_or_create_site_id,
            commands::scan::control::cancel_scan,
            ssl_probe::check_ssl,
            commands::get_events,
            commands::record_verification_event,
            commands::record_update_event,
            commands::record_search_event,
            commands::record_security_event,
            commands::get_correlations,
            commands::refresh_events,
            commands::backfill_events,
            commands::generate_report_data,
            commands::generate_report_html,
            commands::render_report_html_from_data,
            commands::save_report_history,
            commands::get_report_history,
            commands::scan::schedule::save_scan_schedule,
            commands::scan::schedule::get_scan_schedule,
            commands::scan::tools::get_fix_document,
            commands::restart_app,
            commands::log_frontend,
            commands::update_tray_scan_status,
            commands::update_tray_summary,
            commands::send_actionable_desktop_notification,
            commands::get_webhook_configs,
            commands::get_issue_links,
            commands::get_issue_link_for_check,
            commands::count_unread_alerts,
            commands::dismiss_alert,
            commands::get_alerts,
            commands::mark_alerts_viewed_bulk,
            commands::mark_alert_unread,
            commands::mark_alert_viewed,
            commands::block_issue,
            commands::get_current_score,
            commands::get_score_snapshot_history,
            commands::get_issue_state,
            commands::get_issue_check_memory,
            commands::get_work_items,
            commands::ignore_issue,
            commands::mark_issue_fixed,
            commands::reopen_issue,
            commands::snooze_issue,
            commands::verify_issue,
            commands::create_fix_attempt,
            commands::get_fix_attempt_for_issue,
            commands::cancel_fix_attempt,
            commands::detect_agent_tools,
            commands::get_agent_tool_manual_config,
            licensing::commands::get_license_status,
            commands::get_pages_with_issues,
            commands::get_issues_for_page,
            commands::dismiss_integration_hint,
            commands::preview_deploy_risk_cmd,
            commands::whatif_resolve_cmd,
            commands::get_catalog_status,
            commands::confirm_link_license_activation,
            commands::retry_catalog_refresh,
            commands::resolve_fix_guide,
        ])
        .run(tauri::generate_context!());

    if let Err(error) = run_result {
        eprintln!("error while running tauri application: {}", error);
    }
}

#[cfg(all(test, feature = "desktop"))]
mod lib_tests;
