//! SiteCMD CLI for local scanning and connected CI/CD pipelines.

use sitecmd_runtime::cli::check::{self, CheckArgs};
use sitecmd_runtime::cli::connected::{self, ConnectedArgs, GateArgs};
use sitecmd_runtime::cli::connected_submit::{self, DeployArgs, SubmitArgs};
use sitecmd_runtime::cli::fix::{self, FixArgs};
use sitecmd_runtime::cli::init::{self, InitArgs};
use sitecmd_runtime::cli::scan::{self, ScanArgs};
use sitecmd_runtime::cli::watch::{self, WatchArgs};
use sitecmd_runtime::connected_ci::{DeploymentFacts, PublishOrdering};
use std::process::ExitCode;

mod audit_dispatch;
mod help;
#[cfg(test)]
mod tests;
mod validators;
use audit_dispatch::dispatch_audit;
use help::*;
use validators::{parse_categories, parse_positive_seconds, parse_score, warn_deprecated_flag};

fn parse_init_args(mut args: impl Iterator<Item = String>) -> Result<InitArgs, String> {
    let mut url: Option<String> = None;
    let mut name: Option<String> = None;
    let mut yes = false;
    let mut no_deep_link = false;

    while let Some(token) = args.next() {
        match token.as_str() {
            "--help" | "-h" => {
                print_init_help();
                std::process::exit(0);
            }
            "--name" => {
                name = Some(next_value(&mut args, "--name")?);
            }
            "--yes" | "-y" => {
                yes = true;
            }
            "--no-deep-link" => {
                no_deep_link = true;
            }
            t if t.starts_with('-') => {
                return Err(format!("Unknown option: {}", t));
            }
            t => {
                if url.is_none() {
                    url = Some(t.to_string());
                } else {
                    return Err(format!("Unexpected argument: {}", t));
                }
            }
        }
    }

    Ok(InitArgs {
        url,
        name,
        yes,
        no_deep_link,
    })
}

fn parse_scan_args(mut args: impl Iterator<Item = String>) -> Result<ScanArgs, String> {
    use sitecmd_runtime::core::scanner::ScanType;
    let mut url: Option<String> = None;
    let mut scan_type = ScanType::Health;
    let mut fail_under: Option<u32> = None;
    let mut fail_on: Option<sitecmd_runtime::checks::Severity> = None;
    let mut json = false;
    let mut timeout: Option<u64> = None;
    let mut categories: Option<Vec<String>> = None;
    let mut diff = false;
    let mut env_name: Option<String> = None;
    let mut no_browser = false;
    let mut cwv = false;

    while let Some(token) = args.next() {
        match token.as_str() {
            "--help" | "-h" => {
                print_scan_help();
                std::process::exit(0);
            }
            "--url" => {
                url = Some(next_value(&mut args, "--url")?);
            }
            "--type" => {
                let value = next_value(&mut args, "--type")?;
                scan_type = value.parse().map_err(|_| {
                    format!(
                        "Unknown scan type: {}. Use: health, security, accessibility, polish",
                        value
                    )
                })?;
            }
            "--fail-under" => {
                let value = next_value(&mut args, "--fail-under")?;
                fail_under = Some(parse_score(&value, "--fail-under")?);
            }
            "--fail-on" => {
                let value = next_value(&mut args, "--fail-on")?;
                fail_on =
                    Some(value.parse().map_err(|_| {
                        "--fail-on must be critical, high, medium, or low".to_string()
                    })?);
            }
            "--json" => {
                json = true;
            }
            "--output" => {
                let value = next_value(&mut args, "--output")?;
                match value.as_str() {
                    "json" => json = true,
                    "text" => json = false,
                    _ => return Err(format!("Unknown output format: {}. Use: text, json", value)),
                }
            }
            "--timeout" => {
                let value = next_value(&mut args, "--timeout")?;
                timeout = Some(parse_positive_seconds(&value, "--timeout")?);
            }
            "--categories" => {
                let value = next_value(&mut args, "--categories")?;
                categories = Some(parse_categories(&value)?);
            }
            "--diff" => {
                diff = true;
            }
            "--env" => {
                env_name = Some(next_value(&mut args, "--env")?);
            }
            "--no-browser" => {
                no_browser = true;
            }
            "--cwv" => {
                cwv = true;
            }
            t if t.starts_with('-') => {
                return Err(format!("Unknown option: {}", t));
            }
            t => {
                return Err(format!(
                    "Unexpected argument: {}. Did you mean --url {}?",
                    t, t
                ));
            }
        }
    }

    if categories.is_some() && scan_type != ScanType::Health {
        return Err("--categories can only be used with --type health".into());
    }
    if cwv && no_browser {
        return Err("--cwv cannot be combined with --no-browser".into());
    }
    if cwv && !cfg!(feature = "browser") {
        return Err(
            "--cwv requires a browser-enabled source build; release binaries are headless".into(),
        );
    }

    Ok(ScanArgs {
        url,
        scan_type,
        fail_under,
        fail_on,
        json,
        timeout,
        categories,
        diff,
        env_name,
        no_browser,
        cwv,
    })
}

fn parse_fix_args(mut args: impl Iterator<Item = String>) -> Result<FixArgs, String> {
    let mut all = false;
    let mut id: Option<String> = None;
    let mut type_filter: Option<String> = None;
    let mut category: Option<String> = None;

    while let Some(token) = args.next() {
        match token.as_str() {
            "--help" | "-h" => {
                print_fix_help();
                std::process::exit(0);
            }
            "--all" => {
                all = true;
            }
            "--id" => {
                id = Some(next_value(&mut args, "--id")?);
            }
            "--type" => {
                type_filter = Some(next_value(&mut args, "--type")?);
            }
            "--category" => {
                category = Some(next_value(&mut args, "--category")?);
            }
            t if t.starts_with('-') => {
                return Err(format!("Unknown option: {}", t));
            }
            t => {
                return Err(format!("Unexpected argument: {}", t));
            }
        }
    }

    Ok(FixArgs {
        all,
        id,
        type_filter,
        category,
    })
}

fn parse_watch_args(mut args: impl Iterator<Item = String>) -> Result<WatchArgs, String> {
    let mut url: Option<String> = None;
    let mut interval: u64 = 300;
    let mut env_name: Option<String> = None;

    while let Some(token) = args.next() {
        match token.as_str() {
            "--help" | "-h" => {
                print_watch_help();
                std::process::exit(0);
            }
            "--url" => {
                url = Some(next_value(&mut args, "--url")?);
            }
            "--interval" => {
                let value = next_value(&mut args, "--interval")?;
                interval = parse_positive_seconds(&value, "--interval")?;
            }
            "--env" => {
                env_name = Some(next_value(&mut args, "--env")?);
            }
            t if t.starts_with('-') => {
                return Err(format!("Unknown option: {}", t));
            }
            t => {
                return Err(format!("Unexpected argument: {}", t));
            }
        }
    }

    Ok(WatchArgs {
        url,
        interval,
        env_name,
    })
}

fn parse_check_args(mut args: impl Iterator<Item = String>) -> Result<CheckArgs, String> {
    let mut install = false;
    let mut strict = false;
    let mut threshold: Option<u32> = None;

    while let Some(token) = args.next() {
        match token.as_str() {
            "--help" | "-h" => {
                print_check_help();
                std::process::exit(0);
            }
            "--install" => {
                install = true;
            }
            "--strict" => {
                strict = true;
            }
            "--fail-under" => {
                let value = next_value(&mut args, "--fail-under")?;
                threshold = Some(parse_score(&value, "--fail-under")?);
            }
            "--threshold" => {
                warn_deprecated_flag("--threshold", "--fail-under");
                let value = next_value(&mut args, "--threshold")?;
                threshold = Some(parse_score(&value, "--threshold")?);
            }
            t if t.starts_with('-') => {
                return Err(format!("Unknown option: {}", t));
            }
            t => {
                return Err(format!("Unexpected argument: {}", t));
            }
        }
    }

    Ok(CheckArgs {
        install,
        strict,
        threshold,
    })
}

/// Parsed `connected` invocation.
enum ConnectedInvocation {
    Preview(ConnectedArgs),
    Submit(Box<SubmitArgs>),
}

/// The deployment flags both writing commands share, collected as they are
/// seen. `false` when the token was not one of them.
fn take_deployment_flag(
    token: &str,
    args: &mut impl Iterator<Item = String>,
    facts: &mut DeploymentFacts,
) -> Result<bool, String> {
    fn ordering(facts: &mut DeploymentFacts) -> &mut PublishOrdering {
        facts.ordering.get_or_insert_with(|| PublishOrdering {
            kind: "publish_sequence".into(),
            ..PublishOrdering::default()
        })
    }

    match token {
        "--deployment-id" => facts.provider_deployment_id = next_value(args, "--deployment-id")?,
        "--commit" => facts.commit_sha = next_value(args, "--commit")?,
        "--ref" => facts.git_ref = Some(next_value(args, "--ref")?),
        "--previous-sha" => facts.previous_sha = Some(next_value(args, "--previous-sha")?),
        "--target" => facts.target = Some(next_value(args, "--target")?),
        "--deployed-at" => facts.provider_created_at = Some(next_value(args, "--deployed-at")?),
        "--published" => facts.published = true,
        "--ordering-authority" => {
            ordering(facts).authority_id = next_value(args, "--ordering-authority")?
        }
        "--ordering-epoch" => {
            let value = next_value(args, "--ordering-epoch")?;
            ordering(facts).epoch = value
                .parse::<u64>()
                .map_err(|_| format!("Invalid number for --ordering-epoch: {value}"))?;
        }
        "--publish-sequence" => {
            let value = next_value(args, "--publish-sequence")?;
            ordering(facts).publish_sequence = Some(
                value
                    .parse::<u64>()
                    .map_err(|_| format!("Invalid number for --publish-sequence: {value}"))?,
            );
        }
        "--predecessor-deployment-id" => {
            ordering(facts).predecessor_deployment_id =
                Some(next_value(args, "--predecessor-deployment-id")?)
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn parse_connected_args(
    mut args: impl Iterator<Item = String>,
) -> Result<ConnectedInvocation, String> {
    let mut dry_run = false;
    let mut submit = false;
    let mut connection_export = None;
    let mut passphrase_env = "SITECMD_CONNECTION_PASSPHRASE".to_string();
    let mut token_env = "SITECMD_CI_TOKEN".to_string();
    let mut db_path = None;
    let mut project_path = None;
    let mut deployment = DeploymentFacts::default();

    while let Some(token) = args.next() {
        if take_deployment_flag(&token, &mut args, &mut deployment)? {
            continue;
        }
        match token.as_str() {
            "--help" | "-h" => {
                print_connected_help();
                std::process::exit(0);
            }
            "--dry-run" => dry_run = true,
            "--submit" => submit = true,
            "--connection-export" => {
                connection_export = Some(next_value(&mut args, "--connection-export")?.into());
            }
            "--passphrase-env" => {
                passphrase_env = next_value(&mut args, "--passphrase-env")?;
                if passphrase_env.trim().is_empty() {
                    return Err("--passphrase-env cannot be empty".into());
                }
            }
            "--token-env" => {
                token_env = next_value(&mut args, "--token-env")?;
                if token_env.trim().is_empty() {
                    return Err("--token-env cannot be empty".into());
                }
            }
            "--path" => {
                project_path = Some(next_value(&mut args, "--path")?.into());
            }
            "--db" => {
                db_path = Some(next_value(&mut args, "--db")?.into());
            }
            t if t.starts_with('-') => return Err(format!("Unknown option: {}", t)),
            t => return Err(format!("Unexpected argument: {}", t)),
        }
    }
    if dry_run && submit {
        return Err("use --dry-run to preview or --submit to send, not both".into());
    }
    if !dry_run && !submit {
        return Err("--dry-run or --submit is required".into());
    }
    let connection_export =
        connection_export.ok_or_else(|| "--connection-export is required".to_string())?;

    let named_deployment = !deployment.provider_deployment_id.is_empty()
        || !deployment.commit_sha.is_empty()
        || deployment.git_ref.is_some()
        || deployment.previous_sha.is_some()
        || deployment.target.is_some()
        || deployment.provider_created_at.is_some()
        || deployment.published
        || deployment.ordering.is_some();
    if submit && !named_deployment {
        return Err(
            "--submit needs the deployment its evidence is about: pass --deployment-id and --commit"
                .into(),
        );
    }
    if !named_deployment {
        return Ok(ConnectedInvocation::Preview(ConnectedArgs {
            dry_run,
            connection_export,
            passphrase_env,
            db_path,
        }));
    }
    Ok(ConnectedInvocation::Submit(Box::new(SubmitArgs {
        connection_export,
        passphrase_env,
        token_env,
        db_path,
        project_path,
        deployment,
        dry_run,
    })))
}

fn parse_deploy_args(mut args: impl Iterator<Item = String>) -> Result<DeployArgs, String> {
    let mut site_id = None;
    let mut connection_export = None;
    let mut passphrase_env = "SITECMD_CONNECTION_PASSPHRASE".to_string();
    let mut token_env = "SITECMD_CI_TOKEN".to_string();
    let mut deployment = DeploymentFacts::default();

    while let Some(token) = args.next() {
        if take_deployment_flag(&token, &mut args, &mut deployment)? {
            continue;
        }
        match token.as_str() {
            "--help" | "-h" => {
                print_deploy_help();
                std::process::exit(0);
            }
            "--site" => site_id = Some(next_value(&mut args, "--site")?),
            "--connection-export" => {
                connection_export = Some(next_value(&mut args, "--connection-export")?.into());
            }
            "--passphrase-env" => {
                passphrase_env = next_value(&mut args, "--passphrase-env")?;
                if passphrase_env.trim().is_empty() {
                    return Err("--passphrase-env cannot be empty".into());
                }
            }
            "--token-env" => {
                token_env = next_value(&mut args, "--token-env")?;
                if token_env.trim().is_empty() {
                    return Err("--token-env cannot be empty".into());
                }
            }
            t if t.starts_with('-') => return Err(format!("Unknown option: {}", t)),
            t => return Err(format!("Unexpected argument: {}", t)),
        }
    }
    Ok(DeployArgs {
        site_id,
        connection_export,
        passphrase_env,
        token_env,
        deployment,
    })
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("Missing value for {}", flag))
}

fn parse_gate_args(mut args: impl Iterator<Item = String>) -> Result<GateArgs, String> {
    let mut connection_export = None;
    let mut passphrase_env = "SITECMD_CONNECTION_PASSPHRASE".to_string();
    let mut token_env = "SITECMD_CI_TOKEN".to_string();
    let mut db_path = None;
    let mut project_path = None;
    let mut threshold = "high".to_string();
    let mut strict = false;

    while let Some(token) = args.next() {
        match token.as_str() {
            "--help" | "-h" => {
                print_gate_help();
                std::process::exit(0);
            }
            "--connection-export" => {
                connection_export = Some(next_value(&mut args, "--connection-export")?.into());
            }
            "--passphrase-env" => {
                passphrase_env = next_value(&mut args, "--passphrase-env")?;
                if passphrase_env.trim().is_empty() {
                    return Err("--passphrase-env cannot be empty".into());
                }
            }
            "--token-env" => {
                token_env = next_value(&mut args, "--token-env")?;
                if token_env.trim().is_empty() {
                    return Err("--token-env cannot be empty".into());
                }
            }
            "--fail-on" | "--threshold" => {
                if token == "--threshold" {
                    warn_deprecated_flag("--threshold", "--fail-on");
                }
                threshold = next_value(&mut args, &token)?;
                if !matches!(threshold.as_str(), "critical" | "high" | "medium" | "low") {
                    return Err("--fail-on must be critical, high, medium, or low".into());
                }
            }
            "--strict" => strict = true,
            "--path" => {
                project_path = Some(next_value(&mut args, "--path")?.into());
            }
            "--db" => {
                db_path = Some(next_value(&mut args, "--db")?.into());
            }
            t if t.starts_with('-') => return Err(format!("Unknown option: {}", t)),
            t => return Err(format!("Unexpected argument: {}", t)),
        }
    }
    Ok(GateArgs {
        connection_export: connection_export
            .ok_or_else(|| "--connection-export is required".to_string())?,
        db_path,
        passphrase_env,
        project_path,
        strict,
        threshold,
        token_env,
    })
}

fn build_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().expect("failed to build tokio runtime")
}

/// Writes reports to stdout and refusals to stderr. Exit code 2 distinguishes
/// command refusal from the gate's exit code 1 merge block.
fn report(outcome: Result<String, String>) -> ExitCode {
    match outcome {
        Ok(summary) => {
            println!("{}", summary);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Error: {}", error);
            ExitCode::from(2)
        }
    }
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .target(env_logger::Target::Stderr)
        .init();

    let mut argv = std::env::args().skip(1).peekable();

    // No arguments → print help
    let Some(first) = argv.next() else {
        print_main_help();
        return ExitCode::SUCCESS;
    };

    // Handle global help and version before interpreting legacy scan flags.
    if first == "--help" || first == "-h" {
        print_main_help();
        return ExitCode::SUCCESS;
    }
    // stdout, not stderr: install scripts and CI steps capture this.
    if first == "--version" || first == "-V" {
        println!("sitecmd {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    // Preserve flag-only invocations as implicit scan commands.
    if first.starts_with("--") {
        let remaining = std::iter::once(first).chain(argv);
        return dispatch_scan(remaining);
    }

    match first.as_str() {
        "init" => match parse_init_args(argv) {
            Ok(args) => match init::run(args) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    ExitCode::from(2)
                }
            },
            Err(e) => {
                eprintln!("Error: {}\nRun `sitecmd init --help` for usage.", e);
                ExitCode::from(2)
            }
        },

        "audit" => dispatch_audit(argv),

        "scan" => dispatch_scan(argv),

        "fix" => match parse_fix_args(argv) {
            Ok(args) => {
                let rt = build_runtime();
                match rt.block_on(fix::run(args)) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        ExitCode::from(2)
                    }
                }
            }
            Err(e) => {
                eprintln!("Error: {}\nRun `sitecmd fix --help` for usage.", e);
                ExitCode::from(2)
            }
        },

        "watch" => match parse_watch_args(argv) {
            Ok(args) => {
                let rt = build_runtime();
                match rt.block_on(watch::run(args)) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        ExitCode::from(2)
                    }
                }
            }
            Err(e) => {
                eprintln!("Error: {}\nRun `sitecmd watch --help` for usage.", e);
                ExitCode::from(2)
            }
        },

        "check" => match parse_check_args(argv) {
            Ok(args) => {
                let rt = build_runtime();
                match rt.block_on(check::run(args)) {
                    Ok(code) => ExitCode::from(code),
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        ExitCode::from(2)
                    }
                }
            }
            Err(e) => {
                eprintln!("Error: {}\nRun `sitecmd check --help` for usage.", e);
                ExitCode::from(2)
            }
        },

        "connected" => match parse_connected_args(argv) {
            Ok(ConnectedInvocation::Preview(args)) => report(connected::run(args)),
            Ok(ConnectedInvocation::Submit(args)) => {
                report(build_runtime().block_on(connected_submit::run_submit(*args)))
            }
            Err(e) => {
                eprintln!("Error: {}\nRun `sitecmd connected --help` for usage.", e);
                ExitCode::from(2)
            }
        },

        "deploy" => match parse_deploy_args(argv) {
            Ok(args) => report(build_runtime().block_on(connected_submit::run_deploy(args))),
            Err(e) => {
                eprintln!("Error: {}\nRun `sitecmd deploy --help` for usage.", e);
                ExitCode::from(2)
            }
        },

        "gate" => match parse_gate_args(argv) {
            Ok(args) => match build_runtime().block_on(connected::run_gate(args)) {
                Ok((code, summary)) => {
                    println!("{}", summary);
                    ExitCode::from(code)
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    ExitCode::from(2)
                }
            },
            Err(e) => {
                eprintln!("Error: {}\nRun `sitecmd gate --help` for usage.", e);
                ExitCode::from(2)
            }
        },

        "help" | "--help" | "-h" => {
            print_main_help();
            ExitCode::SUCCESS
        }

        unknown => {
            eprintln!(
                "Error: Unknown command: {}\nRun `sitecmd --help` for available commands.",
                unknown
            );
            ExitCode::from(2)
        }
    }
}

fn dispatch_scan(args: impl Iterator<Item = String>) -> ExitCode {
    match parse_scan_args(args) {
        Ok(scan_args) => {
            let rt = build_runtime();
            match rt.block_on(scan::run(scan_args)) {
                Ok((code, _scan)) => ExitCode::from(code),
                Err(e) => {
                    eprintln!("\r\x1b[KScan failed: {}", e);
                    ExitCode::from(2)
                }
            }
        }
        Err(e) => {
            eprintln!("Error: {}\nRun `sitecmd scan --help` for usage.", e);
            ExitCode::from(2)
        }
    }
}
