//! `sitecmd autofix`: the template engine on a checkout (`apply`), and the
//! two halves of a Connect fix job (`run-job`, `publish-job`).

pub mod apply;
pub mod artifact;
pub mod brief;
pub mod brief_publish;
pub mod github_api;
pub mod locate;
pub mod publish_job;
pub mod redact;
pub mod repo;
pub mod run_job;
pub mod secrets;

pub const HELP: &str = concat!(
    "SiteCMD autofix - Apply template fixes, or run a Connect fix job\n\n",
    "Usage:\n  sitecmd autofix <command> [options]\n\n",
    "Commands:\n",
    "  apply                  Apply every applicable template fix to this checkout\n",
    "  run-job <JOB_ID>       The fix job's entry point inside GitHub Actions\n",
    "  publish-job <JOB_ID>   The publish job's entry point inside GitHub Actions\n",
    "  locate                 Print a code finding's identity hash for a check\n\n",
    "Options for apply:\n",
    "  --only <CHECK_ID>      Apply one check's fixer (repeatable)\n",
    "  --dry-run              Plan the patches and print them without writing\n",
    "  --path <PATH>          Checkout root (default: working directory)\n",
    "  --help, -h             Show this help\n\n",
    "Options for run-job:\n",
    "  --connect-origin <URL>\n",
    "                         The SiteCMD origin that issued this job\n",
    "  --connection-export <PATH>\n",
    "                         The connection export this site was connected with\n",
    "  --connection-export-env <NAME>\n",
    "                         Environment variable holding that export instead\n",
    "  --artifact-dir <DIR>   Where to write manifest.json and patch.diff\n",
    "  --outputs <FILE>       Where to write publish=true or publish=false\n",
    "  --passphrase-env <NAME>\n",
    "                         Variable holding its passphrase (default: SITECMD_CONNECTION_PASSPHRASE)\n",
    "  --path <PATH>          Checkout root (default: working directory)\n\n",
    "Options for publish-job:\n",
    "  --connect-origin <URL>\n",
    "                         The SiteCMD origin that issued this job\n",
    "  --artifact-dir <DIR>   Where the fix job left manifest.json and patch.diff\n",
    "  --path <PATH>          Checkout root (default: working directory)\n\n",
    "Options for locate:\n",
    "  --connection-export <PATH>\n",
    "                         The connection export this site was connected with\n",
    "  --connection-export-env <NAME>\n",
    "                         Environment variable holding that export instead\n",
    "  --passphrase-env <NAME>\n",
    "                         Variable holding its passphrase (default: SITECMD_CONNECTION_PASSPHRASE)\n",
    "  --check <SLUG>         Only findings for this rule, such as open-redirect\n",
    "  --path <PATH>          Checkout root (default: working directory)\n\n",
    "Exit codes:\n",
    "  0  Completed\n",
    "  1  A job reported a failure outcome\n",
    "  2  Usage or operational error\n\n",
    "Examples:\n",
    "  sitecmd autofix apply --dry-run\n",
    "  sitecmd autofix apply --only security.headers.x_content_type_options\n",
    "  sitecmd autofix locate --connection-export ./connection.json --check open-redirect\n",
    "  sitecmd autofix run-job job_0123456789abcdef --connect-origin https://connect.sitecmd.com --connection-export-env SITECMD_CONNECTION_EXPORT --artifact-dir ./job\n",
    "  sitecmd autofix publish-job job_0123456789abcdef --connect-origin https://connect.sitecmd.com --artifact-dir ./job\n",
);

#[derive(Debug)]
pub enum AutofixCommand {
    Apply(apply::ApplyArgs),
    Locate(locate::LocateArgs),
    PublishJob(publish_job::PublishJobArgs),
    RunJob(run_job::RunJobArgs),
}

pub fn help_requested(args: &[String]) -> bool {
    args.iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
}

/// A job identifier as the connected service issues it: `job_` and sixteen
/// lowercase hex digits. Anything else is refused before it reaches a URL.
pub(crate) fn is_job_id(value: &str) -> bool {
    value.strip_prefix("job_").is_some_and(|rest| {
        rest.len() == 16 && rest.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
    })
}

pub(crate) fn next_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, String> {
    args.next()
        .filter(|value| !value.starts_with("--"))
        .ok_or_else(|| format!("{flag} requires a value"))
}

pub fn parse_args(args: Vec<String>) -> Result<AutofixCommand, String> {
    let mut args = args.into_iter();
    match args.next().as_deref() {
        Some("apply") => apply::parse(args).map(AutofixCommand::Apply),
        Some("locate") => locate::parse(args).map(AutofixCommand::Locate),
        Some("run-job") => run_job::parse(args).map(AutofixCommand::RunJob),
        Some("publish-job") => publish_job::parse(args).map(AutofixCommand::PublishJob),
        Some(other) => Err(format!("Unknown autofix command: {other}")),
        None => Err("autofix needs a command: apply, run-job, publish-job or locate".into()),
    }
}

pub async fn run(command: AutofixCommand) -> Result<u8, String> {
    match command {
        AutofixCommand::Apply(args) => {
            let (code, summary) = apply::run(&args)?;
            println!("{summary}");
            Ok(code)
        }
        AutofixCommand::Locate(args) => {
            let (code, out) = locate::run(&args)?;
            println!("{out}");
            Ok(code)
        }
        AutofixCommand::PublishJob(args) => {
            let (code, out) = publish_job::run(&args).await?;
            println!("{out}");
            Ok(code)
        }
        AutofixCommand::RunJob(args) => {
            let (code, out) = run_job::run(&args).await?;
            println!("{out}");
            Ok(code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_apply_with_its_flags() {
        let parsed = parse_args(
            [
                "apply",
                "--only",
                "security.headers.x_content_type_options",
                "--dry-run",
                "--path",
                ".",
            ]
            .map(String::from)
            .to_vec(),
        )
        .unwrap();
        match parsed {
            AutofixCommand::Apply(args) => {
                assert_eq!(args.only, vec!["security.headers.x_content_type_options"]);
                assert!(args.dry_run);
                assert_eq!(args.path, std::path::PathBuf::from("."));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parses_locate() {
        let parsed = parse_args(
            [
                "locate",
                "--connection-export-env",
                "SITECMD_CONNECTION_EXPORT",
                "--check",
                "open-redirect",
            ]
            .map(String::from)
            .to_vec(),
        )
        .unwrap();
        match parsed {
            AutofixCommand::Locate(args) => {
                assert_eq!(
                    args.export,
                    crate::cli::autofix::secrets::ExportSource::Env(
                        "SITECMD_CONNECTION_EXPORT".into()
                    )
                );
                assert_eq!(args.check.as_deref(), Some("open-redirect"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parses_run_job() {
        let parsed = parse_args(
            [
                "run-job",
                "job_0123456789abcdef",
                "--connect-origin",
                "https://connect.sitecmd.com",
                "--connection-export-env",
                "SITECMD_CONNECTION_EXPORT",
                "--artifact-dir",
                "/tmp/a",
                "--outputs",
                "/tmp/o",
            ]
            .map(String::from)
            .to_vec(),
        )
        .unwrap();
        match parsed {
            AutofixCommand::RunJob(args) => {
                assert_eq!(args.job_id, "job_0123456789abcdef");
                assert_eq!(args.connect_origin, "https://connect.sitecmd.com");
                assert_eq!(args.artifact_dir, std::path::PathBuf::from("/tmp/a"));
                assert_eq!(args.outputs, Some(std::path::PathBuf::from("/tmp/o")));
            }
            other => panic!("{other:?}"),
        }
        assert!(parse_args(["run-job", "nope"].map(String::from).to_vec())
            .unwrap_err()
            .contains("job id"));
    }

    #[test]
    fn parses_publish_job() {
        let parsed = parse_args(
            [
                "publish-job",
                "job_0123456789abcdef",
                "--connect-origin",
                "https://connect.sitecmd.com",
                "--artifact-dir",
                "/tmp/a",
            ]
            .map(String::from)
            .to_vec(),
        )
        .unwrap();
        match parsed {
            AutofixCommand::PublishJob(args) => {
                assert_eq!(args.job_id, "job_0123456789abcdef");
                assert_eq!(args.connect_origin, "https://connect.sitecmd.com");
                assert_eq!(args.artifact_dir, std::path::PathBuf::from("/tmp/a"));
                assert_eq!(args.path, std::path::PathBuf::from("."));
            }
            other => panic!("{other:?}"),
        }
        assert!(parse_args(
            [
                "publish-job",
                "job_0123456789abcdef",
                "--connect-origin",
                "https://connect.sitecmd.com",
            ]
            .map(String::from)
            .to_vec()
        )
        .unwrap_err()
        .contains("--artifact-dir"));
        assert!(parse_args(
            [
                "publish-job",
                "job_0123456789abcdef",
                "--artifact-dir",
                "/tmp/a",
            ]
            .map(String::from)
            .to_vec()
        )
        .unwrap_err()
        .contains("--connect-origin"));
        assert!(parse_args(
            ["publish-job", "job_0123456789abcdef", "--force"]
                .map(String::from)
                .to_vec()
        )
        .unwrap_err()
        .contains("Unknown option"));
    }

    #[test]
    fn rejects_an_unknown_subcommand_and_a_missing_value() {
        assert!(parse_args(vec!["rewrite".into()])
            .unwrap_err()
            .contains("Unknown autofix command"));
        assert!(parse_args(vec!["apply".into(), "--only".into()])
            .unwrap_err()
            .contains("--only"));
    }
}
