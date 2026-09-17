//! `sitecmd autofix`: the template engine on a checkout (`apply`), and the
//! two halves of a Connect fix job (`run-job`, `publish-job`).

pub mod apply;

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
    "Exit codes:\n",
    "  0  Completed\n",
    "  1  A job reported a failure outcome\n",
    "  2  Usage or operational error\n\n",
    "Examples:\n",
    "  sitecmd autofix apply --dry-run\n",
    "  sitecmd autofix apply --only security.headers.x_content_type_options\n",
);

#[derive(Debug)]
pub enum AutofixCommand {
    Apply(apply::ApplyArgs),
}

pub fn help_requested(args: &[String]) -> bool {
    args.iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
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
        let AutofixCommand::Apply(args) = parsed;
        assert_eq!(args.only, vec!["security.headers.x_content_type_options"]);
        assert!(args.dry_run);
        assert_eq!(args.path, std::path::PathBuf::from("."));
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
