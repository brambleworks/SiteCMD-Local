use std::process::ExitCode;

const HELP: &str = "SiteCMD rules - List Code Scan rules\n\n\
Usage:\n  sitecmd rules [--format text|json]\n\n\
Options:\n  \
  --format <FORMAT>       Output format: text (default), json\n  \
  --help, -h              Show this help\n\n\
Lists producerRuleId, checkId, category, defaultSeverity, and severitySource in producerRuleId order.\n\
severitySource is fixed for registry-pinned grades, or per_finding with a null defaultSeverity.\n\
JSON output includes the CLI version. Successful listings exit 0; invalid arguments exit 2.";

pub(crate) fn dispatch_rules(args: impl Iterator<Item = String>) -> ExitCode {
    let args: Vec<_> = args.collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        eprintln!("{HELP}");
        return ExitCode::SUCCESS;
    }
    render_rules(args.into_iter(), |json| {
        sitecmd_runtime::cli::rules::render(json, env!("CARGO_PKG_VERSION"))
    })
    .unwrap_or_else(|error| {
        eprintln!("{error}");
        ExitCode::from(2)
    })
}

fn render_rules(
    args: impl Iterator<Item = String>,
    render: impl FnOnce(bool) -> Result<String, String>,
) -> Result<ExitCode, String> {
    let json = parse_format(args)
        .map_err(|error| format!("Error: {error}\nRun `sitecmd rules --help` for usage."))?;
    match render(json) {
        Ok(output) => {
            println!("{output}");
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => Err(format!("Error: {error}")),
    }
}

fn parse_format(mut args: impl Iterator<Item = String>) -> Result<bool, String> {
    let mut json = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--format" => {
                let value = args
                    .next()
                    .ok_or_else(|| "Missing value for --format".to_string())?;
                json = match value.as_str() {
                    "json" => true,
                    "text" => false,
                    _ => return Err(format!("Unknown format: {value}. Use: text, json")),
                };
            }
            option if option.starts_with('-') => return Err(format!("Unknown option: {option}")),
            value => return Err(format!("Unexpected argument: {value}")),
        }
    }
    Ok(json)
}

#[cfg(test)]
mod tests {
    #[test]
    fn engine_load_failure_has_no_usage_hint() {
        // An engine load failure can be mistaken for an argument error.
        let error =
            super::render_rules(std::iter::empty(), |_| Err("Could not load engine.".into()));
        assert_eq!(error.unwrap_err(), "Error: Could not load engine.");
    }
}
