use std::process::ExitCode;

const HELP: &str = "SiteCMD rules - List Code Scan rules\n\n\
Usage:\n  sitecmd rules [--format text|json]\n\n\
Options:\n  \
  --format <FORMAT>       Output format: text (default), json\n  \
  --help, -h              Show this help\n\n\
Lists producerRuleId, checkId, domain, defaultSeverity, and severitySource in producerRuleId order.\n\
severitySource is fixed for registry-pinned grades, or per_finding with a null defaultSeverity.\n\
JSON output includes the CLI version. Successful listings exit 0; invalid arguments exit 2.";

pub(crate) fn dispatch_rules(args: impl Iterator<Item = String>) -> ExitCode {
    let args: Vec<_> = args.collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        eprintln!("{HELP}");
        return ExitCode::SUCCESS;
    }
    match parse_format(args.into_iter())
        .and_then(|json| sitecmd_runtime::cli::rules::render(json, env!("CARGO_PKG_VERSION")))
    {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Error: {error}\nRun `sitecmd rules --help` for usage.");
            ExitCode::from(2)
        }
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
