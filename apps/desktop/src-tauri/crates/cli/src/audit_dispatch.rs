use sitecmd_runtime::cli::audit::{self, AuditArgs};
use std::process::ExitCode;

pub(crate) fn dispatch_audit(args: impl Iterator<Item = String>) -> ExitCode {
    let args: Vec<String> = args.collect();
    if audit::help_requested(&args) {
        eprint!("{}", audit::HELP);
        return ExitCode::SUCCESS;
    }

    match audit::parse_args(args) {
        Ok(audit_args) => run_audit(audit_args),
        Err(error) => {
            eprintln!("Error: {error}\nRun `sitecmd audit --help` for usage.");
            ExitCode::from(2)
        }
    }
}

fn run_audit(args: AuditArgs) -> ExitCode {
    match audit::run(&args) {
        Ok(outcome) => {
            if args.output.is_none() {
                println!("{}", outcome.rendered);
            }
            if outcome.threshold_failed {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::from(2)
        }
    }
}
