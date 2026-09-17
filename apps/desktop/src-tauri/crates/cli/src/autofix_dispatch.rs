use sitecmd_runtime::cli::autofix;
use std::process::ExitCode;

pub(crate) fn dispatch_autofix(args: impl Iterator<Item = String>) -> ExitCode {
    let args: Vec<String> = args.collect();
    if autofix::help_requested(&args) {
        eprint!("{}", autofix::HELP);
        return ExitCode::SUCCESS;
    }
    match autofix::parse_args(args) {
        // The one runtime builder every asynchronous command shares.
        Ok(command) => match crate::build_runtime().block_on(autofix::run(command)) {
            Ok(code) => ExitCode::from(code),
            Err(error) => {
                eprintln!("Error: {error}");
                ExitCode::from(2)
            }
        },
        Err(error) => {
            eprintln!("Error: {error}\nRun `sitecmd autofix --help` for usage.");
            ExitCode::from(2)
        }
    }
}
