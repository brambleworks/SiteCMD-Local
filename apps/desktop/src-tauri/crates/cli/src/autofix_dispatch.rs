use sitecmd_runtime::cli::autofix;
use std::process::ExitCode;

pub(crate) fn dispatch_autofix(args: impl Iterator<Item = String>) -> ExitCode {
    let args: Vec<String> = args.collect();
    if autofix::help_requested(&args) {
        eprint!("{}", autofix::HELP);
        return ExitCode::SUCCESS;
    }
    match autofix::parse_args(args) {
        Ok(command) => match tokio::runtime::Runtime::new()
            .expect("failed to build tokio runtime")
            .block_on(autofix::run(command))
        {
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
