//! Authentication argument parsing and exit status translation.

use sitecmd_runtime::cli::login::{self, LoginArgs};
use std::process::ExitCode;

pub(crate) fn parse_login_args(
    mut args: impl Iterator<Item = String>,
) -> Result<LoginArgs, String> {
    let mut connect_origin = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--connect-origin" if connect_origin.is_none() => {
                let value = args
                    .next()
                    .filter(|value| !value.starts_with('-'))
                    .ok_or("--connect-origin requires a URL")?;
                connect_origin = Some(value);
            }
            _ => return Err("expected only --connect-origin <url>".into()),
        }
    }
    Ok(LoginArgs { connect_origin })
}

pub(crate) fn dispatch_login(args: impl Iterator<Item = String>, logout: bool) -> ExitCode {
    let args: Vec<_> = args.collect();
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        super::help::print_login_help(logout);
        return ExitCode::SUCCESS;
    }
    let parsed = match parse_login_args(args.into_iter()) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    let runtime = super::build_runtime();
    let result = if logout {
        runtime.block_on(login::run_logout(parsed))
    } else {
        runtime.block_on(login::run_login(parsed))
    };
    match result {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            if !error.is_empty() {
                eprintln!("{error}");
            }
            ExitCode::from(login::failure_exit_code(&error))
        }
    }
}
