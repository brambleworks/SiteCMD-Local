//! Connection argument parsing and exit status translation.

use sitecmd_runtime::cli::connect::{self, ConnectArgs};
use std::process::ExitCode;

pub(crate) fn parse_connect_args(
    mut args: impl Iterator<Item = String>,
) -> Result<ConnectArgs, String> {
    let mut url = None;
    let mut repository = None;
    let mut rotate = false;
    let mut connect_origin = None;
    let mut path = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--repo" if repository.is_none() => repository = Some(value(&mut args, "--repo")?),
            "--rotate" if !rotate => rotate = true,
            "--connect-origin" if connect_origin.is_none() => {
                connect_origin = Some(value(&mut args, "--connect-origin")?)
            }
            "--path" if path.is_none() => path = Some(value(&mut args, "--path")?.into()),
            arg if !arg.starts_with('-') && url.is_none() => url = Some(arg.to_string()),
            _ => {
                return Err(
                    "expected a site URL and only --repo, --rotate, --connect-origin or --path"
                        .into(),
                )
            }
        }
    }
    Ok(ConnectArgs {
        url: url.ok_or("sitecmd connect requires the site's HTTPS URL")?,
        repository,
        rotate,
        connect_origin,
        path,
    })
}

fn value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .filter(|value| !value.starts_with('-'))
        .ok_or_else(|| format!("{flag} requires a value"))
}

pub(crate) fn dispatch_connect(args: impl Iterator<Item = String>) -> ExitCode {
    let args: Vec<_> = args.collect();
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        super::help::print_connect_help();
        return ExitCode::SUCCESS;
    }
    let parsed = match parse_connect_args(args.into_iter()) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    match super::build_runtime().block_on(connect::run_connect(parsed)) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(connect::failure_exit_code(&error))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_arguments_preserve_repository_rotation_origin_and_path() {
        // Bug: the standalone command can drop rotation or route credentials to a repository-selected origin.
        let args = parse_connect_args(
            [
                "https://example.com",
                "--repo",
                "owner/name",
                "--rotate",
                "--connect-origin",
                "https://connect.example.com",
                "--path",
                ".",
            ]
            .map(str::to_owned)
            .into_iter(),
        )
        .unwrap();
        assert_eq!(args.url, "https://example.com");
        assert_eq!(args.repository.as_deref(), Some("owner/name"));
        assert!(args.rotate);
        assert_eq!(
            args.connect_origin.as_deref(),
            Some("https://connect.example.com")
        );
        assert_eq!(args.path, Some(std::path::PathBuf::from(".")));
    }

    #[test]
    fn connect_arguments_refuse_missing_duplicate_and_unknown_values() {
        // Bug: ambiguous arguments can silently choose an unintended repository or Connect origin.
        for args in [
            vec![],
            vec!["--repo"],
            vec!["https://example.com", "--rotate", "--rotate"],
            vec!["https://example.com", "--repo", "--rotate"],
            vec!["https://a.com", "https://b.com"],
            vec!["https://a.com", "--unknown"],
        ] {
            assert!(parse_connect_args(args.into_iter().map(str::to_owned)).is_err());
        }
    }
}
