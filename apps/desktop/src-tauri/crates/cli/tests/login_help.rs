use std::process::Command;

#[path = "support/cli_binary.rs"]
mod cli_binary;
use cli_binary::cli_binary;

#[test]
fn login_help_prints_aligned_command_and_option_descriptions() {
    // Bug: help can omit authentication dispatch or misalign its descriptions.
    let invoke = |args: &[&str]| {
        let result = Command::new(cli_binary()).args(args).output().unwrap();
        assert!(result.status.success());
        assert!(result.stdout.is_empty());
        String::from_utf8(result.stderr).unwrap()
    };
    let main = invoke(&["--help"]);
    let existing = main
        .lines()
        .find(|line| line.contains("Initialize project with .sitecmd/ config"))
        .unwrap();
    let description_offset = existing.find("Initialize project with .sitecmd/ config");
    for description in [
        "Sign in to SiteCMD on this computer",
        "Sign out and revoke this computer's token",
    ] {
        let line = main
            .lines()
            .find(|line| line.contains(description))
            .unwrap();
        assert_eq!(line.find(description), description_offset);
    }
    for command in ["login", "logout"] {
        let text = invoke(&[command, "--help"]);
        assert!(text.contains(&format!("sitecmd {command} [options]")));
        let origin = text
            .lines()
            .find(|line| line.contains("--connect-origin <url>"))
            .unwrap();
        let help = text
            .lines()
            .find(|line| line.contains("--help, -h"))
            .unwrap();
        assert_eq!(
            origin.find("The SiteCMD Connect to use"),
            help.find("Show this help")
        );
    }
}
