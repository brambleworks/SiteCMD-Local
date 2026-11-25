//! Local suppression details belong only on an interactive terminal outside CI.

use std::io::IsTerminal;

#[derive(Clone, Copy)]
pub(super) struct OutputContext {
    pub terminal: bool,
    pub ci: bool,
}

impl OutputContext {
    pub fn current() -> Self {
        Self {
            terminal: std::io::stdout().is_terminal(),
            ci: is_ci(|name| std::env::var_os(name).is_some()),
        }
    }

    pub fn allows_local_details(self, output_file: bool) -> bool {
        self.terminal && !self.ci && !output_file
    }
}

fn is_ci(present: impl Fn(&str) -> bool) -> bool {
    [
        "CI",
        "GITHUB_ACTIONS",
        "TF_BUILD",
        "JENKINS_URL",
        "BUILD_ID",
        "TEAMCITY_VERSION",
        "BUILDKITE",
        "CIRCLECI",
        "GITLAB_CI",
    ]
    .into_iter()
    .any(present)
}

#[cfg(test)]
mod tests {
    #[test]
    fn recognizes_ci_runners_without_the_ci_variable() {
        // Bug M13: Azure and Jenkins terminal runs are mistaken for local sessions.
        for name in ["CI", "GITHUB_ACTIONS", "TF_BUILD", "JENKINS_URL"] {
            assert!(super::is_ci(|candidate| candidate == name), "{name}");
        }
        assert!(!super::is_ci(|_| false));
    }
}
