// A sweep producer left excluded or without a runner silently loses hosted coverage.

use super::*;

#[test]
fn probes_sweeps_are_claimed_and_never_excluded() {
    let claimed = probe_check_index();
    for id in [
        "security.directory_listing",
        "security.exposed_files.",
        "security.exposed_files.source_secrets",
        "security.exposed_files.summary",
        "security.security_txt",
    ] {
        assert!(claimed.contains_key(id), "{id} has no runner");
        assert!(!EXCLUDED_PROBE_CHECKS
            .iter()
            .any(|(excluded, _)| *excluded == id));
    }
}
