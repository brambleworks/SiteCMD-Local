use super::{redact_log_diagnostic, redact_secrets};

fn pem_cases() -> Vec<String> {
    let mut cases = Vec::new();
    for marker in [
        "",
        "#",
        "//",
        "--",
        ";",
        "*",
        ">",
        "///",
        "//!",
        "##",
        ";;",
        "**",
        "%",
        "<!--",
        "REM",
        "// # ;! % ",
    ] {
        for end in [false, true] {
            let mut source = format!(
                "{marker} -----BEGIN {}-----\n{marker} {}\n{marker} {}\n",
                "PRIVATE KEY",
                "aB3+".repeat(16),
                "aB3+".repeat(4)
            );
            if end {
                source.push_str(&format!("{marker} -----END {}-----\n", "PRIVATE KEY"));
            }
            source.push_str("const ready = true;");
            cases.push(source);
        }
    }
    cases
}

#[test]
fn combined_comment_markers_keep_pem_bodies_private() {
    // Repeated and combined comment markers expose private-key bodies.
    for source in pem_cases()
        .into_iter()
        .filter(|s| s.contains("BEGIN PRIVATE KEY"))
    {
        for rendered in [redact_secrets(&source), redact_log_diagnostic(&source)] {
            assert!(!rendered.contains("aB3+"), "PEM comment body escaped");
            assert!(rendered.contains("const ready = true;"));
        }
    }
}
#[test]
fn base64_prefixes_are_part_of_pem_bodies() {
    // Stripping slash markers can shorten a standalone key body below detection length.
    let body = "aB3+".repeat(9);
    for prefix in ["////", "////////", "////////////"] {
        let source = format!("{prefix}{body}");
        assert!(
            !redact_secrets(&source).contains(&body),
            "base64 body prefix escaped"
        );
    }
}
