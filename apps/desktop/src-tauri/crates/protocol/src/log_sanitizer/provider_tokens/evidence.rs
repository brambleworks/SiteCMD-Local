//! Additional publication masks that do not change route placeholder handling.

use super::SecretPattern;

pub(super) static PATTERNS: [SecretPattern; 9] = [
    secret_pattern!(
        &["glpat-"],
        r"(?-u:\b)(?P<prefix>glpat-)[A-Za-z0-9_-]{20,}",
        "${prefix}***"
    ),
    secret_pattern!(
        &["pk_live_", "pk_test_"],
        r"(?-u:\b)(?P<prefix>pk_(?:live|test)_)[A-Za-z0-9]{20,}",
        "${prefix}***"
    ),
    secret_pattern!(
        &["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."],
        r"(?-u:\b)(?P<prefix>eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.)[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",
        "${prefix}***"
    ),
    secret_pattern!(
        &["npm_"],
        r"(?-u:\b)(?P<prefix>npm_)[A-Za-z0-9]{36,}",
        "${prefix}***"
    ),
    secret_pattern!(
        &["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"],
        r"(?-u:\b)(?P<prefix>xox[baprs]-)[A-Za-z0-9-]{10,}",
        "${prefix}***"
    ),
    secret_pattern!(
        &["SK"],
        r"(?-u:\b)(?P<prefix>SK)[0-9A-Fa-f]{32,}",
        "${prefix}***"
    ),
    secret_pattern!(
        &["SG."],
        r"(?-u:\b)(?P<prefix>SG\.)[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43,}",
        "${prefix}***"
    ),
    secret_pattern!(
        &["hf_", "api_org_"],
        r"(?-u:\b)(?P<prefix>hf_|api_org_)[A-Za-z]{34,}",
        "${prefix}***"
    ),
    secret_pattern!(
        &["key-"],
        r"(?P<boundary>^|[^A-Za-z0-9_-])(?P<prefix>key-)[A-Za-z0-9]{32,}",
        "${boundary}${prefix}***"
    ),
];
