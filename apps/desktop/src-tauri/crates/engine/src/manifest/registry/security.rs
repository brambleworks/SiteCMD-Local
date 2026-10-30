//! Capability metadata for security checks.
//!
//! TLS chain and protocol verdicts compare within trust and transport profiles;
//! expiry and hostname verdicts compare across adapters.

use crate::checks::security::cookies::CHECK_ID_PREFIX as COOKIES_PREFIX;
use crate::checks::security::exposed_files::CHECK_ID_PREFIX as EXPOSED_FILES_PREFIX;
use crate::manifest::{CompareDimension, Entry, RuntimeFact};

/// Every DNS-posture check reads records for the registrable domain, which is
/// what makes the resolver its runtime need rather than a fetch.
const DNS: &[RuntimeFact] = &[RuntimeFact::Resolver];

/// Certificate facts come from a handshake, which the two adapters perform
/// differently while filling the same schema.
const TLS: &[RuntimeFact] = &[RuntimeFact::TlsFacts];

pub const ENTRIES: &[Entry] = &[
    Entry::new("security.cookies"),
    // Dynamic per-cookie ids use this family; fixed parse-condition ids remain
    // separate named entries.
    Entry::new(COOKIES_PREFIX).family(),
    Entry::new("security.cookies.malformed_header"),
    Entry::new("security.cookies.unreadable_headers"),
    Entry::new("security.cors"),
    Entry::new("security.cors_reflection").probe(),
    Entry::new("security.directory_listing").probe().origin(),
    Entry::new("security.dns.caa").probe().origin().needs(DNS),
    Entry::new("security.dns.dangling_cname")
        .probe()
        .origin()
        .needs(DNS),
    Entry::new("security.dns.dkim").probe().origin().needs(DNS),
    Entry::new("security.dns.dmarc").probe().origin().needs(DNS),
    Entry::new("security.dns.dnssec")
        .probe()
        .origin()
        .needs(DNS),
    Entry::new("security.dns.mx").probe().origin().needs(DNS),
    Entry::new("security.dns.spf").probe().origin().needs(DNS),
    // Registration expiry moves on the calendar. A domain crossing its
    // warning band is time passing, not the operator breaking something.
    Entry::new("security.domain_expiry")
        .probe()
        .origin()
        .clock_dependent()
        .needs(&[RuntimeFact::Rdap]),
    Entry::new("security.email_exposure"),
    // One row for every `security.exposed_files.<path>` id the probe walk
    // produces from its sensitive-path list.
    Entry::new(EXPOSED_FILES_PREFIX).family().probe().origin(),
    Entry::new("security.exposed_files.source_secrets")
        .probe()
        .origin(),
    Entry::new("security.exposed_files.summary")
        .probe()
        .origin(),
    Entry::new("security.form_action_hijack"),
    Entry::new("security.headers.cross_origin"),
    Entry::new("security.headers.csp"),
    Entry::new("security.headers.hsts"),
    Entry::new("security.headers.permissions_policy"),
    Entry::new("security.headers.referrer_policy"),
    Entry::new("security.headers.x_content_type_options"),
    Entry::new("security.headers.x_frame_options"),
    Entry::new("security.https_enforcement").probe().origin(),
    Entry::new("security.insecure_form"),
    Entry::new("security.mixed_content"),
    // Revision 2 requires a majority of planned probes before passing.
    Entry::new("security.open_redirect")
        .probe()
        .origin()
        .revision(2),
    // The Expires field is the point of the file, so the verdict is a
    // function of when it was read.
    Entry::new("security.security_txt")
        .probe()
        .origin()
        .clock_dependent(),
    Entry::new("security.server_info.server_header"),
    Entry::new("security.server_info.x_powered_by"),
    Entry::new("security.sri"),
    Entry::new("security.ssl.chain")
        .probe()
        .origin()
        .needs(TLS)
        .compare_on(&[CompareDimension::TrustAuthority]),
    Entry::new("security.ssl.expiry")
        .probe()
        .origin()
        .clock_dependent()
        .needs(TLS),
    Entry::new("security.ssl.hostname")
        .probe()
        .origin()
        .needs(TLS),
    Entry::new("security.ssl.protocol")
        .probe()
        .origin()
        .needs(TLS)
        .compare_on(&[CompareDimension::TlsClientProfile]),
    Entry::new("security.vibe.client_auth"),
    Entry::new("security.vibe.csrf"),
    Entry::new("security.vibe.env_exposure"),
    Entry::new("security.vibe.exposed_keys"),
    Entry::new("security.vibe.exposed_keys.public"),
    Entry::new("security.vibe.hardcoded_secrets"),
    // Libraries come from the page; the verdict comes from a corpus that
    // moves without the site changing, so an identical library set with a
    // changed answer is a detector update rather than a new defect.
    Entry::new("security.vulnerable_libraries")
        .probe()
        .external_corpus()
        .needs(&[RuntimeFact::PageArtifact, RuntimeFact::VulnerabilityCorpus]),
    // These checks require localhost, so a hosted page cannot produce them.
    Entry::new("security.env_leak").unsupported(),
    Entry::new("security.source_maps").unsupported(),
];
