use super::*;
use crate::manifest::{CheckClass, CheckScope, HostedLane};
use std::collections::HashSet;

#[test]
fn the_unsupported_set_is_the_localhost_only_checks() {
    let mut unsupported: Vec<&str> = entries()
        .filter(|entry| entry.lane == HostedLane::Unsupported)
        .map(|entry| entry.check)
        .collect();
    let checks = crate::checks::predeploy::all_predeploy_checks();
    let mut localhost_only: Vec<&str> = checks.iter().map(|check| check.id()).collect();
    unsupported.sort_unstable();
    localhost_only.sort_unstable();
    assert_eq!(unsupported, localhost_only);
}

#[test]
fn every_check_id_appears_once() {
    let mut seen = HashSet::new();
    for entry in entries() {
        assert!(
            seen.insert(entry.check),
            "'{}' has two registry rows; the published manifest is keyed by check id",
            entry.check
        );
    }
}

#[test]
fn runner_ids_never_get_an_entry() {
    let registered: HashSet<&str> = entries().map(|entry| entry.check).collect();
    for (id, reason) in RUNNER_IDS {
        assert!(
            !registered.contains(id),
            "'{id}' is declared a runner id ({reason}) but also has a manifest entry; a contract for an id no observation can carry means nothing"
        );
    }
}

#[test]
fn family_rows_are_keyed_by_the_prefix_their_ids_carry() {
    for entry in entries().filter(|entry| entry.family) {
        assert!(
            entry.check.ends_with('.'),
            "family row '{}' must be keyed by the id prefix, delimiter included, or `starts_with` resolution would match unrelated ids",
            entry.check
        );
    }
    let families: HashSet<&str> = entries()
        .filter(|entry| entry.family)
        .map(|entry| entry.check)
        .collect();
    // Pinned against the source constants, so a renamed namespace cannot
    // leave the family entry pointing at a prefix nothing carries any more.
    assert!(families.contains(crate::checks::accessibility::axe::CHECK_ID_PREFIX));
    assert!(families.contains(crate::checks::security::cookies::CHECK_ID_PREFIX));
    assert!(families.contains(crate::checks::security::exposed_files::CHECK_ID_PREFIX));
    assert_eq!(families.len(), 3);
}

#[test]
fn only_a_deterministic_check_may_declare_complete_inputs() {
    for entry in entries().filter(|entry| !entry.equivalence_inputs.is_empty()) {
        assert_eq!(
            entry.class,
            CheckClass::Deterministic,
            "'{}' declares equivalence_inputs; a clock-dependent or corpus-graded verdict is a function of its inputs AND something else, so equal projections would not imply equal verdicts",
            entry.check
        );
    }
}

#[test]
fn no_check_claims_complete_inputs_yet() {
    let declared: Vec<&str> = entries()
        .filter(|entry| !entry.equivalence_inputs.is_empty())
        .map(|entry| entry.check)
        .collect();
    assert!(
        declared.is_empty(),
        "these rows declare equivalence_inputs without the property test that makes the declaration sound: {declared:?}"
    );
}

#[test]
fn a_measurement_is_something_the_runtime_measured() {
    for entry in entries().filter(|entry| entry.class == CheckClass::Measurement) {
        assert!(
            matches!(entry.lane, HostedLane::ProbeAdapter | HostedLane::Browser),
            "'{}' is classed measurement but runs in the {:?} lane",
            entry.check,
            entry.lane
        );
    }
}

#[test]
fn the_clock_dependent_set_is_deliberate() {
    let mut clock: Vec<&str> = entries()
        .filter(|entry| entry.class == CheckClass::ClockDependent)
        .map(|entry| entry.check)
        .collect();
    clock.sort_unstable();
    assert_eq!(
        clock,
        [
            "security.domain_expiry",
            "security.security_txt",
            "security.ssl.expiry",
        ]
    );
}

#[test]
fn the_external_corpus_set_is_deliberate() {
    let corpus: Vec<&str> = entries()
        .filter(|entry| entry.class == CheckClass::ExternalCorpus)
        .map(|entry| entry.check)
        .collect();
    assert_eq!(corpus, ["security.vulnerable_libraries"]);
}

#[test]
fn only_the_cross_page_checks_are_session_scoped() {
    // Only cross-page checks may use a complete-route-set absence as evidence.
    let mut session: Vec<&str> = entries()
        .filter(|entry| entry.scope == CheckScope::Session)
        .map(|entry| entry.check)
        .collect();
    session.sort_unstable();
    assert_eq!(
        session,
        [
            "seo.canonical_loop",
            "seo.duplicate_description_across_pages",
            "seo.duplicate_h1",
            "seo.duplicate_title_across_pages",
            "seo.hreflang_reciprocity",
            "seo.noindex_in_sitemap",
            "seo.orphan_pages",
        ]
    );
}

#[test]
fn ids_look_like_ids() {
    for entry in entries() {
        assert!(
            entry
                .check
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c)),
            "'{}' is not a well-formed check id",
            entry.check
        );
    }
}
