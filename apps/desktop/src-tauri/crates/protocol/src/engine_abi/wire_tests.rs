use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use crate::vocab::Severity;

use super::*;

fn assert_rejects_extra_field<T: DeserializeOwned>(mut wire: Value) {
    if let Err(error) = serde_json::from_value::<T>(wire.clone()) {
        panic!("{}: {error}", std::any::type_name::<T>());
    }
    wire["extra"] = json!(true);
    assert!(
        serde_json::from_value::<T>(wire).is_err(),
        "{} accepted an extra field",
        std::any::type_name::<T>()
    );
}

#[test]
fn known_session_kinds_reject_extra_fields() {
    // Internally tagged unit variants can silently discard extra fields.
    let audit = json!({"kind": "audit"});
    let task: Task = serde_json::from_value(audit.clone()).unwrap();
    assert_eq!(serde_json::to_value(task).unwrap(), audit);
    assert_rejects_extra_field::<Task>(audit);
    assert_rejects_extra_field::<Want>(json!({"kind": "file", "path": "src/lib.rs"}));
    assert_rejects_extra_field::<WantAnswer>(json!({"kind": "file", "body": {"at": 0, "len": 5}}));
}

#[test]
fn rel_path_rejects_colons_and_ascii_controls() {
    // A listing path can admit alternate stream syntax or invisible control bytes.
    let controls = (0..=31)
        .chain([127])
        .map(|byte| format!("src/a{}b", char::from(byte)));
    for raw in ["src/a:b", "ab:cd"]
        .map(String::from)
        .into_iter()
        .chain(controls)
    {
        assert!(RelPath::parse(&raw).is_err(), "{raw:?}");
        assert!(
            serde_json::from_value::<RelPath>(json!(raw)).is_err(),
            "{raw:?}"
        );
    }
    assert!(RelPath::parse("src/CON").is_ok());
    assert!(RelPath::parse("src/trailing.").is_ok());
}

#[test]
fn database_offer_round_trips_only_its_id_and_engine() {
    // Database offers can disclose a host-side path or connection value.
    let wire = json!({"id": "db-1", "engine": "sqlite"});
    let offer: DatabaseTargetOffer = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(offer).unwrap(), wire);
    assert!(serde_json::from_value::<DatabaseTargetOffer>(json!({
        "id": "db-1"
    }))
    .is_err());
    for field in ["path", "url", "user", "password"] {
        let mut with_extra = wire.clone();
        with_extra[field] = json!("private");
        assert!(serde_json::from_value::<DatabaseTargetOffer>(with_extra).is_err());
    }
}

#[test]
fn unsupported_error_round_trips_as_a_closed_code() {
    // The host can reject unsupported-operation answers as unrecognized errors.
    let wire = json!({"error": "unsupported"});
    let answer: ErrorAnswer = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(answer).unwrap(), wire);
}

fn audit_issue() -> Value {
    json!({
        "rule_id": "example-rule", "id": "example-rule:src/lib.rs",
        "check_id": "code_scan.example-rule", "category": "security",
        "title": "Finding", "description": "Finding details", "path": "src/lib.rs",
        "line": 10, "severity": "high",
        "confidence": "confirmed", "why_now": "Impact", "likely_fix": "Suggested change",
        "verify_hint": "Run the check again", "confidence_reason": "Observed directly",
        "fix_prompt": null, "evidence": "Evidence"
    })
}

fn audit_report() -> Value {
    json!({
        "checked_at": "2026-11-20T00:00:00Z", "framework": null, "issue_count": 1,
        "critical_count": 0, "high_count": 1, "medium_count": 0, "low_count": 0,
        "issues": [audit_issue()],
        "skipped_scopes": {
            "nested_repositories": 3, "gitignored_directories": 2, "sample_names": ["vendor"]
        }
    })
}

#[test]
fn audit_answer_uses_snake_case_and_requires_skipped_scopes() {
    // Camel-case keys or missing scope counts can hide protocol mismatches.
    let mut audit = audit_report();
    let wire = json!({"done": {"audit": audit}});
    let step: Step = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(step).unwrap(), wire);
    audit.as_object_mut().unwrap().remove("skipped_scopes");
    assert!(serde_json::from_value::<AuditReport>(audit).is_err());
}

#[test]
fn audit_rule_skips_are_optional_and_closed() {
    // A free-text sample can carry module wording, and a required field breaks reports without rules files.
    let mut audit = audit_report();
    let report: AuditReport = serde_json::from_value(audit.clone()).unwrap();
    assert_eq!(report.skipped_scopes.rule_blocks_skipped, None);
    assert_eq!(report.skipped_scopes.rule_samples, None);
    audit["skipped_scopes"]["rule_blocks_skipped"] = json!(2);
    audit["skipped_scopes"]["rule_samples"] = json!([
        { "path": "firestore.rules", "line": 3, "column": 5, "reason": { "scope_limit": { "limit": 48 } } },
        { "path": { "id": 0 }, "line": 1, "column": 1, "reason": "unreadable_json" }
    ]);
    let report: AuditReport = serde_json::from_value(audit.clone()).unwrap();
    assert_eq!(serde_json::to_value(report).unwrap(), audit);
    audit["skipped_scopes"]["rule_samples"][1]["reason"] = json!("unreadable JSON rules file");
    assert!(serde_json::from_value::<AuditReport>(audit).is_err());
}

fn local_site_answer() -> Value {
    json!({
        "results": [{
            "check_id": "example-check", "category": "security", "title": "Check",
            "description": "Check details", "status": "skipped", "skip_reason": "blocked",
            "severity": "high", "fix_prompt": "Prompt", "manual_fix": "Manual fix",
            "raw_data": {"sourceKey": true}, "confidence": "confirmed",
            "confidence_reason": "Observed directly", "why_it_matters": "Impact"
        }],
        "score": {
            "overall": 100.0, "per_category": {"security": 100.0}, "critical_count": 0,
            "high_count": 0, "medium_count": 0, "low_count": 0, "exploitable_capped": false,
            "breakdown": {
                "base": 100.0, "critical_points": 0.0, "high_points": 0.0, "medium_points": 0.0,
                "low_points": 0.0, "eff_critical": 0.0, "eff_high": 0.0, "eff_medium": 0.0,
                "eff_low": 0.0, "floor_applied": false, "ceiling_applied": false
            },
            "computed_at": 0
        },
        "fix_points": [],
        "categories": [{
            "category": "polish", "score": 100, "issues_total": 0, "issues_critical": 0,
            "issues_high": 0, "issues_medium": 0, "issues_low": 0, "issues_passed": 1
        }]
    })
}

#[test]
fn local_site_answer_uses_snake_case_for_checks_and_score() {
    // Shared check and score types can introduce camel-case keys into standalone answers.
    let wire = local_site_answer();
    let answer: LocalSiteAnswer = serde_json::from_value(wire.clone()).unwrap();
    assert!(!answer.results[0].covered);
    assert_eq!(serde_json::to_value(answer).unwrap(), wire);
    let mut with_coverage = wire.clone();
    with_coverage["results"][0]["covered"] = json!(true);
    let answer: LocalSiteAnswer = serde_json::from_value(with_coverage.clone()).unwrap();
    assert!(answer.results[0].covered);
    assert_eq!(serde_json::to_value(answer).unwrap(), with_coverage);
    for path in ["/results/0", "/score", "/score/breakdown", "/categories/0"] {
        let mut extra = wire.clone();
        extra.pointer_mut(path).unwrap()["extra"] = json!(true);
        assert!(serde_json::from_value::<LocalSiteAnswer>(extra).is_err());
    }
}

#[test]
fn code_rule_default_severity_round_trips_nullable_grade() {
    // Bug: Rule metadata assigns a grade to a per-finding rule on the wire.
    for (severity, expected) in [(json!(null), None), (json!("high"), Some(Severity::High))] {
        let wire = json!({
            "id": "example-rule", "title": "example-rule", "domain": "security",
            "default_severity": severity, "check_id": "code_scan.example-rule",
            "category": "security", "rationale": null
        });
        let rule: CodeRuleInfo = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(rule.default_severity, expected);
        assert_eq!(serde_json::to_value(rule).unwrap(), wire);
    }
}

#[test]
fn standalone_answers_reject_extra_fields() {
    // An older host can silently accept fields from a mismatched engine module.
    let report = audit_report();
    let patch = json!({"path": "src/lib.rs", "base_sha256": "abc", "content": "updated"});
    let rule = json!({
        "id": "example-rule", "title": "Rule", "domain": "security", "default_severity": "high",
        "check_id": "code_scan.example-rule", "category": "security", "rationale": null
    });
    assert_rejects_extra_field::<AuditIssue>(audit_issue());
    assert_rejects_extra_field::<SkippedScopes>(report["skipped_scopes"].clone());
    assert_rejects_extra_field::<AuditReport>(report);
    assert_rejects_extra_field::<Patch>(patch.clone());
    assert_rejects_extra_field::<FixPlan>(json!({"patches": [patch]}));
    assert_rejects_extra_field::<Brief>(json!({"title": "Finding", "body": "Details"}));
    assert_rejects_extra_field::<CodeRuleInfo>(rule.clone());
    assert_rejects_extra_field::<EngineInfo>(json!({
        "module_version": "1.0.0", "abi_version": super::ENGINE_ABI_VERSION, "manifest_digest": "0123456789abcdef",
        "code_rules": [rule], "local_checks": ["example-check"]
    }));
    assert_rejects_extra_field::<LocalSiteAnswer>(local_site_answer());
}

#[test]
fn listing_requires_ignored_and_skipped_paths_on_the_wire() {
    // Missing listing metadata could hide ignored files and omitted paths.
    let entry = serde_json::json!({"path": ".env", "size": 4, "kind": "file", "ignored": true});
    let wire = serde_json::json!({"entries": [entry], "skipped_paths": 2});
    let listing: super::Listing = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(listing.skipped_paths, 2);
    assert!(listing.entries[0].ignored);
    assert_eq!(serde_json::to_value(listing).unwrap(), wire);

    let mut without_count = wire.clone();
    without_count
        .as_object_mut()
        .unwrap()
        .remove("skipped_paths");
    assert!(serde_json::from_value::<super::Listing>(without_count).is_err());

    let mut without_ignored = wire.clone();
    without_ignored["entries"][0]
        .as_object_mut()
        .unwrap()
        .remove("ignored");
    assert!(serde_json::from_value::<super::Listing>(without_ignored).is_err());

    let mut unknown_field = wire;
    unknown_field["entries"][0]["extra"] = serde_json::json!(true);
    assert!(serde_json::from_value::<super::Listing>(unknown_field).is_err());
}

#[test]
fn audit_host_facts_reject_extra_fields() {
    // Bug: Untyped host fields can silently cross the audit boundary.
    let facts = serde_json::to_value(AuditHostFacts::default()).unwrap();
    assert_rejects_extra_field::<AuditHostFacts>(facts.clone());
    assert_rejects_extra_field::<AuditHooks>(facts["hooks"].clone());
    assert_rejects_extra_field::<AuditNpmAncestor>(json!({"levels": 1, "present": ["bun.lock"]}));
    assert_rejects_extra_field::<AuditFileOffer>(json!({
        "id": 0, "path": "app/sign:in.ts", "kind": {"kind": "inventory", "walk_index": 2, "ignored": false}, "size": 72
    }));
    assert_rejects_extra_field::<AuditFileKind>(
        json!({"kind": "inventory", "walk_index": 2, "ignored": false}),
    );
    for kind in ["metadata", "dependency", "database_location"] {
        assert_rejects_extra_field::<AuditFileKind>(json!({"kind": kind}));
    }
    assert_rejects_extra_field::<AuditPathFact>(
        json!({"path": ".git", "kind": "directory", "safe_directory": true}),
    );
    assert_rejects_extra_field::<FileLocation>(json!({"id": 0}));
    assert_rejects_extra_field::<AuditFileRefusal>(
        json!({"path": {"id": 0}, "reason": "budget_spent"}),
    );
    assert_rejects_extra_field::<AuditEnvFile>(json!({
        "path": ".env", "retained_bytes": 20, "keys": ["APP_DEBUG"], "app_debug": true, "app_debug_line": 1
    }));
    assert_rejects_extra_field::<AuditRemoteDatabase>(
        json!({"path": ".env", "summary": "remote host"}),
    );
    for want in [
        json!({"kind": "offered_file", "id": 0}),
        json!({"kind": "git_tracked_offers", "ids": [0]}),
        json!({"kind": "path_presence", "paths": ["src/lib.rs"]}),
    ] {
        assert_rejects_extra_field::<Want>(want);
    }
    for answer in [
        json!({"kind": "git_tracked_offers", "ids": [0]}),
        json!({"kind": "path_presence", "present": ["src/lib.rs"], "symlinks": ["link/lib.rs"]}),
    ] {
        assert_rejects_extra_field::<WantAnswer>(answer);
    }
    assert_rejects_extra_field::<AuditFailure>(json!({"analysis_failed": "reader failed"}));
    let begin = json!({
        "task": {"kind": "audit"}, "listing": {"entries": [], "skipped_paths": 0},
        "options": {"databases": [], "inspect_local_databases": false}, "now_ms": 0,
        "host": facts, "text_budget": 64_000_000
    });
    assert_rejects_extra_field::<SessionBegin>(begin.clone());
    let mut without_facts = begin;
    without_facts.as_object_mut().unwrap().remove("host");
    assert!(serde_json::from_value::<SessionBegin>(without_facts).is_err());
}

#[test]
fn offer_display_paths_are_bounded_and_cannot_be_issue_paths() {
    // Bug: Unbounded display strings and unvalidated issue locations can cross the wire.
    assert!(DisplayPath::parse(&"x".repeat(4_096)).is_ok());
    assert!(DisplayPath::parse(&"é".repeat(2_049)).is_err());
    assert!(serde_json::from_value::<DisplayPath>(json!("a\0b")).is_err());
    assert!(DisplayPath::parse("sign:in\t.ts").is_ok());
    let mut issue = audit_issue();
    issue["path"] = json!("sign:in\t.ts");
    assert!(serde_json::from_value::<AuditIssue>(issue.clone()).is_err());
    issue["path"] = json!({"id": 0});
    assert_eq!(
        serde_json::from_value::<AuditIssue>(issue).unwrap().path,
        FileLocation::Offer { id: 0 }
    );
}

#[test]
fn code_rule_info_round_trips_with_its_metadata() {
    // Rule metadata can disappear when an engine answer crosses the wire.
    let wire = json!({
        "id": "example-rule", "title": "Rule", "domain": "security", "default_severity": "high",
        "check_id": "code_scan.example-rule", "category": "reliability", "rationale": "Rule rationale."
    });
    let rule: CodeRuleInfo = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(rule).unwrap(), wire);
}

#[test]
fn local_site_answer_refuses_an_unknown_field() {
    // Unknown local score fields can silently enter the display contract.
    let mut wire = local_site_answer();
    wire["categories"] = json!([]);
    assert_rejects_extra_field::<LocalSiteAnswer>(wire);
}

#[test]
fn local_site_answer_requires_categories() {
    // An omitted category field can decode as an explicit null score.
    let mut wire = local_site_answer();
    wire.as_object_mut().unwrap().remove("categories");
    let error = serde_json::from_value::<LocalSiteAnswer>(wire).unwrap_err();
    assert_eq!(error.to_string(), "missing field `categories`");
}
