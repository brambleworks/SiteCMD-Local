//! Reconcile persisted issue lifecycle state when a finding reappears.

use rusqlite::{params, Transaction};
use sitecmd_protocol::vocab::{IssueStatus, VerifiedBy};

use super::DbError;

/// Scans regress verified issues whose absence was observed and reactivate user-claimed fixes.
pub(crate) fn reconcile_reobserved_lifecycle<'a>(
    tx: &Transaction<'_>,
    project_id: i64,
    env_url: &str,
    observed_at: i64,
    check_ids: impl Iterator<Item = &'a str>,
) -> Result<(), DbError> {
    let check_ids: std::collections::BTreeSet<&str> = check_ids.collect();
    if check_ids.is_empty() {
        return Ok(());
    }
    tx.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS temp_reobserved_check_ids (
             check_id TEXT PRIMARY KEY
         ) WITHOUT ROWID;
         DELETE FROM temp_reobserved_check_ids;",
    )?;
    for check_id in check_ids {
        tx.execute(
            "INSERT OR IGNORE INTO temp_reobserved_check_ids(check_id) VALUES (?1)",
            params![check_id],
        )?;
    }

    for verified_by in VerifiedBy::ALL {
        let next = if verified_by.proves_absence() {
            IssueStatus::Regressed
        } else {
            IssueStatus::New
        };
        tx.execute(
            "UPDATE project_issue_states
             SET status = ?1,
                 verified_by = NULL,
                 last_status_changed_at = ?2
             WHERE project_id = ?3 AND env_url = ?4
               AND status = ?5 AND verified_by = ?6
               AND check_id IN (SELECT check_id FROM temp_reobserved_check_ids)",
            params![
                next.as_str(),
                observed_at,
                project_id,
                env_url,
                IssueStatus::Verified.as_str(),
                verified_by.as_str(),
            ],
        )?;
    }

    tx.execute(
        "UPDATE project_issue_states
         SET status = ?1,
             snooze_until = NULL,
             block_reason = NULL,
             last_status_changed_at = ?2
         WHERE project_id = ?3 AND env_url = ?4 AND status = ?5
           AND check_id IN (SELECT check_id FROM temp_reobserved_check_ids)",
        params![
            IssueStatus::New.as_str(),
            observed_at,
            project_id,
            env_url,
            IssueStatus::Ignored.as_str(),
        ],
    )?;
    tx.execute("DELETE FROM temp_reobserved_check_ids", [])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{reconcile_reobserved_lifecycle, IssueStatus, VerifiedBy};
    use crate::db::test_helpers::temp_db;

    const ENVIRONMENT: &str = "https://example.com";
    const FIXED: &str = "security.csp";
    const IGNORED: &str = "seo.title";
    const BLOCKED: &str = "security.hsts";

    fn reconcile_fixture(
        states: Vec<(&'static str, IssueStatus, Option<VerifiedBy>)>,
        observed: Vec<&'static str>,
    ) -> Vec<(String, Option<String>)> {
        let db = temp_db();
        let project_id = db.upsert_project("Lifecycle", "", None).unwrap();
        db.execute_mut(move |conn| {
            let tx = conn.transaction().unwrap();
            for (check_id, status, verified_by) in &states {
                tx.execute(
                    "INSERT INTO project_issue_states
                        (project_id, env_url, check_id, status, verified_by, last_status_changed_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, 1000)",
                    rusqlite::params![
                        project_id,
                        ENVIRONMENT,
                        check_id,
                        status.as_str(),
                        verified_by.map(VerifiedBy::as_str),
                    ],
                )
                .unwrap();
            }
            reconcile_reobserved_lifecycle(
                &tx,
                project_id,
                ENVIRONMENT,
                2000,
                observed.into_iter(),
            )
            .unwrap();
            tx.commit().unwrap();
            states
                .into_iter()
                .map(|(check_id, _, _)| {
                    conn.query_row(
                        "SELECT status, verified_by FROM project_issue_states
                         WHERE project_id = ?1 AND env_url = ?2 AND check_id = ?3",
                        rusqlite::params![project_id, ENVIRONMENT, check_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .unwrap()
                })
                .collect()
        })
        .unwrap()
    }

    #[test]
    fn reobservation_reopens_ignored_regresses_verified_and_preserves_blocked() {
        // Bug: Re-observation can erase a block or keep stale verification.
        let states = reconcile_fixture(
            vec![
                (FIXED, IssueStatus::Verified, Some(VerifiedBy::LocalScan)),
                (IGNORED, IssueStatus::Ignored, None),
                (BLOCKED, IssueStatus::Blocked, None),
            ],
            vec![FIXED, IGNORED, BLOCKED],
        );
        assert_eq!(states[0].0, IssueStatus::Regressed.as_str());
        assert_eq!(states[0].1, None);
        assert_eq!(states[1].0, IssueStatus::New.as_str());
        assert_eq!(states[2].0, IssueStatus::Blocked.as_str());
    }

    #[test]
    fn a_claimed_fix_that_is_reobserved_returns_to_active_not_regressed() {
        // Bug: A user claim can be mistaken for proof of absence.
        let states = reconcile_fixture(
            vec![(FIXED, IssueStatus::Verified, Some(VerifiedBy::UserClaim))],
            vec![FIXED],
        );
        assert_eq!(states[0].0, IssueStatus::New.as_str());
        assert_eq!(states[0].1, None);
    }

    #[test]
    fn verified_issue_not_reobserved_stays_verified() {
        // Bug: Seeing an unrelated check can invalidate a verified issue.
        let states = reconcile_fixture(
            vec![(FIXED, IssueStatus::Verified, Some(VerifiedBy::LocalScan))],
            vec![IGNORED],
        );
        assert_eq!(states[0].0, IssueStatus::Verified.as_str());
    }

    /// The CHECK constraint is the last line of defense against a raw write
    /// bypassing the enum (there should be none, but SQL is stringly-typed).
    #[test]
    fn check_constraint_rejects_unknown_status_strings() {
        let db = temp_db();
        let project_id = db
            .upsert_project("Check Reject", "/tmp/check-reject", Some("nextjs"))
            .expect("upsert");

        let result = db.execute(move |conn| {
            conn.execute(
                "INSERT INTO project_issue_states (
                    project_id, env_url, check_id, status, last_status_changed_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    project_id,
                    "https://example.com",
                    "security.csp",
                    "wontfix",
                    1_000
                ],
            )
            .map_err(|e| e.to_string())?;
            Ok(())
        });
        let err = result
            .map_err(String::from)
            .and_then(|inner: Result<(), String>| inner)
            .expect_err("unknown status must violate the CHECK constraint");
        assert!(
            err.contains("CHECK") || err.contains("constraint"),
            "expected a CHECK constraint violation, got: {err}"
        );
    }

    /// A raw write is the one way an unprovenanced verification could still
    /// appear - the reconcilers ARE raw writes - so the invariant lives in the
    /// schema as well as in the type.
    #[test]
    fn the_schema_refuses_a_verified_row_with_no_prover() {
        let db = temp_db();
        let project_id = db
            .upsert_project("No Prover", "/tmp/no-prover", Some("nextjs"))
            .expect("upsert");

        let err = raw_insert(&db, project_id, "verified", None)
            .expect_err("a verified row must name who verified it");
        assert!(
            err.contains("CHECK") || err.contains("constraint"),
            "expected a CHECK constraint violation, got: {err}"
        );
    }

    /// The other direction: a prover that outlives the verification it
    /// described would let a regressed or reopened row still look proven.
    #[test]
    fn the_schema_refuses_a_prover_on_a_row_that_is_not_verified() {
        let db = temp_db();
        let project_id = db
            .upsert_project("Stale Prover", "/tmp/stale-prover", Some("nextjs"))
            .expect("upsert");

        let err = raw_insert(&db, project_id, "regressed", Some("local_scan"))
            .expect_err("only a verified row may carry a prover");
        assert!(
            err.contains("CHECK") || err.contains("constraint"),
            "expected a CHECK constraint violation, got: {err}"
        );
    }

    /// Insert a fixture directly and return any schema error.
    fn raw_insert(
        db: &crate::db::Database,
        project_id: i64,
        status: &str,
        verified_by: Option<&str>,
    ) -> Result<(), String> {
        let status = status.to_string();
        let verified_by = verified_by.map(str::to_string);
        db.execute(move |conn| {
            conn.execute(
                "INSERT INTO project_issue_states (
                    project_id, env_url, check_id, status, verified_by,
                    last_status_changed_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    project_id,
                    "https://example.com",
                    "security.csp",
                    status,
                    verified_by,
                    1_000
                ],
            )
            .map_err(|e| e.to_string())?;
            Ok(())
        })
        .map_err(String::from)
        .and_then(|inner: Result<(), String>| inner)
    }
}
