use super::{
    config::{Tier, FINAL_GRACE_PERIOD_SECS, OFFLINE_GRACE_PERIOD_SECS},
    store::LicenseState,
};

#[cfg(test)]
use super::store;
#[cfg(test)]
use rusqlite::Connection;

fn parse_iso(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

pub fn is_entitled_license_status(status: &str) -> bool {
    matches!(status, "active" | "on_trial")
}

/// Resolve the effective tier at a fixed time for deterministic grace-window
/// checks. Cached entitlement lasts through both offline grace periods.
pub fn effective_tier_from_state_at(
    state: &LicenseState,
    now: chrono::DateTime<chrono::Utc>,
) -> Tier {
    if !is_entitled_license_status(&state.status) {
        return Tier::Free;
    }

    match parse_iso(&state.last_validated_at) {
        Some(last) => {
            let elapsed = now.signed_duration_since(last).num_seconds();
            if elapsed < 0 || elapsed as u64 > OFFLINE_GRACE_PERIOD_SECS + FINAL_GRACE_PERIOD_SECS {
                Tier::Free
            } else {
                state.tier
            }
        }
        None => Tier::Free,
    }
}

#[tracing::instrument(skip(state))]
pub fn effective_tier_from_state(state: &LicenseState) -> Tier {
    effective_tier_from_state_at(state, chrono::Utc::now())
}

// Tier resolution entitles only the connected service and catalog stream.

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_state() -> LicenseState {
        LicenseState {
            license_key: "test-key".to_string(),
            instance_id: "inst-123".to_string(),
            variant_id: 42,
            tier: Tier::Core,
            status: "active".to_string(),
            last_validated_at: chrono::Utc::now().to_rfc3339(),
            activated_at: chrono::Utc::now().to_rfc3339(),
            expires_at: None,
        }
    }

    #[test]
    fn effective_tier_downgrades_expired_cache() {
        let stale = LicenseState {
            last_validated_at: (chrono::Utc::now()
                - chrono::Duration::seconds(
                    (OFFLINE_GRACE_PERIOD_SECS + FINAL_GRACE_PERIOD_SECS) as i64 + 10,
                ))
            .to_rfc3339(),
            ..test_state()
        };
        assert_eq!(effective_tier_from_state(&stale), Tier::Free);
    }

    #[test]
    fn effective_tier_keeps_recent_active_cache() {
        assert_eq!(effective_tier_from_state(&test_state()), Tier::Core);
    }

    #[test]
    fn effective_tier_keeps_recent_lemon_checkout_trial_cache() {
        let trial = LicenseState {
            status: "on_trial".to_string(),
            ..test_state()
        };
        assert_eq!(effective_tier_from_state(&trial), Tier::Core);
    }

    #[test]
    fn effective_tier_rejects_future_validation_timestamps() {
        let future = LicenseState {
            last_validated_at: (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339(),
            ..test_state()
        };
        assert_eq!(effective_tier_from_state(&future), Tier::Free);
    }

    /// Fixed clock for exact grace-window boundary tests.
    fn fixed_now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-05-09T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    fn state_validated_seconds_ago(seconds: i64) -> LicenseState {
        let last = fixed_now() - chrono::Duration::seconds(seconds);
        LicenseState {
            last_validated_at: last.to_rfc3339(),
            ..test_state()
        }
    }

    const FULL_GRACE_SECS: u64 = OFFLINE_GRACE_PERIOD_SECS + FINAL_GRACE_PERIOD_SECS;

    #[test]
    fn effective_tier_honors_the_final_warning_day() {
        let state = state_validated_seconds_ago(OFFLINE_GRACE_PERIOD_SECS as i64 + 3600);
        assert_eq!(
            effective_tier_from_state_at(&state, fixed_now()),
            Tier::Core,
            "features stay on during the promised final-warning day"
        );
    }

    #[test]
    fn effective_tier_at_grace_boundary_one_second_inside() {
        let state = state_validated_seconds_ago(FULL_GRACE_SECS as i64 - 1);
        assert_eq!(
            effective_tier_from_state_at(&state, fixed_now()),
            Tier::Core,
            "license validated FULL_GRACE - 1 ago must still be active"
        );
    }

    #[test]
    fn effective_tier_at_grace_boundary_exactly_at_limit() {
        let state = state_validated_seconds_ago(FULL_GRACE_SECS as i64);
        assert_eq!(
            effective_tier_from_state_at(&state, fixed_now()),
            Tier::Core,
            "license validated exactly FULL_GRACE ago must still be active (strict >)"
        );
    }

    #[test]
    fn effective_tier_at_grace_boundary_one_second_past() {
        let state = state_validated_seconds_ago(FULL_GRACE_SECS as i64 + 1);
        assert_eq!(
            effective_tier_from_state_at(&state, fixed_now()),
            Tier::Free,
            "license validated FULL_GRACE + 1 ago must downgrade to Free"
        );
    }

    #[test]
    fn effective_tier_at_clock_drift_future_timestamp() {
        // last_validated_at in the future relative to `now` (clock drift /
        // tampering) must downgrade to Free, not silently extend grace.
        let future = LicenseState {
            last_validated_at: (fixed_now() + chrono::Duration::hours(1)).to_rfc3339(),
            ..test_state()
        };
        assert_eq!(
            effective_tier_from_state_at(&future, fixed_now()),
            Tier::Free
        );
    }

    #[test]
    fn store_save_load_round_trip_preserves_state() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("license.db");
        let conn = Connection::open(&db_path).unwrap();
        store::create_table(&conn).unwrap();

        let original = LicenseState {
            license_key: "lc-abcdef".to_string(),
            instance_id: "inst-9999".to_string(),
            variant_id: 12345,
            tier: Tier::Pro,
            status: "active".to_string(),
            last_validated_at: "2026-05-09T11:00:00+00:00".to_string(),
            activated_at: "2026-04-01T08:00:00+00:00".to_string(),
            expires_at: Some("2027-05-09T00:00:00+00:00".to_string()),
        };
        store::save(&conn, &original).unwrap();

        let reloaded = store::load(&conn).unwrap().expect("license state present");
        // license_key is stored in the keyring, not SQLite, so the DB round-trip
        // carries the placeholder rather than the original key.
        assert_eq!(reloaded.license_key, crate::constants::KEYRING_PLACEHOLDER);
        assert_eq!(reloaded.instance_id, original.instance_id);
        assert_eq!(reloaded.variant_id, original.variant_id);
        assert_eq!(reloaded.tier, original.tier);
        assert_eq!(reloaded.status, original.status);
        assert_eq!(reloaded.last_validated_at, original.last_validated_at);
        assert_eq!(reloaded.activated_at, original.activated_at);
        assert_eq!(reloaded.expires_at, original.expires_at);
    }

    #[test]
    fn store_load_returns_none_for_empty_db() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("empty.db");
        let conn = Connection::open(&db_path).unwrap();
        store::create_table(&conn).unwrap();
        assert!(store::load(&conn).unwrap().is_none());
    }
}
