//! Single-row SQLite persistence for the active license.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::db::from_row::i64_from_u64;

use super::config::Tier;

/// License state persisted to SQLite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseState {
    /// The license key. Persisted in the OS keyring, not SQLite (the
    /// `license_state` row holds a placeholder); see `keyring::store_license_key`.
    pub license_key: String,
    /// Instance ID from LS activate response.
    pub instance_id: String,
    /// LS variant ID (maps to tier).
    pub variant_id: u64,
    /// Derived tier.
    pub tier: Tier,
    /// License status: active, expired, disabled.
    pub status: String,
    /// ISO 8601 timestamp of last successful validation.
    pub last_validated_at: String,
    /// ISO 8601 timestamp of initial activation.
    pub activated_at: String,
    /// Subscription expiry date, if known.
    pub expires_at: Option<String>,
}

/// Create the license_state table. Called from db.rs init_tables.
#[tracing::instrument(skip(conn))]
pub fn create_table(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS license_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            license_key TEXT NOT NULL,
            instance_id TEXT NOT NULL,
            variant_id INTEGER NOT NULL,
            tier TEXT NOT NULL DEFAULT 'free',
            status TEXT NOT NULL DEFAULT 'active',
            last_validated_at TEXT NOT NULL,
            activated_at TEXT NOT NULL,
            expires_at TEXT
        );",
    )
    .map_err(|e| format!("Failed to create license_state table: {}", e))
}

/// Save or replace the current license state.
/// The `id = 1` constraint ensures only one row exists.
#[tracing::instrument(skip(conn, state))]
pub fn save(conn: &Connection, state: &LicenseState) -> Result<(), String> {
    // SQLite stores the tier's unquoted JSON string value.
    let tier_serialized = serde_json::to_string(&state.tier)
        .map_err(|e| format!("Failed to serialize tier: {}", e))?;
    let tier_value = tier_serialized.trim_matches('"');
    conn.execute(
        "INSERT OR REPLACE INTO license_state
            (id, license_key, instance_id, variant_id, tier, status, last_validated_at, activated_at, expires_at)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            // SQLite stores only the keyring placeholder; licensing commands
            // own the secret because this layer has no AppHandle.
            crate::constants::KEYRING_PLACEHOLDER,
            state.instance_id,
            i64_from_u64(state.variant_id)?,
            tier_value,
            state.status,
            state.last_validated_at,
            state.activated_at,
            state.expires_at,
        ],
    )
    .map_err(|e| format!("Failed to save license state: {}", e))?;
    Ok(())
}

/// Load the current license state, if any.
#[tracing::instrument(skip(conn))]
pub fn load(conn: &Connection) -> Result<Option<LicenseState>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT license_key, instance_id, variant_id, tier, status,
                    last_validated_at, activated_at, expires_at
             FROM license_state WHERE id = 1",
        )
        .map_err(|e| format!("Failed to prepare license state query: {}", e))?;

    let result = stmt
        .query_row([], |row| {
            let tier_str: String = row.get(3)?;
            let tier = tier_str.parse::<Tier>().unwrap_or(Tier::Free);

            Ok(LicenseState {
                license_key: row.get(0)?,
                instance_id: row.get(1)?,
                variant_id: row.get::<_, i64>(2)? as u64,
                tier,
                status: row.get(4)?,
                last_validated_at: row.get(5)?,
                activated_at: row.get(6)?,
                expires_at: row.get(7)?,
            })
        })
        .optional()
        .map_err(|e| format!("Failed to load license state: {}", e))?;

    Ok(result)
}

/// Clear the license state (on deactivation).
#[tracing::instrument(skip(conn))]
pub fn clear(conn: &Connection) -> Result<(), String> {
    conn.execute("DELETE FROM license_state", [])
        .map_err(|e| format!("Failed to clear license state: {}", e))?;
    Ok(())
}

/// Persist only fields owned by validation; activation owns tier and variant.
/// The explicit column list prevents stale network responses from reverting them.
#[tracing::instrument(
    skip(conn, state),
    fields(status = %state.status, validated_at = %state.last_validated_at)
)]
pub fn update_validation(conn: &Connection, state: &LicenseState) -> Result<(), String> {
    conn.execute(
        "UPDATE license_state
         SET status = ?1, last_validated_at = ?2, expires_at = ?3
         WHERE id = 1",
        rusqlite::params![state.status, state.last_validated_at, state.expires_at],
    )
    .map_err(|e| format!("Failed to update license validation: {}", e))?;
    Ok(())
}

// rusqlite optional helper
trait OptionalExt<T> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error>;
}

impl<T> OptionalExt<T> for Result<T, rusqlite::Error> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        create_table(&conn).unwrap();
        conn
    }

    fn test_state() -> LicenseState {
        LicenseState {
            license_key: "test-key-12345".to_string(),
            instance_id: "inst-abc".to_string(),
            variant_id: 100,
            tier: Tier::Core,
            status: "active".to_string(),
            last_validated_at: "2026-04-01T12:00:00+00:00".to_string(),
            activated_at: "2026-04-01T12:00:00+00:00".to_string(),
            expires_at: None,
        }
    }

    #[test]
    fn save_and_load() {
        let conn = setup_db();
        let state = test_state();

        save(&conn, &state).unwrap();
        let loaded = load(&conn).unwrap().expect("should have a state");

        // License keys live in the keyring; SQLite retains only the placeholder.
        assert_eq!(loaded.license_key, crate::constants::KEYRING_PLACEHOLDER);
        assert_eq!(loaded.instance_id, "inst-abc");
        assert_eq!(loaded.tier, Tier::Core);
        assert_eq!(loaded.status, "active");
    }

    #[test]
    fn load_empty() {
        let conn = setup_db();
        let loaded = load(&conn).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn save_replaces() {
        let conn = setup_db();
        let state1 = test_state();
        save(&conn, &state1).unwrap();

        let state2 = LicenseState {
            license_key: "new-key".to_string(),
            tier: Tier::Pro,
            ..test_state()
        };
        save(&conn, &state2).unwrap();

        let loaded = load(&conn).unwrap().expect("should have a state");
        assert_eq!(loaded.license_key, crate::constants::KEYRING_PLACEHOLDER);
        assert_eq!(loaded.tier, Tier::Pro);
    }

    #[test]
    fn clear_removes() {
        let conn = setup_db();
        save(&conn, &test_state()).unwrap();
        clear(&conn).unwrap();
        assert!(load(&conn).unwrap().is_none());
    }

    #[test]
    fn update_validation_updates_fields() {
        let conn = setup_db();
        save(&conn, &test_state()).unwrap();

        update_validation(
            &conn,
            &LicenseState {
                status: "expired".to_string(),
                last_validated_at: "2026-04-08T12:00:00+00:00".to_string(),
                ..test_state()
            },
        )
        .unwrap();

        let loaded = load(&conn).unwrap().expect("should have a state");
        assert_eq!(loaded.status, "expired");
        assert_eq!(loaded.last_validated_at, "2026-04-08T12:00:00+00:00");
        // Original fields preserved (license_key is the keyring placeholder).
        assert_eq!(loaded.license_key, crate::constants::KEYRING_PLACEHOLDER);
        assert_eq!(loaded.tier, Tier::Core);
    }

    #[test]
    fn update_validation_never_writes_tier_or_variant() {
        let conn = setup_db();
        save(&conn, &test_state()).unwrap();

        update_validation(
            &conn,
            &LicenseState {
                variant_id: 200,
                tier: Tier::Pro,
                last_validated_at: "2026-04-08T12:00:00+00:00".to_string(),
                expires_at: Some("2030-01-01T00:00:00Z".to_string()),
                ..test_state()
            },
        )
        .unwrap();

        let loaded = load(&conn).unwrap().expect("should have a state");
        assert_eq!(loaded.variant_id, test_state().variant_id, "variant stands");
        assert_eq!(loaded.tier, Tier::Core, "tier stands");
        assert_eq!(loaded.last_validated_at, "2026-04-08T12:00:00+00:00");
        assert_eq!(loaded.expires_at.as_deref(), Some("2030-01-01T00:00:00Z"));
    }
}
