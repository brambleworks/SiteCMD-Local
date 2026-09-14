//! License lifecycle command tests.

use super::*;

// Concatenated production source used by source-contract tests.
fn real_code() -> &'static str {
    // Preserve module order for assertions that compare source positions.
    static ALL: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        [
            include_str!("license_lifecycle.rs"),
            include_str!("license_lifecycle_activation.rs"),
            include_str!("license_lifecycle_validation.rs"),
            include_str!("license_lifecycle_deactivation.rs"),
            include_str!("../generation.rs"),
        ]
        .join("\n")
    });
    &ALL
}

#[test]
fn license_key_fingerprint_is_stable_and_non_secret() {
    let key = "sitecmd-test-license-key";
    let fingerprint = license_key_fingerprint(key);

    assert_eq!(fingerprint, license_key_fingerprint(key));
    assert!(fingerprint.starts_with("sha256:"));
    assert_eq!(fingerprint.len(), "sha256:".len() + 16);
    assert!(!fingerprint.contains(key));
    assert!(!fingerprint.contains(&key[..8]));
}

#[test]
fn replacement_detection_distinguishes_normalized_keys() {
    assert!(!license_replacement_required(" SAME-KEY ", "SAME-KEY"));
    assert!(license_replacement_required("OLD-KEY", "NEW-KEY"));
}

#[test]
fn license_activation_audit_detail_uses_fingerprint_not_key_prefix() {
    let key = "sitecmd-test-license-key";
    let fingerprint = license_key_fingerprint(key);
    let detail = license_activation_audit_detail(&fingerprint);
    let serialized = detail.to_string();

    assert_eq!(detail["key_fingerprint"], fingerprint);
    assert!(detail.get("key_prefix").is_none());
    assert!(!serialized.contains(key));
    assert!(!serialized.contains(&key[..8]));
}

#[test]
fn grace_warning_selects_key_unreadable_in_both_grace_windows() {
    use super::GraceCause::{KeyUnreadable, Network};
    use OfflineValidationState::{Expired, Fresh, Stale, StaleFinalWarning};

    // Network failures keep the two-intensity ladder.
    assert_eq!(grace_warning_for(Stale, Network), ValidationWarning::Stale);
    assert_eq!(
        grace_warning_for(StaleFinalWarning, Network),
        ValidationWarning::StaleFinalWarning
    );
    assert_eq!(
        grace_warning_for(Stale, KeyUnreadable),
        ValidationWarning::KeyUnreadable
    );
    assert_eq!(
        grace_warning_for(StaleFinalWarning, KeyUnreadable),
        ValidationWarning::KeyUnreadable
    );
    // Fresh and Expired never carry a banner (Expired downgrades).
    for cause in [Network, KeyUnreadable] {
        assert_eq!(grace_warning_for(Fresh, cause), ValidationWarning::None);
        assert_eq!(grace_warning_for(Expired, cause), ValidationWarning::None);
    }
}

#[test]
fn a_forced_refresh_revalidates_through_a_fresh_cache() {
    use OfflineValidationState::Fresh;
    assert!(revalidation_required(true, Fresh));
    assert!(!revalidation_required(false, Fresh));
}

#[test]
fn a_stale_cache_revalidates_with_or_without_force() {
    use OfflineValidationState::{Expired, Stale, StaleFinalWarning};
    for offline in [Stale, StaleFinalWarning, Expired] {
        assert!(revalidation_required(false, offline), "{offline:?}");
        assert!(revalidation_required(true, offline), "{offline:?}");
    }
}

// Pin the caller's force flag at the revalidation gate.
#[test]
fn validate_license_threads_the_callers_force_flag_into_the_gate() {
    // Whitespace-stripped so the pin survives rustfmt's choice of line breaks.
    let condensed: String = real_code().chars().filter(|c| !c.is_whitespace()).collect();
    assert!(
        condensed.contains("letforce_live=force.unwrap_or(false)||prior_observation.is_some();"),
        "the caller's force flag and the discard retry must both force the live check"
    );
    assert!(
        condensed.contains("revalidation_required(force_live,"),
        "validate_license must pass the derived force flag into revalidation_required"
    );
}

#[test]
fn validate_license_orders_same_instance_verdicts_with_the_write_generation() {
    let condensed: String = real_code().chars().filter(|c| !c.is_whitespace()).collect();
    assert!(
        condensed.contains(
            "letgeneration_at_capture=license_write_generation();letcached=load_cached_license_state(db).await?;"
        ),
        "the generation must be captured BEFORE the row read, or a write landing between them goes unseen"
    );
    assert!(
        condensed.contains("iflicense_write_generation()!=generation_at_capture||current"),
        "the commit compare must refuse a verdict whose capture the write generation has moved past"
    );
    assert!(
        condensed.contains(
            "ifretry_available{returnOk(ValidationPass::DiscardedWithRetry(Box::new(updated)));}"
        ),
        "a discarded verdict must surface the retry while one remains, carrying the observation"
    );
    assert!(
        condensed.contains(
            "ValidationPass::DiscardedWithRetry(observed)=>{prior_observation=Some(observed);"
        ),
        "the caller must spend the retry it was offered, so the loop is bounded"
    );
    assert!(
        condensed.matches("conservative_answer(row_answer,").count() >= 2,
        "the out-of-retries arm and the capping helper must both merge the carried observation conservatively"
    );
    assert!(
        condensed
            .matches("capped_by_observation(info,&state,prior_observation)")
            .count()
            >= 3,
        "the keychain-failure arms and the failed-reread fallback must cap by the carried observation"
    );
    assert!(
        condensed.contains("capped_by_observation(row_answer,&row,prior_observation)"),
        "the failed-retry present-row arm must cap by the carried observation"
    );
}

// Every license-row write site must record its write, or a concurrent
// validation's generation compare passes while the row it read is gone.
#[test]
fn every_license_row_write_site_records_its_write() {
    let count = real_code().matches("record_license_write();").count();
    assert_eq!(
        count, 6,
        "expected one record_license_write() per row-write site"
    );
}

#[test]
fn desktop_row_replacement_invalidates_the_shared_generation() {
    let before = crate::licensing::generation::license_write_generation();
    note_license_rows_replaced();
    assert!(crate::licensing::generation::license_write_generation() > before);
}

// Database restore must invalidate in-flight license validation.
#[test]
fn a_database_restore_bumps_the_write_generation() {
    let backup = include_str!("../../commands/data/backup.rs");
    let import = backup
        .find("fn import_database")
        .expect("the import command exists");
    assert!(
        backup[import..].contains("note_license_rows_replaced();"),
        "import_database must record the license-row replacement, or an in-flight verdict resurrects the pre-import state"
    );
    let lock = backup[import..]
        .find("license_mutation().lock().await")
        .expect("import_database must hold LICENSE_MUTATION across the restore");
    let restore = backup[import..]
        .find("restore_from_backup")
        .expect("the restore call exists");
    let bump = backup[import..]
        .find("note_license_rows_replaced();")
        .expect("checked above");
    assert!(
        lock < restore && restore < bump,
        "the lock must be taken before the restore and released only after the bump, or the read-restore-write interleaving overwrites the restored license row"
    );
    let db_module = include_str!("../../db/mod.rs");
    let restore_fn = db_module
        .find("fn restore_from_backup")
        .expect("the restore implementation exists");
    let body = &db_module[restore_fn..];
    let copy = body.find("conn.restore(").expect("the copy call exists");
    let closure_bump = body
        .find("crate::licensing::generation::note_license_rows_replaced();")
        .expect("the restore closure must bump the write generation itself, or a timed-out restore that lands later resurrects the pre-import license");
    let propagate = body
        .find("restore_result")
        .expect("the closure result is captured so the bump runs before it propagates");
    assert!(
        propagate < copy && copy < closure_bump,
        "the copy must run inside the captured closure and the bump after it on every exit, or an error after the copy skips the bump over rows that already changed"
    );
}

#[test]
fn validate_license_guards_unreadable_keys_before_calling_the_api() {
    let source = real_code();
    let guard = source
        .find("GraceCause::KeyUnreadable")
        .expect("validate_license must route unreadable keys through GraceCause::KeyUnreadable");
    let api_call = source
        .find("api::validate(&license_key")
        .expect("validate_license must still call api::validate with the hydrated key");
    assert!(
        guard < api_call,
        "the unreadable-key guard must run before api::validate so an empty key is never sent"
    );
}

#[test]
fn a_readable_key_releases_upstream_and_a_confirmed_absence_unlinks_locally() {
    assert!(matches!(
        deactivate_key_source(Ok(Some("lc-key".to_string()))),
        Ok(DeactivateKeySource::Key(key)) if key == "lc-key"
    ));
    assert!(matches!(
        deactivate_key_source(Ok(None)),
        Ok(DeactivateKeySource::LocalOnly)
    ));
    assert!(matches!(
        deactivate_key_source(Ok(Some("   ".to_string()))),
        Ok(DeactivateKeySource::LocalOnly)
    ));
}

#[test]
fn an_unreadable_key_refuses_the_deactivation_and_names_the_keychain() {
    let refusal = deactivate_key_source(Err("ACL denied".to_string()));
    let message = match refusal {
        Err(message) => message,
        Ok(_) => panic!("an unreadable key must refuse the deactivation"),
    };
    assert!(message.contains("keychain"));
    assert!(message.contains("ACL denied"));
}

#[test]
fn deactivation_clears_local_state_before_releasing_upstream() {
    let source = real_code();
    let body = &source[source
        .find("pub async fn deactivate_license")
        .expect("deactivate_license exists")..];
    let local_clear = body
        .find("db.execute(store::clear)")
        .expect("deactivate_license clears the license row");
    let release = body
        .find("catalog_refresh::release_credential")
        .expect("deactivate_license releases the catalog credential");
    assert!(
        local_clear < release,
        "local unlink must precede the catalog release so the release is the last word"
    );
}

#[test]
fn re_entering_the_installed_active_key_never_reaches_the_api() {
    assert_eq!(
        activation_plan(true, true, true, true),
        ActivationPlan::AlreadyActive
    );
}

#[test]
fn every_predecessor_with_handles_tears_down_and_only_a_live_replacement_confirms() {
    assert_eq!(
        activation_plan(true, true, false, true),
        ActivationPlan::Teardown { confirm: true }
    );
    assert_eq!(
        activation_plan(true, true, true, false),
        ActivationPlan::Teardown { confirm: false }
    );
    assert_eq!(
        activation_plan(true, true, false, false),
        ActivationPlan::Teardown { confirm: false }
    );
}

#[test]
fn missing_handles_mean_fresh_with_local_hygiene_only() {
    assert_eq!(
        activation_plan(true, false, false, true),
        ActivationPlan::Fresh
    );
    assert_eq!(
        activation_plan(false, true, true, false),
        ActivationPlan::Fresh
    );
    assert_eq!(
        activation_plan(false, false, false, false),
        ActivationPlan::Fresh
    );
}

#[test]
fn only_an_own_seat_limit_refusal_frees_the_machines_predecessor() {
    let replacing_same = ActivationPlan::Teardown { confirm: false };
    assert!(own_seat_retry_applies(
        &replacing_same,
        true,
        true,
        LicenseActivationErrorCode::LimitReached
    ));
    // A different key at its limit is that license's real state.
    assert!(!own_seat_retry_applies(
        &ActivationPlan::Teardown { confirm: true },
        false,
        true,
        LicenseActivationErrorCode::LimitReached
    ));
    // Same key, different refusal: freeing a seat fixes nothing.
    assert!(!own_seat_retry_applies(
        &replacing_same,
        true,
        true,
        LicenseActivationErrorCode::Expired
    ));
    // A keychain-wiped machine's row names its own reclaimable seat.
    assert!(own_seat_retry_applies(
        &ActivationPlan::Fresh,
        false,
        true,
        LicenseActivationErrorCode::LimitReached
    ));
    // Truly fresh: no predecessor seat exists to free.
    assert!(!own_seat_retry_applies(
        &ActivationPlan::Fresh,
        false,
        false,
        LicenseActivationErrorCode::LimitReached
    ));
}

// A parseable activation-limit refusal must still reach the retry gate.
#[test]
fn a_parsed_activation_limit_refusal_reaches_the_retry_gate() {
    let body =
        r#"{"activated": false, "error": "This license key has reached the activation limit."}"#;
    let minted = api::parse_activate_response(body, 123, 400);
    assert!(
        matches!(&minted, Ok(result) if !result.valid),
        "a parseable refusal arrives as Ok(valid: false), not Err"
    );
    assert_eq!(
        mint_refusal_code(&minted),
        Some(LicenseActivationErrorCode::LimitReached)
    );

    // The Err shape still classifies.
    let transport: Result<api::LicenseResult, String> =
        Err("License activation request failed: connection reset".to_string());
    assert_eq!(
        mint_refusal_code(&transport),
        Some(LicenseActivationErrorCode::Network)
    );

    // A successful mint carries no refusal.
    let issued = api::parse_activate_response(
        r#"{"activated": true, "instance": {"id": "inst-1", "name": "machine"}, "meta": {"store_id": 123, "variant_id": 1}, "license_key": {"status": "active"}}"#,
        123,
        200,
    );
    assert_eq!(mint_refusal_code(&issued), None);
}

#[test]
fn an_empty_capture_is_unchanged_only_while_nothing_is_installed() {
    // Activation legitimately captures no row and no key; the CAS must
    // treat "still nothing" as unchanged and any appearance as a race.
    assert!(snapshot_unchanged(None, None, None, None));
    let appeared = generation("inst-9", "key-9");
    assert!(!snapshot_unchanged(
        None,
        Some(&appeared),
        None,
        Some("key-9")
    ));
    assert!(!snapshot_unchanged(None, None, None, Some("key-9")));
}

fn generation(instance: &str, key: &str) -> LicenseState {
    LicenseState {
        license_key: key.to_string(),
        instance_id: instance.to_string(),
        variant_id: 1,
        tier: Tier::Core,
        status: "active".to_string(),
        last_validated_at: "2026-07-29T00:00:00Z".to_string(),
        activated_at: "2026-07-29T00:00:00Z".to_string(),
        expires_at: None,
    }
}

#[test]
fn a_failed_local_clear_records_both_seats_before_returning() {
    let source = real_code();
    let start = source
        .find("pub async fn deactivate_license")
        .expect("deactivate_license exists");
    let body = &source[start..];
    let clear = body
        .find("db.execute(store::clear)")
        .expect("the local clear runs");
    let tail = &body[clear..];
    let tombstone = tail
        .find("record_pending_provider_release(")
        .expect("a failed clear records the release");
    let returns = tail
        .find("return Err(format!(")
        .expect("the arm reports failure");
    assert!(
        tombstone < returns,
        "the tombstone must be written before the command returns, or the seats have no retry handle"
    );
    assert!(
        tail[tombstone..returns].contains("true"),
        "the catalog credential is owed too: the row that named it is gone"
    );
    assert!(
        !tail[..tombstone].contains("await???"),
        "the clear must not return through `?`, which skips every remedy below it"
    );
}

#[test]
fn a_failed_validation_answers_about_the_installed_license() {
    let source = real_code();
    let body = &source[source
        .find("match api::validate(&license_key")
        .expect("validate_license exists")..];
    let err_arm = body
        .find("License validation failed (network?)")
        .expect("the network arm exists");
    let grace = body[err_arm..]
        .find("offline_validation_or_downgrade(&state)")
        .expect("the grace ladder still runs for the unreadable-row fallback");
    let reread = body[err_arm..]
        .find("load_cached_license_state(db).await")
        .expect("the failed arm re-reads the row");
    assert!(
        reread < grace,
        "the row must be re-read before the grace ladder answers from the pre-network capture"
    );
    let same_instance_answer = body[err_arm..]
        .find("offline_validation_or_downgrade(&row)")
        .expect("the err arm answers from the re-read row through the grace ladder");
    assert!(
        same_instance_answer < grace,
        "the re-read row's answer must come before the captured-state fallback, which only a failed re-read may use"
    );
}

#[test]
fn an_empty_stored_key_is_no_key() {
    assert_eq!(usable_key(None), None);
    assert_eq!(usable_key(Some(String::new())), None);
    assert_eq!(usable_key(Some("   ".to_string())), None);
    assert_eq!(
        usable_key(Some("lc_real".to_string())),
        Some("lc_real".to_string())
    );
}

#[test]
fn definite_failures_never_take_the_reconcilable_unknown_code() {
    assert!(
        !real_code().contains("LicenseActivationErrorCode::Unknown"),
        "definite failures answer Incomplete, never the reconcilable Unknown"
    );
}

#[test]
fn conservative_answer_grants_the_lesser_of_row_and_observation() {
    let mut pro_row = generation("inst-1", "KEY");
    pro_row.tier = Tier::Pro;
    let row_answer = info_from_state(&pro_row);

    // A deactivation observed live refuses the paid tier the row re-armed -
    // and carries its own re-enter-the-key banner into the answer.
    let mut deactivated = generation("inst-1", "KEY");
    deactivated.status = INSTANCE_DEACTIVATED_STATUS.to_string();
    let merged = conservative_answer(row_answer.clone(), info_from_state(&deactivated));
    assert_eq!(merged.tier, Tier::Free);
    assert_eq!(
        merged.validation_warning,
        ValidationWarning::InstanceDeactivated
    );

    // A downgrade observation caps the tier without inventing a refusal.
    let core = generation("inst-1", "KEY");
    let merged = conservative_answer(row_answer.clone(), info_from_state(&core));
    assert_eq!(merged.tier, Tier::Core);

    // An observation granting MORE never wins: the committed row stands.
    let core_row_answer = info_from_state(&core);
    let observed_pro = info_from_state(&pro_row);
    assert_eq!(
        conservative_answer(core_row_answer, observed_pro).tier,
        Tier::Core
    );

    // A tie keeps the row's answer, banners included.
    let stale_row_answer = info_from_state_with_warning(&pro_row, ValidationWarning::Stale);
    let merged = conservative_answer(stale_row_answer, info_from_state(&pro_row));
    assert_eq!(merged.validation_warning, ValidationWarning::Stale);

    let mut expired_free = generation("inst-1", "KEY");
    expired_free.tier = Tier::Free;
    let merged = conservative_answer(
        info_from_state(&expired_free),
        info_from_state(&deactivated),
    );
    assert_eq!(merged.tier, Tier::Free);
    assert_eq!(
        merged.validation_warning,
        ValidationWarning::InstanceDeactivated
    );
}

// The capping helper is the single authority every no-fresh-verdict exit
// answers through: it merges only when the observation describes the same
// instance the row does, and leaves a different instance's answer alone.
#[test]
fn capped_by_observation_merges_same_instance_and_ignores_a_replaced_one() {
    let mut pro_row = generation("inst-1", "KEY");
    pro_row.tier = Tier::Pro;

    let mut deactivated = generation("inst-1", "KEY");
    deactivated.status = INSTANCE_DEACTIVATED_STATUS.to_string();
    let capped = capped_by_observation(info_from_state(&pro_row), &pro_row, Some(&deactivated));
    assert_eq!(capped.tier, Tier::Free);
    assert_eq!(
        capped.validation_warning,
        ValidationWarning::InstanceDeactivated
    );

    let mut other_instance = generation("inst-2", "OTHER");
    other_instance.status = INSTANCE_DEACTIVATED_STATUS.to_string();
    let untouched =
        capped_by_observation(info_from_state(&pro_row), &pro_row, Some(&other_instance));
    assert_eq!(untouched.tier, Tier::Pro);

    // And no observation caps nothing.
    let bare = capped_by_observation(info_from_state(&pro_row), &pro_row, None);
    assert_eq!(bare.tier, Tier::Pro);
}

// Preserve the instance-deactivated warning after grace expires.
#[test]
fn the_expired_downgrade_keeps_the_instance_deactivated_banner() {
    let expired_at = (chrono::Utc::now()
        - chrono::Duration::seconds(
            (crate::licensing::config::OFFLINE_GRACE_PERIOD_SECS
                + crate::licensing::config::FINAL_GRACE_PERIOD_SECS
                + 3600) as i64,
        ))
    .to_rfc3339();

    let mut state = generation("inst-1", "key-1");
    state.status = INSTANCE_DEACTIVATED_STATUS.to_string();
    state.last_validated_at = expired_at.clone();
    let info = offline_validation_or_downgrade(&state).expect("info builds");
    assert_eq!(
        info.validation_warning,
        ValidationWarning::InstanceDeactivated
    );
    assert_eq!(info.tier, Tier::Free);
    assert!(!info.is_active);

    // Any other status still downgrades to the bare Free answer.
    let mut state = generation("inst-1", "key-1");
    state.last_validated_at = expired_at;
    let info = offline_validation_or_downgrade(&state).expect("info builds");
    assert_eq!(info.validation_warning, ValidationWarning::None);
    assert_eq!(info.tier, Tier::Free);
}

#[test]
fn the_same_generation_is_the_same_instance_and_the_same_key() {
    let row = generation("inst-1", "key-1");
    assert!(same_license_generation(
        "inst-1",
        Some(&row),
        Some("key-1"),
        Some("key-1")
    ));
    // LocalOnly captured, still LocalOnly now.
    assert!(same_license_generation("inst-1", Some(&row), None, None));
}

#[test]
fn any_change_while_a_dialog_or_request_was_open_refuses_the_write() {
    let replaced = generation("inst-2", "key-2");
    assert!(!same_license_generation(
        "inst-1",
        Some(&replaced),
        Some("key-1"),
        Some("key-2")
    ));
    // Row already gone: someone else finished the unlink first.
    assert!(!same_license_generation(
        "inst-1",
        None,
        Some("key-1"),
        Some("key-1")
    ));
    // A key appeared where the capture saw none (or vice versa).
    assert!(!same_license_generation(
        "inst-1",
        Some(&generation("inst-1", "key-1")),
        None,
        Some("key-1")
    ));
    assert!(!same_license_generation(
        "inst-1",
        Some(&generation("inst-1", "key-1")),
        Some("key-1"),
        None
    ));
}

// Seed the singleton row and return the database.
fn db_with_row(state: &LicenseState) -> crate::db::test_helpers::TestDbArc {
    let db = crate::db::test_helpers::temp_db_arc();
    let seeded = state.clone();
    db.execute(move |conn| store::save(conn, &seeded))
        .expect("db reachable")
        .expect("seed row");
    db
}

fn row_of(db: &Arc<Database>) -> LicenseState {
    db.execute(store::load)
        .expect("db reachable")
        .expect("row readable")
        .expect("row present")
}

#[tokio::test]
async fn a_server_named_tier_is_adopted_onto_the_installed_row() {
    let db = db_with_row(&generation("inst-1", "key-1"));
    adopt_server_tier(&db, "inst-1", "pro").await;
    assert_eq!(row_of(&db).tier, Tier::Pro);
    // And back down, the day a downgrade lands.
    adopt_server_tier(&db, "inst-1", "core").await;
    assert_eq!(row_of(&db).tier, Tier::Core);
}

#[tokio::test]
async fn adoption_refuses_a_stale_instance_and_an_unknown_tier() {
    let db = db_with_row(&generation("inst-2", "key-2"));
    adopt_server_tier(&db, "inst-1", "pro").await;
    assert_eq!(
        row_of(&db).tier,
        Tier::Core,
        "stale instance must not adopt"
    );
    adopt_server_tier(&db, "inst-2", "platinum").await;
    assert_eq!(row_of(&db).tier, Tier::Core, "unknown tier must not adopt");
}

#[test]
fn deactivation_reverifies_the_generation_between_dialog_and_clear() {
    let source = real_code();
    let body = &source[source
        .find("pub async fn deactivate_license")
        .expect("deactivate_license exists")..];
    let dialog = body
        .find("confirm_sensitive_action")
        .expect("deactivate_license confirms");
    let lock = body
        .find("LICENSE_MUTATION.lock()")
        .expect("deactivate_license takes the mutation lock");
    let cas = body
        .find("same_license_generation(")
        .expect("deactivate_license re-verifies the generation");
    let clear = body
        .find("db.execute(store::clear)")
        .expect("deactivate_license clears the license row");
    assert!(dialog < lock, "the lock must not be held across the dialog");
    assert!(
        lock < cas && cas < clear,
        "re-verify under the lock, before the clear"
    );
}

#[test]
fn a_failed_key_delete_is_reported_after_the_unlink_completes() {
    assert_eq!(deactivation_result(None, UpstreamRelease::Released), Ok(()));
    let message = deactivation_result(Some("ACL denied".to_string()), UpstreamRelease::Released)
        .expect_err("a surviving key must be reported");
    assert!(message.contains("unlinked"));
    assert!(message.contains("keychain"));
    assert!(message.contains("ACL denied"));
    assert!(message.contains("activations released"));
    assert!(
        !message.contains("retry"),
        "a completed unlink must not prescribe a retry: {message}"
    );
    let pending = deactivation_result(Some("ACL denied".to_string()), UpstreamRelease::Pending)
        .expect_err("a surviving key must be reported");
    assert!(
        !pending.contains("activations released"),
        "a pending release must not be announced as completed: {pending}"
    );
    assert!(pending.contains("recorded for release"));
    assert!(pending.starts_with(DEACTIVATION_KEYCHAIN_REMNANT));
    // No key at all means nothing upstream was contacted, so neither claim
    // applies.
    let local = deactivation_result(Some("ACL denied".to_string()), UpstreamRelease::None)
        .expect_err("a surviving key must be reported");
    assert!(!local.contains("activations released"));
    assert!(!local.contains("recorded for release"));
    // The frontend keys off the marker rather than English error text.
    assert!(
        message.starts_with(DEACTIVATION_KEYCHAIN_REMNANT),
        "the one Err that is not a failed deactivation must say so in a way the frontend can read: {message}"
    );
}

// A definitively failed local clear must not schedule a remote release.
#[test]
fn a_definitively_failed_clear_records_no_pending_release() {
    let source = real_code();
    let clear = source
        .find("db.execute(store::clear)")
        .expect("the clear dispatch exists");
    // Bound source inspection by the next item rather than a byte count.
    let window_end = source[clear..]
        .find("pub(super) fn worst_release")
        .expect("worst_release follows deactivate_license in the deactivation module")
        + clear;
    let window = &source[clear..window_end];
    assert!(
        window.contains("DbError::WorkerUnavailable"),
        "a failed send has to be told apart from a timeout"
    );
    // Pin the conditional binding so an unreachable read cannot satisfy the test.
    let reread = window
        .find("let row_may_be_gone = if row_may_be_gone {")
        .expect("an ambiguous failure re-reads the row before scheduling a release");
    assert!(
        window[..reread].contains("if let Err(error) = cleared"),
        "the re-read belongs on the failure path, not the happy one"
    );
    let block = &window[reread..];
    assert!(
        block.contains("db.execute(store::load)"),
        "narrowing the ambiguity means actually reading the row back"
    );
    assert!(
        block.contains("row.instance_id == instance"),
        "the row only proves anything if it is THIS machine's row"
    );
    // A matching row proves the DELETE did not commit, so that arm must
    // resolve to false - no tombstone, nothing revoked.
    let matched = block
        .find("row.instance_id == instance")
        .expect("checked above");
    assert!(
        block[matched..matched + 400].contains("false"),
        "a row that is still present must clear the ambiguity, not preserve it"
    );
    let unavailable = window
        .find("DbError::WorkerUnavailable")
        .expect("the arm exists");
    let tombstone = window
        .find("record_pending_provider_release")
        .expect("the tombstone call exists");
    assert!(
        unavailable < tombstone,
        "the classification must precede the tombstone, not follow it"
    );
    assert!(
        window[..tombstone].contains("row_may_be_gone"),
        "the tombstone must be gated on whether the row may already be gone"
    );
    // And the honest message on the definitive path promises nothing. It
    // sits past the window above, so it is matched against the whole file.
    assert!(
        source.contains("still licensed"),
        "a failure that changed nothing must not claim slots were recorded for release"
    );
}

#[test]
fn deactivation_writes_a_license_deactivate_audit_record() {
    let source = real_code();
    let body = &source[source
        .find("pub async fn deactivate_license")
        .expect("deactivate_license exists")..];
    assert!(
        body.contains(
            r#"crate::audit_log::record(
        "license.deactivate""#
        ),
        "deactivate_license must record license.deactivate"
    );
}

#[test]
fn validation_writes_back_only_to_the_instance_it_validated() {
    let source = real_code();
    let body = &source[source
        .find("pub async fn validate_license")
        .expect("validate_license exists")..];
    let call = body
        .find("api::validate(")
        .expect("validate_license calls the API");
    let lock = body
        .find("LICENSE_MUTATION.lock()")
        .expect("validate_license takes the mutation lock");
    // Search under the lock so unrelated instance comparisons cannot satisfy
    // this source contract.
    let cas = lock
        + body[lock..]
            .find("row.instance_id")
            .expect("validate_license compares the row's instance under the lock");
    assert!(
        body[cas..(cas + 80).min(body.len())].contains("validated_instance"),
        "the row's instance must be compared against the instance that was validated"
    );
    let write = body
        .find("store::update_validation")
        .expect("validate_license writes the verdict back");
    assert!(
        call < lock,
        "the lock must not be held across the network wait"
    );
    assert!(
        lock < cas && cas < write,
        "compare under the lock, before the write"
    );
}

#[test]
fn a_lost_release_outranks_every_other_ending() {
    use crate::background::CatalogRelease;
    use crate::background::CatalogRelease::{
        NothingToRelease, PendingLost, PendingRecorded, RefusedUnreleased, Released,
    };
    // Released only when BOTH sides released.
    assert_eq!(worst_release(Released, Released), Released);
    // One owed side demotes a released one, in either position.
    assert_eq!(worst_release(Released, PendingRecorded), PendingRecorded);
    assert_eq!(worst_release(PendingRecorded, Released), PendingRecorded);
    assert_eq!(worst_release(PendingRecorded, PendingLost), PendingLost);
    assert_eq!(worst_release(PendingLost, PendingRecorded), PendingLost);
    assert_eq!(worst_release(Released, PendingLost), PendingLost);
    assert_eq!(worst_release(PendingLost, Released), PendingLost);
    assert_eq!(worst_release(Released, NothingToRelease), NothingToRelease);
    assert_eq!(worst_release(NothingToRelease, Released), NothingToRelease);
    // And it is still weaker than anything owed, in either position.
    assert_eq!(
        worst_release(NothingToRelease, PendingRecorded),
        PendingRecorded
    );
    assert_eq!(worst_release(PendingLost, NothingToRelease), PendingLost);

    const ORDER: [CatalogRelease; 5] = [
        Released,
        NothingToRelease,
        PendingRecorded,
        RefusedUnreleased,
        PendingLost,
    ];
    for (i, a) in ORDER.iter().enumerate() {
        for (j, b) in ORDER.iter().enumerate() {
            let expected = if i >= j { *a } else { *b };
            assert_eq!(
                worst_release(*a, *b),
                expected,
                "worst_release({a:?}, {b:?}) must be the later of the two in the ordering"
            );
            // Commutative, or the sentence depends on which seat was released
            // first rather than on which one supports the least.
            assert_eq!(
                worst_release(*a, *b),
                worst_release(*b, *a),
                "worst_release must not depend on argument order: {a:?}, {b:?}"
            );
        }
        // Idempotent: a pair of identical endings is that ending.
        assert_eq!(worst_release(*a, *a), *a, "{a:?} paired with itself");
    }
    // A conclusive refusal is worse than a recorded pending, because a
    // recorded release still has a retry coming and a refusal has none.
    assert_eq!(
        worst_release(PendingRecorded, RefusedUnreleased),
        RefusedUnreleased
    );
    assert_eq!(worst_release(RefusedUnreleased, PendingLost), PendingLost);
}

// Terminal refusals and absent endpoints must not be reported as releases.
#[test]
fn nothing_left_to_release_is_never_reported_as_a_release() {
    let message = deactivation_result(Some("ACL denied".to_string()), UpstreamRelease::NothingOwed)
        .expect_err("a surviving key must be reported");
    assert!(
        !message.contains("activations released"),
        "a seat the service said was already gone was not released by this unlink: {message}"
    );
    assert!(
        message.contains("nothing left to release"),
        "the sentence still has to say where the seats stand: {message}"
    );
    // And it needs no action, so it must not borrow the stranded ending's
    // remedy either.
    assert!(
        !message.contains("contact support"),
        "nothing is owed here: {message}"
    );
    assert!(deactivation_result(None, UpstreamRelease::NothingOwed).is_ok());
}

#[test]
fn only_an_answer_that_proves_absence_may_settle() {
    let deactivation = include_str!("license_lifecycle_deactivation.rs");
    let start = deactivation
        .find("api::deactivate(license_key, &state.instance_id)")
        .expect("the provider release call exists");
    let absence = start
        + deactivation[start..]
            .find("deactivate_failure_proves_absence")
            .expect("the proven-absence arm exists");
    let terminal = start
        + deactivation[start..]
            .find("deactivate_failure_is_terminal")
            .expect("the conclusive-refusal arm follows it");
    let owed = start
        + deactivation[start..]
            .find("LS deactivation API failed")
            .expect("the owed arm follows the refusal one");
    assert!(absence < terminal, "absence must be tested before terminal");
    for (arm, span, expected) in [
        (
            "Ok",
            &deactivation[start..absence],
            "CatalogRelease::Released",
        ),
        (
            "proven-absence",
            &deactivation[absence..terminal],
            "CatalogRelease::NothingToRelease",
        ),
        (
            "conclusive-refusal",
            &deactivation[terminal..owed],
            "CatalogRelease::RefusedUnreleased",
        ),
    ] {
        assert!(
            span.contains(expected),
            "the {arm} arm must answer {expected}"
        );
        // And it must answer ONLY that, so no arm can quietly adopt a
        // neighbour's stronger claim.
        for other in [
            "CatalogRelease::Released",
            "CatalogRelease::NothingToRelease",
            "CatalogRelease::RefusedUnreleased",
        ] {
            assert!(
                other == expected || !span.contains(other),
                "the {arm} arm must not also answer {other}"
            );
        }
    }

    let refresh = include_str!("../../background/catalog_refresh.rs");
    let release = refresh
        .find("pub(crate) async fn release_credential")
        .expect("release_credential exists");
    let body = &refresh[release..release + 1400];
    assert!(
        body.contains(r#"Ok(0) => "absent""#),
        "the service answers a zero released count when no row matched, and that is not a release"
    );
    assert!(
        body.contains(r#"Ok(_) => "ok""#),
        "only a real Ok may audit as ok"
    );
    assert!(
        body.contains(r#"NoEndpointConfigured) => "unconfigured""#),
        "a build with no activation endpoint contacted nothing and must not share the ok arm"
    );
}

// A lost release is never reported as a completed one, and never silently.
#[test]
fn a_lost_release_is_reported_even_when_the_keychain_delete_succeeded() {
    let clean = deactivation_result(None, UpstreamRelease::Lost)
        .expect_err("a lost release must not be reported as an ordinary success");
    assert!(
        clean.starts_with(DEACTIVATION_KEYCHAIN_REMNANT),
        "the unlink itself completed, so this rides the completed-with-a-loose-end marker \
         rather than being announced as a failed deactivation"
    );
    assert!(
        !clean.contains("released") || clean.contains("without releasing"),
        "it must not claim the activations were released"
    );
    assert!(
        !clean.contains("automatically"),
        "nothing completes this automatically; promising it is the claim being removed"
    );
    assert!(
        clean.contains("at least one") && !clean.contains("retry them"),
        "a mixed recorded/lost pair must not claim NOTHING will be retried: {clean}"
    );

    for stranded in [
        UpstreamRelease::Lost,
        UpstreamRelease::RefusedUnreleased,
        UpstreamRelease::None,
    ] {
        let Err(message) = deactivation_result(None, stranded) else {
            panic!("{stranded:?} strands a seat with no retry handle and must not answer Ok");
        };
        assert!(
            message.starts_with(DEACTIVATION_KEYCHAIN_REMNANT),
            "{stranded:?}: the unlink completed, so this is a loose end and not a failure: {message}"
        );
        assert!(
            message.contains("contact support"),
            "{stranded:?}: support is the only way to free a seat nothing will retry: {message}"
        );
        assert!(
            !message.contains("Nothing else here needs doing"),
            "{stranded:?}: a stranded seat is something that needs doing: {message}"
        );
    }

    // And the endings that owe nothing stay a plain success, so the alarming
    // wording cannot spread to a deactivation that went fine.
    for quiet in [
        UpstreamRelease::Released,
        UpstreamRelease::NothingOwed,
        UpstreamRelease::Pending,
    ] {
        assert!(
            deactivation_result(None, quiet).is_ok(),
            "{quiet:?} leaves nothing for the user to do and must not interrupt a clean \
             deactivation"
        );
    }
}

// A keychain error must not conceal a stranded upstream seat.
#[test]
fn a_keychain_remnant_does_not_dismiss_a_stranded_seat() {
    let both = deactivation_result(Some("ACL denied".to_string()), UpstreamRelease::Lost)
        .expect_err("both loose ends must be reported");
    assert!(
        both.contains("keychain"),
        "the surviving key is still named: {both}"
    );
    assert!(
        !both.contains("Nothing else here needs doing"),
        "a stranded seat is something else that needs doing: {both}"
    );
    assert!(
        both.contains("contact support"),
        "the only way to reclaim a seat with no retry handle: {both}"
    );
    // And the ordinary remnant keeps its reassurance, so the two endings do
    // not converge on the alarming wording.
    let ordinary = deactivation_result(Some("ACL denied".to_string()), UpstreamRelease::Released)
        .expect_err("a surviving key must be reported");
    assert!(ordinary.contains("Nothing else here needs doing"));
    assert!(!ordinary.contains("contact support"));
}

#[test]
fn the_ambiguous_clear_reports_what_the_recorder_actually_did() {
    let source = real_code();
    let start = source
        .find("if row_may_be_gone {")
        .expect("the ambiguous-clear recovery exists");
    let end = source[start..]
        .find("key_delete_failure = match")
        .expect("keychain cleanup follows the local-clear branches")
        + start;
    let block = &source[start..end];
    let call = block
        .find("record_pending_provider_release")
        .expect("the tombstone call exists");
    assert!(
        block[..call].contains("let recorded"),
        "the recorder's answer must be bound, not discarded: {}",
        &block[..call]
    );
    assert!(
        block.contains("DeactivateKeySource::LocalOnly => None"),
        "a deactivation with no key recorded nothing and must not share the recorded sentence"
    );
    assert!(
        !block.contains("activation slots were recorded for release and will be freed"),
        "the promise must come from the helper that reads the recorder's answer, never inline"
    );

    assert!(
        block.contains("ambiguous_clear_clause(recorded)"),
        "the sentence must be built from the recorder's answer, not merely near it: {block}"
    );
    // And the helper it defers to says all three things.
    assert!(source.contains("fn ambiguous_clear_clause"));
    assert!(
        source.contains("No license key was stored"),
        "the no-key ending has to say so"
    );
    assert!(
        source.contains("could NOT be recorded for release"),
        "the lost-tombstone ending has to say so"
    );
}

#[test]
fn the_release_outcome_type_cannot_be_discarded_silently() {
    let source = include_str!("../../background/mod.rs");
    // site went back to being able to discard the answer silently.
    assert!(
        source.contains(
            "#[must_use]\n#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub(crate) enum CatalogRelease {"
        ),
        "the attribute has to sit on the type itself, so it covers the awaited value at every \
         call site rather than the future at one"
    );
}

#[test]
fn only_an_answered_release_maps_to_settled() {
    let source = include_str!("../../background/catalog_refresh.rs");
    let body = &source[source
        .find("pub(crate) async fn release_credential")
        .expect("release_credential exists")..];
    assert_eq!(
        body.matches("match outcome {").count(),
        1,
        "release_credential must map its outcome exactly once; a second occurrence is what a \
         source pin gets aimed at by mistake"
    );
    let mapping = body
        .find("match outcome {")
        .expect("release_credential maps its outcome string to a typed release");
    let arms = &body[mapping..mapping + 600];
    assert!(
        arms.contains(r#""ok" => super::CatalogRelease::Released"#),
        "only a real Ok is a release"
    );
    assert!(
        arms.contains(r#""absent" | "unconfigured" => super::CatalogRelease::NothingToRelease"#),
        "only the endings that prove absence may settle"
    );
    assert!(
        arms.contains(r#""refused" => super::CatalogRelease::RefusedUnreleased"#),
        "a conclusive refusal did not free the seat and must not claim the seat is free"
    );
    assert!(
        arms.contains(r#""unrecorded" => super::CatalogRelease::PendingLost"#),
        "a tombstone that could not be written must map to PendingLost, not to the \
         catch-all - the catch-all is what a later ending falls into"
    );
    assert!(
        !arms.contains("!="),
        "the mapping must not be a negation: every negation of one value admits \
         every value that is not it, which is exactly how unrecorded became settled"
    );
}
