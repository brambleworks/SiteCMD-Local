use super::*;

#[test]
fn a_code_run_claims_no_network_facts_at_all() {
    let engine = sitecmd_engine_host::load().unwrap();
    let profile = code_stamp(engine.info(), Some("code")).execution;
    assert_eq!(profile.scan_profile.as_deref(), Some("code"));
    assert!(profile.transport.is_none());
    assert!(profile.tls_client.is_none());
    assert!(profile.trust_authority.is_none());
    assert!(profile.resolver.is_none());
    assert!(profile.browser_engine.is_none());
    assert_eq!(profile.layers_run, [ExecutionLayer::Code.as_str()]);
}

#[test]
fn the_stamp_names_this_crate_version_and_the_manifest_it_carries() {
    let engine = sitecmd_engine_host::load().unwrap();
    let stamped = code_stamp(engine.info(), Some("code"));
    assert_eq!(stamped.engine_release, env!("CARGO_PKG_VERSION"));
    assert_eq!(
        stamped.manifest_digest,
        engine.info().manifest_digest.as_str()
    );
}
