//! Release provenance for module-backed code scans.

use sitecmd_protocol::engine_abi::EngineInfo;
use sitecmd_protocol::release::{
    ExecutionLayer, ExecutionProfile, ReleaseStamp, CANONICALIZER_VERSION, CRAWL_PROFILE,
};

/// The release every observation this binary produces is stamped with.
pub const ENGINE_RELEASE: &str = env!("CARGO_PKG_VERSION");

/// Stamp a code observation with the manifest that governed its scan.
pub fn code_stamp(info: &EngineInfo, scan_profile: Option<&str>) -> ReleaseStamp {
    ReleaseStamp {
        engine_release: ENGINE_RELEASE.into(),
        manifest_digest: info.manifest_digest.as_str().into(),
        canonicalizer: CANONICALIZER_VERSION,
        crawl_profile: CRAWL_PROFILE,
        execution: ExecutionProfile {
            scan_profile: scan_profile.map(str::to_owned),
            layers_run: vec![ExecutionLayer::Code.as_str().into()],
            ..Default::default()
        },
    }
}

#[cfg(test)]
#[path = "engine_release_tests.rs"]
mod tests;
