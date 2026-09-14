//! Cross-language contract between the JavaScript catalog packer and Rust reader.
//!
//! The inline fixture always runs; a copied built pack is also checked when present.

use super::schema::CatalogPack;

// A pack in exactly the shape `build-catalog.mjs` writes. Kept in sync by
// being the thing that fails when either side drifts.
const PACKER_SHAPE: &str = r#"{
  "schema_version": 1,
  "catalog_version": "2026-07-26",
  "release_sequence": 1,
  "published_at": "2026-07-26T12:00:00.000Z",
  "minimum_engine_version": "1.0.0",
  "guides": {
    "security.csp": {
      "effort": "involved",
      "effort_minutes": 30,
      "default": ["Inventory the scripts and styles the page loads."],
      "frameworks": {
        "next": ["Prefer nonce-based headers over static hashes."]
      }
    },
    "seo.title": {
      "effort": "quick",
      "effort_minutes": 5,
      "default": ["Give the page a unique title under 60 characters."]
    }
  }
}"#;

#[test]
fn the_packer_wire_shape_deserializes_and_validates() {
    let pack: CatalogPack =
        serde_json::from_str(PACKER_SHAPE).expect("packer output must deserialize");
    pack.validate().expect("packer output must pass validation");

    assert_eq!(pack.guides.len(), 2);
    let csp = pack
        .guides
        .get("security.csp")
        .expect("security.csp present");
    assert_eq!(csp.effort_minutes, 30);
    assert!(
        csp.frameworks
            .as_ref()
            .is_some_and(|f| f.contains_key("next")),
        "framework variants must survive the round trip"
    );

    assert!(pack.guides["seo.title"].frameworks.is_none());
}

#[test]
fn every_effort_the_packer_accepts_is_one_this_client_understands() {
    // The packer's VALID_EFFORT set and this enum are the same vocabulary
    // written twice. Drift means a guide that packs and then never renders.
    for effort in ["quick", "moderate", "involved"] {
        let json = format!(r#"{{"effort":"{effort}","effort_minutes":1,"default":["step"]}}"#);
        serde_json::from_str::<super::schema::GuideEntry>(&json)
            .unwrap_or_else(|error| panic!("effort {effort:?} must deserialize: {error}"));
    }
}

#[test]
fn the_generated_pack_is_accepted_when_one_has_been_built() {
    let artifact =
        std::path::Path::new(env!("SITECMD_SOURCE_ROOT")).join("target/catalog/catalog.json");
    let Ok(bytes) = std::fs::read(&artifact) else {
        // No pack built on this machine; the shape fixture above still holds
        // the contract.
        return;
    };

    let pack: CatalogPack = serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("built pack at {artifact:?} must deserialize: {error}"));
    pack.validate()
        .unwrap_or_else(|error| panic!("built pack must pass every capability limit: {error}"));
    assert!(
        !pack.guides.is_empty(),
        "a built pack with no guides means the packer found no sources"
    );
}
