//! Both native suites read the same immutable bundle bytes and provenance.

use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path};

pub fn read(engine_root: &Path) -> Vec<(String, String)> {
    let root = engine_root.join("tests/fixtures/bundles");
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("manifest.json")).unwrap())
            .unwrap();
    let files = manifest["files"].as_array().unwrap();
    let recorded: BTreeSet<_> = files
        .iter()
        .map(|file| file["path"].as_str().unwrap().to_owned())
        .collect();
    let present: BTreeSet<_> = std::fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name != "manifest.json")
        .collect();
    assert_eq!(present, recorded, "unrecorded or missing corpus files");
    let mut texts: Vec<_> = files
        .iter()
        .map(|file| {
            let name = file["path"].as_str().unwrap();
            let bytes = std::fs::read(root.join(name)).unwrap();
            assert_eq!(
                hex::encode(Sha256::digest(&bytes)),
                file["sha256"],
                "{name}"
            );
            assert_eq!(
                bytes.len() as u64,
                file["bytes"].as_u64().unwrap(),
                "{name}"
            );
            (name.to_owned(), String::from_utf8(bytes).unwrap())
        })
        .collect();
    texts.push((
        "axe.min.js".into(),
        std::fs::read_to_string(engine_root.join("browser/axe.min.js")).unwrap(),
    ));
    texts
}
