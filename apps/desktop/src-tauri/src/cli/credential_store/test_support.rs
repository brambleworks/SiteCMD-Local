use super::*;
use keyring_core::api::CredentialStoreApi;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Default)]
pub(crate) struct TestFaults {
    pub cleanup: AtomicBool,
    pub post_persist: AtomicBool,
    pub keyring_write: AtomicBool,
    pub keyring_delete: AtomicBool,
}

impl CredentialStore {
    pub(crate) fn for_test(
        origin: &str,
        source: OriginSource,
        backend: Option<Arc<KeyringStore>>,
        path: Option<PathBuf>,
    ) -> Self {
        let mut store = Self::with_store(origin, backend, path);
        store.origin_source = source;
        store
    }

    pub(crate) fn reopen_for_test(&self) -> Self {
        Self::for_test(
            &self.origin,
            self.origin_source,
            self.backend.clone(),
            self.file_path.clone(),
        )
    }

    pub(super) fn fail_keyring_write(&self) -> bool {
        self.test_faults.keyring_write.load(Ordering::SeqCst)
    }
    pub(super) fn fail_keyring_delete(&self) -> bool {
        self.test_faults.keyring_delete.load(Ordering::SeqCst)
    }
}

pub(crate) fn seed_pair(origin: &str, path: &std::path::Path) -> Arc<CredentialStore> {
    let mock = keyring_core::mock::Store::new().unwrap();
    let file = CredentialStore::with_store(origin, None, Some(path.into()));
    file.save(
        &StoredToken {
            token_id: "shared-id".into(),
            token: Zeroizing::new("file-bearer".into()),
        },
        &|_| {},
    )
    .unwrap();
    let entry = mock
        .build("sitecmd", &normalize_origin(origin).unwrap(), None)
        .unwrap();
    let old = StoredToken {
        token_id: "shared-id".into(),
        token: Zeroizing::new("old-bearer".into()),
    };
    entry
        .set_secret(&Zeroizing::new(serde_json::to_vec(&old).unwrap()))
        .unwrap();
    Arc::new(CredentialStore::for_test(
        origin,
        OriginSource::Command,
        Some(mock),
        Some(path.into()),
    ))
}
