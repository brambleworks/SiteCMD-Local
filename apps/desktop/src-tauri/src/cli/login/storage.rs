//! Persisted-token custody independent of an environment override.

use super::{CredentialStore, StoreLocation, StoredToken};
use crate::cli::credential_store::revoke_token;

pub(super) trait LoginStore: Clone + Send + Sync + 'static {
    fn tokens(&self) -> Result<Vec<StoredToken>, String>;
    fn save(
        &self,
        token: &StoredToken,
        on_commit: &dyn Fn(&StoreLocation),
    ) -> Result<StoreLocation, String>;
    fn delete(&self) -> Result<Option<StoreLocation>, String>;
}

impl LoginStore for std::sync::Arc<CredentialStore> {
    fn tokens(&self) -> Result<Vec<StoredToken>, String> {
        self.as_ref().read_stored_all()
    }
    fn save(
        &self,
        token: &StoredToken,
        on_commit: &dyn Fn(&StoreLocation),
    ) -> Result<StoreLocation, String> {
        self.as_ref().save(token, on_commit)
    }
    fn delete(&self) -> Result<Option<StoreLocation>, String> {
        self.as_ref().delete()
    }
}

pub(super) fn store_name(location: &StoreLocation) -> String {
    match location {
        StoreLocation::Keyring => "your system's keychain".into(),
        StoreLocation::File(path) => path.display().to_string(),
    }
}

pub(super) async fn revoke(origin: &str, tokens: &[StoredToken]) -> bool {
    let mut succeeded = true;
    for token in tokens {
        if revoke_token(origin, token).await.is_err() {
            succeeded = false;
        }
    }
    succeeded
}
