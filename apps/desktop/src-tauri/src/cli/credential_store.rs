//! Origin-scoped CLI credentials in the platform keyring or private local storage.

use std::path::PathBuf;
use std::sync::Arc;

use keyring_core::{CredentialStore as KeyringStore, Entry, Error};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// A personal token; formatting never exposes its bearer.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredToken {
    pub token_id: String,
    #[serde(with = "secret_serde")]
    pub token: Zeroizing<String>,
}

impl std::fmt::Debug for StoredToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoredToken { [redacted] }")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreLocation {
    Keyring,
    File(PathBuf),
}

/// Explicit user choices and the build endpoint may receive an environment bearer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OriginSource {
    /// The person explicitly named this origin on their command line.
    Command,
    /// The endpoint selected by this SiteCMD build.
    Build,
    /// SITECMD_CONNECT_ORIGIN must name the same canonical origin.
    Environment,
    /// Repository configuration never opts into the environment bearer.
    Repository,
}

mod file;
mod record;
use record::Record;

mod revocation;
#[cfg(test)]
pub(crate) mod test_support;
pub(crate) use revocation::revoke_token;

pub struct CredentialStore {
    origin: String,
    entry: Option<Entry>,
    file_path: Option<PathBuf>,
    origin_source: OriginSource,
    #[cfg(test)]
    pub(crate) test_faults: test_support::TestFaults,
    #[cfg(test)]
    backend: Option<Arc<KeyringStore>>,
}

impl CredentialStore {
    /// Callers must preserve whether the person, environment, build or repository named the origin.
    pub fn open_for_origin(connect_origin: &str, source: OriginSource) -> Self {
        let path = crate::app_identity::default_storage_dir()
            .map(|directory| directory.join("credentials.json"));
        let native = normalize_origin(connect_origin).and_then(|_| store_for_open());
        let mut store = Self::with_store(connect_origin, native, path);
        store.origin_source = source;
        store
    }

    fn with_store(
        origin: &str,
        store: Option<Arc<KeyringStore>>,
        file_path: Option<PathBuf>,
    ) -> Self {
        #[cfg(test)]
        let backend = store.clone();
        let origin = normalize_origin(origin).unwrap_or_default();
        let entry = if origin.is_empty() {
            None
        } else {
            store.and_then(|store| store.build("sitecmd", &origin, None).ok())
        };
        Self {
            origin,
            entry,
            file_path,
            origin_source: OriginSource::Repository,
            #[cfg(test)]
            test_faults: test_support::TestFaults::default(),
            #[cfg(test)]
            backend,
        }
    }

    fn validate_origin(&self) -> Result<(), String> {
        if self.origin.is_empty() {
            Err("credential storage requires an HTTP origin without user information".into())
        } else {
            Ok(())
        }
    }

    fn environment_allowed(&self) -> bool {
        if self.origin.is_empty() {
            return false;
        }
        match self.origin_source {
            OriginSource::Command | OriginSource::Build => true,
            OriginSource::Repository => false,
            OriginSource::Environment => std::env::var("SITECMD_CONNECT_ORIGIN")
                .ok()
                .and_then(|value| normalize_origin(&value))
                .is_some_and(|origin| origin == self.origin),
        }
    }

    pub fn read(&self) -> Result<Option<StoredToken>, String> {
        self.validate_origin()?;
        if self.environment_allowed() {
            match std::env::var("SITECMD_TOKEN") {
                Ok(token) if !token.trim().is_empty() => {
                    return Ok(Some(StoredToken {
                        token_id: String::new(),
                        token: Zeroizing::new(token),
                    }))
                }
                Ok(_) | Err(std::env::VarError::NotUnicode(_)) => {
                    return Err("SITECMD_TOKEN must contain a nonempty UTF-8 token".into())
                }
                Err(std::env::VarError::NotPresent) => {}
            }
        }
        self.read_stored()
    }

    pub fn read_stored(&self) -> Result<Option<StoredToken>, String> {
        self.read_stored_record()
            .map(|record| record.map(|(token, _)| token))
    }

    fn read_stored_record(&self) -> Result<Option<(StoredToken, StoreLocation)>, String> {
        self.validate_origin()?;
        let keyring = if let Some(entry) = &self.entry {
            match entry.get_secret() {
                Ok(bytes) => Some(Record::decode(bytes)?),
                Err(Error::NoEntry | Error::NoStorageAccess(_)) => None,
                Err(_) => return Err("could not read the system credential store".into()),
            }
        } else {
            None
        };
        let file = match self.read_file() {
            Ok(mut records) => records.remove(&self.origin),
            Err(_) if keyring.is_some() => None,
            Err(error) => return Err(error),
        };
        match (keyring, file) {
            (Some(keyring), Some(file)) if file.saved_at > keyring.saved_at => Ok(self
                .file_path
                .clone()
                .map(|path| (file.credential, StoreLocation::File(path)))),
            (Some(keyring), _) => Ok(Some((keyring.credential, StoreLocation::Keyring))),
            (None, Some(file)) => Ok(self
                .file_path
                .clone()
                .map(|path| (file.credential, StoreLocation::File(path)))),
            (None, None) => Ok(None),
        }
    }

    /// Notify the caller immediately after a keychain write or file persist commits, before tidy-up.
    pub fn save(
        &self,
        token: &StoredToken,
        on_commit: &dyn Fn(&StoreLocation),
    ) -> Result<StoreLocation, String> {
        self.validate_origin()?;
        let records = self.read_file();
        let record = Record::new(token);
        if let Some(entry) = &self.entry {
            let bytes = Zeroizing::new(
                serde_json::to_vec(&record).map_err(|_| "credential could not be encoded")?,
            );
            #[cfg(test)]
            let result = if self.fail_keyring_write() {
                Err(no_storage_access())
            } else {
                entry.set_secret(&bytes)
            };
            #[cfg(not(test))]
            let result = entry.set_secret(&bytes);
            match result {
                Ok(()) => {
                    on_commit(&StoreLocation::Keyring);
                    let _ = self.remove_file_record();
                    return Ok(StoreLocation::Keyring);
                }
                Err(Error::NoStorageAccess(_)) => {}
                Err(_) => return Err("could not save to the system credential store".into()),
            }
        }
        let mut records = records?;
        records.insert(self.origin.clone(), record);
        let location = self.write_file(&records)?;
        on_commit(&location);
        let _ = self.sync_parent_directory();
        if let Some(entry) = &self.entry {
            #[cfg(test)]
            let _ = if self.fail_keyring_delete() {
                Err(no_storage_access())
            } else {
                entry.delete_credential()
            };
            #[cfg(not(test))]
            let _ = entry.delete_credential();
        }
        Ok(location)
    }

    /// Every persisted backend containing a token, including identical bearer copies.
    pub fn stored_locations(&self) -> Result<Vec<StoreLocation>, String> {
        self.validate_origin()?;
        let mut locations = Vec::new();
        if let Some(entry) = &self.entry {
            match entry.get_secret() {
                Ok(bytes) => {
                    Record::decode(bytes)?;
                    locations.push(StoreLocation::Keyring);
                }
                Err(Error::NoEntry) => {}
                Err(_) => return Err("could not read the system credential store".into()),
            }
        }
        if self.read_file()?.contains_key(&self.origin) {
            if let Some(path) = &self.file_path {
                locations.push(StoreLocation::File(path.clone()));
            }
        }
        Ok(locations)
    }

    /// Remove local copies; interactive logout also removes them after failed revocation.
    pub fn delete(&self) -> Result<Option<StoreLocation>, String> {
        self.validate_origin()?;
        let keyring = self.entry.as_ref().map(|entry| entry.delete_credential());
        // File cleanup still runs when the keychain refuses deletion, so logout never strands that copy.
        let file = self.remove_file_record();
        match keyring {
            Some(Err(error)) if !matches!(error, Error::NoEntry) => {
                Err("could not delete from the system credential store".into())
            }
            Some(Ok(())) => {
                file?;
                Ok(Some(StoreLocation::Keyring))
            }
            _ => file.map(|removed| {
                if removed {
                    self.file_path.clone().map(StoreLocation::File)
                } else {
                    None
                }
            }),
        }
    }
}

fn decode_token(bytes: Vec<u8>) -> Result<StoredToken, String> {
    Record::decode(bytes).map(|record| record.credential)
}

fn normalize_origin(value: &str) -> Option<String> {
    let mut url = url::Url::parse(value.trim()).ok()?;
    crate::connected_service::normalize_origin_host(&mut url).ok()?;
    if !matches!(url.scheme(), "https" | "http")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    Some(url.origin().ascii_serialization())
}

fn store_for_open() -> Option<Arc<KeyringStore>> {
    #[cfg(test)]
    {
        keyring_core::mock::Store::new()
            .ok()
            .map(|store| store as Arc<KeyringStore>)
    }
    #[cfg(not(test))]
    {
        native_store()
    }
}

#[cfg(any(not(test), target_os = "linux"))]
fn native_store() -> Option<Arc<KeyringStore>> {
    #[cfg(target_os = "macos")]
    {
        apple_native_keyring_store::keychain::Store::new()
            .ok()
            .map(|store| store as Arc<KeyringStore>)
    }
    #[cfg(windows)]
    {
        windows_native_keyring_store::Store::new()
            .ok()
            .map(|store| store as Arc<KeyringStore>)
    }
    #[cfg(target_os = "linux")]
    {
        zbus_secret_service_keyring_store::Store::new()
            .ok()
            .map(|store| store as Arc<KeyringStore>)
    }
    #[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
    {
        None
    }
}

pub(crate) mod secret_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S: Serializer>(
        secret: &Zeroizing<String>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(secret.as_str())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Zeroizing<String>, D::Error> {
        String::deserialize(deserializer).map(Zeroizing::new)
    }
}

#[cfg(test)]
#[path = "credential_store/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "credential_store/commit_tests.rs"]
mod commit_tests;

#[cfg(test)]
fn no_storage_access() -> Error {
    Error::NoStorageAccess(Box::new(std::io::Error::other("inaccessible test backend")))
}
