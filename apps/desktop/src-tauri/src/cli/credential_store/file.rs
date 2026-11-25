//! Atomic private-file persistence shared by both keychain states.

use std::collections::BTreeMap;
use std::io::Read;

use super::{CredentialStore, Record, StoreLocation, Zeroizing};

impl CredentialStore {
    pub(super) fn read_file(&self) -> Result<BTreeMap<String, Record>, String> {
        let Some(path) = &self.file_path else {
            return Ok(BTreeMap::new());
        };
        crate::app_identity::validate_private_file_target(path)
            .map_err(|_| "credential storage must be a regular file without links")?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // FILE_FLAG_OPEN_REPARSE_POINT prevents following a replacement link between validation and open.
            options.custom_flags(0x00200000);
        }
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeMap::new())
            }
            Err(_) => return Err("could not read the private credential file".into()),
        };
        let metadata = file
            .metadata()
            .map_err(|_| "could not inspect the credential file")?;
        if !metadata.is_file() {
            return Err("credential storage must be a regular file".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("credential storage must not be a reparse point".into());
            }
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.read_to_end(&mut bytes)
            .map_err(|_| "could not read the private credential file")?;
        let records: BTreeMap<String, Record> =
            serde_json::from_slice(&bytes).map_err(|_| "stored credential file is invalid")?;
        for record in records.values() {
            record.observe();
        }
        Ok(records)
    }

    pub(super) fn write_file(
        &self,
        records: &BTreeMap<String, Record>,
    ) -> Result<StoreLocation, String> {
        let path = self
            .file_path
            .as_ref()
            .ok_or("private credential storage is unavailable")?;
        let parent = path
            .parent()
            .ok_or("private credential storage is unavailable")?;
        crate::app_identity::ensure_private_directory(parent)
            .map_err(|_| "could not prepare private credential storage")?;
        crate::app_identity::validate_private_file_target(path)
            .map_err(|_| "credential storage must be a regular file without links")?;
        let temporary = tempfile::Builder::new()
            .prefix(".credentials-")
            .tempfile_in(parent)
            .map_err(|_| "could not stage the private credential file")?;
        let bytes = Zeroizing::new(
            serde_json::to_vec(records).map_err(|_| "credentials could not be encoded")?,
        );
        crate::app_identity::write_private_file(temporary.path(), &bytes)
            .map_err(|_| "could not write the private credential file")?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|_| "could not flush the private credential file")?;
        temporary
            .persist(path)
            .map_err(|_| "could not replace the private credential file")?;
        Ok(StoreLocation::File(path.clone()))
    }

    pub(super) fn sync_parent_directory(&self) -> Result<(), String> {
        let _parent = self
            .file_path
            .as_ref()
            .and_then(|path| path.parent())
            .ok_or("private credential storage is unavailable")?;
        #[cfg(test)]
        if self
            .test_faults
            .post_persist
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err("could not flush private credential storage".into());
        }
        #[cfg(unix)]
        std::fs::File::open(_parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "could not flush private credential storage")?;
        Ok(())
    }

    pub(super) fn remove_file_record(&self) -> Result<bool, String> {
        #[cfg(test)]
        if self
            .test_faults
            .cleanup
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err("could not remove the credential file".into());
        }
        let mut records = self.read_file()?;
        if records.remove(&self.origin).is_none() {
            return Ok(false);
        }
        if records.is_empty() {
            let path = self
                .file_path
                .as_ref()
                .ok_or("private credential storage is unavailable")?;
            std::fs::remove_file(path).map_err(|_| "could not remove the credential file")?;
        } else {
            self.write_file(&records)?;
            let _ = self.sync_parent_directory();
        }
        Ok(true)
    }
}
