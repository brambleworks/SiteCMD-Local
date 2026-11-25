//! Origin-scoped credential enumeration and authenticated token retirement.

use super::{decode_token, CredentialStore, Error, StoredToken};
use crate::connected_codes::CodeRefusal;
use crate::connected_service::ConnectedServiceClient;

impl CredentialStore {
    /// Enumerate both stores by bearer value, ignoring environment overrides and refusing unreadable stores.
    pub fn read_stored_all(&self) -> Result<Vec<StoredToken>, String> {
        self.validate_origin()?;
        let mut tokens = Vec::new();
        if let Some(entry) = &self.entry {
            match entry.get_secret() {
                Ok(bytes) => tokens.push(decode_token(bytes)?),
                Err(Error::NoEntry) => {}
                Err(_) => {
                    return Err(
                        "could not read all stored credentials from the system credential store"
                            .into(),
                    )
                }
            }
        }
        if let Some(record) = self.read_file()?.remove(&self.origin) {
            let token = record.credential;
            if !tokens
                .iter()
                .any(|known| known.token.as_str() == token.token.as_str())
            {
                tokens.push(token);
            }
        }
        Ok(tokens)
    }
}

pub(crate) async fn revoke_token(origin: &str, stored: &StoredToken) -> Result<(), String> {
    let client =
        ConnectedServiceClient::for_endpoint(origin, Some(stored.token.as_str()), cfg!(test))
            .map_err(|_| "could not prepare stored credential revocation")?;
    match client.revoke_current_token().await {
        Ok(()) => Ok(()),
        // A retry may present an already retired token after a later revocation failed.
        Err(error)
            if error.status == 401 && error.code_refusal() == Some(CodeRefusal::Unauthorized) =>
        {
            Ok(())
        }
        Err(_) => Err("could not revoke a stored SiteCMD token".into()),
    }
}
