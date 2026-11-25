//! Approved recovery copy and conservative mappings for store diagnostics.

const LOGIN_RECOVERY_WORDS: &str = "Couldn't sign you in, because this computer couldn't save your sign-in{reason}. Delete the newest token on your account's Personal tokens page, then run `sitecmd login` again.";

pub(super) const LOGIN_EARLIER_REVOKE_FAILED_WORDS: &str = "SiteCMD could not revoke this computer's earlier token. Revoke it on your account's Personal tokens page.";

pub(super) const LOGIN_WAITING_FOR_SAVE_WORDS: &str =
    "Stopping once your keychain responds. Press Ctrl-C again to stop now.";

pub(super) fn recovery(reason: Option<&str>) -> String {
    let phrase = match reason {
        Some(
            "private credential storage is unavailable"
            | "could not prepare private credential storage"
            | "could not stage the private credential file"
            | "could not write the private credential file"
            | "could not flush the private credential file"
            | "could not replace the private credential file",
        ) => Some("the credentials file couldn't be written"),
        _ => None,
    };
    let suffix = phrase
        .map(|phrase| format!(" ({phrase})"))
        .unwrap_or_default();
    LOGIN_RECOVERY_WORDS.replace("{reason}", &suffix)
}
