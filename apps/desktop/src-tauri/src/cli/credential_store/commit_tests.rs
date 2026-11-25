use super::*;
use std::cell::Cell;
use std::sync::atomic::Ordering;

#[test]
fn login_store_commit_callback_precedes_cleanup_on_both_backends() {
    // Bug: recording a commit after tidy-up can misreport a saved token as unsaved during forced exit.
    for fallback in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        let store = test_support::seed_pair("https://connect.example", &path);
        store
            .test_faults
            .keyring_write
            .store(fallback, Ordering::SeqCst);
        let replacement = StoredToken {
            token_id: "replacement-id".into(),
            token: Zeroizing::new("replacement-fixture".into()),
        };
        let calls = Cell::new(0);
        let expected = if fallback {
            StoreLocation::File(path)
        } else {
            StoreLocation::Keyring
        };
        let saved = store
            .save(&replacement, &|location| {
                calls.set(calls.get() + 1);
                assert_eq!(location, &expected);
                let keyring =
                    decode_token(store.entry.as_ref().unwrap().get_secret().unwrap()).unwrap();
                let mut file = store.read_file().unwrap();
                let file = file.remove("https://connect.example").unwrap().credential;
                let (committed, earlier) = if fallback {
                    (file, keyring)
                } else {
                    (keyring, file)
                };
                assert!(
                    committed.token.as_str() == replacement.token.as_str(),
                    "callback preceded the persistent commit"
                );
                assert!(
                    earlier.token.as_str()
                        == if fallback {
                            "old-bearer"
                        } else {
                            "file-bearer"
                        },
                    "tidy-up preceded the commit callback"
                );
            })
            .unwrap();
        assert_eq!(
            calls.get(),
            1,
            "save did not report its commit exactly once"
        );
        assert_eq!(saved, expected);
        assert_eq!(store.stored_locations().unwrap(), vec![expected]);
        assert!(
            store.read_stored().unwrap().unwrap().token.as_str() == replacement.token.as_str(),
            "later reads did not return the committed replacement"
        );
    }
}
