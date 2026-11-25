//! Wire interface for the standalone engine module.

mod fixes;
pub mod frame;
pub mod guest;
mod local_site_wire;
pub mod types;

#[cfg(test)]
mod wire_tests;

pub use frame::{
    decode_answer, decode_request, encode_answer, encode_request, BodyRef, FrameError,
};
pub use types::*;

/// Version 2 carries product categories and optional Code Scan rules skip coverage.
pub const ENGINE_ABI_VERSION: u32 = 2;

/// Maximum number of source files in one Code Scan.
pub const AUDIT_MAX_FILES: usize = 5_000;
pub const AUDIT_MAX_FILE_BYTES: u64 = 1_000_000;
pub const EXPORTS: &[&str] = &[
    "memory",
    "engine_alloc",
    "engine_free",
    "engine_info",
    "engine_analyze_files",
    "session_begin",
    "session_continue",
    "local_site_evaluate",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trips_json_and_body() {
        // A request can lose binary body bytes or misread the JSON length.
        let json = b"{}";
        let body = b"\0\xff";
        let frame = encode_request(json, body);
        assert_eq!(frame, b"\x02\0\0\0{}\0\xff");
        assert_eq!(decode_request(&frame), Ok((&json[..], &body[..])));
        assert!(decode_request(&frame[..3]).is_err());
        assert!(decode_request(&frame[..5]).is_err());
    }

    #[test]
    fn body_ref_outside_the_region_is_refused() {
        // An out-of-range or overflowing reference can read beyond its region.
        let region = b"abc";
        assert_eq!(BodyRef { at: 1, len: 2 }.slice(region), Ok(&b"bc"[..]));
        assert_eq!(BodyRef { at: 3, len: 0 }.slice(region), Ok(&b""[..]));
        assert!(BodyRef { at: 2, len: 2 }.slice(region).is_err());
        assert!(BodyRef { at: 4, len: 0 }.slice(region).is_err());
        assert!(BodyRef {
            at: u32::MAX,
            len: 1
        }
        .slice(region)
        .is_err());
    }

    #[test]
    fn answer_frame_length_must_match() {
        // An answer can silently accept missing or trailing payload bytes.
        let frame = encode_answer(b"{}");
        assert_eq!(frame, b"\x02\0\0\0{}");
        assert_eq!(decode_answer(&frame), Ok(&b"{}"[..]));
        assert!(decode_answer(&frame[..5]).is_err());
        assert!(decode_answer(b"\x01\0\0\0{}").is_err());
    }

    #[test]
    fn maximum_declared_frame_length_is_truncated() {
        // Adding the prefix to a maximum JSON length can overflow on 32-bit targets.
        let frame = b"\xff\xff\xff\xff";
        assert_eq!(decode_request(frame), Err(FrameError::TruncatedJson));
        assert_eq!(decode_answer(frame), Err(FrameError::TruncatedJson));
    }

    #[test]
    fn unknown_want_kind_does_not_parse() {
        // An unrecognized want could be accepted as a valid host operation.
        assert!(serde_json::from_str::<Want>(r#"{"kind":"read_env"}"#).is_err());
        assert!(matches!(
            serde_json::from_str::<Want>(r#"{"kind":"git_tracked","paths":[]}"#),
            Ok(Want::GitTracked { paths }) if paths.is_empty()
        ));
    }

    #[test]
    fn unknown_refusal_does_not_parse() {
        // An unrecognized refusal could be accepted by the session.
        assert!(serde_json::from_str::<Refusal>(r#""other""#).is_err());
        assert_eq!(
            serde_json::from_str::<Refusal>(r#""not_listed""#).unwrap(),
            Refusal::NotListed
        );
    }

    #[test]
    fn step_uses_only_the_wants_or_done_key() {
        // An added discriminator or ambiguous fields can break session response decoding.
        let wants = serde_json::json!({"wants": []});
        let done = serde_json::json!({"done": {"fix_plan": {"patches": []}}});
        for wire in [wants, done] {
            let step: Step = serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(serde_json::to_value(step).unwrap(), wire);
        }
        assert!(serde_json::from_value::<Step>(serde_json::json!({
            "wants": [], "done": {"fix_plan": {"patches": []}}
        }))
        .is_err());
    }

    #[test]
    fn rel_path_refuses_parent_root_backslash_and_nul() {
        // Direct parsing or JSON decoding could admit an unsafe path spelling.
        for raw in [
            "../a", "a/../b", "/a", "C:/a", "C:a", "a\\b", "a\0b", "", "a//b", "a/./b",
        ] {
            assert!(RelPath::parse(raw).is_err(), "{raw:?}");
            let json = serde_json::to_string(raw).unwrap();
            assert!(serde_json::from_str::<RelPath>(&json).is_err(), "{raw:?}");
        }
        let path = RelPath::parse("src/nested/file.rs").unwrap();
        assert_eq!(path.as_str(), "src/nested/file.rs");
        assert_eq!(
            serde_json::to_string(&path).unwrap(),
            r#""src/nested/file.rs""#
        );
    }

    #[test]
    fn listing_requires_unique_sorted_paths_for_lookup() {
        // Unsorted or duplicate paths can make binary search miss or select an ambiguous entry.
        let dir = serde_json::json!({"path": "src", "size": 0, "kind": "dir", "ignored": false});
        let file =
            serde_json::json!({"path": "src/lib.rs", "size": 12, "kind": "file", "ignored": true});
        let listing: Listing =
            serde_json::from_value(serde_json::json!({"entries": [dir, file], "skipped_paths": 0}))
                .unwrap();
        let dir_path = RelPath::parse("src").unwrap();
        let file_path = RelPath::parse("src/lib.rs").unwrap();
        let missing_path = RelPath::parse("src/main.rs").unwrap();
        assert!(listing.is_dir(&dir_path));
        assert!(!listing.is_file(&dir_path));
        assert!(listing.is_file(&file_path));
        assert!(!listing.is_dir(&file_path));
        assert_eq!(listing.get(&file_path).unwrap().size, 12);
        assert_eq!(listing.get(&missing_path), None);
        for entries in [[&file, &dir], [&dir, &dir]] {
            assert!(serde_json::from_value::<Listing>(
                serde_json::json!({"entries": entries, "skipped_paths": 0})
            )
            .is_err());
        }
    }

    #[test]
    fn exports_list_is_exact() {
        // Missing or extra exports can break module validation.
        assert_eq!(ENGINE_ABI_VERSION, 2);
        assert_eq!(
            EXPORTS,
            &[
                "memory",
                "engine_alloc",
                "engine_free",
                "engine_info",
                "engine_analyze_files",
                "session_begin",
                "session_continue",
                "local_site_evaluate",
            ]
        );
    }

    #[test]
    fn malformed_input_answer_has_only_a_closed_error_code() {
        // A malformed request diagnostic can expose bytes supplied by the caller.
        let response = ErrorAnswer {
            error: ErrorCode::InvalidRequest,
        };
        let frame = encode_answer(&serde_json::to_vec(&response).unwrap());
        assert_eq!(
            decode_answer(&frame),
            Ok(&br#"{"error":"invalid_request"}"#[..])
        );
        assert!(serde_json::from_str::<ErrorAnswer>(r#"{"error":"other"}"#).is_err());
        assert!(serde_json::from_str::<ErrorAnswer>(
            r#"{"error":"invalid_request","detail":"caller data"}"#,
        )
        .is_err());
    }
}
