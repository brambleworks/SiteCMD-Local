//! The request framing every `checks` entry reads.
//!
//! A request is `[JSON length: u32 little-endian][UTF-8 JSON][body region]`, the region possibly
//! empty. A body the engine reads crosses as raw bytes in the region, not inside the JSON: in its
//! place the JSON holds `{"at": offset, "len": byte_length}`, the offset counted in bytes from the
//! region's start. The bodies so referenced are `page.body` at `engine_route_open` and the `body`
//! of each `"kind": "response"` outcome in `probe_outcomes` at `engine_route_plan` and
//! `engine_route_evaluate`, where a null body stays null. Everything else stays in the JSON, and
//! the other three entries leave the region unread.
//!
//! The request, every `probe_outcomes` element and every `outcome` are JSON objects.
//! `probe_outcomes` may be absent, null or an array. Every reference is an object containing
//! only `at` and `len`, both unsigned integers.
//!
//! Sitemap ranges use `decode_sitemap_body`, keeping no text for invalid UTF-8; other ranges
//! use `decode_probe_body`. A probe keeps the whole `ProbeBody`, the page its text.
//! A buffer shorter than its prefix, a JSON length past the buffer,
//! a reference outside the region and a body given inline each answer the
//! error frame. The request is freed before the engine computes its answer.
//! References may share bytes but together read no more than the region holds.
//! Malformed, inline and out-of-range references answer the fixed message
//! `invalid body reference`, without echoing the request value.

use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use sitecmd_engine::evaluation::is_sitemap_probe_key;
use sitecmd_engine::probe::{decode_probe_body, decode_sitemap_body, ProbeBody};

const INVALID_BODY_REFERENCE: &str = "invalid body reference";

pub(super) enum BodyFields {
    None,
    Page,
    Probes,
}

/// Where a body lies in the region: `len` bytes from byte `at`.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BodyReference {
    at: usize,
    len: usize,
}

/// Read `[JSON length: u32 LE][JSON][body region]`, freeing the request before
/// the caller computes its answer.
///
/// # Safety
///
/// `ptr` must be an unfreed `scorer_alloc` buffer of exactly `len` bytes.
pub(super) unsafe fn read_request<T: DeserializeOwned>(
    ptr: *mut u8,
    len: u32,
    fields: BodyFields,
) -> Result<T, String> {
    let request = Box::from_raw(core::ptr::slice_from_raw_parts_mut(ptr, len as usize));
    let (prefix, rest) = request
        .split_first_chunk::<4>()
        .ok_or("request has no JSON length prefix")?;
    let json_len = u32::from_le_bytes(*prefix) as usize;
    let (json, region) = rest
        .split_at_checked(json_len)
        .ok_or("JSON length exceeds request buffer")?;
    if json
        .iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .copied()
        != Some(b'{')
    {
        return Err("request must be an object".into());
    }
    let decode_bodies = match fields {
        BodyFields::None => {
            return serde_json::from_slice::<T>(json).map_err(|error| error.to_string());
        }
        BodyFields::Page => decode_page,
        BodyFields::Probes => decode_probes,
    };
    let mut value: Value = serde_json::from_slice(json).map_err(|error| error.to_string())?;
    let mut remaining = region.len();
    decode_bodies(&mut value, region, &mut remaining)?;
    serde_json::from_value(value).map_err(|error| error.to_string())
}

fn decode_page(value: &mut Value, region: &[u8], remaining: &mut usize) -> Result<(), String> {
    let body = value
        .pointer_mut("/page/body")
        .ok_or(INVALID_BODY_REFERENCE)?;
    *body = Value::String(decode(body, region, remaining, false)?.text);
    Ok(())
}

fn decode(
    reference: &mut Value,
    region: &[u8],
    remaining: &mut usize,
    sitemap: bool,
) -> Result<ProbeBody, String> {
    if !reference.is_object() {
        return Err(INVALID_BODY_REFERENCE.into());
    }
    let reference: BodyReference =
        serde_json::from_value(reference.take()).map_err(|_| INVALID_BODY_REFERENCE)?;
    let end = reference
        .at
        .checked_add(reference.len)
        .ok_or(INVALID_BODY_REFERENCE)?;
    let bytes = region
        .get(reference.at..end)
        .ok_or(INVALID_BODY_REFERENCE)?;
    *remaining = remaining
        .checked_sub(reference.len)
        .ok_or(INVALID_BODY_REFERENCE)?;
    Ok(if sitemap {
        decode_sitemap_body(bytes)
    } else {
        decode_probe_body(bytes.to_vec())
    })
}

fn decode_probes(value: &mut Value, region: &[u8], remaining: &mut usize) -> Result<(), String> {
    let Some(probes) = value
        .get_mut("probe_outcomes")
        .filter(|probes| !probes.is_null())
    else {
        return Ok(());
    };
    let probes = probes
        .as_array_mut()
        .ok_or("probe_outcomes must be an array or null")?;
    for probe in probes {
        let probe = probe
            .as_object_mut()
            .ok_or("probe outcome must be an object")?;
        let sitemap = probe
            .get("key")
            .and_then(Value::as_str)
            .is_some_and(is_sitemap_probe_key);
        let outcome = probe
            .get_mut("outcome")
            .and_then(Value::as_object_mut)
            .ok_or("outcome must be an object")?;
        if outcome.get("kind").and_then(Value::as_str) != Some("response") {
            continue;
        }
        if let Some(body) = outcome.get_mut("body").filter(|body| !body.is_null()) {
            let ProbeBody {
                text,
                bytes,
                utf8_valid,
            } = decode(body, region, remaining, sitemap)?;
            let mut fields = Map::new();
            // Owned values move the decoded text into the engine without another body copy.
            fields.insert("text".into(), Value::String(text));
            fields.insert("bytes".into(), Value::from(bytes));
            fields.insert("utf8_valid".into(), Value::Bool(utf8_valid));
            *body = Value::Object(fields);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sitecmd_engine::evaluation::{RouteCall, RouteOpenRequest};
    use sitecmd_engine::probe::ProbeOutcome;

    fn read<T: DeserializeOwned>(json: Value, region: &[u8], fields: BodyFields) -> T {
        let json = serde_json::to_vec(&json).expect("JSON");
        let mut framed = (json.len() as u32).to_le_bytes().to_vec();
        framed.extend_from_slice(&json);
        framed.extend_from_slice(region);
        unsafe {
            let ptr = crate::scorer_alloc(framed.len() as u32);
            core::ptr::copy_nonoverlapping(framed.as_ptr(), ptr, framed.len());
            read_request(ptr, framed.len() as u32, fields).expect("framed request")
        }
    }

    #[test]
    fn referenced_bodies_preserve_every_decoded_field() {
        let mut samples = vec![
            b"User-agent: *\nDisallow: /private".to_vec(),
            br#""quoted" \\ path"#.to_vec(),
            b"first\r\nsecond\nthird\r".to_vec(),
            "caf\u{e9} \u{4e16}\u{754c} \u{1f680}".as_bytes().to_vec(),
            vec![0xff],
            vec![0xe2, 0x82],
            Vec::new(),
        ];
        samples.extend((0..32).map(|byte| vec![byte]));
        for (index, sample) in samples.into_iter().enumerate() {
            let at = index + 3;
            let mut region = vec![b'Z'; at];
            region.extend_from_slice(&sample);
            region.push(b'Z');
            let reference = json!({"at": at, "len": sample.len()});
            let call: RouteCall = read(
                json!({"probe_outcomes": [{"key": "probe", "outcome": {
                    "kind": "response", "status": 200, "final_url": "https://example.com/",
                    "content_type": null, "body": reference
                }}]}),
                &region,
                BodyFields::Probes,
            );
            let expected = decode_probe_body(sample);
            let probe = call.probe_outcomes.expect("outcomes").remove(0);
            let ProbeOutcome::Response(response) = probe.outcome else {
                panic!("response")
            };
            assert_eq!(
                json!(response.body.expect("body")),
                json!(expected),
                "sample {index}"
            );
            let open: RouteOpenRequest = read(
                json!({"page": {
                    "url": "https://example.com/", "status_code": 200, "headers": [],
                    "evaluation_time": "2026-08-05T00:00:00Z", "body": reference
                }}),
                &region,
                BodyFields::Page,
            );
            assert_eq!(open.page.body, expected.text, "sample {index}");
        }
    }
}
