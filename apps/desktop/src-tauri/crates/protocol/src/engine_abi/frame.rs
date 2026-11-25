//! Length-prefixed JSON with an optional request body region.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    MissingLength,
    TruncatedJson,
    TrailingAnswerBytes,
    InvalidBodyReference,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::MissingLength => "missing frame length",
            Self::TruncatedJson => "JSON length exceeds frame",
            Self::TrailingAnswerBytes => "trailing answer bytes",
            Self::InvalidBodyReference => "invalid body reference",
        })
    }
}

impl std::error::Error for FrameError {}

/// Encode `[u32 LE JSON length][JSON][body region]`.
///
/// Panics if the JSON length cannot fit in a `u32`.
pub fn encode_request(json: &[u8], region: &[u8]) -> Vec<u8> {
    let len = u32::try_from(json.len()).expect("frame JSON length fits in u32");
    let mut frame = Vec::with_capacity(4 + json.len() + region.len());
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(json);
    frame.extend_from_slice(region);
    frame
}

/// Borrow the JSON and body region from a request frame.
pub fn decode_request(frame: &[u8]) -> Result<(&[u8], &[u8]), FrameError> {
    let (prefix, rest) = frame
        .split_first_chunk::<4>()
        .ok_or(FrameError::MissingLength)?;
    let len = u32::from_le_bytes(*prefix) as usize;
    rest.split_at_checked(len).ok_or(FrameError::TruncatedJson)
}

/// Encode `[u32 LE JSON length][JSON]`.
///
/// Panics if the JSON length cannot fit in a `u32`.
pub fn encode_answer(json: &[u8]) -> Vec<u8> {
    encode_request(json, &[])
}

/// Borrow the JSON from a complete answer frame.
pub fn decode_answer(frame: &[u8]) -> Result<&[u8], FrameError> {
    let (json, trailing) = decode_request(frame)?;
    if !trailing.is_empty() {
        return Err(FrameError::TrailingAnswerBytes);
    }
    Ok(json)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BodyRef {
    pub at: u32,
    pub len: u32,
}

impl BodyRef {
    pub fn slice<'a>(&self, region: &'a [u8]) -> Result<&'a [u8], FrameError> {
        let end = self
            .at
            .checked_add(self.len)
            .ok_or(FrameError::InvalidBodyReference)?;
        region
            .get(self.at as usize..end as usize)
            .ok_or(FrameError::InvalidBodyReference)
    }
}
