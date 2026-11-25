//! Allocation and framing for ABI implementations.

use serde::{de::DeserializeOwned, Serialize};

use super::{decode_request, encode_answer, ErrorAnswer, ErrorCode};

pub fn alloc(len: u32) -> *mut u8 {
    Box::into_raw(vec![0u8; len as usize].into_boxed_slice()).cast()
}

/// Take ownership of a guest buffer.
///
/// # Safety
///
/// The pointer and length must identify a live buffer created by this module.
pub unsafe fn take(ptr: *mut u8, len: u32) -> Box<[u8]> {
    // SAFETY: The caller transfers the original allocation with its full length.
    unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len as usize)) }
}

pub fn request<T: DeserializeOwned>(frame: &[u8]) -> Result<(T, &[u8]), ErrorCode> {
    let (json, region) = decode_request(frame).map_err(|_| ErrorCode::InvalidFrame)?;
    let value = serde_json::from_slice(json).map_err(|_| ErrorCode::InvalidRequest)?;
    Ok((value, region))
}

pub fn answer(value: &impl Serialize) -> *const u8 {
    let json = serde_json::to_vec(value).expect("engine answers serialize");
    raw_answer(&json)
}

pub fn raw_answer(json: &[u8]) -> *const u8 {
    Box::into_raw(encode_answer(json).into_boxed_slice()).cast()
}

pub fn error(error: ErrorCode) -> *const u8 {
    answer(&ErrorAnswer { error })
}
