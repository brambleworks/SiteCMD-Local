#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| sitecmd_engine_fuzz::evaluation_payload(data));
