#![no_main]
use libfuzzer_sys::fuzz_target;
use omachat_proto::ipc::RequestDecoder;
fuzz_target!(|data: &[u8]| { let _ = RequestDecoder::default().push(data); });
