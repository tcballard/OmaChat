#![no_main]

use libfuzzer_sys::fuzz_target;
use omachat_mesh::{
    announce::Announcement,
    carrier::NostrCarrier,
    courier::CourierEnvelope,
    fragment::Fragment,
    packet::Packet,
    private::PrivatePayload,
    sync::RequestSync,
};
use omachat_proto::{geohash::Geohash, ipc::RequestDecoder};

fuzz_target!(|data: &[u8]| {
    let _ = Packet::decode(data);
    let _ = Announcement::decode(data);
    let _ = NostrCarrier::decode(data);
    let _ = CourierEnvelope::decode(data);
    let _ = Fragment::decode(data);
    let _ = PrivatePayload::decode(data);
    let _ = RequestSync::decode(data);
    if let Ok(text) = std::str::from_utf8(data) { let _ = Geohash::parse(text); }
    let mut ipc = RequestDecoder::default();
    let _ = ipc.push(data);
});
