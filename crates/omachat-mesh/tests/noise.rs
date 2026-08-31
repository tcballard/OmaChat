use omachat_mesh::noise::{FramedTransport, Handshake, NoiseError, Role, crossed_initiation_role};

fn hex32(value: &str) -> [u8; 32] {
    hex::decode(value)
        .expect("hex")
        .try_into()
        .expect("32 bytes")
}

#[test]
fn exact_swift_cacophony_xx_transcript_matches() {
    let mut initiator = Handshake::new(
        Role::Initiator,
        hex32("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"),
        hex32("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"),
        b"John Galt",
    );
    let mut responder = Handshake::new(
        Role::Responder,
        hex32("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"),
        hex32("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"),
        b"John Galt",
    );
    let m1 = initiator.write_message(b"Ludwig von Mises").expect("m1");
    assert_eq!(
        hex::encode(&m1),
        "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573"
    );
    assert_eq!(
        responder.read_message(&m1).expect("read m1"),
        b"Ludwig von Mises"
    );
    let m2 = responder.write_message(b"Murray Rothbard").expect("m2");
    assert_eq!(
        hex::encode(&m2),
        "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f14480884381cbad1f276e038c48378ffce2b65285e08d6b68aaa3629a5a8639392490e5b9bd5269c2f1e4f488ed8831161f19b7815528f8982ffe09be9b5c412f8a0db50f8814c7194e83f23dbd8d162c9326ad"
    );
    assert_eq!(
        initiator.read_message(&m2).expect("read m2"),
        b"Murray Rothbard"
    );
    let m3 = initiator.write_message(b"F. A. Hayek").expect("m3");
    assert_eq!(
        hex::encode(&m3),
        "c7195ffacac1307ff99046f219750fc47693e23c3cb08b89c2af808b444850a80ae475b9df0f169ae80a89be0865b57f58c9fea0d4ec82a286427402f113e4b6ae769a1d95941d49b25030"
    );
    assert_eq!(
        responder.read_message(&m3).expect("read m3"),
        b"F. A. Hayek"
    );
    assert_eq!(
        hex::encode(initiator.handshake_hash()),
        "c8e5f64e846193be2a834104c2a009868d6c9f3bd3c186299888b488b2f1f58e"
    );
    let mut i = initiator.into_transport().expect("i transport");
    let mut r = responder.into_transport().expect("r transport");
    let c4 = r.encrypt(b"Carl Menger").expect("c4");
    assert_eq!(
        hex::encode(&c4),
        "96763ed773f8e47bb3712f0e29b3060ffc956ffc146cee53d5e1df"
    );
    assert_eq!(i.decrypt(&c4).expect("p4"), b"Carl Menger");
}

#[test]
fn framed_transport_accepts_reordering_and_rejects_replay_and_stale() {
    let mut sender = FramedTransport::new([1; 32], [2; 32]);
    let mut receiver = FramedTransport::new([2; 32], [1; 32]);
    let frames = (0_u32..1_026)
        .map(|index| sender.encrypt(&index.to_be_bytes()).expect("encrypt"))
        .collect::<Vec<_>>();
    assert_eq!(
        receiver.decrypt(&frames[2]).expect("counter two"),
        2_u32.to_be_bytes()
    );
    assert_eq!(
        receiver.decrypt(&frames[0]).expect("reordered zero"),
        0_u32.to_be_bytes()
    );
    assert_eq!(
        receiver.decrypt(&frames[1]).expect("reordered one"),
        1_u32.to_be_bytes()
    );
    assert_eq!(receiver.decrypt(&frames[1]), Err(NoiseError::Replay));
    assert!(receiver.decrypt(&frames[1_025]).is_ok());
    assert_eq!(receiver.decrypt(&frames[0]), Err(NoiseError::Stale));
}

#[test]
fn crossed_initiation_uses_lower_peer_as_initiator() {
    assert_eq!(
        crossed_initiation_role(b"aaaaaaaa", b"bbbbbbbb"),
        Role::Initiator
    );
    assert_eq!(
        crossed_initiation_role(b"bbbbbbbb", b"aaaaaaaa"),
        Role::Responder
    );
}
