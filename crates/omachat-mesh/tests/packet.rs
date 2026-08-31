use ed25519_dalek::SigningKey;
use omachat_mesh::packet::{MessageType, Packet, PacketError, PacketType};

fn packet(version: u8) -> Packet {
    Packet {
        version,
        message_type: MessageType::Message.into(),
        ttl: 7,
        timestamp_ms: 1_725_000_000_123,
        sender: [1; 8],
        recipient: Some([2; 8]),
        route: if version == 2 {
            vec![[3; 8], [4; 8]]
        } else {
            vec![]
        },
        payload: vec![b'a'; 1_000],
        signature: None,
        is_rsr: true,
    }
}

#[test]
fn v1_and_v2_round_trip_compressed_and_bounded() {
    for version in [1, 2] {
        let original = packet(version);
        let wire = original.encode().expect("encode");
        assert_eq!(Packet::decode(&wire).expect("decode"), original);
        for length in 0..wire.len() {
            assert!(Packet::decode(&wire[..length]).is_err());
        }
    }
}

#[test]
fn ttl_and_rsr_mutation_do_not_break_signature_but_payload_does() {
    let key = SigningKey::from_bytes(&[9; 32]);
    let mut signed = packet(2);
    signed.sign(&key).expect("sign");
    signed.verify(&key.verifying_key()).expect("verify");
    signed.ttl = 1;
    signed.is_rsr = false;
    signed.verify(&key.verifying_key()).expect("mutable fields");
    signed.payload[0] ^= 1;
    assert!(matches!(
        signed.verify(&key.verifying_key()),
        Err(PacketError::InvalidSignature)
    ));
}

#[test]
fn unknown_types_parse_but_are_not_relay_safe() {
    let mut wire = packet(1).encode().expect("encode");
    wire[1] = 0xfe;
    let decoded = Packet::decode(&wire).expect("decode unknown");
    assert_eq!(decoded.message_type, PacketType::Unknown(0xfe));
    assert!(!decoded.message_type.relay_safe());
}
