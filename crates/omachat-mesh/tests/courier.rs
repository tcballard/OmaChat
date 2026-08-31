use omachat_mesh::courier::{
    CourierEnvelope, LocalPrekeys, SealCourier, candidate_day_tags, day_tag, open, seal,
};

fn hex32(value: &str) -> [u8; 32] {
    hex::decode(value).expect("hex").try_into().expect("32")
}

#[test]
fn day_tags_match_pinned_swift() {
    let public = hex32("5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b");
    assert_eq!(
        hex::encode(day_tag(&public, 20_000)),
        "4e6207017b791f7431c47012eed740f4"
    );
    let tags = candidate_day_tags(&public, 20_000);
    assert_eq!(hex::encode(tags[0]), "ca25192d8def0d1b668af9400e8bc6fc");
    assert_eq!(hex::encode(tags[2]), "5faca8ed50c4b992eb0ba9d0524dad94");
}

#[test]
fn static_v1_envelope_matches_and_opens_pinned_swift() {
    let recipient_secret =
        hex32("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
    let recipient_public =
        hex32("5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b");
    let envelope = seal(
        &SealCourier {
            sender_static_secret: &hex32(
                "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            ),
            recipient_identity_public: &recipient_public,
            recipient_seal_public: &recipient_public,
            ephemeral_secret: &hex32(
                "4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60",
            ),
            epoch_day: 20_000,
            expiry_ms: 1_700_086_400_000,
            prekey_id: None,
            copies: 1,
        },
        b"omachat synthetic courier v1",
    )
    .expect("seal");
    let wire = envelope.encode().expect("encode");
    assert_eq!(
        hex::encode(&wire),
        "0100104e6207017b791f7431c47012eed740f40200080000018bd50bc40003007c64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d484664487d53040d22df42159b0e0cf249e5b9fdbec370329d14d2ed8a3dfcaddae7778137c2d58f2215271a593133dad7ca3d9b5d7da6ad48865e0dacee2820cbafe9f7480728113f484ed2b92a2957f27c7f03d37233b67e9e9294edd56"
    );
    let decoded = CourierEnvelope::decode(&wire).expect("decode");
    let (payload, sender) = open(&decoded, &recipient_secret, 1_700_000_000_000).expect("open");
    assert_eq!(payload, b"omachat synthetic courier v1");
    assert_eq!(
        hex::encode(sender),
        "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c"
    );
}

#[test]
fn prekey_v2_consumes_once_and_keeps_grace_for_redelivery() {
    let identity_public = hex32("5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b");
    let prekey_secret = hex32("6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80");
    let prekey_public = hex32("244fe3b963e899dd295baffce248d3530f3a9a7479ba063002680ebfe7adad49");
    let envelope = seal(
        &SealCourier {
            sender_static_secret: &hex32(
                "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            ),
            recipient_identity_public: &identity_public,
            recipient_seal_public: &prekey_public,
            ephemeral_secret: &hex32(
                "8182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0",
            ),
            epoch_day: 20_000,
            expiry_ms: 1_700_086_400_000,
            prekey_id: Some(0xa1b2c3d4),
            copies: 4,
        },
        b"omachat synthetic courier v2 prekey",
    )
    .expect("seal");
    assert_eq!(
        hex::encode(envelope.encode().expect("wire")),
        "0100104e6207017b791f7431c47012eed740f40200080000018bd50bc400030083883186b800b41d5cf0429695da9b3cc4f328ebcd184a6e482fa578c103f06c77e9bbdd29655f1acd58be78c3795f21073e112a26f49236a00d93b400e5aba4933242c6b56ec2daf21c3a5484e99f9863bfc544d0963db792e081edd6824575a3fb10cefd47c51e859b043c51b29e9d940fb3243510656302421af29d7b3f5841139a7e04000104050004a1b2c3d4"
    );
    let mut keys = LocalPrekeys::default();
    keys.insert(0xa1b2c3d4, prekey_secret).expect("insert");
    assert!(keys.open(&envelope, 1_700_000_000_000).expect("first").2);
    assert!(
        !keys
            .open(&envelope, 1_700_000_000_001)
            .expect("redelivery")
            .2
    );
}
