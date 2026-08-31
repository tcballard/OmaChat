use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use omachat_crypto::{DerivationSource, IdentitySecrets};

#[test]
fn geohash_identity_matches_pinned_swift_capture() {
    let device_seed =
        hex::decode("4444444444444444444444444444444444444444444444444444444444444444")
            .expect("fixture hex")
            .try_into()
            .expect("32-byte fixture");
    let secrets = IdentitySecrets::from_seeds([1; 32], [2; 32], device_seed);
    let identity = secrets
        .derive_geohash_identity("zzzzzz")
        .expect("derive captured identity");

    assert_eq!(identity.source(), DerivationSource::Candidate(0));
    assert_eq!(
        hex::encode(identity.private_key()),
        "6da90456d841eac28ef45750664b1fee891819126a885aca0e7f99332834aced"
    );
    assert_eq!(
        identity.public_key_hex(),
        "07e1870bb208e66b5189c2dc7b1c0018e26871920148706534dd74ee5a126ff4"
    );
    assert_eq!(
        identity.npub(),
        "npub1qlscwzajprnxk5vfctw8k8qqrr3xsuvjq9y8qef5m46wuksjdl6qm4923y"
    );
}

#[test]
fn long_term_keys_have_distinct_roles_and_valid_signatures() {
    let secrets = IdentitySecrets::from_seeds([7; 32], [8; 32], [9; 32]);
    let public = secrets.public_identity();
    assert_eq!(public.fingerprint_hex.len(), 64);
    assert_eq!(public.peer_id, public.fingerprint_hex[..16]);
    assert_ne!(public.noise_public_key, public.signing_public_key);

    let message = b"authenticated announcement";
    let signature = Signature::from_bytes(&secrets.sign(message));
    VerifyingKey::from_bytes(&public.signing_public_key)
        .expect("public signing key")
        .verify(message, &signature)
        .expect("valid signature");
}
