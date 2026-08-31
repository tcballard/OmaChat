use ed25519_dalek::{Signer, SigningKey};
use omachat_mesh::private::{TrustControl, verify_challenge};

#[test]
fn trust_control_is_bounded_and_challenge_authenticates() {
    let favorite = TrustControl::Favorite {
        fingerprint: "11".repeat(32),
        nostr_public_key: "22".repeat(32),
    };
    assert_eq!(
        TrustControl::decode(&favorite.encode().unwrap()).unwrap(),
        favorite
    );
    let key = SigningKey::from_bytes(&[7; 32]);
    let nonce = [9; 32];
    let signature = key.sign(&nonce).to_bytes();
    verify_challenge(&key.verifying_key().to_bytes(), &nonce, &signature).unwrap();
    let mut wrong = nonce;
    wrong[0] ^= 1;
    assert!(verify_challenge(&key.verifying_key().to_bytes(), &wrong, &signature).is_err());
    assert!(TrustControl::decode(&vec![0; 2_049]).is_err());
}
