use omachat_store::{BlockList, PeerTrustStore, RequestedProvider, SealedStore};

#[tokio::test]
async fn trust_survives_restart_and_enforces_policy() {
    let temporary = tempfile::tempdir().unwrap();
    {
        let store = SealedStore::open(temporary.path(), RequestedProvider::File)
            .await
            .unwrap();
        let mut trust = PeerTrustStore::load(&store).unwrap();
        trust
            .pin_authenticated("peer".into(), [1; 32], [2; 32])
            .unwrap();
        trust.set_favorite("peer", true).unwrap();
        assert!(trust.set_favorite("geohash-only", true).is_err());
        assert!(
            trust
                .pin_authenticated("peer".into(), [9; 32], [2; 32])
                .is_err()
        );
        BlockList::load(&store)
            .unwrap()
            .block("ab".repeat(32))
            .unwrap();
    }
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .unwrap();
    assert!(PeerTrustStore::load(&store).unwrap().peers()[0].favorite);
    assert!(BlockList::load(&store).unwrap().contains(&"ab".repeat(32)));
}
