use omachat_store::{PublicArchive, PublicArchiveEntry, RequestedProvider, SealedStore};

#[tokio::test]
async fn archive_survives_restart() {
    let temporary = tempfile::tempdir().unwrap();
    {
        let store = SealedStore::open(temporary.path(), RequestedProvider::File)
            .await
            .unwrap();
        let mut archive = PublicArchive::load(&store, 10_000).unwrap();
        archive
            .insert(
                PublicArchiveEntry {
                    event_id: "e1".into(),
                    created_at: 10_000,
                    payload: b"public".to_vec(),
                },
                10_000,
            )
            .unwrap();
    }
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .unwrap();
    assert_eq!(
        PublicArchive::load(&store, 10_001).unwrap().entries().len(),
        1
    );
}
