use omachat_store::{
    CourierPool, CourierPoolError, CourierTier, Handover, RequestedProvider, SealedStore,
};
use tempfile::tempdir;

#[tokio::test]
async fn quotas_reserve_capacity_and_restart_preserves_spray_budget() {
    let temporary = tempdir().expect("temporary directory");
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .expect("store");
    let mut pool = CourierPool::load(&store, 0).expect("pool");
    for index in 0..20 {
        pool.deposit(
            format!("v{index}"),
            format!("verified-{index}"),
            "00".repeat(16),
            vec![index as u8; 10],
            CourierTier::Verified,
            false,
            true,
            index,
            10_000,
            4,
        )
        .expect("verified slot");
    }
    assert!(matches!(
        pool.deposit(
            "overflow".into(),
            "another".into(),
            "00".repeat(16),
            vec![1],
            CourierTier::Verified,
            false,
            true,
            30,
            10_000,
            4
        ),
        Err(CourierPoolError::Quota)
    ));
    for index in 0..20 {
        pool.deposit(
            format!("f{index}"),
            format!("favorite-{index}"),
            "11".repeat(16),
            vec![index as u8; 10],
            CourierTier::Favorite,
            true,
            false,
            100 + index,
            10_000,
            4,
        )
        .expect("favorite reservation");
    }
    assert_eq!(pool.entries().len(), 40);
    drop(pool);

    let mut reopened = CourierPool::load(&store, 200).expect("reopen");
    let Handover::Spray {
        transferred_copies,
        retained_copies,
        ..
    } = reopened
        .handover("f0", "carrier-a", false, false, 1_000)
        .expect("spray")
    else {
        panic!("spray expected")
    };
    assert_eq!(transferred_copies + retained_copies, 4);
    assert_eq!(
        reopened
            .handover("f0", "carrier-a", false, false, 2_000)
            .expect("duplicate"),
        Handover::Wait
    );
}

#[tokio::test]
async fn direct_delivery_removes_exactly_once_and_backing_is_sealed() {
    let temporary = tempdir().expect("temporary directory");
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .expect("store");
    let mut pool = CourierPool::load(&store, 0).expect("pool");
    pool.deposit(
        "id".into(),
        "friend".into(),
        "22".repeat(16),
        b"private courier plaintext".to_vec(),
        CourierTier::Favorite,
        true,
        false,
        0,
        10_000,
        4,
    )
    .expect("deposit");
    assert!(matches!(
        pool.handover("id", "recipient", true, false, 1)
            .expect("deliver"),
        Handover::DirectDelivery { .. }
    ));
    assert!(matches!(
        pool.handover("id", "recipient", true, false, 2),
        Err(CourierPoolError::NotFound)
    ));
    let backing = std::fs::read(temporary.path().join("records/courier-pool-v1")).expect("backing");
    assert!(
        !backing
            .windows(25)
            .any(|window| window == b"private courier plaintext")
    );
}
