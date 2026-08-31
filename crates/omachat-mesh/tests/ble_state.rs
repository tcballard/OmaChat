use omachat_mesh::ble::{ConnectionManager, LinkDirection, PhysicalLink};

#[test]
fn duplicate_links_choose_stable_direction_and_adapter_loss_resets() {
    let mut manager = ConnectionManager::default();
    let local = [1; 8];
    let remote = [2; 8];
    assert!(manager.register(
        local,
        remote,
        PhysicalLink {
            direction: LinkDirection::Peripheral,
            connected_at_ms: 1
        }
    ));
    assert!(manager.register(
        local,
        remote,
        PhysicalLink {
            direction: LinkDirection::Central,
            connected_at_ms: 2
        }
    ));
    assert_eq!(
        manager.link(&remote).unwrap().direction,
        LinkDirection::Central
    );
    assert!(!manager.register(
        local,
        remote,
        PhysicalLink {
            direction: LinkDirection::Peripheral,
            connected_at_ms: 3
        }
    ));
    let first = manager.disconnected(remote);
    let second = manager.disconnected(remote);
    assert!(second > first);
    manager.adapter_lost();
    assert_eq!(manager.adapter_generation(), 1);
    assert!(manager.link(&remote).is_none());
}
