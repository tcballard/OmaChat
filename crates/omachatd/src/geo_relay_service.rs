//! Opt-in pinned georelay routing. Each cell owns an isolated, bounded pool.

use crate::{CoreError, NostrHandle, NostrService};
use omachat_nostr::{
    event::SignedEvent,
    geochat::subscription_filter,
    georelay::{
        GeoRelayOverrideMode, GeoRelayOverrides, GeoRelaySelectionStatus, GeoRelaySelector,
    },
    pool::{PoolNotification, PoolPublishResult, RelayPoolError},
    relay::RelayHealth,
};
use omachat_proto::geohash::Geohash;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};

pub const MAX_GEO_CELLS: usize = 8;
const REFRESH: Duration = Duration::from_secs(30);
const RETRY_AFTER: Duration = Duration::from_secs(300);

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum GeoRelayMode {
    #[default]
    Supplement,
    Replace,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct GeoRelayConfig {
    pub mode: GeoRelayMode,
    pub overrides: Vec<String>,
}

impl GeoRelayConfig {
    pub(crate) fn validate(&self) -> Result<(), CoreError> {
        if self.overrides.len() > 10
            || (self.mode == GeoRelayMode::Replace && self.overrides.is_empty())
        {
            return Err(CoreError::InvalidConfig);
        }
        let mut seen = BTreeSet::new();
        for url in &self.overrides {
            if url.len() > 256 {
                return Err(CoreError::InvalidConfig);
            }
            if !seen.insert(crate::config::canonical_publication_url(url)?) {
                return Err(CoreError::InvalidConfig);
            }
        }
        Ok(())
    }

    fn overrides(&self) -> GeoRelayOverrides {
        GeoRelayOverrides {
            mode: match self.mode {
                GeoRelayMode::Supplement => GeoRelayOverrideMode::Supplement,
                GeoRelayMode::Replace => GeoRelayOverrideMode::Replace,
            },
            urls: self.overrides.clone(),
        }
    }
}

struct ActiveCell {
    handle: Option<NostrHandle>,
    status: GeoRelaySelectionStatus,
}

#[derive(Clone)]
pub struct GeoRelayHandle {
    cells: watch::Sender<BTreeSet<String>>,
    active: Arc<Mutex<BTreeMap<String, ActiveCell>>>,
    stop: watch::Sender<bool>,
    stopped: watch::Receiver<bool>,
}

impl GeoRelayHandle {
    pub fn set_cells(&self, cells: BTreeSet<String>) -> Result<(), CoreError> {
        validate_cells(&cells)?;
        if *self.stop.borrow() || *self.stopped.borrow() {
            return Err(CoreError::Subscription);
        }
        self.cells.send_replace(cells);
        Ok(())
    }

    pub fn status(&self) -> Value {
        let active = self.active.lock().expect("geo relay mutex poisoned");
        let cells = active.values().map(|cell| {
            let s = &cell.status;
            json!({"geohash": s.geohash, "compatibility_profile": s.compatibility_profile,
                "swift_snapshot_sha256": s.swift_snapshot_sha256, "android_snapshot_sha256": s.android_snapshot_sha256,
                "selected_relays": s.urls(), "skipped_unhealthy": s.skipped_unhealthy.iter().take(10).collect::<Vec<_>>(),
                "skipped_unhealthy_count": s.skipped_unhealthy.len(),
                "pool_active": cell.handle.is_some()})
        }).collect::<Vec<_>>();
        json!({"requested_cells": self.cells.borrow().iter().collect::<Vec<_>>(), "cells": cells, "stopped": *self.stop.borrow() || *self.stopped.borrow()})
    }

    pub async fn publish(
        &self,
        cell: &str,
        event: SignedEvent,
    ) -> Result<PoolPublishResult, RelayPoolError> {
        if *self.stop.borrow() || *self.stopped.borrow() || !self.cells.borrow().contains(cell) {
            return Err(RelayPoolError::InvalidConfig("geo cell is not active"));
        }
        let handle = self
            .active
            .lock()
            .expect("geo relay mutex poisoned")
            .get(cell)
            .and_then(|entry| entry.handle.clone())
            .ok_or(RelayPoolError::InvalidConfig(
                "geo cell has no ready relay pool",
            ))?;
        handle.publish(event).await
    }

    pub async fn quiesce(&self) {
        self.stop.send_replace(true);
        let mut stopped = self.stopped.clone();
        while !*stopped.borrow() {
            if stopped.changed().await.is_err() {
                break;
            }
        }
    }
}

pub struct GeoRelayService {
    handle: GeoRelayHandle,
    task: JoinHandle<()>,
}

impl GeoRelayService {
    pub fn spawn(
        config: GeoRelayConfig,
        cells: BTreeSet<String>,
        inbound: mpsc::Sender<PoolNotification>,
    ) -> Result<Self, CoreError> {
        config.validate()?;
        validate_cells(&cells)?;
        let selector = GeoRelaySelector::pinned().map_err(|_| CoreError::InvalidConfig)?;
        let (cells_sender, cells_receiver) = watch::channel(cells);
        let (stop, stop_receiver) = watch::channel(false);
        let (stopped_sender, stopped) = watch::channel(false);
        let active = Arc::new(Mutex::new(BTreeMap::new()));
        let handle = GeoRelayHandle {
            cells: cells_sender,
            active: active.clone(),
            stop,
            stopped,
        };
        let task = tokio::spawn(run(
            config,
            selector,
            cells_receiver,
            inbound,
            active,
            stop_receiver,
            stopped_sender,
        ));
        Ok(Self { handle, task })
    }

    pub fn handle(&self) -> GeoRelayHandle {
        self.handle.clone()
    }

    pub async fn shutdown(self) {
        self.handle.quiesce().await;
    }
}

impl Drop for GeoRelayService {
    fn drop(&mut self) {
        self.handle.stop.send_replace(true);
        self.task.abort();
    }
}

fn validate_cells(cells: &BTreeSet<String>) -> Result<(), CoreError> {
    if cells.len() > MAX_GEO_CELLS {
        return Err(CoreError::InvalidConfig);
    }
    for cell in cells {
        Geohash::parse(cell).map_err(|_| CoreError::InvalidGeohash)?;
    }
    Ok(())
}

struct PoolOwner {
    urls: Vec<String>,
    service: NostrService,
}

async fn run(
    config: GeoRelayConfig,
    selector: GeoRelaySelector,
    mut cells: watch::Receiver<BTreeSet<String>>,
    inbound: mpsc::Sender<PoolNotification>,
    active: Arc<Mutex<BTreeMap<String, ActiveCell>>>,
    mut stop: watch::Receiver<bool>,
    stopped: watch::Sender<bool>,
) {
    let mut pools = BTreeMap::<String, PoolOwner>::new();
    // At most the two frozen directories plus ten explicit overrides per cell.
    let mut failed = BTreeMap::<String, HashMap<String, Instant>>::new();
    let mut tick = tokio::time::interval(REFRESH);
    loop {
        if *stop.borrow() {
            break;
        }
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            changed = cells.changed() => { if changed.is_err() { break; } },
            _ = tick.tick() => {},
        }
        let desired = cells.borrow_and_update().clone();
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            _ = reconcile(&config, &selector, &desired, &inbound, &active, &mut pools, &mut failed) => {},
        }
    }
    active.lock().expect("geo relay mutex poisoned").clear();
    for (_, pool) in pools {
        let _ = pool.service.shutdown().await;
    }
    stopped.send_replace(true);
}

async fn reconcile(
    config: &GeoRelayConfig,
    selector: &GeoRelaySelector,
    desired: &BTreeSet<String>,
    inbound: &mpsc::Sender<PoolNotification>,
    active: &Arc<Mutex<BTreeMap<String, ActiveCell>>>,
    pools: &mut BTreeMap<String, PoolOwner>,
    failed: &mut BTreeMap<String, HashMap<String, Instant>>,
) {
    let removed = pools
        .keys()
        .filter(|cell| !desired.contains(*cell))
        .cloned()
        .collect::<Vec<_>>();
    active
        .lock()
        .expect("geo relay mutex poisoned")
        .retain(|cell, _| desired.contains(cell));
    failed.retain(|cell, _| desired.contains(cell));
    for cell in removed {
        if let Some(pool) = pools.remove(&cell) {
            let _ = pool.service.shutdown().await;
        }
    }
    for cell in desired {
        let recent = failed.entry(cell.clone()).or_default();
        recent.retain(|_, at| at.elapsed() < RETRY_AFTER);
        if let Some(pool) = pools.get(cell) {
            for (url, health) in pool.urls.iter().zip(pool.service.handle().health()) {
                if matches!(health, RelayHealth::Disconnected | RelayHealth::Stopped) {
                    recent.insert(url.clone(), Instant::now());
                } else if health == RelayHealth::Connected {
                    recent.remove(url);
                }
            }
        }
        let health = recent
            .keys()
            .map(|url| (url.clone(), RelayHealth::Disconnected))
            .collect();
        let Ok(status) = selector.select(
            &Geohash::parse(cell).expect("validated cell"),
            &config.overrides(),
            &health,
        ) else {
            continue;
        };
        let urls = status
            .urls()
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let changed = pools.get(cell).is_none_or(|pool| pool.urls != urls);
        if changed {
            active
                .lock()
                .expect("geo relay mutex poisoned")
                .remove(cell);
            if let Some(old) = pools.remove(cell) {
                let _ = old.service.shutdown().await;
            }
            if !urls.is_empty() {
                // Apply the daemon's fail-closed TLS policy to snapshot output too.
                if urls
                    .iter()
                    .any(|url| crate::config::canonical_publication_url(url).is_err())
                {
                    continue;
                }
                if let Ok(service) = NostrService::spawn_geo(&urls, cell.clone(), inbound.clone()) {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs());
                    let filter = subscription_filter(
                        &Geohash::parse(cell).expect("validated cell"),
                        now.saturating_sub(21600),
                        1000,
                    );
                    // The pool stores subscriptions while disconnected and replays on connect.
                    let _ = service
                        .handle()
                        .subscribe_results("omachat-geo-v1".into(), vec![filter])
                        .await;
                    pools.insert(cell.clone(), PoolOwner { urls, service });
                }
            }
        }
        let handle = pools.get(cell).map(|pool| pool.service.handle());
        active
            .lock()
            .expect("geo relay mutex poisoned")
            .insert(cell.clone(), ActiveCell { handle, status });
    }
}
