//! BlueR central/peripheral runtime and deterministic dual-link ownership.

use bluer::{
    Adapter, AdapterEvent, Address, DiscoveryFilter, DiscoveryTransport,
    adv::{Advertisement, AdvertisementHandle},
    gatt::{
        CharacteristicReader, CharacteristicWriter,
        local::{
            Application, ApplicationHandle, Characteristic, CharacteristicNotify,
            CharacteristicNotifyMethod, CharacteristicRead, CharacteristicWrite,
            CharacteristicWriteMethod, Service,
        },
        remote::Characteristic as RemoteCharacteristic,
    },
};
use futures::{FutureExt, StreamExt, pin_mut};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, broadcast, mpsc},
    time::timeout,
};

pub const SERVICE_UUID: bluer::Uuid = bluer::Uuid::from_u128(0xF47B5E2D4A9E4C5A9B3F8E1D2C3A4B5C);
pub const CHARACTERISTIC_UUID: bluer::Uuid =
    bluer::Uuid::from_u128(0xA1B2C3D4E5F64A5B8C9D0E1F2A3B4C5D);

pub struct BleRuntime {
    adapter: Adapter,
    _application: ApplicationHandle,
    _advertisement: AdvertisementHandle,
    notifications: broadcast::Sender<Vec<u8>>,
}

impl BleRuntime {
    pub async fn start(
        adapter_name: Option<&str>,
        inbound: mpsc::Sender<Vec<u8>>,
    ) -> Result<Self, BleError> {
        let session = bluer::Session::new().await?;
        let adapter = match adapter_name {
            Some(name) => session.adapter(name)?,
            None => session.default_adapter().await?,
        };
        adapter.set_powered(true).await?;
        if adapter.supported_advertising_instances().await? == 0 {
            return Err(BleError::AdvertisingUnavailable);
        }
        let (notifications, _) = broadcast::channel(64);
        let application = adapter
            .serve_gatt_application(local_application(inbound, notifications.clone()))
            .await?;
        let advertisement = adapter
            .advertise(Advertisement {
                service_uuids: HashSet::from([SERVICE_UUID]).into_iter().collect(),
                discoverable: Some(true),
                ..Default::default()
            })
            .await?;
        adapter
            .set_discovery_filter(DiscoveryFilter {
                uuids: HashSet::from([SERVICE_UUID]),
                transport: DiscoveryTransport::Le,
                ..Default::default()
            })
            .await?;
        Ok(Self {
            adapter,
            _application: application,
            _advertisement: advertisement,
            notifications,
        })
    }

    pub fn notify(&self, packet: Vec<u8>) -> Result<usize, BleError> {
        if packet.is_empty() {
            return Err(BleError::EmptyPacket);
        }
        self.notifications
            .send(packet)
            .map_err(|_| BleError::NoSubscribers)
    }

    pub async fn discover_and_connect(&self, deadline: Duration) -> Result<BleLink, BleError> {
        let discovery = self.adapter.discover_devices().await?;
        pin_mut!(discovery);
        let device = timeout(deadline, async {
            while let Some(event) = discovery.next().await {
                if let AdapterEvent::DeviceAdded(address) = event {
                    let device = self.adapter.device(address)?;
                    if device
                        .uuids()
                        .await?
                        .is_some_and(|ids| ids.contains(&SERVICE_UUID))
                    {
                        return Ok(device);
                    }
                }
            }
            Err(BleError::DiscoveryEnded)
        })
        .await
        .map_err(|_| BleError::Timeout)??;
        if !device.is_connected().await? {
            device.connect().await?;
        }
        let characteristic = find_characteristic(&device).await?;
        Ok(BleLink {
            address: device.address(),
            reader: characteristic.notify_io().await?,
            writer: characteristic.write_io().await?,
        })
    }
}

pub struct BleLink {
    pub address: Address,
    reader: CharacteristicReader,
    writer: CharacteristicWriter,
}
impl BleLink {
    #[must_use]
    pub fn receive_mtu(&self) -> usize {
        self.reader.mtu()
    }
    #[must_use]
    pub fn write_mtu(&self) -> usize {
        self.writer.mtu()
    }
    pub async fn send(&mut self, bytes: &[u8]) -> Result<(), BleError> {
        if bytes.is_empty() || bytes.len() > self.writer.mtu() {
            return Err(BleError::PacketTooLarge);
        }
        self.writer.write_all(bytes).await?;
        Ok(())
    }
    pub async fn receive(&mut self) -> Result<Vec<u8>, BleError> {
        let mut bytes = vec![0; self.reader.mtu()];
        let count = self.reader.read(&mut bytes).await?;
        if count == 0 {
            return Err(BleError::Disconnected);
        }
        bytes.truncate(count);
        Ok(bytes)
    }
}

fn local_application(
    inbound: mpsc::Sender<Vec<u8>>,
    notifications: broadcast::Sender<Vec<u8>>,
) -> Application {
    let last_value = Arc::new(Mutex::new(Vec::new()));
    let read_value = last_value.clone();
    let write_value = last_value;
    Application {
        services: vec![Service {
            uuid: SERVICE_UUID,
            primary: true,
            characteristics: vec![Characteristic {
                uuid: CHARACTERISTIC_UUID,
                read: Some(CharacteristicRead {
                    read: true,
                    fun: Box::new(move |_| {
                        let value = read_value.clone();
                        async move { Ok(value.lock().await.clone()) }.boxed()
                    }),
                    ..Default::default()
                }),
                write: Some(CharacteristicWrite {
                    write: true,
                    write_without_response: true,
                    method: CharacteristicWriteMethod::Fun(Box::new(move |value, _| {
                        let inbound = inbound.clone();
                        let last = write_value.clone();
                        async move {
                            *last.lock().await = value.clone();
                            inbound
                                .send(value)
                                .await
                                .map_err(|_| bluer::gatt::local::ReqError::Failed)
                        }
                        .boxed()
                    })),
                    ..Default::default()
                }),
                notify: Some(CharacteristicNotify {
                    notify: true,
                    method: CharacteristicNotifyMethod::Fun(Box::new(move |mut notifier| {
                        let mut receiver = notifications.subscribe();
                        async move {
                            tokio::spawn(async move {
                                while !notifier.is_stopped() {
                                    let Ok(packet) = receiver.recv().await else {
                                        break;
                                    };
                                    if notifier.notify(packet).await.is_err() {
                                        break;
                                    }
                                }
                            });
                        }
                        .boxed()
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    }
}

async fn find_characteristic(device: &bluer::Device) -> Result<RemoteCharacteristic, BleError> {
    for service in device.services().await? {
        if service.uuid().await? == SERVICE_UUID {
            for characteristic in service.characteristics().await? {
                if characteristic.uuid().await? == CHARACTERISTIC_UUID {
                    return Ok(characteristic);
                }
            }
        }
    }
    Err(BleError::MissingCharacteristic)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkDirection {
    Central,
    Peripheral,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalLink {
    pub direction: LinkDirection,
    pub connected_at_ms: u64,
}
#[derive(Default)]
pub struct ConnectionManager {
    links: HashMap<[u8; 8], PhysicalLink>,
    adapter_generation: u64,
    failures: HashMap<[u8; 8], u8>,
}
impl ConnectionManager {
    pub fn register(
        &mut self,
        local_peer: [u8; 8],
        remote_peer: [u8; 8],
        proposed: PhysicalLink,
    ) -> bool {
        let preferred = if local_peer < remote_peer {
            LinkDirection::Central
        } else {
            LinkDirection::Peripheral
        };
        match self.links.get(&remote_peer) {
            None => {
                self.links.insert(remote_peer, proposed);
                true
            }
            Some(existing)
                if proposed.direction == preferred && existing.direction != preferred =>
            {
                self.links.insert(remote_peer, proposed);
                true
            }
            _ => false,
        }
    }
    pub fn disconnected(&mut self, peer: [u8; 8]) -> Duration {
        self.links.remove(&peer);
        let failures = self.failures.entry(peer).or_default();
        *failures = failures.saturating_add(1).min(8);
        Duration::from_millis(250_u64.saturating_mul(1 << *failures))
    }
    pub fn adapter_lost(&mut self) {
        self.links.clear();
        self.adapter_generation = self.adapter_generation.saturating_add(1);
    }
    #[must_use]
    pub fn adapter_generation(&self) -> u64 {
        self.adapter_generation
    }
    #[must_use]
    pub fn link(&self, peer: &[u8; 8]) -> Option<PhysicalLink> {
        self.links.get(peer).copied()
    }
}

#[derive(Debug)]
pub enum BleError {
    Bluer(bluer::Error),
    Io(std::io::Error),
    AdvertisingUnavailable,
    DiscoveryEnded,
    Timeout,
    MissingCharacteristic,
    EmptyPacket,
    PacketTooLarge,
    NoSubscribers,
    Disconnected,
}
impl From<bluer::Error> for BleError {
    fn from(value: bluer::Error) -> Self {
        Self::Bluer(value)
    }
}
impl From<std::io::Error> for BleError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl fmt::Display for BleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bluetooth transport error: {self:?}")
    }
}
impl Error for BleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Bluer(e) => Some(e),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}
