use bluer::{
    AdapterEvent, Address, DiscoveryFilter, DiscoveryTransport, Uuid,
    adv::Advertisement,
    gatt::{
        local::{
            Application, Characteristic, CharacteristicNotify, CharacteristicNotifyMethod,
            CharacteristicRead, CharacteristicWrite, CharacteristicWriteMethod, Service,
        },
        remote::Characteristic as RemoteCharacteristic,
    },
};
use futures::{FutureExt, StreamExt, pin_mut};
use serde::Serialize;
use std::{
    collections::HashSet,
    env,
    error::Error,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
    time::{sleep, timeout},
};

type ProbeError = Box<dyn Error + Send + Sync>;
const SERVICE_UUID: Uuid = Uuid::from_u128(0xF47B5E2D4A9E4C5A9B3F8E1D2C3A4B5C);
const CHARACTERISTIC_UUID: Uuid = Uuid::from_u128(0xA1B2C3D4E5F64A5B8C9D0E1F2A3B4C5D);
const QUALIFICATION_SECONDS: u64 = 30 * 60;

struct Arguments {
    adapter_name: Option<String>,
    peer_address: Address,
    duration: Duration,
    output: PathBuf,
}

#[derive(Clone, Debug, Default, Serialize)]
struct TrafficMetrics {
    local_reads: u64,
    local_writes: u64,
    local_notifications: u64,
    remote_writes: u64,
    remote_notifications: u64,
    local_write_mtus: Vec<u16>,
    remote_write_mtu: Option<usize>,
    remote_notify_mtu: Option<usize>,
}

#[derive(Debug, Serialize)]
struct CapabilityReport {
    schema_version: u32,
    result: &'static str,
    adapter_name: String,
    adapter_address: String,
    peer_address: String,
    duration_seconds: u64,
    powered: bool,
    discoverable: bool,
    pairable: bool,
    supported_advertising_instances: u8,
    active_advertising_instances_before: u8,
    supported_advertising_system_includes: String,
    supported_advertising_secondary_channels: String,
    supported_advertising_capabilities: String,
    supported_advertising_features: String,
    local_gatt_registered: bool,
    connectable_advertising_registered: bool,
    scan_active_during_advertising: bool,
    inbound_and_outbound_links: bool,
    traffic: TrafficMetrics,
    eatt_observation: &'static str,
    qualification: &'static str,
}

#[derive(Debug, Serialize)]
struct FailureReport {
    schema_version: u32,
    result: &'static str,
    error: String,
    next_action: &'static str,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let arguments = match parse_arguments() {
        Ok(arguments) => arguments,
        Err(error) => {
            eprintln!("BlueR dual-role probe argument error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let output = arguments.output.clone();
    match run(arguments).await {
        Ok(report) => match write_report(&output, &report) {
            Ok(()) => {
                println!("wrote BlueR qualification report to {}", output.display());
                if report.result == "passed" {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                }
            }
            Err(error) => {
                eprintln!("failed to write BlueR report: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            let failure = FailureReport {
                schema_version: 1,
                result: "failed",
                error: error.to_string(),
                next_action: "inspect BlueZ D-Bus policy, adapter power/state, peer address, and service discovery; do not add root or a broad polkit rule",
            };
            if let Err(write_error) = write_report(&output, &failure) {
                eprintln!("failed to write BlueR failure report: {write_error}");
            }
            eprintln!("BlueR dual-role probe failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_arguments() -> Result<Arguments, ProbeError> {
    let mut adapter_name = None;
    let mut peer_address = None;
    let mut duration = Duration::from_secs(QUALIFICATION_SECONDS);
    let mut output = None;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--adapter" => adapter_name = arguments.next(),
            "--peer" => {
                peer_address = Some(Address::from_str(
                    &arguments.next().ok_or("--peer requires an address")?,
                )?)
            }
            "--duration-seconds" => {
                duration = Duration::from_secs(
                    arguments
                        .next()
                        .ok_or("--duration-seconds requires a value")?
                        .parse()?,
                )
            }
            "--output" => output = Some(arguments.next().ok_or("--output requires a path")?.into()),
            "--help" | "-h" => {
                println!(
                    "usage: bluer_dual_role_probe --peer AA:BB:CC:DD:EE:FF --output report.json [--adapter hci0] [--duration-seconds 1800]"
                );
                return Err("help requested".into());
            }
            _ => return Err(format!("unknown argument {argument}").into()),
        }
    }
    Ok(Arguments {
        adapter_name,
        peer_address: peer_address.ok_or("--peer is required")?,
        duration,
        output: output.ok_or("--output is required")?,
    })
}

async fn run(arguments: Arguments) -> Result<CapabilityReport, ProbeError> {
    let session = bluer::Session::new().await?;
    let adapter = match arguments.adapter_name.as_deref() {
        Some(name) => session.adapter(name)?,
        None => session.default_adapter().await?,
    };
    adapter.set_powered(true).await?;
    let adapter_name = adapter.name().to_owned();
    let adapter_address = adapter.address().await?.to_string();
    let active_advertising_instances_before = adapter.active_advertising_instances().await?;
    let supported_advertising_instances = adapter.supported_advertising_instances().await?;
    if supported_advertising_instances == 0 {
        return Err("adapter reports zero supported LE advertising instances".into());
    }

    let metrics = Arc::new(Mutex::new(TrafficMetrics::default()));
    let (application, advertised_value) = local_application(metrics.clone());
    let application_handle = adapter.serve_gatt_application(application).await?;
    let advertisement_handle = adapter
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
    let discovery = adapter.discover_devices().await?;
    pin_mut!(discovery);
    let peer = timeout(Duration::from_secs(60), async {
        while let Some(event) = discovery.next().await {
            if matches!(event, AdapterEvent::DeviceAdded(address) if address == arguments.peer_address) {
                return Ok::<_, ProbeError>(adapter.device(arguments.peer_address)?);
            }
        }
        Err("discovery ended before the named peer appeared".into())
    }).await.map_err(|_| "peer was not discovered within 60 seconds")??;
    if !peer.is_connected().await? {
        peer.connect().await?;
    }
    sleep(Duration::from_secs(2)).await;
    let characteristic = find_characteristic(&peer).await?;
    let mut notifier = characteristic.notify_io().await?;
    let mut writer = characteristic.write_io().await?;
    {
        let mut locked = metrics.lock().await;
        locked.remote_notify_mtu = Some(notifier.mtu());
        locked.remote_write_mtu = Some(writer.mtu());
    }
    let started = Instant::now();
    let mut counter = 0_u64;
    while started.elapsed() < arguments.duration {
        counter += 1;
        let mut payload = b"omachat-g0-dual-role".to_vec();
        payload.extend_from_slice(&counter.to_be_bytes());
        writer.write_all(&payload).await?;
        metrics.lock().await.remote_writes += 1;
        let mut received = vec![0_u8; notifier.mtu()];
        let read = timeout(Duration::from_secs(5), notifier.read(&mut received))
            .await
            .map_err(|_| "peer notification timed out")??;
        if read == 0 {
            return Err("peer notification stream closed".into());
        }
        metrics.lock().await.remote_notifications += 1;
        sleep(Duration::from_secs(1)).await;
    }
    let duration_seconds = started.elapsed().as_secs();
    let traffic = metrics.lock().await.clone();
    let inbound_and_outbound_links = traffic.local_writes > 0
        && traffic.local_notifications > 0
        && traffic.remote_writes > 0
        && traffic.remote_notifications > 0;
    let qualified = duration_seconds >= QUALIFICATION_SECONDS && inbound_and_outbound_links;
    drop(advertised_value);
    drop(writer);
    drop(notifier);
    drop(application_handle);
    drop(advertisement_handle);
    let _ = peer.disconnect().await;
    Ok(CapabilityReport {
        schema_version: 1,
        result: if qualified { "passed" } else { "incomplete" },
        adapter_name,
        adapter_address,
        peer_address: arguments.peer_address.to_string(),
        duration_seconds,
        powered: adapter.is_powered().await?,
        discoverable: adapter.is_discoverable().await?,
        pairable: adapter.is_pairable().await?,
        supported_advertising_instances,
        active_advertising_instances_before,
        supported_advertising_system_includes: format!(
            "{:?}",
            adapter.supported_advertising_system_includes().await?
        ),
        supported_advertising_secondary_channels: format!(
            "{:?}",
            adapter.supported_advertising_secondary_channels().await?
        ),
        supported_advertising_capabilities: format!(
            "{:?}",
            adapter.supported_advertising_capabilities().await?
        ),
        supported_advertising_features: format!(
            "{:?}",
            adapter.supported_advertising_features().await?
        ),
        local_gatt_registered: true,
        connectable_advertising_registered: true,
        scan_active_during_advertising: true,
        inbound_and_outbound_links,
        traffic,
        eatt_observation: "BlueR 0.17.4 does not expose bearer count; parallel write/notify acquisition is recorded here and btmon must record whether BlueZ negotiated EATT",
        qualification: if qualified {
            "thirty-minute-dual-role-pass"
        } else {
            "requires-thirty-minutes-and-bidirectional-traffic"
        },
    })
}

fn local_application(metrics: Arc<Mutex<TrafficMetrics>>) -> (Application, Arc<Mutex<Vec<u8>>>) {
    let value = Arc::new(Mutex::new(b"omachat-g0-ready".to_vec()));
    let value_read = value.clone();
    let value_write = value.clone();
    let value_notify = value.clone();
    let read_metrics = metrics.clone();
    let write_metrics = metrics.clone();
    let notify_metrics = metrics;
    let application = Application {
        services: vec![Service {
            uuid: SERVICE_UUID,
            primary: true,
            characteristics: vec![Characteristic {
                uuid: CHARACTERISTIC_UUID,
                read: Some(CharacteristicRead {
                    read: true,
                    fun: Box::new(move |_| {
                        let value = value_read.clone();
                        let metrics = read_metrics.clone();
                        async move {
                            metrics.lock().await.local_reads += 1;
                            Ok(value.lock().await.clone())
                        }
                        .boxed()
                    }),
                    ..Default::default()
                }),
                write: Some(CharacteristicWrite {
                    write: true,
                    write_without_response: true,
                    method: CharacteristicWriteMethod::Fun(Box::new(move |new_value, request| {
                        let value = value_write.clone();
                        let metrics = write_metrics.clone();
                        async move {
                            *value.lock().await = new_value;
                            let mut locked = metrics.lock().await;
                            locked.local_writes += 1;
                            if !locked.local_write_mtus.contains(&request.mtu) {
                                locked.local_write_mtus.push(request.mtu);
                            }
                            Ok(())
                        }
                        .boxed()
                    })),
                    ..Default::default()
                }),
                notify: Some(CharacteristicNotify {
                    notify: true,
                    method: CharacteristicNotifyMethod::Fun(Box::new(move |mut notifier| {
                        let value = value_notify.clone();
                        let metrics = notify_metrics.clone();
                        async move {
                            tokio::spawn(async move {
                                while !notifier.is_stopped() {
                                    if notifier.notify(value.lock().await.clone()).await.is_err() {
                                        break;
                                    }
                                    metrics.lock().await.local_notifications += 1;
                                    sleep(Duration::from_millis(250)).await;
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
    };
    (application, value)
}

async fn find_characteristic(peer: &bluer::Device) -> Result<RemoteCharacteristic, ProbeError> {
    for service in peer.services().await? {
        if service.uuid().await? != SERVICE_UUID {
            continue;
        }
        for characteristic in service.characteristics().await? {
            if characteristic.uuid().await? == CHARACTERISTIC_UUID {
                return Ok(characteristic);
            }
        }
    }
    Err("peer does not expose the pinned OmaChat service and characteristic".into())
}

fn write_report(path: &Path, report: &impl Serialize) -> Result<(), ProbeError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(report)?)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}
