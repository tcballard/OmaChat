//! Bounded loopback host runtime for the authoritative registry service.
//!
//! TLS termination, secret provisioning, and process policy deliberately remain
//! outside this library. A production process should expose this loopback-only
//! listener through a separately configured TLS reverse proxy.

mod process;

pub use process::{
    REGISTRYD_HELP, RegistryProcessCommand, RegistryProcessConfig, RegistryProcessConfigError,
    load_registry_signing_seed, parse_registry_process_args,
};

use omachat_registry_transport::{
    PendingRegistryWebSocketRequest, RegistryService, RegistryServiceError,
    RegistryWebSocketServerError, accept_registry_websocket_request,
};
use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    future::Future,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    task::{JoinError, JoinSet},
    time::timeout,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryHostLimits {
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    pub request_admission_timeout: Duration,
    pub shutdown_grace: Duration,
}

impl Default for RegistryHostLimits {
    fn default() -> Self {
        Self {
            max_connections: 128,
            max_connections_per_ip: 8,
            request_admission_timeout: Duration::from_secs(10),
            shutdown_grace: Duration::from_secs(10),
        }
    }
}

impl RegistryHostLimits {
    pub fn validate(self) -> Result<Self, RegistryHostError> {
        if self.max_connections == 0
            || self.max_connections_per_ip == 0
            || self.max_connections_per_ip > self.max_connections
            || self.request_admission_timeout.is_zero()
            || self.shutdown_grace.is_zero()
        {
            return Err(RegistryHostError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RegistryHostReport {
    pub admitted_connections: u64,
    pub completed_responses: u64,
    pub rejected_global_limit: u64,
    pub rejected_per_ip_limit: u64,
    pub admission_timeouts: u64,
    pub rejected_websockets: u64,
    pub rejected_protocol_requests: u64,
    pub response_failures: u64,
    pub forced_shutdown: bool,
    pub aborted_connections: usize,
}

type PendingRequest = PendingRegistryWebSocketRequest<TcpStream>;
type AdmissionResult = (IpAddr, Result<PendingRequest, AdmissionFailure>);
type ResponseResult = (IpAddr, Result<(), RegistryWebSocketServerError>);

#[derive(Debug)]
enum AdmissionFailure {
    Timeout,
    WebSocket(RegistryWebSocketServerError),
}

/// Run a bounded registry host on an already bound loopback listener.
///
/// Handshakes and request reads run concurrently without registry access. Once
/// admitted, each request is applied synchronously to preserve the state
/// machine's single authoritative order, then its response is flushed
/// concurrently. Shutdown stops acceptance and drains within the configured
/// grace period.
pub async fn run_registry_host<C, S>(
    listener: TcpListener,
    service: &mut RegistryService<'_>,
    limits: RegistryHostLimits,
    mut accepted_at: C,
    shutdown: S,
) -> Result<RegistryHostReport, RegistryHostError>
where
    C: FnMut() -> Result<u64, RegistryHostError>,
    S: Future<Output = ()>,
{
    let limits = limits.validate()?;
    let local_address = listener.local_addr().map_err(RegistryHostError::Listener)?;
    if !local_address.ip().is_loopback() {
        return Err(RegistryHostError::NonLoopbackListener(local_address));
    }

    let mut admissions: JoinSet<AdmissionResult> = JoinSet::new();
    let mut responses: JoinSet<ResponseResult> = JoinSet::new();
    let mut active_by_ip: BTreeMap<IpAddr, usize> = BTreeMap::new();
    let mut active_total = 0_usize;
    let mut report = RegistryHostReport::default();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, peer) = accepted.map_err(RegistryHostError::Listener)?;
                let ip = peer.ip();
                if active_total >= limits.max_connections {
                    report.rejected_global_limit += 1;
                    continue;
                }
                if active_by_ip.get(&ip).copied().unwrap_or(0)
                    >= limits.max_connections_per_ip
                {
                    report.rejected_per_ip_limit += 1;
                    continue;
                }
                active_total += 1;
                *active_by_ip.entry(ip).or_default() += 1;
                report.admitted_connections += 1;
                let admission_timeout = limits.request_admission_timeout;
                admissions.spawn(async move {
                    let result = match timeout(
                        admission_timeout,
                        accept_registry_websocket_request(stream),
                    )
                    .await
                    {
                        Ok(result) => result.map_err(AdmissionFailure::WebSocket),
                        Err(_) => Err(AdmissionFailure::Timeout),
                    };
                    (ip, result)
                });
            }
            joined = admissions.join_next(), if !admissions.is_empty() => {
                process_admission(
                    joined.expect("non-empty admission set must yield a result"),
                    service,
                    &mut accepted_at,
                    &mut responses,
                    &mut active_by_ip,
                    &mut active_total,
                    &mut report,
                )?;
            }
            joined = responses.join_next(), if !responses.is_empty() => {
                process_response(
                    joined.expect("non-empty response set must yield a result"),
                    &mut active_by_ip,
                    &mut active_total,
                    &mut report,
                )?;
            }
        }
    }

    let drain = async {
        while !admissions.is_empty() || !responses.is_empty() {
            tokio::select! {
                joined = admissions.join_next(), if !admissions.is_empty() => {
                    process_admission(
                        joined.expect("non-empty admission set must yield a result"),
                        service,
                        &mut accepted_at,
                        &mut responses,
                        &mut active_by_ip,
                        &mut active_total,
                        &mut report,
                    )?;
                }
                joined = responses.join_next(), if !responses.is_empty() => {
                    process_response(
                        joined.expect("non-empty response set must yield a result"),
                        &mut active_by_ip,
                        &mut active_total,
                        &mut report,
                    )?;
                }
            }
        }
        Ok::<(), RegistryHostError>(())
    };
    match timeout(limits.shutdown_grace, drain).await {
        Ok(result) => result?,
        Err(_) => {
            report.forced_shutdown = true;
            report.aborted_connections = active_total;
            admissions.abort_all();
            responses.abort_all();
        }
    }
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn process_admission<C>(
    joined: Result<AdmissionResult, JoinError>,
    service: &mut RegistryService<'_>,
    accepted_at: &mut C,
    responses: &mut JoinSet<ResponseResult>,
    active_by_ip: &mut BTreeMap<IpAddr, usize>,
    active_total: &mut usize,
    report: &mut RegistryHostReport,
) -> Result<(), RegistryHostError>
where
    C: FnMut() -> Result<u64, RegistryHostError>,
{
    let (ip, result) = joined.map_err(RegistryHostError::Task)?;
    match result {
        Ok(pending) => match service.handle(pending.request(), accepted_at()?) {
            Ok(response) => {
                responses.spawn(async move { (ip, pending.respond(response).await) });
            }
            Err(RegistryServiceError::Protocol(_)) => {
                report.rejected_protocol_requests += 1;
                release_connection(ip, active_by_ip, active_total)?;
            }
            Err(error) => return Err(RegistryHostError::Service(error)),
        },
        Err(AdmissionFailure::Timeout) => {
            report.admission_timeouts += 1;
            release_connection(ip, active_by_ip, active_total)?;
        }
        Err(AdmissionFailure::WebSocket(error)) => {
            let _ = error;
            report.rejected_websockets += 1;
            release_connection(ip, active_by_ip, active_total)?;
        }
    }
    Ok(())
}

fn process_response(
    joined: Result<ResponseResult, JoinError>,
    active_by_ip: &mut BTreeMap<IpAddr, usize>,
    active_total: &mut usize,
    report: &mut RegistryHostReport,
) -> Result<(), RegistryHostError> {
    let (ip, result) = joined.map_err(RegistryHostError::Task)?;
    match result {
        Ok(()) => report.completed_responses += 1,
        Err(_) => report.response_failures += 1,
    }
    release_connection(ip, active_by_ip, active_total)
}

fn release_connection(
    ip: IpAddr,
    active_by_ip: &mut BTreeMap<IpAddr, usize>,
    active_total: &mut usize,
) -> Result<(), RegistryHostError> {
    let count = active_by_ip
        .get_mut(&ip)
        .ok_or(RegistryHostError::InvalidRuntimeState)?;
    *count = count
        .checked_sub(1)
        .ok_or(RegistryHostError::InvalidRuntimeState)?;
    if *count == 0 {
        active_by_ip.remove(&ip);
    }
    *active_total = active_total
        .checked_sub(1)
        .ok_or(RegistryHostError::InvalidRuntimeState)?;
    Ok(())
}

#[derive(Debug)]
pub enum RegistryHostError {
    InvalidLimits,
    NonLoopbackListener(SocketAddr),
    Listener(std::io::Error),
    Service(RegistryServiceError),
    Task(JoinError),
    ClockBeforeUnixEpoch,
    InvalidRuntimeState,
}

impl fmt::Display for RegistryHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("registry host limits are invalid"),
            Self::NonLoopbackListener(address) => {
                write!(
                    formatter,
                    "registry host listener {address} is not loopback"
                )
            }
            Self::Listener(error) => write!(formatter, "registry listener failed: {error}"),
            Self::Service(error) => write!(formatter, "registry service failed: {error}"),
            Self::Task(error) => write!(formatter, "registry connection task failed: {error}"),
            Self::ClockBeforeUnixEpoch => {
                formatter.write_str("registry host clock is before the Unix epoch")
            }
            Self::InvalidRuntimeState => {
                formatter.write_str("registry host connection accounting is inconsistent")
            }
        }
    }
}

impl Error for RegistryHostError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Listener(error) => Some(error),
            Self::Service(error) => Some(error),
            Self::Task(error) => Some(error),
            _ => None,
        }
    }
}
