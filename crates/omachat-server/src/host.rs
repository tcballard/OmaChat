//! TCP listener, connection limits and graceful shutdown.
//!
//! The listener is loopback-only: a TLS reverse proxy such as Caddy owns the
//! public socket, certificates and HTTP hygiene, the same deployment shape as
//! the registry host.

use crate::{
    auth::ServerIdentity,
    service::ServiceHandle,
    session::{CloseReason, SessionContext, SessionLimits, SessionReport, run_session},
};
use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{net::TcpListener, sync::watch, task::JoinSet, time::timeout};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostLimits {
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    pub session: SessionLimits,
    pub shutdown_grace: Duration,
}

impl Default for HostLimits {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            max_connections_per_ip: 32,
            session: SessionLimits::default(),
            shutdown_grace: Duration::from_secs(10),
        }
    }
}

impl HostLimits {
    pub fn validate(self) -> Result<Self, HostError> {
        if self.max_connections == 0
            || self.max_connections_per_ip == 0
            || self.max_connections_per_ip > self.max_connections
            || self.session.admission_timeout.is_zero()
            || self.session.unauthenticated_timeout.is_zero()
            || self.session.idle_timeout.is_zero()
            || self.session.requests_per_second == 0
            || self.session.request_burst == 0
            || self.shutdown_grace.is_zero()
        {
            return Err(HostError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HostReport {
    pub admitted_connections: u64,
    pub rejected_global_limit: u64,
    pub rejected_per_ip_limit: u64,
    pub authenticated_sessions: u64,
    pub failed_sessions: u64,
    pub lagged_sessions: u64,
    pub forced_shutdown: bool,
    pub aborted_connections: usize,
}

/// Serve until `shutdown` completes, then drain sessions within the grace
/// period.
pub async fn run_host<F>(
    listener: TcpListener,
    service: ServiceHandle,
    identity: Arc<ServerIdentity>,
    limits: HostLimits,
    shutdown: F,
) -> Result<HostReport, HostError>
where
    F: Future<Output = ()>,
{
    let limits = limits.validate()?;
    let local_address = listener.local_addr().map_err(HostError::Listener)?;
    if !local_address.ip().is_loopback() {
        return Err(HostError::NonLoopbackListener(local_address));
    }
    let (stop_sender, stop_receiver) = watch::channel(false);
    let mut sessions: JoinSet<(IpAddr, SessionReport)> = JoinSet::new();
    let mut active_by_ip: BTreeMap<IpAddr, usize> = BTreeMap::new();
    let mut active_total = 0_usize;
    let mut next_session_id = 1_u64;
    let mut report = HostReport::default();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, peer) = accepted.map_err(HostError::Listener)?;
                let ip = peer.ip();
                if active_total >= limits.max_connections {
                    report.rejected_global_limit += 1;
                    continue;
                }
                if active_by_ip.get(&ip).copied().unwrap_or(0) >= limits.max_connections_per_ip {
                    report.rejected_per_ip_limit += 1;
                    continue;
                }
                active_total += 1;
                *active_by_ip.entry(ip).or_default() += 1;
                report.admitted_connections += 1;
                let context = SessionContext {
                    service: service.clone(),
                    identity: Arc::clone(&identity),
                    limits: limits.session,
                    session_id: next_session_id,
                    shutdown: stop_receiver.clone(),
                };
                next_session_id += 1;
                sessions.spawn(async move { (ip, run_session(stream, context).await) });
            }
            joined = sessions.join_next(), if !sessions.is_empty() => {
                if let Some(joined) = joined {
                    finish(joined, &mut active_by_ip, &mut active_total, &mut report);
                }
            }
        }
    }

    let _ = stop_sender.send(true);
    let drain = async {
        while let Some(joined) = sessions.join_next().await {
            finish(joined, &mut active_by_ip, &mut active_total, &mut report);
        }
    };
    if timeout(limits.shutdown_grace, drain).await.is_err() {
        report.forced_shutdown = true;
        report.aborted_connections = active_total;
        sessions.abort_all();
    }
    Ok(report)
}

type Joined = Result<(IpAddr, SessionReport), tokio::task::JoinError>;

fn finish(
    joined: Joined,
    active_by_ip: &mut BTreeMap<IpAddr, usize>,
    active_total: &mut usize,
    report: &mut HostReport,
) {
    match joined {
        Ok((ip, session)) => {
            release(ip, active_by_ip, active_total);
            if session.authenticated {
                report.authenticated_sessions += 1;
            }
            if session.reason == CloseReason::Lagged {
                report.lagged_sessions += 1;
            }
            if session.error.is_some() {
                report.failed_sessions += 1;
            }
        }
        Err(_) => {
            // A panicked or aborted task: counts were already attributed to
            // its IP at admission, but the IP is unknown here; the aggregate
            // count is corrected and the per-IP entry is left to drain with
            // its neighbours at shutdown.
            *active_total = active_total.saturating_sub(1);
            report.failed_sessions += 1;
        }
    }
}

fn release(ip: IpAddr, active_by_ip: &mut BTreeMap<IpAddr, usize>, active_total: &mut usize) {
    *active_total = active_total.saturating_sub(1);
    if let Some(count) = active_by_ip.get_mut(&ip) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            active_by_ip.remove(&ip);
        }
    }
}

#[derive(Debug)]
pub enum HostError {
    InvalidLimits,
    Listener(std::io::Error),
    NonLoopbackListener(SocketAddr),
}

impl fmt::Display for HostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter
                .write_str("host limits must all be positive and per-IP must not exceed global"),
            Self::Listener(error) => write!(formatter, "listener failed: {error}"),
            Self::NonLoopbackListener(address) => write!(
                formatter,
                "refusing to listen on {address}: bind to loopback and expose through a TLS reverse proxy"
            ),
        }
    }
}

impl Error for HostError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Listener(error) => Some(error),
            _ => None,
        }
    }
}
