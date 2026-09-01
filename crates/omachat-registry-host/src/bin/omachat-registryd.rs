use omachat_registry_host::{
    REGISTRYD_HELP, RegistryAcceptanceClock, RegistryProcessCommand, RegistryProcessConfig,
    load_registry_signing_seed, parse_registry_process_args, run_registry_host,
};
use omachat_registry_transport::RegistryService;
use omachat_store::{RequestedProvider, SealedStore};
use std::{error::Error, ffi::OsString};
use tokio::{
    net::TcpListener,
    signal::unix::{SignalKind, signal},
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run(std::env::args_os()).await {
        eprintln!("omachat-registryd: {error}");
        std::process::exit(1);
    }
}

async fn run(args: impl IntoIterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    match parse_registry_process_args(args)? {
        RegistryProcessCommand::Help => {
            print!("{REGISTRYD_HELP}");
            Ok(())
        }
        RegistryProcessCommand::Version => {
            println!("omachat-registryd {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        RegistryProcessCommand::Run(config) => run_service(config).await,
    }
}

async fn run_service(config: RegistryProcessConfig) -> Result<(), Box<dyn Error>> {
    let signing_seed = load_registry_signing_seed(&config.signing_seed_file)?;
    let store = SealedStore::open(&config.data_dir, RequestedProvider::File).await?;
    let mut service = RegistryService::open(&store, *signing_seed)?;
    drop(signing_seed);
    let listener = TcpListener::bind(config.listen).await?;
    let local_address = listener.local_addr()?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let shutdown = async move {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
    };

    eprintln!(
        "omachat-registryd: listening on {local_address}; expose only through a TLS reverse proxy"
    );
    eprintln!(
        "omachat-registryd: pinned registry key {}",
        hex::encode(service.verifying_key())
    );
    let mut clock = RegistryAcceptanceClock::new();
    let report = run_registry_host(
        listener,
        &mut service,
        config.limits,
        || clock.now(),
        shutdown,
    )
    .await?;
    eprintln!(
        "omachat-registryd: stopped; admitted={} completed={} rejected_global={} rejected_per_ip={} timeouts={} websocket_rejections={} protocol_rejections={} response_failures={} forced={} aborted={}",
        report.admitted_connections,
        report.completed_responses,
        report.rejected_global_limit,
        report.rejected_per_ip_limit,
        report.admission_timeouts,
        report.rejected_websockets,
        report.rejected_protocol_requests,
        report.response_failures,
        report.forced_shutdown,
        report.aborted_connections,
    );
    Ok(())
}
