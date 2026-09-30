use omachat_server::{
    HostLimits, Registration, SERVERD_HELP, ServerIdentity, ServerProcessCommand,
    ServerProcessConfig, ServiceConfig, Storage, generate_seed_file, load_invite_codes,
    load_seed_file, parse_server_process_args, prepare_data_dir, process::RegistrationMode,
    run_host, spawn_service,
};
use std::{error::Error, ffi::OsString, sync::Arc};
use tokio::{
    net::TcpListener,
    signal::unix::{SignalKind, signal},
};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    if let Err(error) = run(std::env::args_os()).await {
        eprintln!("omachat-serverd: {error}");
        std::process::exit(1);
    }
}

async fn run(args: impl IntoIterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    match parse_server_process_args(args)? {
        ServerProcessCommand::Help => {
            print!("{SERVERD_HELP}");
            Ok(())
        }
        ServerProcessCommand::Version => {
            println!("omachat-serverd {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        ServerProcessCommand::GenerateSecret(path) => {
            generate_seed_file(&path)?;
            eprintln!("omachat-serverd: wrote {}", path.display());
            Ok(())
        }
        ServerProcessCommand::Run(config) => serve(config).await,
    }
}

async fn serve(config: ServerProcessConfig) -> Result<(), Box<dyn Error>> {
    let server_seed = load_seed_file(&config.server_key_file)?;
    let identity = Arc::new(ServerIdentity::from_seed(&server_seed));
    drop(server_seed);
    let storage_key = load_seed_file(&config.storage_key_file)?;
    let database = prepare_data_dir(&config.data_dir)?;
    let storage = Storage::open(&database, storage_key)?;
    let registration = match config.registration {
        RegistrationMode::Open => Registration::Open,
        RegistrationMode::Closed => Registration::Closed,
        RegistrationMode::Invite => load_invite_codes(
            config
                .invite_code_file
                .as_deref()
                .ok_or("invite mode requires --invite-code-file")?,
        )?,
    };
    let registration_label = registration.label();
    let service = spawn_service(
        storage,
        ServiceConfig {
            registration,
            server_public_key: identity.public_key(),
        },
    )?;
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
        "omachat-serverd: listening on {local_address}; expose only through a TLS reverse proxy"
    );
    eprintln!(
        "omachat-serverd: server public key {}; registration {registration_label}",
        hex::encode(identity.public_key())
    );
    if registration_label == "open" {
        eprintln!("omachat-serverd: warning: open registration accepts any device key");
    }
    let limits: HostLimits = config.limits;
    let report = run_host(listener, service, identity, limits, shutdown).await?;
    eprintln!("omachat-serverd: stopped: {report:?}");
    Ok(())
}
