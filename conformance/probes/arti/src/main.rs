use arti_client::{TorClient, TorClientConfig};
use serde::Serialize;
use std::{env, error::Error, process::ExitCode, time::Duration};

type ProbeError = Box<dyn Error + Send + Sync>;

#[derive(Serialize)]
struct ProbeResult {
    implementation: &'static str,
    target_host: String,
    target_port: u16,
    bootstrap: &'static str,
    connect: &'static str,
    dns_owner: &'static str,
    shutdown: &'static str,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(result) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&result).expect("fixed result serializes")
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Arti bootstrap probe failed: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<ProbeResult, ProbeError> {
    let mut host = None;
    let mut port = None;
    let mut timeout_seconds = 180;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--host" => host = arguments.next(),
            "--port" => {
                port = Some(arguments.next().ok_or("--port requires a value")?.parse()?);
            }
            "--timeout-seconds" => {
                timeout_seconds = arguments
                    .next()
                    .ok_or("--timeout-seconds requires a value")?
                    .parse()?;
            }
            "--help" | "-h" => {
                println!(
                    "usage: omachat-g0-arti-probe --host <relay-host> --port <port> [--timeout-seconds N]"
                );
                return Err("help requested".into());
            }
            _ => return Err(format!("unknown argument {argument}").into()),
        }
    }
    let host = host.ok_or("--host is required")?;
    let port = port.ok_or("--port is required")?;
    let client = tokio::time::timeout(
        Duration::from_secs(timeout_seconds),
        TorClient::create_bootstrapped(TorClientConfig::default()),
    )
    .await
    .map_err(|_| "Arti bootstrap timed out")??;
    let stream = tokio::time::timeout(
        Duration::from_secs(30),
        client.connect((host.as_str(), port)),
    )
    .await
    .map_err(|_| "Arti target connection timed out")??;
    drop(stream);
    drop(client);
    Ok(ProbeResult {
        implementation: "arti-client-0.45.0",
        target_host: host,
        target_port: port,
        bootstrap: "passed",
        connect: "passed",
        dns_owner: "arti",
        shutdown: "streams-and-client-dropped",
    })
}
