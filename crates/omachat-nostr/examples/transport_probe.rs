#[path = "../tests/support/transport_probe.rs"]
#[allow(dead_code)]
mod transport_probe;

use std::{env, process::ExitCode};
use transport_probe::{Route, run_probe};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("transport probe failed: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), transport_probe::ProbeError> {
    let mut url = None;
    let mut socks5 = None;
    let mut attempts = 2;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--url" => url = arguments.next(),
            "--socks5" => socks5 = arguments.next(),
            "--attempts" => {
                attempts = arguments
                    .next()
                    .ok_or("--attempts requires a value")?
                    .parse()?
            }
            "--help" | "-h" => {
                println!(
                    "usage: transport_probe --url <ws[s]://host/path> [--socks5 host:port] [--attempts N]"
                );
                return Ok(());
            }
            _ => return Err(format!("unknown argument {argument}").into()),
        }
    }
    let url = url.ok_or("--url is required")?;
    let route = socks5.as_deref().map_or(Route::Direct, Route::Socks5);
    let result = run_probe(&url, route, attempts).await?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
