//! Minimal command-line client for the hosted server: one authenticated
//! request per invocation, or `listen` to print events. Intended for
//! operators, reviewers and scripted tests, not for end users.

use futures_util::{SinkExt, StreamExt};
use omachat_server::auth::{
    decode_key, generate_seed_file, load_seed_file, sign_device_challenge, verify_hello_signature,
};
use serde_json::{Value, json};
use std::{error::Error, ffi::OsString, path::PathBuf};
use tokio_tungstenite::{connect_async, tungstenite::Message};

const HELP: &str = "\
Usage: omachat-server-cli --url URL --device-key-file PATH [OPTIONS] COMMAND [ARGS]\n\
       omachat-server-cli --generate-device-key PATH\n\
\n\
Options:\n\
  --server-public-key HEX     Pin the server identity (strongly recommended)\n\
  --display-name NAME         Display name used if this device registers\n\
\n\
Commands:\n\
  status\n\
  claim-handle HANDLE\n\
  resolve-handle HANDLE\n\
  raw METHOD [PARAMS_JSON]    Send any request verbatim\n\
\n\
Responses and events are printed as one JSON object per line. The exit\n\
status is 1 when the server answers with an error.\n";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    match run(std::env::args_os()).await {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(error) => {
            eprintln!("omachat-server-cli: {error}");
            std::process::exit(2);
        }
    }
}

struct Options {
    url: String,
    device_key_file: PathBuf,
    server_public_key: Option<[u8; 32]>,
    display_name: Option<String>,
    command: Vec<String>,
}

fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Option<Options>, Box<dyn Error>> {
    let mut arguments = args.into_iter().skip(1).peekable();
    let mut url = None;
    let mut device_key_file = None;
    let mut server_public_key = None;
    let mut display_name = None;
    let mut command = Vec::new();
    while let Some(argument) = arguments.next() {
        let argument = argument
            .into_string()
            .map_err(|_| "arguments must be UTF-8")?;
        if !command.is_empty() {
            command.push(argument);
            continue;
        }
        let mut value = |name: &str| -> Result<String, Box<dyn Error>> {
            arguments
                .next()
                .ok_or_else(|| format!("{name} needs a value"))?
                .into_string()
                .map_err(|_| format!("{name} must be UTF-8").into())
        };
        match argument.as_str() {
            "--help" => {
                print!("{HELP}");
                return Ok(None);
            }
            "--generate-device-key" => {
                let path = PathBuf::from(value("--generate-device-key")?);
                generate_seed_file(&path)?;
                eprintln!("omachat-server-cli: wrote {}", path.display());
                return Ok(None);
            }
            "--url" => url = Some(value("--url")?),
            "--device-key-file" => {
                device_key_file = Some(PathBuf::from(value("--device-key-file")?))
            }
            "--server-public-key" => {
                server_public_key = Some(
                    decode_key(&value("--server-public-key")?)
                        .map_err(|_| "--server-public-key must be 64 hex characters")?,
                );
            }
            "--display-name" => display_name = Some(value("--display-name")?),
            other if other.starts_with("--") => {
                return Err(format!("unknown option {other}").into());
            }
            _ => command.push(argument),
        }
    }
    if command.is_empty() {
        return Err("a command is required; see --help".into());
    }
    Ok(Some(Options {
        url: url.ok_or("--url is required")?,
        device_key_file: device_key_file.ok_or("--device-key-file is required")?,
        server_public_key,
        display_name,
        command,
    }))
}

fn build_request(command: &[String]) -> Result<(String, Value), Box<dyn Error>> {
    let argument = |index: usize, name: &str| -> Result<String, Box<dyn Error>> {
        command
            .get(index)
            .cloned()
            .ok_or_else(|| format!("{} needs {name}", command[0]).into())
    };
    let request = match command[0].as_str() {
        "status" => ("status".to_owned(), Value::Null),
        "claim-handle" | "resolve-handle" => (
            command[0].clone(),
            json!({"handle": argument(1, "HANDLE")?}),
        ),
        "raw" => {
            let params = match command.get(2) {
                Some(text) => serde_json::from_str(text)?,
                None => Value::Null,
            };
            (argument(1, "METHOD")?, params)
        }
        other => return Err(format!("unknown command {other}; see --help").into()),
    };
    Ok(request)
}

async fn run(args: impl IntoIterator<Item = OsString>) -> Result<bool, Box<dyn Error>> {
    let Some(options) = parse(args)? else {
        return Ok(true);
    };
    let (method, params) = build_request(&options.command)?;
    let seed = load_seed_file(&options.device_key_file)?;
    let device_public_key = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();

    let (mut socket, _) = connect_async(&options.url).await?;
    let mut next_id = 1_u64;

    let hello = call(
        &mut socket,
        &mut next_id,
        "hello",
        json!({
            "minimum_version": 1,
            "maximum_version": 1,
            "device_public_key": hex::encode(device_public_key),
        }),
    )
    .await?;
    let Some(result) = hello.get("result") else {
        println!("{hello}");
        return Ok(false);
    };
    let challenge = decode_key(result["challenge"].as_str().unwrap_or(""))
        .map_err(|_| "server sent a malformed challenge")?;
    let observed = decode_key(result["server_public_key"].as_str().unwrap_or(""))
        .map_err(|_| "server sent a malformed public key")?;
    let signature = hex::decode(result["server_signature"].as_str().unwrap_or(""))
        .ok()
        .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
        .ok_or("server sent a malformed signature")?;
    verify_hello_signature(&observed, &challenge, &device_public_key, &signature)
        .map_err(|_| "server signature did not verify")?;
    match options.server_public_key {
        Some(pinned) if pinned != observed => {
            return Err(format!(
                "server public key {} does not match the pinned key",
                hex::encode(observed)
            )
            .into());
        }
        Some(_) => {}
        None => eprintln!(
            "omachat-server-cli: warning: server key {} is not pinned; pass --server-public-key",
            hex::encode(observed)
        ),
    }
    let device_signature = sign_device_challenge(&seed, &observed, &challenge);
    drop(seed);
    let mut authenticate = json!({"signature": hex::encode(device_signature)});
    if let Some(name) = options.display_name {
        authenticate["display_name"] = json!(name);
    }
    let authenticated = call(&mut socket, &mut next_id, "authenticate", authenticate).await?;
    if authenticated["ok"] != Value::Bool(true) {
        println!("{authenticated}");
        return Ok(false);
    }
    eprintln!(
        "omachat-server-cli: authenticated as {} (new account: {})",
        authenticated["result"]["account_id"], authenticated["result"]["new_account"]
    );

    let response = call(&mut socket, &mut next_id, &method, params).await?;
    println!("{response}");
    let _ = socket.close(None).await;
    Ok(response["ok"] == Value::Bool(true))
}

async fn call<S>(
    socket: &mut S,
    next_id: &mut u64,
    method: &str,
    params: Value,
) -> Result<Value, Box<dyn Error>>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
{
    let id = next_id.to_string();
    *next_id += 1;
    let mut request = json!({"version": 1, "id": id, "method": method});
    if !params.is_null() {
        request["params"] = params;
    }
    exchange(socket, request.to_string()).await
}

async fn exchange<S>(socket: &mut S, frame: String) -> Result<Value, Box<dyn Error>>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
{
    socket.send(Message::Text(frame.into())).await?;
    while let Some(message) = socket.next().await {
        match message? {
            Message::Text(text) => {
                let value: Value = serde_json::from_str(text.as_str())?;
                if value.get("event").is_some() {
                    println!("{value}");
                    continue;
                }
                return Ok(value);
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
    Err("connection closed before a response arrived".into())
}
