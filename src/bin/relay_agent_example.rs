//! Minimal reference agent: dials the relay tunnel and answers proxied HTTP
//! by forwarding them to a local CrossPaste paste server (default 127.0.0.1:port).
//!
//! This is a development aid — production clients should embed the tunnel in-app.
//!
//! Usage:
//!   cargo run --bin relay_agent_example -- \
//!     --relay ws://127.0.0.1:39445/v1/tunnel \
//!     --app-instance-id my-device \
//!     --local-base http://127.0.0.1:13129

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio_tungstenite::{connect_async, tungstenite::Message};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "ws://127.0.0.1:39445/v1/tunnel")]
    relay: String,
    #[arg(long)]
    app_instance_id: String,
    #[arg(long, default_value = "example-device")]
    device_name: String,
    #[arg(long, default_value = "http://127.0.0.1:13129")]
    local_base: String,
    #[arg(long, default_value = "")]
    token: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum TunnelFrame {
    Hello {
        app_instance_id: String,
        device_name: Option<String>,
        app_version: Option<String>,
        sync_info_b64: Option<String>,
    },
    HelloAck {
        session_id: String,
        relay_version: String,
    },
    Ping {
        ts: i64,
    },
    Pong {
        ts: i64,
    },
    HttpRequest {
        request_id: String,
        method: String,
        path: String,
        headers: HashMap<String, String>,
        #[serde(default)]
        body_b64: Option<String>,
    },
    HttpResponse {
        request_id: String,
        status: u16,
        headers: HashMap<String, String>,
        #[serde(default)]
        body_b64: Option<String>,
        #[serde(default)]
        error: Option<String>,
    },
    Error {
        message: String,
    },
    #[serde(other)]
    Other,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let mut url = args.relay.clone();
    if !args.token.is_empty() {
        let sep = if url.contains('?') { '&' } else { '?' };
        url = format!("{url}{sep}token={}", args.token);
    }

    println!("connecting to {url}");
    let (ws, _) = connect_async(&url).await.context("connect relay")?;
    let (mut write, mut read) = ws.split();

    let hello = TunnelFrame::Hello {
        app_instance_id: args.app_instance_id.clone(),
        device_name: Some(args.device_name.clone()),
        app_version: Some(env!("CARGO_PKG_VERSION").into()),
        sync_info_b64: None,
    };
    write
        .send(Message::Text(serde_json::to_string(&hello)?.into()))
        .await?;

    let client = reqwest::Client::new();

    while let Some(msg) = read.next().await {
        let msg = msg?;
        let text = match msg {
            Message::Text(t) => t.to_string(),
            Message::Ping(d) => {
                write.send(Message::Pong(d)).await?;
                continue;
            }
            Message::Close(_) => break,
            _ => continue,
        };
        let frame: TunnelFrame = serde_json::from_str(&text)?;
        match frame {
            TunnelFrame::HelloAck {
                session_id,
                relay_version,
            } => {
                println!("registered session={session_id} relay={relay_version}");
            }
            TunnelFrame::Ping { ts } => {
                let pong = TunnelFrame::Pong { ts };
                write
                    .send(Message::Text(serde_json::to_string(&pong)?.into()))
                    .await?;
            }
            TunnelFrame::HttpRequest {
                request_id,
                method,
                path,
                headers,
                body_b64,
            } => {
                let resp =
                    forward_local(&client, &args.local_base, &method, &path, headers, body_b64)
                        .await;
                let out = match resp {
                    Ok((status, hdrs, body)) => TunnelFrame::HttpResponse {
                        request_id,
                        status,
                        headers: hdrs,
                        body_b64: if body.is_empty() {
                            None
                        } else {
                            Some(B64.encode(body))
                        },
                        error: None,
                    },
                    Err(e) => TunnelFrame::HttpResponse {
                        request_id,
                        status: 502,
                        headers: HashMap::new(),
                        body_b64: None,
                        error: Some(e.to_string()),
                    },
                };
                write
                    .send(Message::Text(serde_json::to_string(&out)?.into()))
                    .await?;
            }
            TunnelFrame::Error { message } => {
                eprintln!("relay error: {message}");
            }
            _ => {}
        }
    }
    Ok(())
}

async fn forward_local(
    client: &reqwest::Client,
    base: &str,
    method: &str,
    path: &str,
    headers: HashMap<String, String>,
    body_b64: Option<String>,
) -> Result<(u16, HashMap<String, String>, Vec<u8>)> {
    let url = format!(
        "{}{}",
        base.trim_end_matches('/'),
        if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        }
    );
    let m = method
        .parse::<reqwest::Method>()
        .unwrap_or(reqwest::Method::GET);
    let mut req = client.request(m, &url);
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("host") || k.eq_ignore_ascii_case("content-length") {
            continue;
        }
        req = req.header(k, v);
    }
    if let Some(b) = body_b64 {
        req = req.body(B64.decode(b.as_bytes())?);
    }
    let resp = req.send().await?;
    let status = resp.status().as_u16();
    let mut out_headers = HashMap::new();
    for (k, v) in resp.headers().iter() {
        if let Ok(s) = v.to_str() {
            out_headers.insert(k.as_str().to_string(), s.to_string());
        }
    }
    let body = resp.bytes().await?.to_vec();
    if !(200..600).contains(&status) {
        bail!("unexpected status {status}");
    }
    Ok((status, out_headers, body))
}
