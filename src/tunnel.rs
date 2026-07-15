//! Device WebSocket tunnel: keeps a long-lived connection so the server can
//! push HTTP requests into the device's private network.

use crate::auth::check_auth_query;
use crate::config::Config;
use crate::database::Database;
use crate::hub::Hub;
use crate::protocol::TunnelFrame;
use crate::registry::Registry;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Query, State, WebSocketUpgrade};
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

#[derive(Clone)]
pub struct AppState {
    pub registry: Registry,
    pub config: Arc<Config>,
    pub hub: Hub,
    pub database: Database,
}

#[derive(Debug, Deserialize)]
pub struct TunnelQuery {
    pub token: Option<String>,
}

pub async fn tunnel_ws(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Query(q): Query<TunnelQuery>,
) -> Result<impl IntoResponse, crate::error::RelayError> {
    check_auth_query(&state.config, q.token.as_deref())?;
    Ok(ws.on_upgrade(move |socket| handle_socket(state, socket)))
}

async fn handle_socket(state: AppState, socket: WebSocket) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<TunnelFrame>();

    // Writer task: frames from registry → websocket
    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            match serde_json::to_string(&frame) {
                Ok(text) => {
                    if sink.send(Message::Text(text.into())).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    error!(%e, "serialize tunnel frame");
                    break;
                }
            }
        }
    });

    let mut app_instance_id: Option<String> = None;
    let mut session_id: Option<String> = None;

    while let Some(Ok(msg)) = stream.next().await {
        match msg {
            Message::Text(text) => {
                let frame: TunnelFrame = match serde_json::from_str(&text) {
                    Ok(f) => f,
                    Err(e) => {
                        warn!(%e, "invalid tunnel frame json");
                        let _ = tx.send(TunnelFrame::Error {
                            message: format!("invalid frame: {e}"),
                        });
                        continue;
                    }
                };
                match frame {
                    TunnelFrame::Hello {
                        app_instance_id: id,
                        device_name,
                        app_version,
                        sync_info_b64,
                    } => {
                        let effective_id = id;
                        if effective_id.trim().is_empty() {
                            let _ = tx.send(TunnelFrame::Error {
                                message: "app_instance_id required".into(),
                            });
                            continue;
                        }
                        let session = state.registry.register_device(
                            effective_id.clone(),
                            device_name,
                            app_version,
                            sync_info_b64,
                            tx.clone(),
                        );
                        app_instance_id = Some(effective_id);
                        session_id = Some(session.session_id.clone());
                        let _ = tx.send(TunnelFrame::HelloAck {
                            session_id: session.session_id.clone(),
                            relay_version: env!("CARGO_PKG_VERSION").to_string(),
                        });
                    }
                    TunnelFrame::Ping { ts } => {
                        let _ = tx.send(TunnelFrame::Pong { ts });
                        if let Some(id) = &app_instance_id {
                            state.registry.touch_device(id);
                        }
                    }
                    TunnelFrame::Pong { .. } => {
                        if let Some(id) = &app_instance_id {
                            state.registry.touch_device(id);
                        }
                    }
                    TunnelFrame::HttpResponse { .. } => {
                        if let Some(id) = &app_instance_id {
                            state.registry.complete_request(id, frame);
                        }
                    }
                    other => {
                        debug!(?other, "ignored client frame");
                    }
                }
            }
            Message::Ping(data) => {
                let _ = tx.send(TunnelFrame::Pong { ts: now_ms() });
                let _ = data;
            }
            Message::Close(_) => break,
            Message::Binary(_) => {
                warn!("binary frames are not supported on control tunnel");
            }
            Message::Pong(_) => {}
        }
    }

    if let (Some(id), Some(sid)) = (app_instance_id, session_id) {
        state.registry.unregister_device(&id, &sid);
    }
    writer.abort();
    info!("tunnel socket closed");
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
