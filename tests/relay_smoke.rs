use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::time::Duration;
use tokio::time::timeout;
use tokio_tungstenite::{connect_async, tungstenite::Message};

async fn wait_health(base: &str) {
    let client = reqwest::Client::new();
    for _ in 0..50 {
        if let Ok(resp) = client.get(format!("{base}/health")).send().await {
            if resp.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("server not ready");
}

#[tokio::test]
async fn tunnel_proxy_roundtrip() {
    // Start server in-process via binary would be heavy; spawn process.
    let port = 39446u16;
    let listen = format!("127.0.0.1:{port}");
    let base = format!("http://{listen}");
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_crosspaste-relay"))
        .args(["--listen", &listen, "--log", "error"])
        .kill_on_drop(true)
        .spawn()
        .expect("spawn relay");

    wait_health(&base).await;

    // Connect tunnel as device A
    let (ws, _) = connect_async(format!("ws://{listen}/v1/tunnel"))
        .await
        .expect("ws");
    let (mut write, mut read) = ws.split();

    let hello = json!({
        "type": "hello",
        "app_instance_id": "device-a",
        "device_name": "A",
        "app_version": "0.1.0",
        "sync_info_b64": null
    });
    write
        .send(Message::Text(hello.to_string().into()))
        .await
        .unwrap();

    // Expect hello_ack
    let ack = timeout(Duration::from_secs(2), read.next())
        .await
        .expect("ack timeout")
        .expect("ws closed")
        .expect("ws err");
    let Message::Text(text) = ack else {
        panic!("expected text");
    };
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["type"], "hello_ack");

    // Health should show 1 device
    let health: serde_json::Value = reqwest::Client::new()
        .get(format!("{base}/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["onlineDevices"], 1);

    // Spawn task that answers one HTTP request with fixed payload
    let answerer = tokio::spawn(async move {
        while let Some(Ok(msg)) = read.next().await {
            if let Message::Text(t) = msg {
                let v: serde_json::Value = serde_json::from_str(&t).unwrap();
                if v["type"] == "http_request" {
                    let request_id = v["request_id"].as_str().unwrap().to_string();
                    // body "hello" base64 = aGVsbG8=
                    let resp = json!({
                        "type": "http_response",
                        "request_id": request_id,
                        "status": 200,
                        "headers": { "content-type": "text/plain" },
                        "body_b64": "aGVsbG8=",
                        "error": null
                    });
                    write
                        .send(Message::Text(resp.to_string().into()))
                        .await
                        .unwrap();
                    break;
                }
            }
        }
    });

    // Proxy request to device-a
    let resp = reqwest::Client::new()
        .post(format!("{base}/r/device-a/sync/paste"))
        .header("appInstanceId", "device-b")
        .header("targetAppInstanceId", "device-a")
        .header("content-type", "application/json")
        .body(r#"{"cipher":"opaque"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "hello");

    let _ = answerer.await;
    let _ = child.kill().await;
}
