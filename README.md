# crosspaste-relay

基于 [CrossPaste](https://github.com/CrossPaste/crosspaste-desktop) 设备间协议实现的 **纯中转共享服务端**（Rust）。

## 定位

CrossPaste 桌面端默认是 **LAN 直连 + 端到端加密**（Ktor HTTP / WebSocket，`secure: 1` 时 body 已是密文）。本服务 **不解密、不落库剪贴板内容**，只做：

1. 设备出站 WebSocket 隧道注册（穿透 NAT）
2. 将 A→B 的 HTTP 请求按原路径/头/体透明转发到 B 的隧道
3. 房间码发现（让跨网设备互相找到 `appInstanceId`）

端到端密钥协商（`/sync/trust`、`/sync/trust/v2/*`）与 AES 密文仍在设备之间完成；中转只搬运字节。

## 与桌面端协议的对应关系

| 桌面端路径 | 经中转访问 |
| --- | --- |
| `POST /sync/paste` | `POST /r/{targetAppInstanceId}/sync/paste` |
| `GET /sync/heartbeat` | `GET /r/{target}/sync/heartbeat` |
| `POST /sync/trust` | `POST /r/{target}/sync/trust` |
| `POST /pull/file` 等 | `POST /r/{target}/pull/file` … |

请求头保持桌面端语义：

- `appInstanceId`：源设备
- `targetAppInstanceId`：目标设备（`/p/*` 模式必填；`/r/{target}/*` 可从路径推断）
- `secure: 1`：body 为对端密文，中转 **原样** 转发

Sync API version 与桌面端一致：`3`（见 `SyncApi.VERSION`）。

## 架构

```
Device A  --HTTP-->  Relay  --WS tunnel-->  Device B local paste server
                ^
                |
         Device B 出站连接 /v1/tunnel
```

## 快速开始

```bash
# 启动中转
cargo run --release -- --listen 0.0.0.0:39445 --auth-token 'secret'

# 设备侧参考 Agent（把隧道请求转到本机 CrossPaste 端口）
cargo run --bin relay_agent_example -- \
  --relay ws://RELAY_HOST:39445/v1/tunnel \
  --app-instance-id device-a \
  --local-base http://127.0.0.1:13129 \
  --token secret
```

健康检查：

```bash
curl http://127.0.0.1:39445/health
```

## HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/health` | 健康与在线数 |
| GET | `/v1/devices` | 在线设备列表（需鉴权） |
| POST | `/v1/rooms` | 创建房间码 |
| GET | `/v1/rooms/{code}` | 房间成员 |
| POST | `/v1/rooms/{code}/join` | 加入房间 `{"app_instance_id":"..."}` |
| POST | `/v1/rooms/{code}/leave` | 离开房间 |
| GET(WS) | `/v1/tunnel?token=` | 设备长连接隧道 |
| ANY | `/r/{target}/{*path}` | 透明代理到目标设备 |
| ANY | `/p/{*path}` | 透明代理（目标取自 `targetAppInstanceId` 头） |

鉴权：配置 `RELAY_AUTH_TOKEN` 后，控制面与代理请求需带 `x-relay-token: <token>`（或 `Authorization: Bearer <token>`）；隧道用 query `token=`。

## 隧道帧（JSON）

设备连接 WebSocket 后：

```json
{"type":"hello","app_instance_id":"uuid","device_name":"Mac","app_version":"2.1.6","sync_info_b64":null}
```

中转下发代理请求：

```json
{"type":"http_request","request_id":"...","method":"POST","path":"/sync/paste","headers":{"appInstanceId":"...","secure":"1"},"body_b64":"..."}
```

设备应答：

```json
{"type":"http_response","request_id":"...","status":200,"headers":{"content-type":"application/json"},"body_b64":"...","error":null}
```

## 配置

见 `config/relay.example.env`。常用环境变量：

- `RELAY_LISTEN`（默认 `0.0.0.0:39445`）
- `RELAY_AUTH_TOKEN`
- `RELAY_MAX_BODY_BYTES`（默认 64MiB）
- `RELAY_REQUEST_TIMEOUT_SECS`（默认 60）

## 安全边界

- **会看见**：路径、头字段、密文字节长度、设备在线状态
- **看不见**：剪贴板明文、ECDH 派生的会话密钥、AES 明文
- 生产务必开启 `RELAY_AUTH_TOKEN`，并在 TLS 终结后部署（nginx/caddy）
- 本服务不实现完整桌面端业务（token 弹窗、SQLDelight、文件落盘），需设备本地仍运行 CrossPaste 或兼容 peer server

## 与「改造桌面端」的关系

当前桌面端只支持直连 peer。接入本中转需要客户端增加：

1. 出站连接 `/v1/tunnel` 的 agent（可用 `relay_agent_example` 作旁路）
2. 将 peer base URL 从 `http://lan-ip:port` 改为 `http://relay/r/{peerAppInstanceId}`

本仓库只提供服务端与参考 agent，不修改 `crosspaste-desktop` 源码。

## 开发

```bash
cargo test
cargo build --release
```

## License

AGPL-3.0（与 CrossPaste 桌面端一致）
