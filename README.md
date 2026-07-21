# crosspaste-server

Rust 实现的 CrossPaste 兼容中心服务端。目标不是让客户端互相直连，而是让所有原版客户端按正常流程连接本项目：局域网发现或扫码添加 → 输入 6 位验证码配对 → 后续剪贴板都发给 `crosspaste-server`，再由服务端同步给其他已配对客户端。

## 当前定位

- 服务端作为一个稳定的 CrossPaste 设备暴露给客户端。
- 服务端通过 mDNS 广播 `_crosspasteService._tcp.local.`。
- 二维码内容使用原版 `QRCodeGenerator` 兼容格式。
- 当前原版客户端走 `/sync/trust/v2/exchange` 与 `/sync/trust/v2/confirm`，服务端显示双方公钥计算出的 6 位 SAS 验证码。
- 扫码添加仍兼容 `/sync/trust` v1 token 流程。
- `secure: 1` 请求体会按 CrossPaste ECDH/AES 流程解密或加密，用于 Hub 分发。

## 正常连接流程

1. 启动 `crosspaste-server`。
2. 客户端在局域网发现中看到 `CrossPaste Server`，或扫描 `/v1/pairing/qr.png`。
3. 客户端打开验证码输入框后发起 v2 密钥交换，服务端终端输出 6 位 SAS；用户将它填入客户端。
4. 客户端确认 SAS 后调用 `/sync/trust/v2/confirm`，服务端校验签名并保存客户端公钥。
5. 客户端向服务端发送 `/sync/heartbeat/syncInfo` 和 `/sync/paste`。
6. 服务端把收到的剪贴板内容广播给其他已配对客户端。

## 项目结构

```text
src/                 服务端源码（协议路由、Hub、SQLite、管理后台 API）
assets/admin/        管理后台前端（构建时嵌入二进制）
data/                运行时数据目录（SQLite / 图标 / 传输缓存，默认 gitignore）
.env.demo            启动级配置示例
Dockerfile           多架构镜像构建
docker-compose.yml   本地/部署编排
.github/workflows/   发布与 Docker 推送
crosspaste-desktop/  原版协议参考源码
```

## 快速开始

```bash
cargo run --release -- --listen 0.0.0.0:39445
```

生成二维码和固定 6 位验证码：

```bash
curl "http://127.0.0.1:39445/v1/pairing/qr?token=123456"
curl -o qr.png "http://127.0.0.1:39445/v1/pairing/qr.png?token=123456"
```

健康检查：

```bash
curl http://127.0.0.1:39445/health
```

管理后台：`http://SERVER_HOST:39445/admin`

- 默认用户名：`admin`
- 默认密码：`CrossPaste@123`
- 首次登录必须修改默认密码，密码需至少 12 位并包含大小写字母、数字和特殊字符。
- 支持可选 TOTP MFA，可使用常见 Authenticator 应用。
- 登录页仅在账号已启用 MFA 且密码验证通过后显示 6 位验证码输入框。
- 管理会话使用 HttpOnly、SameSite=Strict Cookie，密码使用 Argon2id 哈希。

查看已完成配对的客户端：

```bash
curl -H "x-crosspaste-server-token: $CROSSPASTE_SERVER_AUTH_TOKEN" \
  http://127.0.0.1:39445/v1/clients
```

当前原版客户端正常配对时，服务端日志应依次出现 `/sync/telnet`、`/sync/trust/v2/exchange`、`/sync/trust/v2/confirm` 和 `/sync/heartbeat/syncInfo`。扫码添加使用 `/sync/trust`。其中 `/sync/telnet` 必须返回协议版本 `3`；未保存有效服务端密钥的客户端心跳会收到 `DECRYPT_FAIL(2008)`，随后重新进入验证码配对流程。



## Docker

本地构建并启动：

```bash
docker compose up -d --build
```

使用发布镜像（CI 推送到 GHCR 的标签为 `0.1.0` / `v0.1.0` / `latest`）：

```bash
docker pull ghcr.io/<owner>/crosspaste-server:0.1.0
docker run --rm -p 39445:39445 -v crosspaste-data:/data ghcr.io/<owner>/crosspaste-server:0.1.0

# 或通过 compose 指定镜像
IMAGE=ghcr.io/<owner>/crosspaste-server:0.1.0 docker compose up -d
```

管理后台：`http://SERVER_HOST:39445/admin`

默认会把 SQLite 与运行数据写到容器内 `/data`。

## 发布

推送到 `main`，或手动触发 `.github/workflows/release.yml`：

1. 读取 `Cargo.toml` 版本
2. 若 `vX.Y.Z` 尚未发布，则构建 Windows / Linux / macOS 二进制
3. 构建并推送 `linux/amd64` + `linux/arm64` Docker 镜像到 GHCR
4. 创建 GitHub Release，并附带二进制包

## 配置

见 `.env.demo`。其中仅保留后台管理无法修改的启动级配置。复制为项目根目录的 `.env` 后，程序启动时会自动加载；系统环境变量和命令行参数仍可覆盖其中配置。

```bash
cp .env.demo .env
cargo run
```

常用环境变量：

- `CROSSPASTE_SERVER_LISTEN`：监听地址，默认 `0.0.0.0:39445`
- `CROSSPASTE_SERVER_PUBLIC_HOST`：写入二维码和 mDNS 的服务端地址
- `CROSSPASTE_SERVER_NETWORK_INTERFACE`：指定发现网卡，例如 `en0` 或 `eth0`
- `CROSSPASTE_SERVER_DATA_DIR`：密钥、配对关系和文件缓存目录，默认 `data`
- `CROSSPASTE_SERVER_ENABLE_MDNS`：是否开启局域网发现，默认 `true`
- `CROSSPASTE_SERVER_INSTANCE_ID`：服务端设备 ID，默认 `crosspaste-server`
- `CROSSPASTE_SERVER_DEVICE_NAME`：客户端看到的设备名
- `CROSSPASTE_SERVER_MAX_BODY_BYTES`：请求体上限，默认 64MiB

`PUBLIC_HOST`、`NETWORK_INTERFACE` 等可选项不需要配置时应删除或注释对应行，不要写成空值，否则 Clap 会尝试解析空字符串。

## 兼容接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/sync/heartbeat` | 原版心跳 |
| POST | `/sync/heartbeat/syncInfo` | 接收客户端 SyncInfo |
| GET | `/sync/syncInfo` | 返回服务端 SyncInfo |
| GET | `/sync/telnet` | 原版探测 |
| GET | `/sync/showToken` | 生成验证码并输出到服务端终端 |
| POST | `/sync/trust` | v1 6 位 token 配对 |
| POST | `/sync/trust/v2/exchange` | 当前原版客户端密钥交换并生成 SAS |
| POST | `/sync/trust/v2/confirm` | 当前原版客户端确认配对 |
| POST | `/sync/paste` | 接收并广播剪贴板 |
| POST | `/sync/file/push` | 接收文件分块 |
| POST | `/sync/paste/push/complete` | 完成上传并向其他客户端分发 |
| POST | `/sync/icon/push/{source}` | 接收来源应用图标 |
| POST | `/pull/file` | 提供原版 pull 文件分块 |
| GET | `/pull/icon/{source}` | 提供来源应用图标 |
| GET | `/v1/pairing/qr` | 生成扫码 payload |
| GET | `/v1/pairing/qr.png` | 生成二维码图片 |
| GET | `/v1/discovery/txt-record` | 查看 mDNS TXT 分片 |
| GET | `/v1/clients` | 查看已配对客户端，需管理鉴权 |

## 持久化与文件同步

- SQLite 数据库位于 `data/crosspaste.db`，存储服务端密钥、客户端公钥、设置、管理员、会话、审计日志、剪贴板元数据和文件分块。
- 旧版 `data/hub-state.json` 会在首次启动时自动导入 SQLite，并重命名为 `hub-state.json.migrated`。
- 服务端私钥和客户端公钥持久化后，正常重启不需要重新配对。
- 文件与图片同时支持原版 push 和 pull 路径，默认按 1 MiB 分块传输。
- 服务端为文件分配全局 pasteId，缓存完整内容后再向其他客户端同步。
- 生产环境需要监控并定期清理 `data/transfers`，避免磁盘持续增长。

## 后台管理

- 仪表盘：服务版本、配对设备数、在线隧道和数据库位置。
- 同步设置：加密、中继、文件大小限制及各剪贴板类型全局开关。
- 设备管理：查看或移除已配对客户端。
- 设备详情：显示设备名、平台版本、客户端版本、地址、在线状态和最后心跳。
- 配对中心：网页实时显示客户端发起的 6 位 SAS，并可生成扫码配对二维码。
- 安全设置：修改密码、配置或关闭 TOTP MFA。
- 审计日志：记录登录、改密、MFA、设置修改和设备移除操作。
- 运行日志：SQLite 持久化最近的 HTTP、同步、配对和异常请求，后台每 3 秒刷新。
- 日志分类：后台按路径分为 API 日志和同步日志，并支持成功、异常状态筛选。
- 设置中心：同步策略和安全中心归入二级导航；系统设置可调整请求日志保留上限，默认 10,000 条。

## 开发验证

```bash
cargo fmt
cargo test
cargo build --release
```
