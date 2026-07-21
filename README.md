# crosspaste-server

> **纯 AI Vibe Coding 作品**  
> 本项目由 AI 全程 vibe coding 生成与迭代，无人工手写核心代码；仅供学习、验证与自托管实验。

Rust 实现的 [CrossPaste](https://github.com/CrossPaste/crosspaste-desktop) 兼容中心服务端。

客户端之间不直接互联：所有原版客户端按正常流程连接本服务——局域网发现或扫码添加 → 输入 6 位验证码配对 → 剪贴板统一发给 `crosspaste-server`，再由服务端同步到其他已配对客户端。

---

## 目录

- [当前定位](#当前定位)
- [正常连接流程](#正常连接流程)
- [项目结构](#项目结构)
- [快速开始](#快速开始)
- [Docker](#docker)
- [发布](#发布)
- [配置](#配置)
- [兼容接口](#兼容接口)
- [持久化与文件同步](#持久化与文件同步)
- [后台管理](#后台管理)
- [开发验证](#开发验证)

---

## 当前定位

| 能力 | 说明 |
| --- | --- |
| 设备角色 | 作为稳定的 CrossPaste 设备暴露给客户端 |
| 局域网发现 | 通过 mDNS 广播 `_crosspasteService._tcp.local.` |
| 扫码格式 | 二维码内容兼容原版 `QRCodeGenerator` |
| 配对协议 | 原版客户端走 `/sync/trust/v2/exchange` 与 `/sync/trust/v2/confirm`；服务端展示双方公钥计算出的 6 位 SAS |
| 兼容路径 | 扫码添加仍兼容 `/sync/trust` v1 token 流程 |
| 加密分发 | `secure: 1` 请求体按 CrossPaste ECDH/AES 解密或加密，用于 Hub 分发 |

---

## 正常连接流程

```text
启动服务 → 客户端发现 / 扫码 → 密钥交换拿 SAS → 填入 6 位码 → 确认配对 → 心跳 + 剪贴板同步
```

1. 启动 `crosspaste-server`
2. 客户端在局域网发现中看到 `CrossPaste Server`，或扫描 `/v1/pairing/qr.png`
3. 客户端打开验证码输入框并发起 v2 密钥交换，服务端终端输出 6 位 SAS
4. 用户将 SAS 填入客户端；确认后调用 `/sync/trust/v2/confirm`，服务端校验签名并保存客户端公钥
5. 客户端向服务端发送 `/sync/heartbeat/syncInfo` 与 `/sync/paste`
6. 服务端将收到的剪贴板内容广播给其他已配对客户端

---

## 项目结构

```text
.
├── src/                  # 服务端源码（协议路由、Hub、SQLite、管理后台 API）
├── assets/admin/         # 管理后台前端（构建时嵌入二进制）
├── data/                 # 运行时数据（SQLite / 图标 / 传输缓存，默认 gitignore）
├── .env.demo             # 启动级配置示例
├── Dockerfile            # 多架构镜像构建
├── docker-compose.yml    # 本地 / 部署编排
├── .github/workflows/    # 发布与 Docker 推送
└── crosspaste-desktop/   # 原版协议参考源码
```

---

## 快速开始

### 本地运行

```bash
cargo run --release -- --listen 0.0.0.0:39445
```

### 配对二维码

```bash
# 生成固定 6 位验证码的二维码 payload
curl "http://127.0.0.1:39445/v1/pairing/qr?token=123456"

# 下载二维码图片
curl -o qr.png "http://127.0.0.1:39445/v1/pairing/qr.png?token=123456"
```

### 健康检查

```bash
curl http://127.0.0.1:39445/health
```

### 管理后台

地址：`http://SERVER_HOST:39445/admin`

| 项 | 默认值 |
| --- | --- |
| 用户名 | `admin` |
| 密码 | `CrossPaste@123` |

- 首次登录必须修改默认密码；密码至少 12 位，且包含大小写字母、数字和特殊字符
- 支持可选 TOTP MFA（常见 Authenticator 应用）
- 登录页仅在账号已启用 MFA 且密码验证通过后显示 6 位验证码输入框
- 管理会话使用 `HttpOnly`、`SameSite=Strict` Cookie；密码使用 Argon2id 哈希

### 已配对客户端

```bash
curl -H "x-crosspaste-server-token: $CROSSPASTE_SERVER_AUTH_TOKEN" \
  http://127.0.0.1:39445/v1/clients
```

### 日志预期

原版客户端正常配对时，服务端日志应依次出现：

```text
/sync/telnet
/sync/trust/v2/exchange
/sync/trust/v2/confirm
/sync/heartbeat/syncInfo
```

- 扫码添加使用 `/sync/trust`
- `/sync/telnet` 必须返回协议版本 `3`
- 未保存有效服务端密钥的客户端心跳会收到 `DECRYPT_FAIL(2008)`，随后重新进入验证码配对流程

---

## Docker

### 本地构建并启动

```bash
docker compose up -d --build
```

### 使用发布镜像

CI 推送到 GHCR 的标签：`0.1.0` / `v0.1.0` / `latest`

```bash
docker pull ghcr.io/<owner>/crosspaste-server:0.1.0
docker run --rm -p 39445:39445 -v crosspaste-data:/data \
  ghcr.io/<owner>/crosspaste-server:0.1.0

# 或通过 compose 指定镜像
IMAGE=ghcr.io/<owner>/crosspaste-server:0.1.0 docker compose up -d
```

- 管理后台：`http://SERVER_HOST:39445/admin`
- 默认将 SQLite 与运行数据写到容器内 `/data`

---

## 发布

推送到 `main`，或手动触发 `.github/workflows/release.yml`：

1. 读取 `Cargo.toml` 版本
2. 若 `vX.Y.Z` 尚未发布，则构建 Windows / Linux / macOS 二进制
3. 构建并推送 `linux/amd64` + `linux/arm64` Docker 镜像到 GHCR
4. 创建 GitHub Release，并附带二进制包

---

## 配置

见 [`.env.demo`](.env.demo)。其中仅保留后台管理无法修改的启动级配置。

```bash
cp .env.demo .env
cargo run
```

复制为项目根目录的 `.env` 后，程序启动时会自动加载；系统环境变量和命令行参数仍可覆盖其中配置。

### 常用环境变量

| 变量 | 说明 | 默认值 |
| --- | --- | --- |
| `CROSSPASTE_SERVER_LISTEN` | 监听地址 | `0.0.0.0:39445` |
| `CROSSPASTE_SERVER_PUBLIC_HOST` | 写入二维码和 mDNS 的服务端地址 | — |
| `CROSSPASTE_SERVER_NETWORK_INTERFACE` | 指定发现网卡，例如 `en0` / `eth0` | — |
| `CROSSPASTE_SERVER_DATA_DIR` | 密钥、配对关系和文件缓存目录 | `data` |
| `CROSSPASTE_SERVER_ENABLE_MDNS` | 是否开启局域网发现 | `true` |
| `CROSSPASTE_SERVER_INSTANCE_ID` | 服务端设备 ID | `crosspaste-server` |
| `CROSSPASTE_SERVER_DEVICE_NAME` | 客户端看到的设备名 | — |
| `CROSSPASTE_SERVER_MAX_BODY_BYTES` | 请求体上限 | `64MiB` |

> **注意**：`PUBLIC_HOST`、`NETWORK_INTERFACE` 等可选项不需要配置时，应删除或注释对应行，不要写成空值，否则 Clap 会尝试解析空字符串。

---

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
| GET | `/v1/clients` | 查看已配对客户端（需管理鉴权） |

---

## 持久化与文件同步

| 项 | 说明 |
| --- | --- |
| 数据库 | `data/crosspaste.db`，存储密钥、客户端公钥、设置、管理员、会话、审计、剪贴板元数据与文件分块 |
| 迁移 | 旧版 `data/hub-state.json` 首次启动自动导入 SQLite，并重命名为 `hub-state.json.migrated` |
| 配对状态 | 服务端私钥与客户端公钥持久化后，正常重启无需重新配对 |
| 文件传输 | 图片与文件同时支持原版 push / pull，默认 1 MiB 分块 |
| 分发策略 | 服务端为文件分配全局 pasteId，缓存完整内容后再向其他客户端同步 |
| 运维注意 | 生产环境需监控并定期清理 `data/transfers`，避免磁盘持续增长 |

---

## 后台管理

| 模块 | 能力 |
| --- | --- |
| 仪表盘 | 服务版本、配对设备数、在线隧道、数据库位置 |
| 同步设置 | 加密、中继、文件大小限制、各剪贴板类型全局开关 |
| 设备管理 | 查看或移除已配对客户端 |
| 设备详情 | 设备名、平台版本、客户端版本、地址、在线状态、最后心跳 |
| 配对中心 | 网页实时显示客户端发起的 6 位 SAS，并可生成扫码二维码 |
| 安全设置 | 修改密码、配置或关闭 TOTP MFA |
| 审计日志 | 登录、改密、MFA、设置修改、设备移除 |
| 运行日志 | SQLite 持久化 HTTP / 同步 / 配对 / 异常请求，后台每 3 秒刷新 |
| 日志分类 | 按路径分为 API 日志与同步日志，支持成功 / 异常筛选 |
| 设置中心 | 同步策略与安全中心归入二级导航；系统设置可调整请求日志保留上限（默认 10,000 条） |

---

## 开发验证

```bash
cargo fmt
cargo test
cargo build --release
```

---

## 说明

本仓库为 **纯 AI Vibe Coding** 实验性作品：架构、协议兼容、管理后台与部署脚本均由 AI 协作完成。适合自托管验证与二次研究；生产使用前请自行评估安全与稳定性。
