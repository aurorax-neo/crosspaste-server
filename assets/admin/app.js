const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

let currentUser = null;
let settings = {};
let mfaChallengeActive = false;
let requestLogs = [];
let pairingTimer = null;
let pairingCountdownTimer = null;
let activePairingChallenge = null;
let logTimer = null;
let presenceTimer = null;
let pairingQrCode = null;
let currentPage = "overview";
let pageLoadToken = 0;

const POLL_MS = {
  presence: 10000,
  pairingIdle: 4000,
  pairingActive: 2000,
  logs: 5000,
};

const inflightGet = new Map();
const inflightLoaders = new Map();

const settingDefinitions = {
  encrypt_sync: ["加密同步", "传输内容使用配对密钥加密", "SEC"],
  limit_file_size: ["同步文件大小限制", "阻止超过限制的文件和图片", "LIM"],
  max_file_size_mb: ["最大同步文件大小", "单位 MB，允许 1-102400", "MB"],
  clipboard_relay: ["启用剪贴板中继", "允许客户端通过服务端同步内容", "HUB"],
  sync_text: ["文本", "纯文本剪贴板", "TXT"],
  sync_url: ["链接", "URL 与链接内容", "URL"],
  sync_html: ["HTML", "网页富格式内容", "HTM"],
  sync_rtf: ["富文本", "RTF 格式内容", "RTF"],
  sync_image: ["图片", "图片与截图", "IMG"],
  sync_file: ["文件", "文件和目录", "FIL"],
  sync_color: ["颜色", "颜色值剪贴板", "CLR"],
};

function canBackgroundPoll() {
  return Boolean(currentUser) && !document.hidden;
}

async function api(url, options = {}) {
  const method = String(options.method || "GET").toUpperCase();
  const isGet = method === "GET" && !options.body;
  if (isGet && inflightGet.has(url)) {
    return inflightGet.get(url);
  }

  const request = (async () => {
    const response = await fetch(url, {
      credentials: "same-origin",
      ...options,
      headers: { "content-type": "application/json", ...(options.headers || {}) },
    });
    if (response.status === 204) return null;
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.message || `请求失败 (${response.status})`);
    return body;
  })();

  if (isGet) {
    inflightGet.set(url, request);
    try {
      return await request;
    } finally {
      if (inflightGet.get(url) === request) inflightGet.delete(url);
    }
  }

  return request;
}

function withLoader(key, task) {
  if (inflightLoaders.has(key)) return inflightLoaders.get(key);
  const promise = Promise.resolve()
    .then(task)
    .finally(() => {
      if (inflightLoaders.get(key) === promise) inflightLoaders.delete(key);
    });
  inflightLoaders.set(key, promise);
  return promise;
}

function toast(message) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.add("show");
  clearTimeout(node.timer);
  node.timer = setTimeout(() => node.classList.remove("show"), 2800);
}

function showRoot(view) {
  ["loginView", "passwordView", "appView"].forEach((id) => {
    $("#" + id).hidden = id !== view;
  });
}

async function bootstrap() {
  try {
    currentUser = await api("/api/admin/me");
    if (currentUser.mustChangePassword) showRoot("passwordView");
    else await enterConsole();
  } catch {
    showRoot("loginView");
  }
}

async function enterConsole() {
  showRoot("appView");
  $("#operatorName").textContent = currentUser.username;
  renderMfaState();
  await loadDashboard({ silent: true });
  startPresencePolling();
}

$("#loginForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = Object.fromEntries(new FormData(form));
  try {
    const result = await api("/api/admin/login", { method: "POST", body: JSON.stringify(payload) });
    if (result.mfaRequired) {
      mfaChallengeActive = true;
      $("#mfaField").hidden = false;
      $("#mfaField input").required = true;
      $("#mfaField input").focus();
      toast("密码验证成功，请输入 MFA 验证码");
      return;
    }
    currentUser = result.user;
    if (currentUser.mustChangePassword) showRoot("passwordView");
    else await enterConsole();
  } catch (error) {
    toast(error.message);
  }
});

$$('#loginForm input[name="username"], #loginForm input[name="password"]').forEach((input) => {
  input.addEventListener("input", () => {
    if (!mfaChallengeActive) return;
    mfaChallengeActive = false;
    $("#mfaField").hidden = true;
    $("#mfaField input").required = false;
    $("#mfaField input").value = "";
  });
});

$("#passwordForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/api/admin/password", { method: "POST", body: JSON.stringify(Object.fromEntries(new FormData(event.currentTarget))) });
    toast("密码修改成功，请重新登录");
    setTimeout(() => location.reload(), 900);
  } catch (error) {
    toast(error.message);
  }
});

$("#logoutButton").onclick = async () => {
  stopAllPolling();
  await api("/api/admin/logout", { method: "POST" });
  location.reload();
};

$$("nav [data-page]").forEach((button) => {
  button.onclick = () => navigate(button.dataset.page);
});
$$("[data-jump]").forEach((button) => {
  button.onclick = () => navigate(button.dataset.jump);
});

$("#settingsMenu").onclick = () => {
  const expanded = $("#settingsMenu").getAttribute("aria-expanded") === "true";
  setSettingsMenu(!expanded);
};

function setSettingsMenu(expanded) {
  $("#settingsMenu").setAttribute("aria-expanded", String(expanded));
  $("#settingsMenu").classList.toggle("open", expanded);
  $("#settingsSubnav").hidden = !expanded;
}

async function navigate(page) {
  if (currentPage === page && page !== "overview") {
    // Keep same-page clicks cheap: only re-open settings group.
    if (["settings", "sync", "security"].includes(page)) setSettingsMenu(true);
    return;
  }

  const token = ++pageLoadToken;
  currentPage = page;
  $$("nav [data-page]").forEach((button) => button.classList.toggle("active", button.dataset.page === page));
  const settingsPage = ["settings", "sync", "security"].includes(page);
  $("#settingsMenu").classList.toggle("active", settingsPage);
  if (settingsPage) setSettingsMenu(true);
  $$(".page").forEach((node) => {
    node.hidden = node.id !== page + "Page";
  });
  $("#pageTitle").textContent = {
    overview: "运行概览",
    settings: "设置中心 / 系统设置",
    sync: "设置中心 / 同步策略",
    clients: "配对设备",
    security: "设置中心 / 安全中心",
    audit: "审计日志",
    logs: "运行日志",
  }[page];

  stopPagePolling();

  try {
    if (page === "settings") await loadSystemSettings();
    if (page === "sync") await loadSettings();
    if (page === "clients") {
      await Promise.all([loadClients({ silent: true }), loadPairingStatus({ silent: true })]);
      if (token !== pageLoadToken) return;
      startPairingPolling();
    }
    if (page === "security") renderMfaState();
    if (page === "audit") await loadAudit({ silent: false });
    if (page === "logs") {
      await loadRequestLogs({ silent: true });
      if (token !== pageLoadToken) return;
      startLogPolling();
    }
  } catch (error) {
    if (token === pageLoadToken) toast(error.message);
  }
}

function stopPagePolling() {
  stopPairingPolling();
  stopLogPolling();
}

function stopAllPolling() {
  stopPresencePolling();
  stopPagePolling();
}

function startPresencePolling() {
  stopPresencePolling();
  presenceTimer = setInterval(() => {
    refreshPresence().catch(() => {});
  }, POLL_MS.presence);
}

function stopPresencePolling() {
  clearInterval(presenceTimer);
  presenceTimer = null;
}

async function refreshPresence() {
  if (!canBackgroundPoll()) return;
  const tasks = [loadDashboard({ silent: true })];
  if (currentPage === "clients") tasks.push(loadClients({ silent: true }));
  await Promise.all(tasks);
}

document.addEventListener("visibilitychange", () => {
  if (!currentUser) return;
  if (document.hidden) return;
  refreshVisiblePage().catch(() => {});
});

async function refreshVisiblePage() {
  if (!canBackgroundPoll()) return;
  if (currentPage === "overview") {
    await loadDashboard({ silent: true });
    return;
  }
  if (currentPage === "clients") {
    await Promise.all([
      loadDashboard({ silent: true }),
      loadClients({ silent: true }),
      loadPairingStatus({ silent: true }),
    ]);
    return;
  }
  if (currentPage === "logs") {
    await loadRequestLogs({ silent: true });
  }
}

async function loadDashboard({ silent = false } = {}) {
  return withLoader("dashboard", async () => {
    try {
      const data = await api("/api/admin/dashboard");
      $("#pairedCount").textContent = data.pairedClients;
      $("#onlineCount").textContent = data.onlineClients;
      $("#version").textContent = data.version;
      $("#databasePath").textContent = data.databasePath;
      renderMfaState();
      return data;
    } catch (error) {
      if (!silent) toast(error.message);
      throw error;
    }
  });
}

function renderMfaState() {
  if (!currentUser) return;
  const enabled = currentUser.mfaEnabled;
  $("#operatorSecurity").textContent = enabled ? "密码 + MFA" : "仅密码认证";
  $("#mfaOverviewTag").textContent = enabled ? "MFA 已启用" : "MFA 未启用";
  $("#mfaOverviewTag").className = "tag " + (enabled ? "good" : "warn");
  $("#securityMfaTag").textContent = enabled ? "MFA 已启用" : "MFA 未启用";
  $("#securityMfaTag").className = "tag " + (enabled ? "good" : "warn");
  $("#mfaDisabledState").hidden = enabled;
  $("#mfaEnabledState").hidden = !enabled;
  if (enabled) $("#mfaSetup").hidden = true;
}

async function loadSettings() {
  return withLoader("settings", async () => {
    settings = await api("/api/admin/settings");
    renderSettings("#generalSettings", ["encrypt_sync", "limit_file_size", "max_file_size_mb", "clipboard_relay"]);
    renderSettings("#typeSettings", ["sync_text", "sync_url", "sync_html", "sync_rtf", "sync_image", "sync_file", "sync_color"]);
    return settings;
  });
}

async function loadSystemSettings() {
  return withLoader("system-settings", async () => {
    settings = await api("/api/admin/settings");
    $("#logRetentionCount").value = settings.log_retention_count || "10000";
    return settings;
  });
}

$("#saveSystemSettings").onclick = async () => {
  const value = $("#logRetentionCount").value;
  try {
    await api("/api/admin/settings", { method: "PUT", body: JSON.stringify({ log_retention_count: value }) });
    toast("系统设置已保存，日志保留策略已生效");
  } catch (error) {
    toast(error.message);
  }
};

function renderSettings(target, keys) {
  $(target).innerHTML = keys
    .map((key) => {
      const [title, description, icon] = settingDefinitions[key];
      const control =
        key === "max_file_size_mb"
          ? `<input type="number" min="1" max="102400" data-setting="${key}" value="${escapeHtml(settings[key] || "512")}">`
          : `<button type="button" class="switch ${settings[key] !== "false" ? "on" : ""}" data-setting="${key}" aria-label="${title}"></button>`;
      return `<div class="setting-row"><span class="setting-icon">${icon}</span><div><strong>${title}</strong><div class="row-meta">${description}</div></div>${control}</div>`;
    })
    .join("");
  $$(target + " .switch").forEach((button) => {
    button.onclick = () => button.classList.toggle("on");
  });
}

$("#saveSettings").onclick = async () => {
  const payload = {};
  $$("[data-setting]").forEach((node) => {
    payload[node.dataset.setting] = node.matches(".switch") ? String(node.classList.contains("on")) : node.value;
  });
  try {
    await api("/api/admin/settings", { method: "PUT", body: JSON.stringify(payload) });
    toast("同步策略已保存");
  } catch (error) {
    toast(error.message);
  }
};

$("#toggleAllTypes").onclick = () => {
  $("#typeSettings").querySelectorAll(".switch").forEach((button) => button.classList.add("on"));
};

async function loadClients({ silent = false } = {}) {
  return withLoader("clients", async () => {
    try {
      const clients = await api("/api/admin/clients");
      $("#clientCountTag").textContent = `${clients.length} 台`;
      $("#clientList").innerHTML = clients.length
        ? clients.map(renderClient).join("")
        : `<div class="table-empty">暂无已配对设备</div>`;
      $$("[data-remove]").forEach((button) => {
        button.onclick = async () => {
          if (!confirm("确认移除此设备？该设备需要重新配对。")) return;
          try {
            await api(`/api/admin/clients/${button.dataset.remove}`, { method: "DELETE" });
            toast("设备已移除");
            await Promise.all([loadClients({ silent: true }), loadDashboard({ silent: true })]);
          } catch (error) {
            toast(error.message);
          }
        };
      });
      return clients;
    } catch (error) {
      if (!silent) toast(error.message);
      throw error;
    }
  });
}

$("#refreshClients").onclick = async () => {
  const button = $("#refreshClients");
  if (button.disabled) return;
  button.disabled = true;
  button.textContent = "刷新中...";
  try {
    await Promise.all([
      loadClients({ silent: false }),
      loadPairingStatus({ silent: false }),
      loadDashboard({ silent: true }),
    ]);
    toast("设备状态已刷新");
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
    button.textContent = "刷新设备";
  }
};

function renderClient(client) {
  const platform = platformInfo(client);
  const address = client.addresses.length
    ? `${client.addresses.join(", ")}${client.port ? `:${client.port}` : ""}`
    : "未上报网络地址";
  const detail = [client.appVersion && `CrossPaste ${client.appVersion}`, client.architecture, client.userName]
    .filter(Boolean)
    .join(" · ");
  return `<article class="device-card ${client.online ? "online" : "offline"}"><div class="device-main"><div class="platform-icon ${platform.className}">${platform.symbol}</div><div class="device-identity"><div class="device-title"><strong>${escapeHtml(client.deviceName)}</strong>${client.isServer ? '<span class="tag server">服务端</span>' : ""}</div><span>${escapeHtml(platform.label)}</span></div><span class="presence ${client.online ? "good" : "bad"}">${client.online ? "同步正常" : "离线"}</span>${client.isServer ? "" : `<button class="row-action" data-remove="${encodeURIComponent(client.appInstanceId)}">移除</button>`}</div><div class="device-details"><div><span>实例 ID</span><strong>${escapeHtml(client.appInstanceId)}</strong></div><div><span>系统信息</span><strong>${escapeHtml(detail || "未上报")}</strong></div><div><span>网络地址</span><strong>${escapeHtml(address)}</strong></div><div><span>最后在线</span><strong>${formatLastSeen(client.lastSeenMs)}</strong></div>${client.pairedAtMs ? `<div><span>配对时间</span><strong>${new Date(client.pairedAtMs).toLocaleString()}</strong></div>` : ""}</div></article>`;
}

function platformInfo(client) {
  const name = (client.platformName || "").toLowerCase();
  if (name.includes("android")) return { className: "android", symbol: "A", label: `Android ${client.platformVersion || ""}`.trim() };
  if (name.includes("windows")) return { className: "windows", symbol: "W", label: `Windows ${client.platformVersion || ""}`.trim() };
  if (name.includes("mac") || name.includes("darwin")) return { className: "apple", symbol: "M", label: `macOS ${client.platformVersion || ""}`.trim() };
  if (name.includes("linux")) return { className: "linux", symbol: "L", label: `Linux ${client.platformVersion || ""}`.trim() };
  return { className: "unknown", symbol: "?", label: client.platformName || "未知平台" };
}

function formatLastSeen(value) {
  if (!value) return "暂无心跳";
  const seconds = Math.max(0, Math.floor((Date.now() - value) / 1000));
  if (seconds < 10) return "刚刚";
  if (seconds < 60) return `${seconds} 秒前`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`;
  return new Date(value).toLocaleString();
}

async function loadPairingStatus({ silent = true } = {}) {
  return withLoader("pairing", async () => {
    try {
      const data = await api("/api/admin/pairing");
      renderPairing(data.challenges[0]);
      schedulePairingPolling();
      return data;
    } catch (error) {
      if (!silent) toast(error.message);
      throw error;
    }
  });
}

function renderPairing(challenge, qrDataUri = null) {
  activePairingChallenge = challenge || null;
  $("#pairingEmpty").hidden = Boolean(challenge);
  $("#pairingChallenge").hidden = !challenge;
  if (!challenge) {
    stopPairingCountdown();
    pairingQrCode = null;
    return;
  }
  $("#pairingCode").textContent = challenge.code;
  $("#pairingClient").textContent = challenge.clientId;
  $("#pairingType").textContent = challenge.kind === "sas-v2" ? "客户端 SAS 验证" : "扫码 / 验证码配对";
  if (qrDataUri) pairingQrCode = { code: challenge.code, data: qrDataUri };
  const activeQr = pairingQrCode?.code === challenge.code ? pairingQrCode.data : null;
  $("#pairingQr").hidden = !activeQr;
  if (activeQr) $("#pairingQr").src = activeQr;
  startPairingCountdown();
}

function startPairingCountdown() {
  stopPairingCountdown();
  updatePairingCountdown();
  pairingCountdownTimer = setInterval(updatePairingCountdown, 250);
}

function stopPairingCountdown() {
  clearInterval(pairingCountdownTimer);
  pairingCountdownTimer = null;
}

function updatePairingCountdown() {
  if (!activePairingChallenge) return;
  const remainingMs = activePairingChallenge.expiresAtMs - Date.now();
  if (remainingMs <= 0) {
    activePairingChallenge = null;
    stopPairingCountdown();
    $("#pairingChallenge").hidden = true;
    $("#pairingEmpty").hidden = false;
    $("#pairingEmpty").textContent = "配对码已失效，等待新的配对请求";
    pairingQrCode = null;
    schedulePairingPolling();
    return;
  }
  $("#pairingCountdown").textContent = `${Math.ceil(remainingMs / 1000)} 秒后失效`;
}

function startPairingPolling() {
  schedulePairingPolling(true);
}

function schedulePairingPolling(forceRestart = false) {
  if (currentPage !== "clients") {
    stopPairingPolling();
    return;
  }
  const nextMs = activePairingChallenge ? POLL_MS.pairingActive : POLL_MS.pairingIdle;
  if (!forceRestart && pairingTimer && pairingTimer.intervalMs === nextMs) return;
  stopPairingPolling(false);
  pairingTimer = setInterval(() => {
    if (!canBackgroundPoll() || currentPage !== "clients") return;
    loadPairingStatus({ silent: true }).catch(() => {});
  }, nextMs);
  pairingTimer.intervalMs = nextMs;
}

function stopPairingPolling(clearCountdown = true) {
  clearInterval(pairingTimer);
  pairingTimer = null;
  if (clearCountdown) stopPairingCountdown();
}

$("#createPairing").onclick = async () => {
  const button = $("#createPairing");
  if (button.disabled) return;
  button.disabled = true;
  try {
    const data = await api("/api/admin/pairing", { method: "POST" });
    renderPairing(
      { code: data.code, clientId: "等待扫码设备", kind: "token-v1", expiresAtMs: data.expiresAtMs },
      data.qrDataUri,
    );
    schedulePairingPolling(true);
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
  }
};

$("#securityPasswordForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/api/admin/password", { method: "POST", body: JSON.stringify(Object.fromEntries(new FormData(event.currentTarget))) });
    toast("密码已修改，请重新登录");
    setTimeout(() => location.reload(), 900);
  } catch (error) {
    toast(error.message);
  }
});

$("#setupMfa").onclick = async () => {
  try {
    const data = await api("/api/admin/mfa/setup", { method: "POST" });
    $("#mfaQr").src = data.qrDataUri;
    $("#mfaSecret").value = data.secret;
    $("#mfaSetup").hidden = false;
  } catch (error) {
    toast(error.message);
  }
};

$("#enableMfa").onclick = async () => {
  try {
    await api("/api/admin/mfa/enable", { method: "POST", body: JSON.stringify({ code: $("#mfaEnableCode").value }) });
    currentUser = await api("/api/admin/me");
    renderMfaState();
    toast("MFA 已启用");
  } catch (error) {
    toast(error.message);
  }
};

$("#disableMfa").onclick = async () => {
  try {
    await api("/api/admin/mfa/disable", {
      method: "POST",
      body: JSON.stringify({ password: $("#disableMfaPassword").value, code: $("#disableMfaCode").value }),
    });
    currentUser = await api("/api/admin/me");
    renderMfaState();
    toast("MFA 已关闭");
  } catch (error) {
    toast(error.message);
  }
};

async function loadAudit({ silent = false } = {}) {
  return withLoader("audit", async () => {
    try {
      const logs = await api("/api/admin/audit");
      $("#auditList").innerHTML = logs.length
        ? logs
            .map(
              (log) =>
                `<div class="audit-row"><div><div class="row-title">${escapeHtml(actionName(log.action))}</div><div class="row-meta"><span>${escapeHtml(log.username || "系统")}</span><span>${new Date(log.createdAtMs).toLocaleString()}</span><span>${escapeHtml(log.remoteAddr || "本地")}</span></div><div class="row-meta">${escapeHtml(log.detail)}</div></div><span class="tag">#${log.id}</span></div>`,
            )
            .join("")
        : `<div class="table-empty">暂无审计日志</div>`;
      return logs;
    } catch (error) {
      if (!silent) toast(error.message);
      throw error;
    }
  });
}

$("#refreshAudit").onclick = async () => {
  const button = $("#refreshAudit");
  if (button.disabled) return;
  button.disabled = true;
  try {
    await loadAudit({ silent: false });
  } finally {
    button.disabled = false;
  }
};

async function loadRequestLogs({ silent = true } = {}) {
  return withLoader("logs", async () => {
    try {
      requestLogs = await api("/api/admin/logs");
      renderRequestLogs();
      return requestLogs;
    } catch (error) {
      if (!silent) toast(error.message);
      throw error;
    }
  });
}

function startLogPolling() {
  stopLogPolling();
  logTimer = setInterval(() => {
    if (!canBackgroundPoll() || currentPage !== "logs") return;
    loadRequestLogs({ silent: true }).catch(() => {});
  }, POLL_MS.logs);
}

function stopLogPolling() {
  clearInterval(logTimer);
  logTimer = null;
}

function renderRequestLogs() {
  const category = $("#logCategory .active").dataset.logCategory;
  const status = $("#logStatus").value;
  const apiLogs = requestLogs.filter((log) => !isSyncLog(log));
  const syncLogs = requestLogs.filter(isSyncLog);
  $("#apiLogCount").textContent = apiLogs.length;
  $("#syncLogCount").textContent = syncLogs.length;
  const categoryLogs = category === "sync" ? syncLogs : apiLogs;
  const logs = categoryLogs.filter((log) =>
    status === "all" ? true : status === "error" ? log.status >= 400 : log.status < 400,
  );
  $("#requestLogList").innerHTML = logs.length
    ? logs
        .map(
          (log) =>
            `<div class="log-row"><span><b class="http-status ${log.status >= 400 ? "error" : "ok"}">${log.status}</b></span><span><strong>${escapeHtml(log.method)}</strong> ${escapeHtml(log.path)}${log.secure ? '<em class="secure-mark">加密</em>' : ""}</span><span>${escapeHtml(log.clientId || "-")}<small>→ ${escapeHtml(log.targetId || "-")}</small></span><span>${escapeHtml(log.remoteAddr)}</span><span>${log.elapsedMs} ms</span><span>${new Date(log.createdAtMs).toLocaleString()}</span></div>`,
        )
        .join("")
    : `<div class="table-empty">暂无符合条件的日志</div>`;
}

function isSyncLog(log) {
  return ["/sync/", "/pull/", "/r/", "/p/"].some((prefix) => log.path.startsWith(prefix));
}

$("#refreshLogs").onclick = async () => {
  const button = $("#refreshLogs");
  if (button.disabled) return;
  button.disabled = true;
  try {
    await loadRequestLogs({ silent: false });
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
  }
};
$("#logStatus").onchange = renderRequestLogs;
$$("[data-log-category]").forEach((button) => {
  button.onclick = () => {
    $$("[data-log-category]").forEach((item) => item.classList.toggle("active", item === button));
    renderRequestLogs();
  };
});

function actionName(action) {
  return (
    {
      login: "管理员登录",
      login_failed: "登录失败",
      password_changed: "密码修改",
      mfa_enabled: "启用 MFA",
      mfa_disabled: "关闭 MFA",
      settings_updated: "更新同步策略",
      client_removed: "移除配对设备",
      pairing_code_created: "生成配对码",
    }[action] || action
  );
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character]);
}

bootstrap();
