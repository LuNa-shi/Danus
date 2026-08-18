const $ = (id) => document.getElementById(id);

function replaceMarkupIfChanged(element, markup) {
  if (element.__danusMarkup === markup) return false;
  element.innerHTML = markup;
  element.__danusMarkup = markup;
  return true;
}

const state = {
  csrf: null,
  current: null,
  project: null,
  projects: [],
  files: [],
  messages: [],
  mainAgentEvents: [],
  mainAgentEventLastId: 0,
  workers: [],
  logs: [],
  logMetaByWorker: {},
  logErrorsByWorker: {},
  logsRefreshing: null,
  facts: { nodes: [], edges: [] },
  memory: { total: 0, channels: [] },
  reports: { files: [] },
  outputs: { files: [] },
  runtime: {},
  config: {},
  orchestration: {},
  activeWorker: null,
  drawerViews: {},
  factCy: null,
  factGraphSignature: null,
  selectedFactId: null,
  pendingMessage: null,
  timer: null,
  pendingTimer: null,
  toastTimer: null,
  refreshingProject: null,
  pendingRefreshingProject: null,
  reclaimPlan: null,
  reclaimTarget: "",
};

const START_RUN_MESSAGE = "The operator requested starting the current bounded Project Run. Inspect the current Project state, then use `danus-web-agent start` to activate the assigned Worker swarm through the authenticated lifecycle broker. Report the broker result.";
const STOP_RUN_MESSAGE = "The operator requested a graceful stop for the current Project Run. Use `danus-web-agent stop` now so the authenticated lifecycle broker performs the stop, then report the result.";

function lifecycleIntentMessage(action, worker) {
  const target = worker ? ` Worker ${worker}` : " all Workers";
  const command = `danus-web-agent ${action}${worker ? ` ${worker}` : ""}`;
  return `The operator requested ${action} for${target}. Inspect current Project state, then use \`${command}\` through the authenticated host lifecycle broker. Preserve existing assignments and report the exact broker result.`;
}

function currentPendingMessage() {
  return state.pendingMessage?.project_id === state.current ? state.pendingMessage : null;
}

function startPendingPolling() {
  if (!currentPendingMessage()) return;
  setComposerBusy(true);
  window.clearInterval(state.pendingTimer);
  state.pendingTimer = window.setInterval(() => {
    refreshPendingMessages().catch(() => {});
  }, 1500);
  refreshPendingMessages().catch(() => {});
}

function stopPendingPolling() {
  window.clearInterval(state.pendingTimer);
  state.pendingTimer = null;
  setComposerBusy(false);
}

async function api(path, opts = {}) {
  const headers = {
    ...(opts.headers || {}),
    ...(state.csrf ? { "X-CSRF-Token": state.csrf } : {}),
    ...(opts.method && opts.method !== "GET" ? { Origin: location.origin } : {}),
  };
  const response = await fetch(path, { ...opts, headers });
  let data = {};
  try {
    data = await response.json();
  } catch {
    data = {};
  }
  if (!response.ok) {
    const error = new Error(data.detail || `HTTP ${response.status}`);
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[char]);
}

function notify(message, tone = "") {
  const toast = $("toast");
  if (!toast) return;
  toast.textContent = message;
  toast.className = `toast is-visible ${tone}`;
  window.clearTimeout(state.toastTimer);
  state.toastTimer = window.setTimeout(() => {
    toast.className = "toast";
  }, 3400);
}

function showConsole() {
  $("login-panel").hidden = true;
  $("console").hidden = false;
  $("logout").hidden = false;
  $("auth-state").innerHTML = '<i></i>已连接';
  $("auth-state").classList.add("is-connected");
}

function availableWorkerModels() {
  const rows = state.config.worker_models || state.config.models || [];
  return Array.isArray(rows) ? rows.map((row) => typeof row === "string" ? { id: row, selectable: true } : row).filter((row) => row?.id) : [];
}

function defaultWorkerModel() {
  return state.config.default_worker_model || state.config.defaults?.worker_model || availableWorkerModels().find((model) => model.selectable !== false)?.id || "";
}

function defaultParallelWorkers() {
  const value = Number(state.config.default_max_parallel_workers || state.config.limits?.default_max_parallel_workers || 1);
  return Number.isFinite(value) ? Math.max(1, Math.min(8, value)) : 1;
}

function renderConfiguration() {
  const select = $("model");
  if (!select) return;
  const models = availableWorkerModels();
  const selectable = models.filter((model) => model.selectable !== false);
  select.innerHTML = `<option value="">跟随服务端默认${defaultWorkerModel() ? ` · ${esc(defaultWorkerModel())}` : ""}</option>` + selectable.map((model) => `<option value="${esc(model.id)}">${esc(model.id)}</option>`).join("");
  const unavailable = models.filter((model) => model.selectable === false);
  const help = $("model-help");
  if (help) help.textContent = unavailable.length ? `已读取 ${models.length} 个模型；${unavailable.length} 个非文本模型不会用于 Worker。` : (models.length ? `已从服务端读取 ${models.length} 个可用 Worker 模型。` : "模型目录暂不可用，将跟随服务端默认。 ");
  const parallel = $("max-parallel-workers");
  if (parallel) parallel.value = String(defaultParallelWorkers());
  const main = state.config.main_agent || {};
  const strategy = state.config.strategy || {};
  const mode = $("main-agent-mode");
  if (mode) mode.innerHTML = `<span class="status-dot online"></span><span><strong>${esc(main.backend || state.config.main_agent_backend || "server")}</strong> Main Agent · strategy ${esc(strategy.transport || state.config.strategy_transport || "server")}</span>`;
}

async function loadConfiguration() {
  try {
    state.config = await api("/api/config");
  } catch {
    state.config = {};
  }
  renderConfiguration();
}

const RAIL_PREF_KEY = "danus:rail-widths:v1";

function railPreferences() {
  try {
    return JSON.parse(window.localStorage.getItem(RAIL_PREF_KEY) || "{}") || {};
  } catch {
    return {};
  }
}

function setRailWidth(kind, width, persist = false) {
  const bounds = kind === "project" ? [168, 360] : [210, 480];
  const value = Math.max(bounds[0], Math.min(bounds[1], Math.round(Number(width) || bounds[0])));
  document.documentElement.style.setProperty(kind === "project" ? "--project-rail-width" : "--worker-rail-width", `${value}px`);
  if (persist) {
    const prefs = railPreferences();
    prefs[kind] = value;
    window.localStorage.setItem(RAIL_PREF_KEY, JSON.stringify(prefs));
  }
  return value;
}

function restoreRailWidths() {
  const prefs = railPreferences();
  if (prefs.project) setRailWidth("project", prefs.project);
  if (prefs.worker) setRailWidth("worker", prefs.worker);
}

function bindRailResizer(id, kind) {
  const handle = $(id);
  if (!handle || handle.dataset.bound === "true") return;
  handle.dataset.bound = "true";
  const target = () => kind === "project" ? document.querySelector(".sidebar") : document.querySelector(".worker-rail");
  let startX = 0;
  let startWidth = 0;
  const move = (event) => {
    const delta = event.clientX - startX;
    setRailWidth(kind, startWidth + (kind === "project" ? delta : -delta));
  };
  const finish = (event) => {
    handle.releasePointerCapture?.(event.pointerId);
    window.removeEventListener("pointermove", move);
    window.removeEventListener("pointerup", finish);
    const node = target();
    if (node) setRailWidth(kind, node.getBoundingClientRect().width, true);
    document.body.classList.remove("is-resizing-rail");
  };
  handle.addEventListener("pointerdown", (event) => {
    const node = target();
    if (!node) return;
    startX = event.clientX;
    startWidth = node.getBoundingClientRect().width;
    handle.setPointerCapture?.(event.pointerId);
    document.body.classList.add("is-resizing-rail");
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", finish);
  });
  handle.addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowRight", "Home"].includes(event.key)) return;
    event.preventDefault();
    const node = target();
    if (!node) return;
    if (event.key === "Home") return void setRailWidth(kind, kind === "project" ? 210 : 250, true);
    const screenDelta = event.key === "ArrowRight" ? 16 : -16;
    setRailWidth(kind, node.getBoundingClientRect().width + (kind === "project" ? screenDelta : -screenDelta), true);
  });
}

function formatTime(timestamp) {
  if (!timestamp) return "刚刚";
  return new Intl.DateTimeFormat("zh-CN", { hour: "2-digit", minute: "2-digit" }).format(new Date(Number(timestamp) * 1000));
}

function formatBytes(bytes) {
  const size = Number(bytes || 0);
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1024 / 1024).toFixed(1)} MB`;
}

function initials(value) {
  const text = String(value || "D").trim();
  return text.slice(0, 2).toUpperCase();
}

function roleName(worker) {
  const role = String(worker?.role || worker?.worker || "worker").toLowerCase();
  return role.startsWith("xhigh") ? "证明 worker" : "探索 worker";
}

function roleDescription(worker) {
  const role = String(worker?.role || worker?.worker || "").toLowerCase();
  return role.startsWith("xhigh") ? "深度推理 · lemma 验证" : "快速探索 · 反例与线索";
}

function processIdentityLabel(worker) {
  const identity = String(worker?.process_identity || "unknown").toLowerCase();
  return ({
    matched: "matched · 已验证",
    mismatch: "mismatch · PID 不匹配",
    dead: "dead · 无存活进程",
    unknown: "unknown · 无法验证",
  })[identity] || `${identity} · 未知状态`;
}

function processIdentityClass(worker) {
  const identity = String(worker?.process_identity || "unknown").toLowerCase();
  return ["matched", "mismatch", "dead", "unknown"].includes(identity) ? identity : "unknown";
}

function workerDesiredState(worker) {
  if (worker?.stop_requested) return { key: "stopped", label: "Graceful stop requested" };
  if (worker?.pause_requested) return { key: "paused", label: "Pause after round requested" };
  const desired = String(worker?.desired_state || "running").toLowerCase();
  return ({
    stopped: { key: "stopped", label: "Graceful stop requested" },
    paused: { key: "paused", label: "Pause after round requested" },
    running: { key: "running", label: "Running" },
  })[desired] || { key: desired, label: desired };
}

function workerPid(worker) {
  const pid = Number(worker?.pid);
  return Number.isInteger(pid) && pid > 0 ? String(pid) : "—";
}

function workerStatus(worker) {
  const stateName = String(worker?.state || "").toLowerCase();
  const persistedState = String(worker?.persisted_state || "").toLowerCase();
  const recordedActiveState = stateName === "stale" ? persistedState : stateName;
  const labelName = String(worker?.label || "").toLowerCase();
  if (worker?.process_identity === "mismatch") return { label: "PID 不匹配", className: "error" };
  if (!worker?.alive && ["running", "retrying"].includes(recordedActiveState)) {
    return { label: recordedActiveState === "retrying" ? "重试状态已过期" : "运行状态已过期", className: "attention" };
  }
  if (worker?.alive && worker?.stop_requested) return { label: "本轮后停止", className: "stopping" };
  if (worker?.alive && worker?.pause_requested) return { label: "本轮后暂停", className: "pausing" };
  if (worker?.alive) {
    if (stateName === "queued") return { label: "等待 API", className: "queued" };
    if (stateName === "retrying") return { label: String(worker?.last_error || "").includes("429") ? "限流退避" : "等待重试", className: "attention" };
    if (labelName === "stuck?") return { label: "需要关注", className: "attention" };
    return { label: "执行中", className: "working" };
  }
  if (worker?.process_identity === "unknown" && ["running", "retrying"].includes(stateName)) {
    return { label: "进程身份未知", className: "attention" };
  }
  const labels = {
    created: "已配置",
    idle: worker?.pause_requested ? "已暂停" : "空闲",
    stopped: "已停止",
    deadline: "到达期限",
    max_rounds: "达到轮次",
    terminated: "已终止",
    reclaimed: "已回收",
    error: "出错",
    dead: "离线",
  };
  const className = stateName === "error" ? "error" : ["deadline", "max_rounds", "stopped", "terminated", "reclaimed"].includes(stateName) ? "terminal" : "idle";
  return { label: labels[stateName] || labels[labelName] || "待命", className };
}

function workerIdentityClass(worker) {
  return String(worker?.worker || "").toLowerCase().startsWith("xhigh") ? "xhigh-avatar" : "high-avatar";
}

function compactValue(value, fallback = "—") {
  const text = String(value ?? "").trim();
  return text || fallback;
}

function shortText(value, max = 96) {
  const text = String(value ?? "").replace(/\s+/g, " ").trim();
  if (text.length <= max) return text;
  return `${text.slice(0, Math.max(0, max - 1)).trim()}…`;
}

function workerRound(worker) {
  const round = Number(worker?.round || 0);
  return Number.isFinite(round) ? round : 0;
}

function workerCurrentAction(worker) {
  const round = workerRound(worker);
  const stateName = String(worker?.state || "").toLowerCase();
  const persistedState = String(worker?.persisted_state || "").toLowerCase();
  const recordedActiveState = stateName === "stale" ? persistedState : stateName;
  if (worker?.process_identity === "mismatch") return `PID ${workerPid(worker)} 属于其他进程；状态记录已过期`;
  if (!worker?.alive && recordedActiveState === "retrying") return "没有 identity-matched retry loop；持久化重试状态已过期";
  if (!worker?.alive && recordedActiveState === "running") return "没有 identity-matched Worker loop；持久化运行状态已过期";
  if (worker?.alive && worker?.stop_requested) return `正在完成第 ${round} 轮，随后优雅停止`;
  if (worker?.alive && worker?.pause_requested) return `正在完成第 ${round} 轮，随后暂停`;
  if (stateName === "queued") return "排队等待可用 API 槽位";
  if (stateName === "retrying") {
    const wait = Math.max(0, Math.ceil(Number(worker?.next_retry_at || 0) - Date.now() / 1000));
    return wait ? `${wait}s 后重试 · 第 ${round} 轮未完成` : `准备重试 · 第 ${round} 轮未完成`;
  }
  if (worker?.alive && stateName === "running") return `正在执行第 ${round} 轮`;
  if (worker?.alive) return `在线同步 · ${compactValue(worker?.state, "working")}`;
  if (worker?.pause_requested || worker?.desired_state === "paused") return round ? `第 ${round} 轮完成，保持暂停` : "已暂停，保留现有任务与研究状态";
  if (stateName === "idle") return round ? `第 ${round} 轮完成，等待下一轮` : "等待第一轮任务";
  if (stateName === "created") return "已配置，等待 Main Agent 启动 Run";
  if (stateName === "deadline") return "运行期限已到达";
  if (stateName === "max_rounds") return "已达到最大轮次";
  if (stateName === "stopped") return "已完成优雅停止";
  if (stateName === "terminated") return "进程已强制终止";
  if (stateName === "reclaimed") return "已清理陈旧进程记录";
  if (stateName === "error") return compactValue(worker?.error, "Worker loop 报错");
  return worker?.last_fact_id ? `最近产出 fact ${worker.last_fact_id}` : "等待新任务";
}

function textFromEventValue(value) {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(textFromEventValue).join("");
  if (value && typeof value === "object") {
    for (const key of ["text", "message", "content", "output_text", "last_agent_message", "error"]) {
      const text = textFromEventValue(value[key]);
      if (text) return text;
    }
  }
  return "";
}

function normalizeLogLine(line) {
  const text = String(line ?? "").trim();
  if (!text) return "";
  if (!text.startsWith("{")) return text;
  try {
    const event = JSON.parse(text);
    const payload = event.payload || event.item || event;
    const parsed = textFromEventValue(payload);
    if (parsed) return parsed;
  } catch {
    return text;
  }
  return text;
}

function workerRoundLogGroups(workerName) {
  const groups = new Map();
  state.logs.forEach((item) => {
    if (item.worker !== workerName) return;
    const match = String(item.name || "").match(/^round_(\d+)\.log$/);
    if (!match) return;
    const round = Number(match[1]);
    if (!groups.has(round)) groups.set(round, { round, entries: [], lines: [] });
    const group = groups.get(round);
    group.entries.push(item);
    group.lines.push(...(item.lines || []));
  });
  return [...groups.values()].sort((left, right) => left.round - right.round);
}

function latestWorkerRoundSelection(workerName) {
  const groups = workerRoundLogGroups(workerName);
  return groups.length ? String(groups[groups.length - 1].round) : "all";
}

function workerLogEntries(workerName) {
  return state.logs.filter((entry) => entry.worker === workerName).slice().sort((left, right) => {
    const rank = (entry) => entry.name === "loop.log" ? 0 : entry.kind === "round" ? 1 : 2;
    const ranked = rank(left) - rank(right);
    if (ranked) return ranked;
    if (left.kind === "round" && right.kind === "round") return Number(left.round || 0) - Number(right.round || 0);
    return String(left.name || "").localeCompare(String(right.name || ""));
  });
}

function latestRawLogSelection(workerName) {
  const entries = workerLogEntries(workerName);
  const loop = entries.find((entry) => entry.name === "loop.log");
  return loop?.name || entries[entries.length - 1]?.name || "";
}

function logMetaForWorker(workerName) {
  return state.logMetaByWorker[workerName] || state.logMetaByWorker["*"] || {};
}

function logErrorForWorker(workerName) {
  return state.logErrorsByWorker[workerName] || state.logErrorsByWorker["*"] || null;
}

function applyLogProjection(projection, scopedWorker = null) {
  if (!projection || !Array.isArray(projection.entries)) return;
  if (scopedWorker) {
    state.logs = state.logs.filter((entry) => entry.worker !== scopedWorker).concat(projection.entries);
  } else {
    state.logs = projection.entries;
  }
  const meta = {
    fetched_at: projection.fetched_at || Date.now() / 1000,
    tail: projection.tail || 200,
    max_bytes: projection.max_bytes || 65536,
  };
  const workers = scopedWorker
    ? [scopedWorker]
    : [...new Set(projection.entries.map((entry) => entry.worker).filter(Boolean))];
  if (!workers.length) state.logMetaByWorker[scopedWorker || "*"] = meta;
  workers.forEach((workerName) => {
    state.logMetaByWorker[workerName] = meta;
    delete state.logErrorsByWorker[workerName];
  });
  if (!scopedWorker) {
    state.logMetaByWorker["*"] = meta;
    delete state.logErrorsByWorker["*"];
  }
}

function recordLogError(error, workerName = null) {
  state.logErrorsByWorker[workerName || "*"] = {
    message: error?.message || "日志获取失败",
    at: Date.now() / 1000,
  };
}

function workerLogUrl(projectId, workerName = null) {
  const worker = workerName ? `&worker=${encodeURIComponent(workerName)}` : "";
  return `/api/projects/${projectId}/logs?tail=200&max_bytes=65536${worker}`;
}

function pendingLogRequest(projectAtStart) {
  return state.activeWorker ? api(workerLogUrl(projectAtStart, state.activeWorker)) : Promise.resolve(null);
}

function renderRawWorkerLog(workerName, selectedName) {
  const entries = workerLogEntries(workerName);
  const entry = entries.find((item) => item.name === selectedName) || null;
  const meta = logMetaForWorker(workerName);
  const error = logErrorForWorker(workerName);
  const errorMarkup = error
    ? `<div class="log-fetch-error" role="status"><strong>日志获取失败</strong><span>${esc(error.message)}</span><small>${entries.length ? "显示上一次成功获取的 bounded snapshot" : "当前没有可回退的日志快照"}</small></div>`
    : "";
  if (!entries.length) {
    const empty = meta.fetched_at ? "尚未生成日志文件。" : "尚未获取日志；打开 Worker 后会加载 bounded tail。";
    return `${errorMarkup}<div class="raw-log-empty"><strong>${esc(empty)}</strong><span>loop.log 与 round_N.log 出现后会列在这里。</span></div>`;
  }
  const tabs = entries.map((item) => `<button class="raw-log-tab ${item.name === selectedName ? "is-active" : ""}" type="button" data-worker-log="${esc(item.name)}" aria-pressed="${item.name === selectedName ? "true" : "false"}">${esc(item.name)}${item.truncated ? " · truncated" : ""}</button>`).join("");
  if (!entry) return `${errorMarkup}<div class="raw-log-empty"><strong>所选日志不再存在。</strong><span>请选择另一个日志快照。</span></div>`;
  const refreshed = meta.fetched_at ? formatTime(meta.fetched_at) : "尚未刷新";
  const modified = entry.modified_at ? formatTime(entry.modified_at) : "未知";
  const rawBody = entry.empty
    ? '<div class="raw-log-empty"><strong>日志文件存在，但当前为空。</strong><span>Worker 可能尚未写入第一行。</span></div>'
    : entry.lines?.length
      ? `<pre class="raw-log-tail"><code>${esc(entry.lines.join("\n"))}</code></pre>`
      : '<div class="raw-log-empty"><strong>日志存在，但 bounded tail 没有返回完整行。</strong><span>可刷新后重试。</span></div>';
  return `${errorMarkup}<div class="raw-log-tabs" role="tablist" aria-label="选择 raw Worker log">${tabs}</div><div class="raw-log-metadata"><span><strong>Source</strong>${esc(entry.name)}</span><span><strong>Kind</strong>${esc(entry.kind || "other")}</span><span><strong>Size</strong>${esc(formatBytes(entry.size))}</span><span><strong>Modified</strong>${esc(modified)}</span><span><strong>Returned</strong>${esc(entry.returned_lines || 0)} lines</span><span><strong>Bounds</strong>tail ${esc(meta.tail || 200)} · ${esc(formatBytes(meta.max_bytes || 65536))}</span><span><strong>Refresh</strong>${esc(refreshed)}</span><span><strong>Truncation</strong>${entry.truncated ? "truncated" : "complete within bounds"}</span></div>${rawBody}`;
}

async function refreshWorkerLogs(workerName, options = {}) {
  if (!state.current || !workerName || state.logsRefreshing === workerName) return;
  const projectAtStart = state.current;
  state.logsRefreshing = workerName;
  renderWorkerDrawer();
  try {
    const projection = await api(workerLogUrl(projectAtStart, workerName));
    if (state.current !== projectAtStart) return;
    applyLogProjection(projection, workerName);
    if (options.notify) notify(`${workerName} 日志已刷新`, "success");
  } catch (error) {
    if (state.current === projectAtStart) {
      recordLogError(error, workerName);
      if (options.notify) notify(error.message || "日志获取失败", "error");
    }
  } finally {
    if (state.logsRefreshing === workerName) state.logsRefreshing = null;
    if (state.current === projectAtStart) renderWorkerDrawer();
  }
}

function workerLogLines(workerName) {
  const groups = workerRoundLogGroups(workerName);
  return (groups[groups.length - 1]?.lines || [])
    .map(normalizeLogLine)
    .filter(Boolean);
}

function pendingFactVerifications() {
  return state.workers.flatMap((worker) => {
    let pending = 0;
    workerLogLines(worker.worker).forEach((line) => {
      if (/mcp:\s+danus\/fact_submit started/i.test(line)) pending += 1;
      if (/mcp:\s+danus\/fact_submit.*(?:completed|failed|error)/i.test(line)) pending = Math.max(0, pending - 1);
    });
    return pending ? [{ worker: worker.worker, count: pending }] : [];
  });
}

function transcriptMarker(line) {
  const text = normalizeLogLine(line);
  const lower = text.toLowerCase();
  if (["codex", "assistant"].includes(lower)) return "agent";
  if (["exec", "apply patch"].includes(lower)) return "tool";
  if (lower === "user") return "user";
  if (/^mcp:\s/i.test(text)) return "mcp";
  if (/^(web search:|patch:\s)/i.test(text)) return "tool-inline";
  return "";
}

function transcriptBlocks(lines) {
  const raw = lines.map((line) => String(line ?? ""));
  const blocks = [];
  const isBoundary = (line) => Boolean(transcriptMarker(line));
  for (let index = 0; index < raw.length;) {
    const marker = transcriptMarker(raw[index]);
    if (marker === "agent" || marker === "user" || marker === "tool") {
      const start = index;
      index += 1;
      const body = [];
      while (index < raw.length && !isBoundary(raw[index])) body.push(raw[index++]);
      const text = body.map(normalizeLogLine).join("\n").trim();
      if (text) blocks.push({ id: `${marker}-${start}`, kind: marker, text });
      continue;
    }
    if (marker === "mcp") {
      const start = index;
      const text = normalizeLogLine(raw[index++]);
      const match = text.match(/^mcp:\s+(.+?)(?:\s+started|\s+\((completed|failed)\))$/i);
      const name = match?.[1] || text.replace(/^mcp:\s*/i, "");
      let status = match?.[2] || (/started$/i.test(text) ? "running" : "completed");
      if (status === "running" && index < raw.length) {
        const next = normalizeLogLine(raw[index]);
        if (next.toLowerCase().startsWith(`mcp: ${name.toLowerCase()}`) && /\((completed|failed)\)$/i.test(next)) {
          status = /\(failed\)$/i.test(next) ? "failed" : "completed";
          index += 1;
        }
      }
      blocks.push({ id: `mcp-${start}`, kind: "mcp", title: name, status, text: status === "completed" ? "调用已完成" : status === "failed" ? "调用失败" : "调用中" });
      continue;
    }
    if (marker === "tool-inline") {
      blocks.push({ id: `tool-${index}`, kind: "tool", title: shortText(normalizeLogLine(raw[index]), 96), status: "completed", text: normalizeLogLine(raw[index]) });
      index += 1;
      continue;
    }
    index += 1;
  }
  return blocks;
}

function toolTitle(block) {
  if (block.title) return block.title;
  const first = String(block.text || "").split("\n").find(Boolean) || "工具调用";
  const shell = first.match(/\/bin\/(?:zsh|bash|sh)\s+-lc\s+["'](.+?)["']\s+in\s+/);
  return shortText(shell?.[1] || first.replace(/\s+in\s+\/.*$/, ""), 105);
}

function renderWorkerMessage(role, text, worker) {
  const fromMainAgent = role === "main-agent";
  const avatarClass = fromMainAgent ? "main-agent-avatar" : workerIdentityClass(worker);
  const avatar = fromMainAgent ? "M" : initials(worker?.worker);
  const label = fromMainAgent ? "Main Agent" : compactValue(worker?.worker, "Worker");
  return `<article class="message-row assistant worker-message ${fromMainAgent ? "worker-assignment" : "worker-response"}"><div class="message-avatar ${avatarClass}">${esc(avatar)}</div><div class="message-content"><div class="message-meta"><strong>${esc(label)}</strong><span>${fromMainAgent ? "Delegated task" : "Worker"}</span></div><div class="message-bubble">${renderMarkdown(text)}</div></div></article>`;
}

function renderTranscript(lines, worker, options = {}) {
  const blocks = transcriptBlocks(lines);
  const visible = blocks.filter((block) => block.kind !== "user");
  if (options.includeAssignment !== false && worker?.assigned === true && String(worker.task || "").trim()) {
    visible.unshift({ id: "assignment", kind: "assignment", text: worker.task });
  }
  const rendered = visible.map((block) => {
    if (block.kind === "assignment") return renderWorkerMessage("main-agent", block.text, worker);
    if (block.kind === "agent") {
      return renderWorkerMessage("worker", block.text, worker);
    }
    const isMcp = block.kind === "mcp";
    const failed = block.status === "failed" || /(?:failed|error|non-zero|exited with)/i.test(block.text || "");
    const status = failed ? "失败" : block.status === "running" ? "运行中" : "完成";
    const body = isMcp ? `<div class="trace-markdown">${renderMarkdown(block.text)}</div>` : `<pre><code>${esc(block.text)}</code></pre>`;
    return `<details class="trace-tool ${isMcp ? "mcp" : "shell"} ${failed ? "failed" : ""}" data-trace-id="${esc(`${options.idPrefix || ""}${block.id}`)}"><summary><span class="trace-tool-icon">${isMcp ? "M" : "›_"}</span><span class="trace-tool-copy"><strong>${esc(toolTitle(block))}</strong><small>${isMcp ? "Danus MCP" : "Shell / tool"}</small></span><span class="trace-tool-status">${status}</span><span class="trace-tool-chevron">⌄</span></summary><div class="trace-tool-body">${body}</div></details>`;
  }).join("");
  if (rendered || options.emptyMarkup === false) return rendered;
  return '<div class="drawer-empty"><span>⌁</span><p>还没有任务或运行记录。</p><small>Main Agent 分配任务或 Worker 开始运行后，完整对话会显示在这里。</small></div>';
}

function renderWorkerRoundTranscript(groups, selectedRound, worker) {
  const selectedGroups = selectedRound === "all" ? groups : groups.filter((group) => String(group.round) === selectedRound);
  const assignment = worker?.assigned === true && String(worker.task || "").trim()
    ? renderWorkerMessage("main-agent", worker.task, worker)
    : "";
  const rounds = selectedGroups.map((group) => {
    const transcript = renderTranscript(group.lines, worker, {
      includeAssignment: false,
      emptyMarkup: false,
      idPrefix: `round-${group.round}-`,
    });
    const sources = group.entries.map((entry) => entry.name).join(" · ");
    return `<section class="round-transcript-group" data-round="${esc(group.round)}"><div class="round-transcript-heading"><strong>第 ${esc(group.round)} 轮</strong><small>${esc(group.lines.length)} 行 · ${esc(sources)}</small></div>${transcript || '<div class="round-log-empty">本轮日志存在，但 transcript parser 没有可显示消息；请查看下方 raw tail。</div>'}</section>`;
  }).join("");
  if (assignment || rounds) return `${assignment}${rounds}`;
  return renderTranscript([], worker);
}

function statusText(status) {
  return ({
    pending: "正在发送",
    submitted: "Main Agent 处理中",
    retrying: "上游模型繁忙，正在自动续接",
    completed: "已完成",
    failed: "未完成",
  })[status] || "";
}

function inlineMarkdown(value) {
  let text = esc(value);
  text = text.replace(/`([^`\n]+)`/g, "<code>$1</code>");
  text = text.replace(/\*\*([^*\n]+)\*\*/g, "<strong>$1</strong>");
  text = text.replace(/__([^_\n]+)__/g, "<strong>$1</strong>");
  text = text.replace(/\*([^*\n]+)\*/g, "<em>$1</em>");
  text = text.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noreferrer">$1</a>');
  return text;
}

function markdownTableCells(line) {
  const value = String(line || "").trim();
  if (!value.includes("|")) return [];
  return value.replace(/^\|/, "").replace(/\|$/, "").split("|").map((cell) => cell.trim());
}

function isMarkdownTableDivider(line) {
  const cells = markdownTableCells(line);
  return cells.length > 1 && cells.every((cell) => /^:?-{3,}:?$/.test(cell));
}

function renderMarkdown(value) {
  const source = String(value || "").replace(/\\n/g, "\n").replace(/\r\n/g, "\n");
  const lines = source.split("\n");
  let html = "";
  let code = false;
  let codeLines = [];
  const listStack = [];

  const closeTopList = () => {
    const list = listStack.pop();
    if (!list) return;
    if (list.itemOpen) html += "</li>";
    html += `</${list.type}>`;
  };
  const closeLists = () => {
    while (listStack.length) closeTopList();
  };

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (line.trim().startsWith("```")) {
      if (code) {
        html += `<pre><code>${esc(codeLines.join("\n"))}</code></pre>`;
        codeLines = [];
        code = false;
      } else {
        closeLists();
        code = true;
      }
      continue;
    }
    if (code) {
      codeLines.push(line);
      continue;
    }
    if (!line.trim()) {
      closeLists();
      continue;
    }
    const tableHead = markdownTableCells(line);
    if (tableHead.length > 1 && isMarkdownTableDivider(lines[index + 1])) {
      closeLists();
      const rows = [];
      index += 2;
      while (index < lines.length && lines[index].trim()) {
        const cells = markdownTableCells(lines[index]);
        if (cells.length !== tableHead.length) break;
        rows.push(cells);
        index += 1;
      }
      index -= 1;
      html += '<div class="markdown-table-wrap"><table><thead><tr>';
      html += tableHead.map((cell) => `<th>${inlineMarkdown(cell)}</th>`).join("");
      html += "</tr></thead><tbody>";
      html += rows.map((cells) => `<tr>${cells.map((cell) => `<td>${inlineMarkdown(cell)}</td>`).join("")}</tr>`).join("");
      html += "</tbody></table></div>";
      continue;
    }
    const heading = line.match(/^(#{1,3})\s+(.+)$/);
    if (heading) {
      closeLists();
      const level = heading[1].length;
      html += `<h${level}>${inlineMarkdown(heading[2])}</h${level}>`;
      continue;
    }
    const listItem = line.match(/^([ \t]*)([-*+•]|\d+[.)、])\s+(.+)$/);
    if (listItem) {
      const indent = listItem[1].replace(/\t/g, "  ").length;
      const type = /^\d/.test(listItem[2]) ? "ol" : "ul";
      while (listStack.length && indent < listStack[listStack.length - 1].indent) closeTopList();
      if (listStack.length && indent === listStack[listStack.length - 1].indent && type !== listStack[listStack.length - 1].type) closeTopList();
      if (!listStack.length || indent > listStack[listStack.length - 1].indent) {
        html += `<${type}>`;
        listStack.push({ type, indent, itemOpen: false });
      }
      const current = listStack[listStack.length - 1];
      if (current.itemOpen) html += "</li>";
      html += `<li>${inlineMarkdown(listItem[3])}`;
      current.itemOpen = true;
      continue;
    }
    if (listStack.length && /^\s+/.test(line)) {
      html += `<br>${inlineMarkdown(line.trim())}`;
      continue;
    }
    if (/^\s*>\s?/.test(line)) {
      closeLists();
      html += `<blockquote>${inlineMarkdown(line.replace(/^\s*>\s?/, ""))}</blockquote>`;
      continue;
    }
    closeLists();
    html += `<p>${inlineMarkdown(line)}</p>`;
  }
  if (code) html += `<pre><code>${esc(codeLines.join("\n"))}</code></pre>`;
  closeLists();
  return html || '<p class="muted">暂无内容</p>';
}

function renderProjectList(rows) {
  state.projects = rows;
  $("project-count").textContent = String(rows.length);
  $("project-list").innerHTML = rows.map((project) => {
    const workers = Array.isArray(project.workers) ? project.workers : [];
    const live = workers.filter((worker) => worker.alive).length;
    return `<button class="project-item ${project.id === state.current ? "is-active" : ""}" data-project-id="${esc(project.id)}">
      <span class="project-icon">${esc(initials(project.name))}</span>
      <span class="project-item-copy"><strong>${esc(project.name)}</strong><small>${esc(project.problem || "未填写问题").slice(0, 42)}</small></span>
      <span class="project-live-count">${live || workers.length || "·"}</span>
    </button>`;
  }).join("") || '<div class="project-list-empty">还没有项目<br><span>从中间的输入框开始</span></div>';
}

async function refreshProjects() {
  const rows = await api("/api/projects");
  renderProjectList(rows);
  if (state.current && !rows.some((project) => project.id === state.current)) {
    destroyFactGraph();
    state.factGraphSignature = null;
    state.selectedFactId = null;
    state.current = null;
    state.project = null;
    $("topbar-project-name").textContent = "未选择项目";
    $("project-view").innerHTML = '<div class="empty-project-state"><div class="empty-mark"><span></span><span></span><span></span></div><p class="eyebrow">WELCOME TO DANUS</p><h1>从一个问题开始。</h1><p>创建一个项目，让 Main Agent 拆解方向，再把具体工作交给一组可观测的 workers。</p><form id="starter-form" class="starter-composer"><textarea id="starter-message" placeholder="比如：帮我研究这个猜想，先找出三个可能的证明方向……" required></textarea><div class="starter-composer-footer"><span>直接开始对话，Danus 会自动创建项目</span><button type="submit" class="primary-button">开始协作 <span aria-hidden="true">↗</span></button></div></form><button id="start-empty-project" class="link-button" type="button">或打开完整项目配置</button></div>';
    bindEmptyState();
  }
}

function bindEmptyState() {
  $("start-empty-project")?.addEventListener("click", openProjectModal);
  $("starter-form")?.addEventListener("submit", handleStarterSubmit);
}

function openProjectModal() {
  renderConfiguration();
  $("project-modal").hidden = false;
  window.setTimeout(() => $("project-name")?.focus(), 40);
}

function closeProjectModal() {
  $("project-modal").hidden = true;
}

function roleSpec() {
  const high = Math.max(0, Math.min(9, Number($("high-count")?.value || 0)));
  const xhigh = Math.max(0, Math.min(9, Number($("xhigh-count")?.value || 0)));
  const values = [];
  if (high) values.push(`high:${high}`);
  if (xhigh) values.push(`xhigh:${xhigh}`);
  const spec = values.join(",");
  $("roles").value = spec;
  return spec;
}

function shortProjectName(text) {
  const clean = String(text || "").replace(/[\n\r]+/g, " ").trim();
  const compact = clean.replace(/[“”"'，。！？!?：:]/g, "").trim();
  const slug = compact.replace(/[^A-Za-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48);
  return slug || `research-${Date.now().toString(36)}`;
}

function configuredStrategyTransport() {
  return state.config.strategy?.transport || state.config.strategy_transport || "off";
}

function mainAgentInitializationMessage({ problem, roles, model, max_parallel_workers: capacity }) {
  const strategy = configuredStrategyTransport();
  const strategyStep = strategy === "off"
    ? "Strategy consult：off（部署策略；不要调用 consult，由 Main Agent 自己形成 elaboration 与 master_guidance）"
    : `Strategy consult：${strategy}（只使用服务端配置的 transport/model，不要硬编码模型）`;
  return `请按 Danus Main Agent operating contract 初始化这个项目。\n\n项目问题：${problem}\n用户已确认 Worker roster：${roles}\nWorker 模型：${model || defaultWorkerModel() || "服务端默认"}\n资源并发上限：${capacity || defaultParallelWorkers()}（这只是 Control Plane 资源限制，不改变你的策略权力）\n${strategyStep}\n\n请先执行 Danus 的真实启动顺序：检查项目状态 → 形成 elaboration → 写入 master_guidance → 通过项目级 lifecycle CLI 为每个 Worker 写入不同或明确复用的 TASK.md。不要直接做数学，也不要启动 Worker swarm；完成后在回复中列出你实际执行成功的编排动作、每个 Worker 的任务和下一次监控条件。`;
}

async function createProject(payload) {
  const project = await api("/api/projects", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  await refreshProjects();
  await openProject(project.id);
  return project;
}

async function handleStarterSubmit(event) {
  event.preventDefault();
  const input = $("starter-message");
  const button = event.currentTarget.querySelector("button[type=submit]");
  const text = input.value.trim();
  if (!text) return;
  button.disabled = true;
  button.classList.add("is-loading");
  try {
    const setup = { name: shortProjectName(text), problem: text, roles: "high:1,xhigh:1", model: defaultWorkerModel() || null, max_parallel_workers: defaultParallelWorkers() };
    const project = await createProject(setup);
    await sendMessageText(mainAgentInitializationMessage(setup));
    notify(`已创建项目「${project.name}」`, "success");
  } catch (error) {
    notify(error.message || "项目创建失败", "error");
    button.disabled = false;
    button.classList.remove("is-loading");
  }
}

function renderProjectShell(project) {
  const model = project.model || project.worker_model || defaultWorkerModel() || "server default";
  const capacity = project.max_parallel_workers || project.config?.max_parallel_workers || defaultParallelWorkers();
  $("project-view").innerHTML = `<div class="conversation-layout">
    <section class="conversation-view">
      <header class="project-header">
        <div class="project-header-copy"><p class="eyebrow">PROJECT / ${esc(project.name)}</p><div class="project-title-row"><h1>${esc(project.name)}</h1><span id="main-status" class="status-pill idle"><i></i>Main Agent 待命</span></div><p class="project-problem">${esc(project.problem || "还没有描述问题")}</p><div class="project-config-chips"><span>Worker · ${esc(model)}</span><span>并发 · ${esc(capacity)}</span></div></div>
        <div class="project-header-actions"><button id="workers-logs-open" class="secondary-button workers-logs-button" type="button" aria-expanded="false" aria-controls="worker-rail"><span aria-hidden="true">☷</span>Workers / Logs</button><button id="run-start" class="secondary-button"><span class="button-dot"></span>启动 workers</button><button id="delete-project" class="quiet-button danger-text">删除</button></div>
      </header>
      <section class="lifecycle-controls" aria-label="Worker controls">
        <div class="lifecycle-copy"><strong>Worker controls</strong><small>当前项目的全部 Workers</small></div>
        <div class="lifecycle-actions"><button id="run-pause" class="control-button" type="button">本轮后暂停</button><button id="run-resume" class="control-button" type="button">继续运行</button><button id="run-force-stop" class="control-button danger" type="button">立即强制停止</button></div>
        <div id="lifecycle-safety" class="lifecycle-safety" role="status"></div>
      </section>
      <div id="conversation-scroll" class="conversation-scroll">
        <section id="main-agent-control" class="main-agent-control" aria-label="Main Agent orchestration state"></section>
        <div id="main-activity" class="main-activity" hidden><span class="thinking-dots"><i></i><i></i><i></i></span><span>Main Agent 会话执行中 · 正在读取真实项目状态并编排</span><span class="activity-line"></span></div>
        <div id="chat" class="message-stream"></div>
        <div class="insight-grid"><details class="insight-card"><summary><span class="summary-label"><span class="summary-icon">⌁</span>资料库</span><span id="file-count" class="summary-count">0</span></summary><div id="files" class="insight-content"></div><form id="upload-form" class="upload-form"><label class="upload-button">＋ 上传资料<input id="upload" type="file" accept=".pdf,.tex,.latex,.ltx,.md,.markdown,.txt,.text,.rst,.csv"></label></form></details><details id="fact-graph-card" class="insight-card insight-card-fact"><summary><span class="summary-label"><span class="summary-icon">◈</span>Fact Graph</span><span id="fact-count" class="summary-count">0 / 0</span></summary><div id="facts" class="insight-content insight-content-wide"></div></details><details class="insight-card"><summary><span class="summary-label"><span class="summary-icon">◎</span>共享记忆</span><span id="memory-count" class="summary-count">0</span></summary><div id="memory" class="insight-content"></div></details><details class="insight-card"><summary><span class="summary-label"><span class="summary-icon">↗</span>产物</span><span id="artifact-count" class="summary-count">0</span></summary><div id="artifacts" class="insight-content"></div></details></div>
      </div>
      <div class="composer-wrap"><form id="chat-form" class="composer"><div class="composer-top"><div class="composer-tools"><label class="composer-tool" for="attachment" title="添加资料">＋</label><select id="attachment" aria-label="选择附件"><option value="">添加资料</option></select><span class="composer-divider"></span><span class="agent-selector"><span class="mini-agent-avatar">M</span>Main Agent <span class="chevron">⌄</span></span></div><span class="composer-context">项目上下文已载入</span></div><textarea id="message" rows="1" placeholder="继续和 Main Agent 对话……" required></textarea><div class="composer-bottom"><span class="composer-hint">Enter 发送 · Shift + Enter 换行</span><button class="send-button" type="submit" aria-label="发送">↑</button></div></form></div>
    </section>
    <div id="worker-rail-resizer" class="rail-resizer rail-resizer-right" role="separator" aria-label="调整 Worker 侧栏宽度" aria-orientation="vertical" tabindex="0"></div>
    <aside id="worker-rail" class="worker-rail" aria-label="Worker fleet"><div class="rail-header"><div><p class="eyebrow">OBSERVABILITY</p><h2>Workers / Logs</h2></div><div class="rail-header-actions"><span id="worker-count" class="count-badge">0</span><button id="worker-rail-close" class="close-button worker-rail-close" type="button" aria-label="关闭 Workers / Logs">×</button></div></div><p class="rail-intro">点选一个 Worker，查看结构化 round transcript、loop.log 与 raw bounded tails。</p><div id="workers" class="worker-list"></div><div class="rail-runtime"><div class="rail-runtime-top"><span class="status-dot online"></span><span id="run-state">Run 尚未启动</span></div><div class="rail-runtime-bar"><span id="run-progress-bar"></span></div><p id="run-progress-detail">主 agent 负责方向，workers 并行推进证明。</p></div></aside>
    <aside id="worker-drawer" class="worker-drawer" hidden aria-label="Worker details"></aside>
  </div>`;
  bindProjectControls();
  bindRailResizer("worker-rail-resizer", "worker");
}

function setWorkerRailOpen(open) {
  const rail = $("worker-rail");
  const button = $("workers-logs-open");
  if (!rail || !button) return;
  rail.classList.toggle("is-open", open);
  button.setAttribute("aria-expanded", open ? "true" : "false");
  if (open) window.requestAnimationFrame(() => rail.querySelector("[data-worker]")?.focus());
}

function bindProjectControls() {
  $("chat-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    await sendMessageText($("message").value, $("attachment").value);
  });
  $("message").addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      $("chat-form").requestSubmit();
    }
  });
  $("workers").addEventListener("click", (event) => {
    const card = event.target.closest("[data-worker]");
    if (card) openWorkerDrawer(card.dataset.worker);
  });
  $("workers-logs-open").addEventListener("click", () => setWorkerRailOpen(true));
  $("worker-rail-close").addEventListener("click", () => setWorkerRailOpen(false));
  $("run-start").addEventListener("click", startRun);
  $("run-pause").addEventListener("click", pauseRun);
  $("run-resume").addEventListener("click", resumeRun);
  $("run-force-stop").addEventListener("click", forceStopRun);
  $("delete-project").addEventListener("click", deleteProject);
  $("upload-form").addEventListener("submit", handleUpload);
  $("upload").addEventListener("change", () => {
    if ($("upload").files?.length) $("upload-form").requestSubmit();
  });
  $("fact-graph-card").addEventListener("toggle", (event) => {
    if (event.currentTarget.open) window.requestAnimationFrame(mountFactGraph);
  });
  $("facts").addEventListener("click", handleFactGraphClick);
  $("facts").addEventListener("change", handleFactGraphChange);
  $("facts").addEventListener("keydown", handleFactGraphKeydown);
}

async function openProject(id) {
  if (state.timer) {
    window.clearInterval(state.timer);
    state.timer = null;
  }
  stopPendingPolling();
  state.pendingMessage = null;
  destroyFactGraph();
  state.factGraphSignature = null;
  state.selectedFactId = null;
  state.current = id;
  state.activeWorker = null;
  state.logs = [];
  state.logMetaByWorker = {};
  state.logErrorsByWorker = {};
  state.reclaimPlan = null;
  state.reclaimTarget = "";
  state.messages = [];
  state.mainAgentEvents = [];
  state.mainAgentEventLastId = 0;
  const project = await api(`/api/projects/${id}`);
  if (state.current !== id) return;
  state.project = project;
  $("topbar-project-name").textContent = project.name;
  renderProjectList(state.projects);
  renderProjectShell(project);
  await refreshProject();
  state.timer = window.setInterval(() => {
    if (!currentPendingMessage()) refreshProject().catch(() => {});
  }, 8000);
}

function mainAgentFailureMarkup(message) {
  const error = message.error || "请重试，或先检查运行环境";
  return `<div class="message-error"><strong>Main Agent 没有完成这次回复</strong><span>${esc(error)}</span></div>`;
}

function mainAgentEventLabel(type) {
  return ({
    "turn.started": "会话启动",
    "agent.progress": "Reasoning / progress summary",
    "agent.message": "Emitted progress",
    "tool.started": "Tool started",
    "tool.completed": "Tool completed",
    "turn.retry": "自动续接",
    "turn.completed": "执行完成",
    "turn.failed": "执行失败",
  })[type] || "执行事件";
}

function mainAgentEventMeta(event) {
  const values = [`event #${event.id ?? "—"}`, String(event.type || "event")];
  if (event.status) values.push(String(event.status));
  if (event.attempt != null) values.push(`attempt ${event.attempt}/${event.max_attempts || event.attempt}`);
  if (event.delay_seconds != null) values.push(`retry in ${event.delay_seconds}s`);
  if (event.duration_seconds != null) values.push(`duration ${event.duration_seconds}s`);
  if (event.message_id) values.push(`message ${String(event.message_id).slice(0, 10)}`);
  if (event.main_agent_session_id) values.push(`session ${String(event.main_agent_session_id).slice(0, 10)}`);
  if (event.run_id) values.push(`run ${String(event.run_id).slice(0, 10)}`);
  if (event.call_id) values.push(`call ${String(event.call_id).slice(0, 10)}`);
  return values.join(" · ");
}

function renderMainAgentEvents(messageId) {
  const events = state.mainAgentEvents
    .filter((event) => event.message_id === messageId);
  if (!events.length) return "";
  const orderedEvents = events.slice().sort((left, right) => Number(left.id || 0) - Number(right.id || 0));
  const message = state.messages.find((row) => row.id === messageId);
  const live = message && ["submitted", "retrying", "pending"].includes(message.status);
  const rows = orderedEvents.map((event) => {
    const type = String(event.type || "event");
    const label = mainAgentEventLabel(type);
    const tool = event.tool ? `<strong>${esc(event.tool)}</strong>` : "";
    const detail = String(event.detail || "");
    const detailMarkup = detail
      ? (type === "agent.message" ? `<div class="main-agent-event-message">${renderMarkdown(detail)}</div>` : `<pre>${esc(detail)}</pre>`)
      : '<div class="main-agent-event-empty">No additional safe detail was emitted.</div>';
    return `<li class="main-agent-event ${esc(type.replace(/\./g, "-"))}" data-event-id="${esc(event.id)}"><i></i><div><div class="main-agent-event-head"><span>${esc(label)}</span>${tool}<time>${formatTime(event.created_at)}</time></div><small class="main-agent-event-meta">${esc(mainAgentEventMeta(event))}</small>${detailMarkup}</div></li>`;
  }).join("");
  return `<details class="main-agent-events ${live ? "is-live" : ""}" open><summary><span>Emitted progress + tool trace · 执行过程</span><small>${orderedEvents.length} 个持久事件${live ? " · 实时更新" : ""}</small></summary><div class="main-agent-event-boundary"><strong>运行时提供的安全事件流</strong><span>Shows the safe progress/tool events made available by the Main Agent runtime; private chain-of-thought is not exposed.</span></div><ol>${rows}</ol></details>`;
}

function renderMessages() {
  const chat = $("chat");
  if (!chat) return;
  const scroll = $("conversation-scroll");
  const previousScrollTop = scroll?.scrollTop || 0;
  const followTail = !scroll || scroll.scrollHeight - scroll.scrollTop - scroll.clientHeight < 72;
  const messages = state.messages.slice();
  const pendingMessage = currentPendingMessage();
  const persistedPending = pendingMessage && messages.some((message) => (
    message.id !== pendingMessage.id
    && message.role === "user"
    && message.text === pendingMessage.text
    && Number(message.created_at || 0) >= Number(pendingMessage.created_at || 0) - 5
  ));
  if (pendingMessage && !persistedPending && !messages.some((message) => message.id === pendingMessage.id)) messages.push(pendingMessage);
  if (!messages.length) {
    const markup = '<div class="chat-empty"><div class="main-agent-avatar large">M</div><p class="eyebrow">MAIN AGENT</p><h2>项目已经准备好了。</h2><p>问一个问题、上传一份材料，或者让 Main Agent 先给出拆解方向。</p><div class="suggestion-row"><button data-suggestion="先分析问题，给出三个互相独立的解决方向。">先拆解问题</button><button data-suggestion="先检查现有材料中最关键的假设。">检查关键假设</button></div></div>';
    if (!replaceMarkupIfChanged(chat, markup)) return;
    chat.querySelectorAll("[data-suggestion]").forEach((button) => button.addEventListener("click", () => {
      $("message").value = button.dataset.suggestion;
      $("message").focus();
    }));
    return;
  }
  const markup = messages.map((message) => {
    const user = message.role === "user";
    const isFailed = message.status === "failed";
    const pending = message.status === "submitted" || message.status === "pending" || message.status === "retrying";
    const status = message.status === "retrying" && message.error ? message.error : statusText(message.status);
    const body = user ? `<p>${esc(message.text).replace(/\n/g, "<br>")}</p>` : (message.text ? renderMarkdown(message.text) : mainAgentFailureMarkup(message));
    const execution = user ? renderMainAgentEvents(message.id) : "";
    return `<article class="message-row ${user ? "user" : "assistant"} ${pending ? "is-pending" : ""} ${isFailed ? "is-failed" : ""}"><div class="message-avatar ${user ? "user-avatar" : "main-agent-avatar"}">${user ? "L" : "M"}</div><div class="message-content"><div class="message-meta"><strong>${user ? "你" : "Main Agent"}</strong><span>${formatTime(message.created_at)}</span>${pending ? `<span class="message-status"><i></i>${esc(status)}</span>` : ""}</div><div class="message-bubble">${body}</div>${execution}</div></article>`;
  }).join("");
  if (!replaceMarkupIfChanged(chat, markup)) return;
  if (scroll) window.requestAnimationFrame(() => {
    scroll.scrollTop = followTail ? scroll.scrollHeight : previousScrollTop;
  });
}

function renderActivity() {
  const activity = $("main-activity");
  if (!activity) return;
  activity.hidden = !currentPendingMessage();
}

function memoryKindEntry(kind) {
  const channel = (state.memory.channels || []).find((item) => String(item.kind || item.name || "").toLowerCase() === kind);
  return channel?.entries?.[0] || null;
}

function orchestrationText(value) {
  if (typeof value === "string") return value;
  if (!value || typeof value !== "object") return "";
  return value.claim || value.message || value.summary || value.evidence || value.text || "";
}

function renderMainAgentControl() {
  const container = $("main-agent-control");
  if (!container) return;
  const snapshot = state.orchestration || {};
  const main = snapshot.main_agent || snapshot.session || {};
  const total = Number(snapshot.workers_total ?? state.workers.length);
  const assigned = Number(snapshot.assigned_workers ?? state.workers.filter((worker) => worker.assigned === true).length);
  const unassigned = Array.isArray(snapshot.unassigned_workers) ? snapshot.unassigned_workers : state.workers.filter((worker) => worker.assigned === false).map((worker) => worker.worker);
  const guidance = snapshot.master_guidance || snapshot.guidance || memoryKindEntry("master_guidance");
  const elaboration = snapshot.elaboration || memoryKindEntry("elaboration");
  const sessionStatus = currentPendingMessage() ? "active" : (main.status || snapshot.main_agent_status || (state.messages.some((message) => message.role === "assistant" && message.status === "completed") ? "inactive" : "not_started"));
  const activeRun = state.runtime.run;
  const statusLabels = { active: "会话执行中", inactive: "会话可恢复", not_started: "尚未激活", failed: "上次会话失败" };
  const steps = [
    { label: "问题讨论", done: sessionStatus !== "not_started", hint: sessionStatus === "not_started" ? "等待首次 Main Agent 对话" : "项目会话已建立" },
    { label: "战略提炼", done: Boolean(elaboration), hint: elaboration ? "已有 elaboration" : "等待真实策略记录" },
    { label: "Master guidance", done: Boolean(guidance), hint: guidance ? "共享方向已记录" : "尚无共享方向" },
    { label: "Worker 分工", done: total > 0 && assigned === total, warning: assigned < total, hint: `${assigned} / ${total} 已分配` },
    { label: "监控与汇总", done: Boolean(activeRun), hint: activeRun ? `Run ${activeRun.status}` : "Run 尚未启动" },
  ];
  const runningUnassigned = Boolean(activeRun && total && assigned < total);
  const configMain = state.config.main_agent || {};
  const backend = main.backend || snapshot.main_agent_backend || configMain.backend || "server";
  container.innerHTML = `<div class="main-agent-control-head"><div class="main-agent-identity"><span class="main-agent-avatar">M</span><div><p class="eyebrow">MAIN AGENT · STRATEGIC ORCHESTRATOR</p><h2>负责 strategy、master guidance、派工与汇总</h2></div></div><div class="main-agent-session ${esc(sessionStatus)}"><i></i><span>${esc(statusLabels[sessionStatus] || sessionStatus)}</span><small>${esc(backend)}</small></div></div>
    <div class="orchestration-steps">${steps.map((step) => `<div class="orchestration-step ${step.done ? "is-done" : ""} ${step.warning ? "is-warning" : ""}"><span class="step-mark">${step.done ? "✓" : step.warning ? "!" : "·"}</span><span><strong>${esc(step.label)}</strong><small>${esc(step.hint)}</small></span></div>`).join("")}</div>
    ${runningUnassigned ? `<div class="orchestration-warning"><strong>当前 Run 在 Main Agent 完成分工前就启动了</strong><span>未分配：${esc(unassigned.join("、") || `${total - assigned} 个 workers`)}。这不是有效的 Danus 策略循环；请先在中间对话要求 Main Agent 完成 consult / guidance / assign。</span></div>` : ""}
    ${guidance ? `<details class="main-guidance"><summary><span>最新 master guidance</span><small>由 Main Agent 的策略流程写入，不是前端生成</small></summary><div>${renderMarkdown(orchestrationText(guidance))}</div></details>` : ""}`;
}

function renderWorkers() {
  const container = $("workers");
  if (!container) return;
  $("worker-count").textContent = String(state.workers.length);
  if (!state.workers.length) {
    container.innerHTML = '<div class="worker-empty"><span class="empty-worker-icon">∿</span><strong>还没有 worker</strong><p>创建项目时的 worker roster 会出现在这里。</p></div>';
    renderLifecycleControls();
    return;
  }
  container.innerHTML = state.workers.map((worker) => {
    const status = workerStatus(worker);
    const desired = workerDesiredState(worker);
    const selected = state.activeWorker === worker.worker;
    const action = workerCurrentAction(worker);
    const task = worker.assigned === false ? "尚未由 Main Agent 分工" : compactValue(worker.task, "等待任务投影");
    return `<button class="worker-card ${selected ? "is-selected" : ""}" data-worker="${esc(worker.worker)}">
      <span class="worker-avatar ${workerIdentityClass(worker)}">${esc(initials(worker.worker))}</span>
      <span class="worker-card-copy">
        <span class="worker-card-title"><strong>${esc(worker.worker)}</strong><span class="worker-state ${status.className}"><i></i>${status.label}</span></span>
        <small>${esc(roleDescription(worker))}</small>
        <span class="worker-card-action"><span>Action</span><strong>${esc(action)}</strong></span>
        <span class="worker-card-task ${worker.assigned === false ? "is-unassigned" : ""}"><em>Task</em><strong>${esc(shortText(task, 112))}</strong></span>
        <span class="worker-process-row"><span><em>PID</em><strong>${esc(workerPid(worker))}</strong></span><span><em>Process identity</em><strong class="process-identity ${processIdentityClass(worker)}">${esc(processIdentityLabel(worker))}</strong></span></span>
        <span class="worker-desired-state ${esc(desired.key)}"><em>Desired state</em><strong>${esc(desired.label)}</strong></span>
        <span class="worker-card-fields">
          <span><em>Round</em><strong>${esc(workerRound(worker))}</strong></span>
          <span><em>Model</em><strong>${esc(shortText(compactValue(worker.model, "default"), 18))}</strong></span>
          <span><em>Effort</em><strong>${esc(compactValue(worker.reasoning_effort, "inherit"))}</strong></span>
        </span>
      </span>
      <span class="worker-chevron">›</span>
    </button>`;
  }).join("");
  renderLifecycleControls();
}

function openWorkerDrawer(workerName) {
  state.activeWorker = workerName;
  const selectedRound = latestWorkerRoundSelection(workerName);
  state.drawerViews[workerName] = {
    selectedRound,
    selectedRawLog: latestRawLogSelection(workerName),
    positions: {
      [selectedRound]: { scrollTop: 0, followTail: true, forceBottom: true, openTools: [] },
    },
  };
  setWorkerRailOpen(false);
  renderWorkers();
  renderWorkerDrawer({ remember: false });
  void refreshWorkerLogs(workerName);
}

function closeWorkerDrawer() {
  state.activeWorker = null;
  renderWorkers();
  renderWorkerDrawer();
}

function isTraceNearBottom(trace) {
  return trace.scrollHeight - trace.scrollTop - trace.clientHeight < 28;
}

function rememberDrawerView(drawer) {
  const workerName = drawer?.dataset.worker;
  const selectedRound = drawer?.dataset.roundSelection;
  const trace = drawer?.querySelector(".trace-list");
  const view = state.drawerViews[workerName];
  if (!workerName || !selectedRound || !trace || !view) return;
  view.positions ||= {};
  view.positions[selectedRound] = {
    scrollTop: trace.scrollTop,
    followTail: isTraceNearBottom(trace),
    forceBottom: false,
    openTools: [...trace.querySelectorAll("details[data-trace-id][open]")].map((node) => node.dataset.traceId),
  };
}

function selectWorkerRound(workerName, selectedRound) {
  const groups = workerRoundLogGroups(workerName);
  if (selectedRound !== "all" && !groups.some((group) => String(group.round) === selectedRound)) return;
  const drawer = $("worker-drawer");
  rememberDrawerView(drawer);
  const view = state.drawerViews[workerName] || { selectedRound, positions: {} };
  view.selectedRound = selectedRound;
  view.positions[selectedRound] = { scrollTop: 0, followTail: true, forceBottom: true, openTools: [] };
  state.drawerViews[workerName] = view;
  renderWorkerDrawer({ remember: false });
}

function selectWorkerRawLog(workerName, selectedName) {
  const view = state.drawerViews[workerName];
  if (!view || !workerLogEntries(workerName).some((entry) => entry.name === selectedName)) return;
  view.selectedRawLog = selectedName;
  renderWorkerDrawer();
}

function renderWorkerDrawer(options = {}) {
  const drawer = $("worker-drawer");
  if (!drawer) return;
  if (options.remember !== false) rememberDrawerView(drawer);
  const metadataWasOpen = Boolean(drawer.querySelector(".worker-metadata")?.open);
  const worker = state.workers.find((item) => item.worker === state.activeWorker);
  if (!worker) {
    drawer.hidden = true;
    drawer.innerHTML = "";
    return;
  }
  const status = workerStatus(worker);
  const desired = workerDesiredState(worker);
  const groups = workerRoundLogGroups(worker.worker);
  const rawEntries = workerLogEntries(worker.worker);
  const latestRound = groups.length ? String(groups[groups.length - 1].round) : "all";
  const view = state.drawerViews[worker.worker] || { selectedRound: latestRound, selectedRawLog: latestRawLogSelection(worker.worker), positions: {} };
  if (view.selectedRound !== "all" && !groups.some((group) => String(group.round) === view.selectedRound)) {
    view.selectedRound = latestRound;
    view.positions[latestRound] = { scrollTop: 0, followTail: true, forceBottom: true, openTools: [] };
  }
  if (!rawEntries.some((entry) => entry.name === view.selectedRawLog)) view.selectedRawLog = latestRawLogSelection(worker.worker);
  view.positions ||= {};
  const selectedRound = view.selectedRound || latestRound;
  const selectedRawLog = view.selectedRawLog || "";
  const saved = view.positions[selectedRound] || { scrollTop: 0, followTail: true, forceBottom: true, openTools: [] };
  view.positions[selectedRound] = saved;
  state.drawerViews[worker.worker] = view;
  const roundTabs = [{ value: "all", label: "全部轮次" }, ...groups.map((group) => ({ value: String(group.round), label: `第 ${group.round} 轮` }))];
  const action = workerCurrentAction(worker);
  const checkpoint = worker.checkpoint && worker.checkpoint.message ? worker.checkpoint : null;
  drawer.hidden = false;
  drawer.dataset.worker = worker.worker;
  drawer.dataset.roundSelection = selectedRound;
  drawer.innerHTML = `<div class="drawer-header"><div><p class="eyebrow">WORKER TRACE</p><h2>${esc(worker.worker)}</h2></div><button id="worker-drawer-close" class="close-button" type="button" aria-label="关闭 worker 详情">×</button></div>
    <div class="drawer-identity"><span class="worker-avatar large ${workerIdentityClass(worker)}">${esc(initials(worker.worker))}</span><div><strong>${esc(roleName(worker))}</strong><p>${esc(roleDescription(worker))}</p></div><span class="worker-state ${status.className}"><i></i>${status.label}</span></div>
    <div class="worker-state-panel">
      <div><span>State</span><strong>${esc(compactValue(worker.state, "idle"))}</strong></div>
      <div><span>Action</span><strong>${esc(action)}</strong></div>
      <div><span>PID</span><strong>${esc(workerPid(worker))}</strong></div>
      <div><span>Desired state</span><strong>${esc(desired.label)}</strong></div>
    </div>
    <details class="worker-metadata" ${metadataWasOpen ? "open" : ""}><summary><span>运行详情</span><small>PID ${esc(workerPid(worker))} · ${esc(processIdentityLabel(worker))} · memory ${esc(worker.local_memory_count || 0)}</small></summary><div class="worker-config-grid">
        <div><span>Role</span><strong>${esc(compactValue(worker.role || worker.worker))}</strong></div>
        <div><span>Round</span><strong>${esc(workerRound(worker))}</strong></div>
        <div><span>PID</span><strong>${esc(workerPid(worker))}</strong></div>
        <div><span>Process identity</span><strong class="process-identity ${processIdentityClass(worker)}">${esc(processIdentityLabel(worker))}</strong></div>
        <div><span>Desired state</span><strong>${esc(desired.label)}</strong></div>
        <div><span>Stop marker</span><strong>${worker.stop_requested ? "present" : "absent"}</strong></div>
        <div><span>Pause marker</span><strong>${worker.pause_requested ? "present" : "absent"}</strong></div>
        <div><span>Effort</span><strong>${esc(compactValue(worker.reasoning_effort, "inherit"))}</strong></div>
        <div><span>Model</span><strong>${esc(compactValue(worker.model, "project default"))}</strong></div>
        <div><span>Last fact</span><strong>${esc(compactValue(worker.last_fact_id))}</strong></div>
        <div><span>Age</span><strong>${esc(worker.age_s == null ? "—" : `${worker.age_s}s`)}</strong></div>
        <div><span>Previous result</span><strong>${worker.last_rc == null ? "—" : `exit ${esc(worker.last_rc)}`}</strong></div>
        <div><span>Failures</span><strong>${esc(worker.consecutive_failures || 0)}</strong></div>
        <div><span>Retry</span><strong>${worker.next_retry_at ? esc(formatTime(worker.next_retry_at)) : "—"}</strong></div>
        <div><span>Local memory</span><strong>${esc(worker.local_memory_count || 0)}</strong></div>
      </div>${checkpoint ? `<section class="worker-checkpoint"><div><span>CHECKPOINT</span><small>${esc(checkpoint.source || "local memory")}${checkpoint.round != null ? ` · round ${esc(checkpoint.round)}` : ""}${checkpoint.fact_id ? ` · fact ${esc(checkpoint.fact_id)}` : ""}</small></div><div class="state-panel-markdown">${renderMarkdown(checkpoint.message)}</div></section>` : ""}</details>
    <div class="drawer-trace-body">
      <section class="drawer-section"><div class="drawer-section-heading"><div><p class="eyebrow">STRUCTURED ROUND TRANSCRIPT</p><h3>执行轨迹</h3></div><span>${groups.length ? `${esc(groups.length)} 个保留轮次` : "暂无轮次日志"}</span></div><div class="worker-round-tabs" role="tablist" aria-label="选择 Worker 轮次">${roundTabs.map((tab) => `<button class="worker-round-tab ${tab.value === selectedRound ? "is-active" : ""}" type="button" role="tab" aria-selected="${tab.value === selectedRound ? "true" : "false"}" data-worker-round="${esc(tab.value)}">${esc(tab.label)}</button>`).join("")}</div><div class="trace-list">${renderWorkerRoundTranscript(groups, selectedRound, worker)}</div></section>
      <section class="raw-log-panel"><div class="drawer-section-heading"><div><p class="eyebrow">RAW BOUNDED LOGS</p><h3>loop.log + retained round logs</h3></div><button class="log-refresh-button" type="button" data-refresh-worker-log="${esc(worker.worker)}" ${state.logsRefreshing === worker.worker ? "disabled" : ""}>${state.logsRefreshing === worker.worker ? "Refreshing…" : "Refresh"}</button></div>${renderRawWorkerLog(worker.worker, selectedRawLog)}</section>
    </div>
    <div class="drawer-footer"><span class="status-dot ${worker.alive ? "online" : "offline"}"></span><span>${worker.alive ? "identity-matched Worker loop" : `not live · ${esc(processIdentityLabel(worker))}`}</span><span class="drawer-footer-spacer"></span><span>author: ${esc(worker.author || worker.worker)}</span></div>`;
  $("worker-drawer-close").addEventListener("click", closeWorkerDrawer);
  drawer.querySelectorAll("[data-worker-round]").forEach((button) => {
    button.addEventListener("click", () => selectWorkerRound(worker.worker, button.dataset.workerRound));
  });
  drawer.querySelectorAll("[data-worker-log]").forEach((button) => {
    button.addEventListener("click", () => selectWorkerRawLog(worker.worker, button.dataset.workerLog));
  });
  drawer.querySelector("[data-refresh-worker-log]")?.addEventListener("click", () => {
    void refreshWorkerLogs(worker.worker, { notify: true });
  });
  const trace = drawer.querySelector(".trace-list");
  if (trace) {
    const open = new Set(saved.openTools || []);
    trace.querySelectorAll("details[data-trace-id]").forEach((node) => { node.open = open.has(node.dataset.traceId); });
    window.requestAnimationFrame(() => {
      const followBottom = saved.forceBottom || saved.followTail;
      trace.scrollTop = followBottom ? trace.scrollHeight : Math.min(saved.scrollTop || 0, Math.max(0, trace.scrollHeight - trace.clientHeight));
      saved.forceBottom = false;
    });
  }
}

function renderFiles() {
  $("file-count").textContent = String(state.files.length);
  $("files").innerHTML = state.files.map((file) => `<div class="file-row"><span class="file-type">${esc((file.filename || file.logical_name || "file").split(".").pop().toUpperCase().slice(0, 4))}</span><span class="file-row-copy"><strong>${esc(file.filename || file.logical_name)}</strong><small>v${esc(file.version || 1)} · ${formatBytes(file.size)}</small></span><span class="file-read-state ${file.read_status === "read" ? "is-read" : ""}">${file.read_status === "read" ? "已读" : "未读"}</span></div>`).join("") || '<p class="muted">还没有上传资料。</p>';
  $("attachment").innerHTML = '<option value="">添加资料</option>' + state.files.map((file) => `<option value="${esc(file.id)}">${esc(file.filename || file.logical_name)} v${esc(file.version || 1)}</option>`).join("");
}

const FACT_AUTHOR_COLORS = ["#86a88f", "#8fa6bd", "#ba9b76", "#9c91b8", "#b68f91", "#79a8a2", "#a8a279"];
const FACT_DEPTH_COLORS = ["#355d43", "#668277", "#7a7897", "#8c735b", "#747d89"];

function factNodeOrder(left, right) {
  const depth = Number(left?.depth || 0) - Number(right?.depth || 0);
  if (depth) return depth;
  const leftId = String(left?.id || "");
  const rightId = String(right?.id || "");
  return leftId < rightId ? -1 : leftId > rightId ? 1 : 0;
}

function numberedFacts(nodes = state.facts.nodes || []) {
  const sorted = nodes.slice().sort(factNodeOrder);
  const digits = Math.max(2, String(sorted.length).length);
  return sorted.map((node, index) => ({ node, visibleNumber: `F${String(index + 1).padStart(digits, "0")}` }));
}

function stableFactValue(value) {
  if (Array.isArray(value)) return value.map(stableFactValue);
  if (value && typeof value === "object") {
    return Object.keys(value).sort().reduce((result, key) => {
      result[key] = stableFactValue(value[key]);
      return result;
    }, {});
  }
  return value;
}

function factGraphSignature(nodes, edges) {
  const stableNodes = nodes.slice().sort(factNodeOrder).map(stableFactValue);
  const stableEdges = edges.slice().map((edge) => ({ source: String(edge?.source || ""), target: String(edge?.target || "") }))
    .sort((left, right) => {
      const leftKey = `${left.source}\u0000${left.target}`;
      const rightKey = `${right.source}\u0000${right.target}`;
      return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
    });
  return JSON.stringify({ nodes: stableNodes, edges: stableEdges });
}

function factAuthorPaletteIndex(author) {
  const text = String(author || "unknown");
  let hash = 0;
  for (let index = 0; index < text.length; index += 1) hash = (hash * 31 + text.charCodeAt(index)) >>> 0;
  return hash % FACT_AUTHOR_COLORS.length;
}

function factAuthorColor(author) {
  return FACT_AUTHOR_COLORS[factAuthorPaletteIndex(author)];
}

function factDepthColor(depth) {
  return FACT_DEPTH_COLORS[Math.abs(Number(depth || 0)) % FACT_DEPTH_COLORS.length];
}

function factGraphElements(nodes, edges) {
  const numbered = numberedFacts(nodes);
  const knownIds = new Set(numbered.map(({ node }) => String(node.id)));
  const graphNodes = numbered.map(({ node, visibleNumber }) => {
    const predecessors = Array.isArray(node.predecessors) ? node.predecessors : [];
    const depth = Number(node.depth || 0);
    return {
      group: "nodes",
      data: {
        id: String(node.id),
        label: `${visibleNumber} · D${depth}\n${String(node.id)}`,
        visibleNumber,
        depth,
        author: node.author || "unknown",
        authorColor: factAuthorColor(node.author),
        depthColor: factDepthColor(depth),
      },
      classes: predecessors.length ? "" : "fact-root",
    };
  });
  const graphEdges = edges
    .map((edge) => ({ source: String(edge?.source || ""), target: String(edge?.target || "") }))
    .filter((edge) => edge.source && edge.target && knownIds.has(edge.source) && knownIds.has(edge.target))
    .sort((left, right) => {
      const leftKey = `${left.source}\u0000${left.target}`;
      const rightKey = `${right.source}\u0000${right.target}`;
      return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
    })
    .map((edge, index) => ({ group: "edges", data: { id: `dependency-${index}-${edge.source}-${edge.target}`, source: edge.source, target: edge.target } }));
  return [...graphNodes, ...graphEdges];
}

function factEntry(factId) {
  return numberedFacts().find(({ node }) => String(node.id) === String(factId)) || null;
}

function factReferenceText(factId) {
  const entry = factEntry(factId);
  return entry ? `Fact ${entry.visibleNumber}（不可变 ID：${entry.node.id}）` : `Fact（不可变 ID：${factId}）`;
}

function factFeedbackPrefix(factId) {
  return `关于 ${factReferenceText(factId)}的反馈：\n`;
}

function factValueText(value) {
  if (Array.isArray(value)) return value.map(factValueText).join(", ");
  if (value && typeof value === "object") return JSON.stringify(value);
  return String(value ?? "");
}

function factReferencesMarkup(references) {
  if (!references.length) return '<p class="fact-section-empty">没有外部引用。</p>';
  return `<div class="fact-references">${references.map((reference, index) => {
    if (!reference || typeof reference !== "object") return `<article><strong>Reference ${index + 1}</strong><div class="fact-markdown">${renderMarkdown(reference)}</div></article>`;
    const title = reference.title || reference.key || reference.arxiv_id || reference.arxiv || `Reference ${index + 1}`;
    const fields = Object.entries(reference).filter(([key]) => key !== "title");
    return `<article><strong>${esc(title)}</strong><dl class="fact-reference-fields">${fields.map(([key, value]) => `<div><dt>${esc(key.replace(/_/g, " "))}</dt><dd class="fact-markdown">${renderMarkdown(factValueText(value))}</dd></div>`).join("")}</dl></article>`;
  }).join("")}</div>`;
}

function factInspectorMarkup(entry) {
  if (!entry) return '<div class="fact-inspector-empty"><span>⌁</span><strong>选择一个真实 Fact</strong><p>点击图中的节点，或使用上方选择器查看完整 statement、proof 与依赖。</p></div>';
  const { node, visibleNumber } = entry;
  const predecessors = Array.isArray(node.predecessors) ? node.predecessors : [];
  const glossary = Object.entries(node.glossary_introduces || {}).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
  const references = Array.isArray(node.external_refs) ? node.external_refs : [];
  const predecessorMarkup = predecessors.length
    ? predecessors.map((id) => {
      const predecessor = factEntry(id);
      return predecessor
        ? `<button type="button" class="fact-predecessor-chip" data-fact-select="${esc(id)}"><strong>${esc(predecessor.visibleNumber)}</strong><code>${esc(id)}</code></button>`
        : `<code class="fact-missing-predecessor">${esc(id)}</code>`;
    }).join("")
    : '<span class="fact-root-label">Root · 没有前置 Fact</span>';
  const glossaryMarkup = glossary.length
    ? `<dl class="fact-glossary">${glossary.map(([term, meaning]) => `<div><dt><code>${esc(term)}</code></dt><dd class="fact-markdown">${renderMarkdown(factValueText(meaning))}</dd></div>`).join("")}</dl>`
    : '<p class="fact-section-empty">没有新增术语。</p>';
  return `<div class="fact-inspector-header"><div><span class="fact-visible-number">${esc(visibleNumber)}</span><span class="fact-depth-badge">Depth ${esc(node.depth || 0)}</span></div><p class="eyebrow">SELECTED FACT</p><h3>${esc(shortText(node.statement || node.id || "未命名 Fact", 120))}</h3><div class="fact-identity"><span>Author <strong>${esc(node.author || "unknown")}</strong></span><span>Immutable ID <code>${esc(node.id)}</code></span></div><div class="fact-inspector-actions"><button type="button" class="secondary-button" data-fact-feedback="${esc(node.id)}">向 Main Agent 反馈</button><button type="button" class="quiet-button" data-fact-copy="${esc(node.id)}">复制引用</button></div></div>
    <div class="fact-inspector-body"><section><h4>Statement</h4><div class="fact-markdown">${renderMarkdown(node.statement)}</div></section><section><h4>Proof</h4><div class="fact-markdown">${renderMarkdown(node.proof)}</div></section><section><h4>Intuition</h4><div class="fact-markdown">${renderMarkdown(node.intuition)}</div></section><section><h4>Predecessor facts</h4><div class="fact-predecessors">${predecessorMarkup}</div></section><section><h4>Glossary additions</h4>${glossaryMarkup}</section><section><h4>External references</h4>${factReferencesMarkup(references)}</section></div>`;
}

function factLegendMarkup(numbered) {
  const authors = [...new Set(numbered.map(({ node }) => String(node.author || "unknown")))].sort();
  return `<div class="fact-legend" aria-label="Fact Graph 图例"><span><i class="fact-legend-root">◇</i>Root</span><span><i class="fact-legend-depth">D#</i>依赖深度</span><span><i class="fact-legend-arrow">→</i>前置到依赖</span>${authors.map((author) => `<span><i class="fact-legend-author fact-author-${factAuthorPaletteIndex(author)}"></i>${esc(author)}</span>`).join("")}</div>`;
}

function factFallbackList(numbered) {
  return numbered.map(({ node, visibleNumber }) => {
    const root = !(Array.isArray(node.predecessors) && node.predecessors.length);
    return `<button type="button" class="fact-fallback-node ${root ? "is-root" : ""}" data-fact-select="${esc(node.id)}" aria-pressed="${state.selectedFactId === String(node.id) ? "true" : "false"}"><span>${esc(visibleNumber)}</span><span><strong>${esc(node.statement || "未命名 Fact")}</strong><small>D${esc(node.depth || 0)} · ${esc(node.author || "unknown")} · ${esc(node.id)}</small></span></button>`;
  }).join("");
}

function factPipelineMarkup(verifying, verifyingCount) {
  return verifyingCount ? `<div class="fact-pipeline"><i></i><span><strong>${verifyingCount} 个候选 Fact 验证中</strong><small>${esc(verifying.map((item) => item.worker).join("、"))}</small></span></div>` : "";
}

function updateFactPipeline(verifying, verifyingCount) {
  const slot = $("fact-pipeline-slot");
  if (slot) slot.innerHTML = factPipelineMarkup(verifying, verifyingCount);
}

function destroyFactGraph() {
  if (state.factCy) {
    try {
      state.factCy.destroy();
    } catch {
      // A missing canvas during project switches is safe; the next graph mounts fresh.
    }
  }
  state.factCy = null;
}

function showFactGraphFallback(message) {
  const canvas = $("fact-graph-canvas");
  const fallback = $("fact-graph-fallback");
  const status = $("fact-graph-status");
  if (canvas) canvas.hidden = true;
  if (fallback) fallback.hidden = false;
  if (status) status.textContent = message;
}

function runFactLayout(shouldFit = true) {
  const cy = state.factCy;
  if (!cy) return;
  const roots = cy.nodes(".fact-root");
  const options = {
    name: "breadthfirst",
    directed: true,
    circle: false,
    grid: true,
    spacingFactor: 1.35,
    avoidOverlap: true,
    padding: 38,
    animate: false,
  };
  if (roots.length) options.roots = roots;
  cy.layout(options).run();
  if (shouldFit) window.requestAnimationFrame(() => cy.fit(cy.elements(), 38));
}

function syncFactSelection() {
  const selectedId = state.selectedFactId;
  const picker = $("fact-node-picker");
  if (picker) picker.value = selectedId || "";
  document.querySelectorAll(".fact-fallback-node[data-fact-select]").forEach((button) => {
    const selected = button.dataset.factSelect === selectedId;
    button.classList.toggle("is-selected", selected);
    button.setAttribute("aria-pressed", selected ? "true" : "false");
  });
  const cy = state.factCy;
  if (!cy) return;
  cy.elements().removeClass("is-selected is-neighbor is-dimmed");
  if (!selectedId) return;
  const selected = cy.$id(selectedId);
  if (!selected.length) return;
  cy.elements().addClass("is-dimmed");
  const neighborhood = selected.closedNeighborhood();
  neighborhood.removeClass("is-dimmed").addClass("is-neighbor");
  selected.removeClass("is-neighbor").addClass("is-selected");
}

function selectFact(factId) {
  const entry = factEntry(factId);
  if (!entry) return;
  state.selectedFactId = String(entry.node.id);
  const inspector = $("fact-inspector");
  if (inspector) inspector.innerHTML = factInspectorMarkup(entry);
  syncFactSelection();
}

function mountFactGraph() {
  const card = $("fact-graph-card");
  const canvas = $("fact-graph-canvas");
  const fallback = $("fact-graph-fallback");
  if (!card?.open || !canvas || !(state.facts.nodes || []).length) return;
  if (state.factCy && state.factCy.container() === canvas) {
    state.factCy.resize();
    syncFactSelection();
    return;
  }
  destroyFactGraph();
  if (typeof window.cytoscape !== "function") {
    showFactGraphFallback("图形组件未载入；下方保留全部真实 Fact 的可读列表与检查器。");
    return;
  }
  try {
    canvas.hidden = false;
    if (fallback) fallback.hidden = true;
    state.factCy = window.cytoscape({
      container: canvas,
      elements: factGraphElements(state.facts.nodes || [], state.facts.edges || []),
      layout: { name: "preset" },
      minZoom: 0.22,
      maxZoom: 2.8,
      wheelSensitivity: 0.18,
      boxSelectionEnabled: false,
      style: [
        { selector: "node", style: { label: "data(label)", width: 122, height: 50, shape: "round-rectangle", "background-color": "data(authorColor)", "background-opacity": 0.3, "border-color": "data(depthColor)", "border-width": 3, color: "#27332a", "font-size": 8, "font-weight": 700, "text-wrap": "wrap", "text-max-width": 112, "text-valign": "center", "text-halign": "center", "overlay-opacity": 0, "transition-property": "opacity, border-width, background-opacity", "transition-duration": "140ms" } },
        { selector: "node.fact-root", style: { shape: "diamond", width: 84, height: 64, "border-width": 4, "background-opacity": 0.42 } },
        { selector: "edge", style: { width: 1.5, "line-color": "#a8b2aa", "target-arrow-color": "#718077", "target-arrow-shape": "triangle", "arrow-scale": 0.8, "curve-style": "taxi", "taxi-direction": "downward", "taxi-turn": 18, opacity: 0.62 } },
        { selector: ".is-dimmed", style: { opacity: 0.14 } },
        { selector: "node.is-neighbor", style: { opacity: 1, "border-width": 4, "background-opacity": 0.43 } },
        { selector: "edge.is-neighbor", style: { opacity: 0.95, width: 2.5, "line-color": "#668277", "target-arrow-color": "#355d43" } },
        { selector: "node.is-selected", style: { opacity: 1, "border-color": "#203f2b", "border-width": 5, "background-opacity": 0.68, "overlay-color": "#5d8068", "overlay-opacity": 0.12, "overlay-padding": 7, "z-index": 10 } },
      ],
    });
    state.factCy.on("tap", "node", (event) => selectFact(event.target.id()));
    runFactLayout(true);
    syncFactSelection();
  } catch (error) {
    destroyFactGraph();
    showFactGraphFallback(`图形渲染不可用（${error?.message || "unknown error"}）；下方仍可阅读和选择全部真实 Fact。`);
  }
}

function controlFactGraph(action) {
  const cy = state.factCy;
  if (!cy) {
    if (action === "reset-layout") mountFactGraph();
    return;
  }
  if (action === "fit") return void cy.fit(cy.elements(), 38);
  if (action === "reset-layout") return void runFactLayout(true);
  const factor = action === "zoom-in" ? 1.22 : action === "zoom-out" ? 1 / 1.22 : 1;
  const level = Math.max(cy.minZoom(), Math.min(cy.maxZoom(), cy.zoom() * factor));
  cy.zoom({ level, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
}

function prefillFactFeedback(factId) {
  const composer = $("message");
  if (!composer) return;
  const prefix = factFeedbackPrefix(factId);
  composer.value = prefix;
  composer.focus();
  composer.setSelectionRange?.(prefix.length, prefix.length);
  notify(`${factReferenceText(factId)} 已写入 Main Agent 输入框`, "success");
}

async function copyFactReference(factId) {
  const reference = factReferenceText(factId);
  try {
    await navigator.clipboard.writeText(reference);
    notify("Fact 引用已复制", "success");
  } catch {
    window.prompt("复制 Fact 引用", reference);
  }
}

function handleFactGraphClick(event) {
  const control = event.target.closest("[data-fact-control]");
  if (control) return void controlFactGraph(control.dataset.factControl);
  const selectable = event.target.closest("[data-fact-select]");
  if (selectable) return void selectFact(selectable.dataset.factSelect);
  const feedback = event.target.closest("[data-fact-feedback]");
  if (feedback) return void prefillFactFeedback(feedback.dataset.factFeedback);
  const copy = event.target.closest("[data-fact-copy]");
  if (copy) copyFactReference(copy.dataset.factCopy);
}

function handleFactGraphChange(event) {
  if (event.target.matches("#fact-node-picker")) selectFact(event.target.value);
}

function handleFactGraphKeydown(event) {
  if (!event.target.matches("#fact-graph-canvas")) return;
  const keys = ["ArrowLeft", "ArrowUp", "ArrowRight", "ArrowDown", "Home", "End"];
  if (!keys.includes(event.key)) return;
  event.preventDefault();
  const numbered = numberedFacts();
  if (!numbered.length) return;
  const current = numbered.findIndex(({ node }) => String(node.id) === state.selectedFactId);
  let next = current < 0 ? 0 : current;
  if (["ArrowRight", "ArrowDown"].includes(event.key)) next = (next + 1) % numbered.length;
  if (["ArrowLeft", "ArrowUp"].includes(event.key)) next = (next - 1 + numbered.length) % numbered.length;
  if (event.key === "Home") next = 0;
  if (event.key === "End") next = numbered.length - 1;
  selectFact(numbered[next].node.id);
}

function renderFacts() {
  const nodes = state.facts.nodes || [];
  const edges = state.facts.edges || [];
  const verifying = pendingFactVerifications();
  const verifyingCount = verifying.reduce((total, item) => total + item.count, 0);
  $("fact-count").textContent = verifyingCount ? `${nodes.length} / ${edges.length} · ${verifyingCount} 验证中` : `${nodes.length} / ${edges.length}`;
  if (!nodes.length) {
    destroyFactGraph();
    state.factGraphSignature = null;
    state.selectedFactId = null;
    const failed = state.workers.some((worker) => worker.last_rc && worker.last_error);
    const verifyingWorkers = verifying.map((item) => item.worker).join("、");
    const detail = verifyingCount
      ? `${verifyingWorkers} 已提交 ${verifyingCount} 个候选结论；verifier 通过后会自动生成节点。`
      : failed
        ? "当前有 worker 轮次未完成；只有通过 verifier 的结论才会进入图。"
        : "worker 通过 verifier 提交结论后，依赖关系会显示在这里。";
    $("facts").innerHTML = `<div class="insight-empty ${verifyingCount ? "is-verifying" : ""}"><span>◈</span><strong>${verifyingCount ? `${verifyingCount} 个 Fact 正在验证` : "还没有已验证 Fact"}</strong><p>${esc(detail)}</p></div>`;
    return;
  }
  const signature = factGraphSignature(nodes, edges);
  if (signature === state.factGraphSignature && $("facts").querySelector(".fact-graph-surface")) {
    updateFactPipeline(verifying, verifyingCount);
    syncFactSelection();
    return;
  }
  const retainedSelection = state.selectedFactId && nodes.some((node) => String(node.id) === state.selectedFactId) ? state.selectedFactId : null;
  destroyFactGraph();
  state.factGraphSignature = signature;
  state.selectedFactId = retainedSelection;
  const numbered = numberedFacts(nodes);
  const maxDepth = Number(state.facts.max_depth || Math.max(...nodes.map((node) => Number(node.depth || 0))));
  const roots = nodes.filter((node) => !(Array.isArray(node.predecessors) && node.predecessors.length)).length;
  $("facts").innerHTML = `<div class="fact-graph-surface" data-fact-graph="real"><div id="fact-pipeline-slot">${factPipelineMarkup(verifying, verifyingCount)}</div><div class="fact-graph-topbar"><div class="fact-overview"><span><strong>${nodes.length}</strong> nodes</span><span><strong>${edges.length}</strong> edges</span><span><strong>${roots}</strong> roots</span><span><strong>${maxDepth}</strong> max depth</span></div><div class="fact-graph-controls" role="group" aria-label="Fact Graph 视图控制"><button type="button" data-fact-control="zoom-in" aria-label="放大 Fact Graph" title="放大">＋</button><button type="button" data-fact-control="zoom-out" aria-label="缩小 Fact Graph" title="缩小">−</button><button type="button" data-fact-control="fit">适配</button><button type="button" data-fact-control="reset-layout">重排</button></div></div>${factLegendMarkup(numbered)}<div class="fact-explorer"><section class="fact-canvas-column" aria-label="Fact 依赖图"><label class="fact-node-picker-label" for="fact-node-picker"><span>键盘选择 Fact</span><select id="fact-node-picker"><option value="">请选择节点…</option>${numbered.map(({ node, visibleNumber }) => `<option value="${esc(node.id)}" ${state.selectedFactId === String(node.id) ? "selected" : ""}>${esc(visibleNumber)} · D${esc(node.depth || 0)} · ${esc(node.id)}</option>`).join("")}</select></label><div id="fact-graph-canvas" class="fact-graph-canvas" role="application" tabindex="0" aria-label="真实有向 Fact 依赖图；方向键逐个选择节点" aria-describedby="fact-graph-instructions"></div><p id="fact-graph-instructions" class="sr-only">依赖箭头从 predecessor 指向 dependent。使用方向键浏览节点，或使用上方选择器。</p><div id="fact-graph-fallback" class="fact-graph-fallback" hidden><div class="fact-fallback-notice"><strong>可读图形后备</strong><p id="fact-graph-status">图形组件不可用；以下是按深度和不可变 ID 排序的真实 Fact。</p></div><div class="fact-fallback-list">${factFallbackList(numbered)}</div></div></section><aside id="fact-inspector" class="fact-inspector" aria-label="Fact inspector" aria-live="polite">${factInspectorMarkup(factEntry(state.selectedFactId))}</aside></div></div>`;
  if ($("fact-graph-card")?.open) window.requestAnimationFrame(mountFactGraph);
}

function renderMemory() {
  const channels = state.memory.channels || [];
  $("memory-count").textContent = String(state.memory.total || 0);
  const entries = channels.flatMap((channel) => (channel.entries || []).map((entry) => ({ ...entry, kind: channel.kind, channelRole: channel.role })));
  const liveWorkers = state.workers.filter((worker) => worker.alive).length;
  $("memory").innerHTML = entries.slice(0, 16).map((entry) => {
    const message = entry.claim || entry.statement || entry.evidence || entry.verdict || "已记录一条共享进展";
    const evidence = entry.evidence && entry.evidence !== message ? entry.evidence : "";
    const metadata = [entry.author || "unknown", entry.timestamp_utc, entry.verdict ? `verdict ${entry.verdict}` : "", entry.fact_id ? `fact ${entry.fact_id}` : ""].filter(Boolean).join(" · ");
    return `<div class="memory-row ${esc(entry.channelRole || "strategy")}"><span class="memory-kind">${esc(entry.kind)}</span><div><strong>${esc(shortText(message, 140))}</strong>${evidence ? `<span class="memory-evidence">${esc(shortText(evidence, 160))}</span>` : ""}<small>${esc(metadata)}</small></div></div>`;
  }).join("") || `<div class="insight-empty"><span>◎</span><strong>共享记忆为空</strong><p>${liveWorkers ? `${liveWorkers} 个 worker 正在工作；首次 gm_add 后这里会按频道实时归档。` : "plans、obstacles、proof attempts 和 verification 记录会汇总到这里。"}</p></div>`;
}

function renderArtifacts() {
  const files = [...(state.reports.files || []), ...(state.outputs.files || [])];
  $("artifact-count").textContent = String(files.length);
  $("artifacts").innerHTML = files.map((file) => `<div class="artifact-row"><span>↗</span><span><strong>${esc(file.name)}</strong><small>${formatBytes(file.size)}</small></span></div>`).join("") || '<p class="muted">还没有报告或输出。</p>';
}

function runtimeProgress() {
  const activeRun = state.runtime.run || {};
  const progress = state.runtime.progress || {};
  const expected = Number(activeRun.expected_workers ?? progress.expected_workers ?? state.workers.length ?? 0);
  const live = Number(activeRun.live_workers ?? progress.live_workers ?? state.workers.filter((worker) => worker.alive).length);
  const pending = Number(activeRun.stop_pending_workers ?? progress.stop_pending_workers ?? state.workers.filter((worker) => worker.alive && worker.stop_requested).length);
  const stale = Number(activeRun.stale_workers ?? progress.stale_workers ?? state.workers.filter((worker) => worker.process_identity === "mismatch").length);
  const stopped = Number(activeRun.stopped_workers ?? progress.stopped_workers ?? Math.max(0, expected - live - stale));
  return {
    expected_workers: Math.max(0, expected),
    live_workers: Math.max(0, live),
    stop_pending_workers: Math.max(0, pending),
    stopped_workers: Math.max(0, stopped),
    stale_workers: Math.max(0, stale),
  };
}

function gracefulStopProgressText(progress) {
  const stale = progress.stale_workers ? ` · ${progress.stale_workers} stale process record${progress.stale_workers === 1 ? "" : "s"}` : "";
  if (progress.live_workers > 0 && progress.stop_pending_workers === 0) {
    return `Graceful stop intent recorded · awaiting Main Agent / host broker · ${progress.live_workers} still running${stale}`;
  }
  return `Graceful stop in progress · ${progress.stop_pending_workers} finishing current round · ${progress.stopped_workers} stopped${stale}`;
}

function lifecycleTargetValue() {
  return "";
}

function lifecycleTargetWorkers(target = lifecycleTargetValue()) {
  return target ? state.workers.filter((worker) => worker.worker === target) : state.workers.slice();
}

function forceStopSafety(target = lifecycleTargetValue()) {
  const workers = lifecycleTargetWorkers(target);
  const blocking = workers.filter((worker) => worker.pid != null && worker.process_identity !== "matched");
  const matched = workers.filter((worker) => worker.process_identity === "matched" && worker.alive);
  if (blocking.length) {
    return { allowed: false, reason: `Blocked: ${blocking.map((worker) => `${worker.worker} PID ${workerPid(worker)} is ${worker.process_identity || "unknown"}`).join("; ")}` };
  }
  if (!matched.length) return { allowed: false, reason: "Blocked: no identity-matched live Worker process is selected." };
  return { allowed: true, reason: `Identity safety passed for ${matched.length} live Worker process${matched.length === 1 ? "" : "es"}.` };
}

function reclaimCandidate(worker) {
  const identity = String(worker?.process_identity || "unknown");
  return worker?.reclaim_candidate === true || identity === "mismatch" || (worker?.pid != null && identity === "dead");
}

function renderLifecycleControls() {
  const workers = state.workers.slice();
  const live = workers.filter((worker) => worker.alive);
  const paused = workers.filter((worker) => worker.pause_requested || worker.desired_state === "paused");
  const forceSafety = forceStopSafety("");
  const pause = $("run-pause");
  const resume = $("run-resume");
  const force = $("run-force-stop");
  const mainAgentBusy = Boolean(currentPendingMessage());
  if (pause) pause.disabled = mainAgentBusy || !live.some((worker) => !worker.pause_requested && !worker.stop_requested);
  if (resume) resume.disabled = mainAgentBusy || !paused.length;
  if (force) {
    force.disabled = !forceSafety.allowed;
    force.title = forceSafety.reason;
  }
  const safety = $("lifecycle-safety");
  if (safety) {
    safety.className = `lifecycle-safety ${forceSafety.allowed ? "safe" : "blocked"}`;
    safety.innerHTML = `<strong>全部 Workers</strong><span>${live.length} 运行中 · ${paused.length} 已暂停</span><small>强制停止仅在所有运行进程身份匹配时可用。</small>`;
  }
}

async function lifecycleRequest(endpoint, payload, successMessage) {
  if (!state.current) return null;
  const result = await api(`/api/projects/${state.current}/${endpoint}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  notify(successMessage, "success");
  await refreshProject();
  return result;
}

async function pauseRun() {
  const worker = lifecycleTargetValue();
  const label = worker || "all Workers";
  if (!window.confirm(`Pause after round for ${label}? Current rounds may finish and persist before pause.`)) return;
  try {
    await lifecycleRequest("pause", worker ? { worker } : {}, `Pause intent recorded for ${label}`);
    const activated = await sendMessageText(lifecycleIntentMessage("pause", worker));
    notify(activated ? `Main Agent is applying pause-after-round for ${label}` : "Pause intent recorded, but Main Agent did not activate", activated ? "success" : "error");
  } catch (error) {
    notify(error.message || "Pause request failed", "error");
  }
}

async function resumeRun() {
  const worker = lifecycleTargetValue();
  const label = worker || "all paused Workers";
  if (!window.confirm(`Resume ${label} with their existing assigned tasks? This does not change strategy or tasks.`)) return;
  try {
    await lifecycleRequest("resume", worker ? { worker } : {}, `Resume intent recorded for ${label}`);
    const activated = await sendMessageText(lifecycleIntentMessage("resume", worker));
    notify(activated ? `Main Agent is resuming ${label} through the host broker` : "Resume intent recorded, but Main Agent did not activate", activated ? "success" : "error");
  } catch (error) {
    notify(error.message || "Resume failed", "error");
  }
}

function closeReclaimPlan() {
  const modal = $("reclaim-modal");
  if (modal) modal.hidden = true;
}

function renderReclaimPlan() {
  const modal = $("reclaim-modal");
  const body = $("reclaim-plan-body");
  const confirm = $("reclaim-confirm");
  if (!modal || !body || !confirm || !state.reclaimPlan) return;
  const plan = state.reclaimPlan;
  const rows = (plan.workers || []).map((worker) => `<article class="reclaim-target ${worker.safe_to_execute ? "safe" : "blocked"}"><div><strong>${esc(worker.worker)}</strong><span>PID ${esc(worker.pid ?? "—")} · identity ${esc(worker.process_identity || "unknown")}</span></div><dl><div><dt>Stale artifacts</dt><dd>${esc((worker.stale_artifacts || []).join(", ") || "none")}</dd></div><div><dt>Orphan processes</dt><dd>${esc((worker.orphan_processes || []).length)}</dd></div><div><dt>Safe to execute</dt><dd>${worker.safe_to_execute ? "yes" : "no"}</dd></div></dl></article>`).join("");
  body.innerHTML = `<div class="reclaim-summary ${plan.safe_to_execute ? "safe" : "blocked"}"><strong>${plan.safe_to_execute ? "Dry-run passed identity safety checks" : "Dry-run blocked destructive reclaim"}</strong><span>Target: ${esc(state.reclaimTarget || "all Workers")} · token expires after the backend safety window.</span></div>${rows || '<div class="raw-log-empty"><strong>No reclaim targets returned.</strong></div>'}`;
  confirm.disabled = plan.safe_to_execute !== true || !plan.confirmation_token;
  modal.hidden = false;
}

async function reclaimDryRun() {
  const worker = lifecycleTargetValue();
  try {
    const plan = await api(`/api/projects/${state.current}/reclaim`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(worker ? { worker, execute: false } : { execute: false }),
    });
    state.reclaimPlan = plan;
    state.reclaimTarget = worker;
    renderReclaimPlan();
  } catch (error) {
    notify(error.message || "Reclaim dry-run failed", "error");
  }
}

async function confirmReclaim() {
  const plan = state.reclaimPlan;
  if (!plan?.safe_to_execute || !plan.confirmation_token || !state.project) return;
  const confirmation = window.prompt(`输入项目名「${state.project.name}」确认清理 dry-run 中列出的 stale artifacts。不会修改任务或研究策略。`);
  if (confirmation !== state.project.name) return;
  try {
    const worker = state.reclaimTarget;
    const result = await api(`/api/projects/${state.current}/reclaim`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...(worker ? { worker } : {}), execute: true, confirm: confirmation, confirmation_token: plan.confirmation_token }),
    });
    const remaining = (result.remaining_project_processes || []).length;
    closeReclaimPlan();
    state.reclaimPlan = null;
    notify(remaining ? `Reclaim completed, but ${remaining} project process(es) remain` : "Reclaim completed; no selected-Project processes remain", remaining ? "error" : "success");
    await refreshProject();
  } catch (error) {
    notify(error.message || "Reclaim refused", "error");
  }
}

async function forceStopRun() {
  const worker = lifecycleTargetValue();
  const safety = forceStopSafety(worker);
  if (!safety.allowed || !state.project) {
    notify(safety.reason, "error");
    return;
  }
  const confirmation = window.prompt(`输入项目名「${state.project.name}」确认 Force stop now ${worker || "all identity-matched Workers"}。Host 将先 TERM，必要时 KILL；PID identity 会在发信号前再次验证。`);
  if (confirmation !== state.project.name) return;
  try {
    await lifecycleRequest("force-stop", { ...(worker ? { worker } : {}), confirm: confirmation }, "Emergency force stop completed");
  } catch (error) {
    notify(error.message || "Force stop refused by identity safety", "error");
  }
}

function updateRuntime() {
  const progress = runtimeProgress();
  const live = progress.live_workers;
  const activeRun = state.runtime.run;
  const main = state.orchestration.main_agent || state.orchestration.session || {};
  const assigned = Number(state.orchestration.assigned_workers ?? state.workers.filter((worker) => worker.assigned === true).length);
  const total = Number(state.orchestration.workers_total ?? state.workers.length);
  const ready = total > 0 && assigned === total;
  const status = $("main-status");
  if (status) {
    const sessionStatus = main.status || state.orchestration.main_agent_status;
    const text = currentPendingMessage() ? "Main Agent 编排中" : sessionStatus === "active" ? "Main Agent 会话中" : sessionStatus === "inactive" ? "Main Agent 可恢复" : "Main Agent 尚未激活";
    status.className = `status-pill ${currentPendingMessage() || sessionStatus === "active" ? "working" : "idle"}`;
    status.innerHTML = `<i></i>${text}`;
  }
  const stopping = activeRun?.status === "stopping";
  const progressText = stopping
    ? gracefulStopProgressText(progress)
    : activeRun
      ? `Run ${activeRun.status} · ${progress.live_workers}/${progress.expected_workers} identity-matched live · 截止 ${formatTime(activeRun.deadline)}`
      : live
        ? `${live} 个 identity-matched Worker 在线`
        : ready ? `已完成 ${assigned}/${total} 分工` : `等待 Main Agent 分工 · ${assigned}/${total}`;
  const runState = $("run-state");
  if (runState) runState.textContent = progressText;
  const detail = $("run-progress-detail");
  if (detail) detail.textContent = activeRun
    ? `${progress.stop_pending_workers} stop pending · ${progress.stopped_workers} stopped · ${progress.stale_workers} stale`
    : "主 agent 负责正常方向与分工；此处仅显示 host-observed lifecycle state。";
  const bar = $("run-progress-bar");
  if (bar) bar.style.width = `${progress.expected_workers ? Math.min(100, Math.round((progress.stopped_workers / progress.expected_workers) * 100)) : 0}%`;
  const start = $("run-start");
  const mainAgentBusy = Boolean(currentPendingMessage());
  if (start) {
    start.disabled = Boolean(activeRun || live || !ready || mainAgentBusy);
    start.title = mainAgentBusy ? "等待当前 Main Agent 回复完成" : ready ? "启动已完成 Main Agent 分工的 Worker swarm" : "先让 Main Agent 完成所有 Worker 的 TASK.md 分工";
  }
  renderLifecycleControls();
}

async function refreshPendingMessages() {
  const pending = currentPendingMessage();
  if (!pending || !state.current) return;
  const projectAtStart = pending.project_id;
  if (state.pendingRefreshingProject === projectAtStart) return;
  const after = state.mainAgentEventLastId;
  const logWorkerAtStart = state.activeWorker;
  state.pendingRefreshingProject = projectAtStart;
  try {
    const [messagesResult, eventsResult, workersResult, runtimeResult, logsResult, orchestrationResult] = await Promise.allSettled([
      api(`/api/projects/${projectAtStart}/messages`),
      api(`/api/projects/${projectAtStart}/main-agent-events?after=${after}`),
      api(`/api/projects/${projectAtStart}/workers`),
      api(`/api/projects/${projectAtStart}/runtime`),
      pendingLogRequest(projectAtStart),
      api(`/api/projects/${projectAtStart}/orchestration`),
    ]);
    if (state.current !== projectAtStart || state.pendingMessage !== pending) return;
    let persistedTurnTerminal = false;
    if (messagesResult.status === "fulfilled") {
      state.messages = messagesResult.value;
      if (pending.persisted) {
        const persisted = state.messages.find((message) => message.id === pending.id);
        persistedTurnTerminal = Boolean(
          persisted && !["submitted", "retrying", "pending"].includes(persisted.status)
        );
      }
    }
    if (eventsResult.status === "fulfilled") {
      const incoming = eventsResult.value.events || [];
      if (incoming.length) {
        const known = new Set(state.mainAgentEvents.map((event) => event.id));
        state.mainAgentEvents = [...state.mainAgentEvents, ...incoming.filter((event) => !known.has(event.id))];
      }
      state.mainAgentEventLastId = Math.max(state.mainAgentEventLastId, Number(eventsResult.value.last_id || 0));
    }
    if (workersResult.status === "fulfilled") {
      const projection = workersResult.value;
      state.workers = Array.isArray(projection) ? projection : (projection.workers || []);
    }
    if (runtimeResult.status === "fulfilled") state.runtime = runtimeResult.value;
    if (orchestrationResult.status === "fulfilled") state.orchestration = orchestrationResult.value;
    if (logsResult.status === "fulfilled" && logsResult.value && logWorkerAtStart) {
      applyLogProjection(logsResult.value, logWorkerAtStart);
    } else if (logsResult.status === "rejected" && logWorkerAtStart) {
      recordLogError(logsResult.reason, logWorkerAtStart);
    }
    const hasTerminalEvent = state.mainAgentEvents.some((event) => (
      event.message_id === pending.id && ["turn.completed", "turn.failed"].includes(event.type)
    ));
    const hasFollowingAssistant = state.messages.some((message) => (
      message.role === "assistant" && Number(message.created_at || 0) >= Number(pending.created_at || 0)
    ));
    if (persistedTurnTerminal && (hasTerminalEvent || hasFollowingAssistant) && state.pendingMessage === pending) {
      state.pendingMessage = null;
      stopPendingPolling();
    }
    renderMessages();
    renderActivity();
    renderMainAgentControl();
    renderWorkers();
    renderWorkerDrawer();
    updateRuntime();
  } finally {
    if (state.pendingRefreshingProject === projectAtStart) state.pendingRefreshingProject = null;
  }
}

async function refreshProject() {
  if (!state.current || currentPendingMessage()) return;
  const projectAtStart = state.current;
  const logWorkerAtStart = state.activeWorker;
  if (state.refreshingProject === projectAtStart) return;
  state.refreshingProject = projectAtStart;
  try {
    const results = await Promise.allSettled([
      api(`/api/projects/${projectAtStart}/files`),
      api(`/api/projects/${projectAtStart}/messages`),
      api(`/api/projects/${projectAtStart}/workers`),
      api(`/api/projects/${projectAtStart}/fact-graph`),
      api(`/api/projects/${projectAtStart}/memory`),
      api(`/api/projects/${projectAtStart}/runtime`),
      logWorkerAtStart
        ? api(workerLogUrl(projectAtStart, logWorkerAtStart))
        : Promise.resolve(null),
      api(`/api/projects/${projectAtStart}/reports`),
      api(`/api/projects/${projectAtStart}/outputs`),
      api(`/api/projects/${projectAtStart}/orchestration`),
      api(`/api/projects/${projectAtStart}/main-agent-events`),
    ]);
    if (state.current !== projectAtStart || currentPendingMessage()) return;
    const value = (result, fallback) => result.status === "fulfilled" ? result.value : fallback;
    state.files = value(results[0], []);
    state.messages = value(results[1], []);
    const workersResult = value(results[2], { workers: [] });
    state.workers = Array.isArray(workersResult) ? workersResult : (workersResult.workers || []);
    state.facts = value(results[3], { nodes: [], edges: [] });
    state.memory = value(results[4], { total: 0, channels: [] });
    state.runtime = value(results[5], {});
    if (logWorkerAtStart && results[6].status === "fulfilled") {
      applyLogProjection(results[6].value, logWorkerAtStart);
    } else if (logWorkerAtStart) {
      recordLogError(results[6].reason, logWorkerAtStart);
    }
    state.reports = value(results[7], { files: [] });
    state.outputs = value(results[8], { files: [] });
    state.orchestration = value(results[9], {});
    const eventSnapshot = value(results[10], { events: [], last_id: 0 });
    state.mainAgentEvents = eventSnapshot.events || [];
    state.mainAgentEventLastId = Number(eventSnapshot.last_id || 0);
    const restoredPending = state.messages.slice().reverse().find((message) => (
      message.role === "user" && ["submitted", "retrying", "pending"].includes(message.status)
    ));
    if (restoredPending) state.pendingMessage = { ...restoredPending, project_id: projectAtStart, persisted: true };
    renderMessages();
    renderActivity();
    renderMainAgentControl();
    renderWorkers();
    renderWorkerDrawer();
    renderFiles();
    renderFacts();
    renderMemory();
    renderArtifacts();
    updateRuntime();
    if (restoredPending) startPendingPolling();
  } finally {
    if (state.refreshingProject === projectAtStart) state.refreshingProject = null;
  }
}

function setComposerBusy(isBusy) {
  const form = $("chat-form");
  if (!form) return;
  form.classList.toggle("is-busy", isBusy);
  $("message").disabled = isBusy;
  $("attachment").disabled = isBusy;
  form.querySelector("button[type=submit]").disabled = isBusy;
}

async function sendMessageText(text, attachmentId = "") {
  const clean = String(text || "").trim();
  if (!clean || !state.current || currentPendingMessage()) return false;
  const projectAtStart = state.current;
  const localMessage = { id: `local-${Date.now()}`, project_id: projectAtStart, role: "user", text: clean, status: "pending", created_at: Date.now() / 1000, error: null, attachment_ids: attachmentId ? [attachmentId] : [] };
  state.pendingMessage = localMessage;
  state.messages = [...state.messages, localMessage];
  renderMessages();
  renderActivity();
  renderMainAgentControl();
  updateRuntime();
  $("message").value = "";
  startPendingPolling();
  try {
    await api(`/api/projects/${projectAtStart}/messages`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text: clean, attachment_ids: attachmentId ? [attachmentId] : [] }) });
    if (state.pendingMessage === localMessage) state.pendingMessage = null;
    if (state.current === projectAtStart) await refreshProject();
    return true;
  } catch (error) {
    if (state.pendingMessage === localMessage) state.pendingMessage = null;
    localMessage.status = "failed";
    localMessage.error = error.data?.detail || error.message;
    if (state.current === projectAtStart) {
      state.messages = state.messages.filter((message) => message.id !== localMessage.id).concat(localMessage);
      renderMessages();
      renderActivity();
      renderMainAgentControl();
    }
    if (state.current === projectAtStart) {
      notify(localMessage.error || "Main Agent 暂时不可用", "error");
      await refreshProject().catch(() => {});
    }
    return false;
  } finally {
    if (!currentPendingMessage()) stopPendingPolling();
    renderMainAgentControl();
    updateRuntime();
  }
}

async function startRun() {
  if (!state.current || currentPendingMessage()) return;
  const projectAtStart = state.current;
  try {
    const intent = await api(`/api/projects/${projectAtStart}/runs`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ duration_seconds: 3600 }) });
    const activated = state.current === projectAtStart && await sendMessageText(
      `${START_RUN_MESSAGE} Run id: ${intent.run_id || "unknown"}. Do not claim success for a partial fleet.`,
    );
    notify(activated ? "Run intent 已记录；Main Agent 正在启动 Worker fleet" : "Run intent 已记录，但 Main Agent 未能激活", activated ? "success" : "error");
    await refreshProjects();
  } catch (error) {
    notify(error.message || "Run intent 提交失败", "error");
  }
}

async function stopRun() {
  if (!state.current || currentPendingMessage()) return;
  if (!window.confirm("Graceful stop the Project Run? Every live Worker may finish its current round before exiting.")) return;
  const projectAtStart = state.current;
  try {
    await api(`/api/projects/${projectAtStart}/stop`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    const activated = state.current === projectAtStart && await sendMessageText(STOP_RUN_MESSAGE);
    notify(activated ? "停止 intent 已记录；Main Agent 正在执行优雅停止" : "停止 intent 已记录，但 Main Agent 未能激活", activated ? "success" : "error");
  } catch (error) {
    notify(error.message || "Graceful stop failed", "error");
  }
}

async function handleUpload(event) {
  event.preventDefault();
  const file = $("upload").files?.[0];
  if (!file || !state.current) return;
  try {
    const form = new FormData();
    form.append("file", file);
    const response = await api(`/api/projects/${state.current}/files`, { method: "POST", body: form });
    if (response.conflict_id) {
      const choice = window.prompt(`文件冲突：${response.current.filename}。输入 replace / new_version / cancel`, "new_version");
      if (choice) await api(`/api/projects/${state.current}/file-conflicts/${response.conflict_id}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ choice }) });
    }
    $("upload").value = "";
    await refreshProject();
    notify("资料已加入项目", "success");
  } catch (error) {
    notify(error.message || "资料上传失败", "error");
  }
}

async function deleteProject() {
  if (!state.project) return;
  const confirmation = window.prompt(`输入「${state.project.name}」确认删除项目`);
  if (confirmation !== state.project.name) return;
  try {
    await api(`/api/projects/${state.current}`, { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ confirm_name: confirmation }) });
    state.current = null;
    state.project = null;
    await refreshProjects();
    notify("项目已删除", "success");
  } catch (error) {
    notify(error.message || "项目删除失败", "error");
  }
}

$("project-list").addEventListener("click", (event) => {
  const item = event.target.closest("[data-project-id]");
  if (item) openProject(item.dataset.projectId).catch((error) => notify(error.message || "项目打开失败", "error"));
});
$("new-project").addEventListener("click", openProjectModal);
$("start-empty-project").addEventListener("click", openProjectModal);
$("starter-form").addEventListener("submit", handleStarterSubmit);
$("modal-close").addEventListener("click", closeProjectModal);
$("cancel-project").addEventListener("click", closeProjectModal);
$("project-modal").addEventListener("click", (event) => { if (event.target === $("project-modal")) closeProjectModal(); });
$("project-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const roles = roleSpec();
  if (!roles) {
    notify("至少配置一个 worker", "error");
    return;
  }
  const submit = form.querySelector("button[type=submit]");
  submit.disabled = true;
  submit.classList.add("is-loading");
  try {
    const setup = { name: $("project-name").value.trim(), problem: $("problem").value.trim(), roles, model: $("model").value || null, max_parallel_workers: Number($("max-parallel-workers").value || defaultParallelWorkers()) };
    const project = await createProject(setup);
    closeProjectModal();
    await sendMessageText(mainAgentInitializationMessage(setup));
    form.reset();
    $("high-count").value = "1";
    $("xhigh-count").value = "1";
    $("roles").value = "high:1,xhigh:1";
    renderConfiguration();
    notify(`已创建项目「${project.name}」`, "success");
  } catch (error) {
    notify(error.message || "项目创建失败", "error");
  } finally {
    submit.disabled = false;
    submit.classList.remove("is-loading");
  }
});

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const errorNode = $("login-error");
  errorNode.textContent = "";
  try {
    const result = await api("/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password: $("password").value }) });
    state.csrf = result.csrf_token;
    showConsole();
    await loadConfiguration();
    await refreshProjects();
    bindEmptyState();
  } catch (error) {
    errorNode.textContent = error.message || "登录失败";
  }
});

$("logout").addEventListener("click", async () => {
  try {
    await api("/api/auth/logout", { method: "POST", body: "{}" });
  } finally {
    window.location.reload();
  }
});

window.addEventListener("keydown", (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
    event.preventDefault();
    if (!$("console").hidden) openProjectModal();
  }
  if (event.key === "Escape" && !$("project-modal").hidden) closeProjectModal();
});

restoreRailWidths();
bindRailResizer("project-rail-resizer", "project");

(async () => {
  try {
    const session = await api("/api/auth/session");
    state.csrf = session.csrf_token;
    showConsole();
    await loadConfiguration();
    await refreshProjects();
    bindEmptyState();
  } catch {
    // The login screen is the expected initial state for a new session.
  }
})();
