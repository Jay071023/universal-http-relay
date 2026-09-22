const express = require('express');
const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const crypto = require('crypto');
const httpProxy = require('http-proxy');
const WebSocket = require('ws');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const { Writable } = require('stream');
const msgpack = require('@msgpack/msgpack');

// ==================== 进程守护（防崩溃 + 内存监控） ====================
process.on('uncaughtException', (err) => {
  console.error(`\n  ⚠️  [FATAL] 未捕获异常: ${err.message}`);
  console.error(`  ${err.stack}\n`);
  // 未捕获异常后继续运行可能留下半损坏的服务状态；交给 Windows
  // supervisor/PM2 重启，避免 UI 看似在线但请求和 WebSocket 已失效。
  if (!process.__fatalExitScheduled) {
    process.__fatalExitScheduled = true;
    setTimeout(() => process.exit(1), 100);
  }
});
process.on('unhandledRejection', (reason) => {
  console.error(`\n  ⚠️  [WARN] 未处理的 Promise 拒绝: ${reason instanceof Error ? reason.message : reason}`);
  if (reason instanceof Error) console.error(`  ${reason.stack}\n`);
});

// 每 60 秒打印一次内存使用，排查泄漏
setInterval(() => {
  const mem = process.memoryUsage();
  const rss = (mem.rss / 1024 / 1024).toFixed(1);
  const heap = (mem.heapUsed / 1024 / 1024).toFixed(1);
  const heapTotal = (mem.heapTotal / 1024 / 1024).toFixed(1);
  console.log(`  📊 内存: RSS=${rss}MB  堆=${heap}/${heapTotal}MB  后端=${backends.size}  日志=${requestLogs.length}`);
}, 60000);

// ==================== Admin 认证（HMAC Token + 防暴力破解） ====================
let ADMIN_SECRET = '';

function initAdminSecret() {
  if (CONFIG.admin_secret) {
    ADMIN_SECRET = CONFIG.admin_secret;
    return false;
  } else {
    ADMIN_SECRET = crypto.randomBytes(32).toString('hex');
    CONFIG.admin_secret = ADMIN_SECRET;
    return true; // 需要持久化
  }
}

const loginFails = new Map();  // IP → { count, lastFail }
const LOGIN_MAX_TRIES = 5;
const LOGIN_LOCKOUT_MS = 60000;
const TOKEN_TTL_MS = 604800000; // 7 天

// 活动会话（多设备登录）— 持久化到 config.json，重启不丢失
const activeSessions = new Map();  // token → { id, ip, ua, createdAt, lastActive, name }
const MAX_SESSIONS = 20;          // 最多保留 20 个会话

function hmacSign(data) { return crypto.createHmac('sha256', ADMIN_SECRET).update(data).digest('hex'); }

function createToken(meta = {}) {
  const id = uuidv4();
  const ts = Date.now();
  const exp = ts + TOKEN_TTL_MS;
  const payload = `${id}.${ts}.${exp}`;
  const token = `${payload}.${hmacSign(payload)}`;
  activeSessions.set(token, {
    id,
    ip: meta.ip || 'unknown',
    ua: meta.ua || 'unknown',
    name: meta.name || '',
    createdAt: ts,
    lastActive: ts,
    exp
  });
  // 清理过期的
  for (const [t, s] of activeSessions) {
    if (Date.now() > s.exp) activeSessions.delete(t);
  }
  // 超过上限清理最早的
  while (activeSessions.size > MAX_SESSIONS) {
    const firstKey = activeSessions.keys().next().value;
    activeSessions.delete(firstKey);
  }
  saveSessions();
  return token;
}

function removeToken(token) {
  if (activeSessions.delete(token)) saveSessions();
}

function touchSession(token) {
  const s = activeSessions.get(token);
  if (s) { s.lastActive = Date.now(); }
}

function saveSessions() {
  try {
    const list = Array.from(activeSessions.entries()).map(([token, s]) => ({ token, ...s }));
    CONFIG._sessions = list;
    saveConfig();
  } catch (_) {}
}

function loadSessions() {
  try {
    const list = CONFIG._sessions || [];
    const now = Date.now();
    for (const item of list) {
      if (now < item.exp && item.token) {
        activeSessions.set(item.token, {
          id: item.id, ip: item.ip, ua: item.ua, name: item.name || '',
          createdAt: item.createdAt, lastActive: item.lastActive, exp: item.exp
        });
      }
    }
  } catch (_) {}
}

function verifyToken(token) {
  if (!token) return false;
  const parts = token.split('.');
  if (parts.length !== 4) return false;
  const payload = `${parts[0]}.${parts[1]}.${parts[2]}`;
  const expected = Buffer.from(hmacSign(payload), 'utf8');
  const actual = Buffer.from(parts[3], 'utf8');
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) return false;
  if (Date.now() > parseInt(parts[2])) return false;
  return true;
}

// 带 session 追踪的 token 验证
function verifyTokenAndTouch(token) {
  if (!verifyToken(token)) return false;
  touchSession(token);
  return true;
}

function getClientIp(req) {
  return (req.headers['x-forwarded-for']||'').split(',')[0].trim()
    || req.socket?.remoteAddress || req.connection?.remoteAddress || '127.0.0.1';
}

// Auth middleware
function requireAdmin(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '')
    || req.query._token;
  if (!token || !verifyTokenAndTouch(token)) {
    return res.status(401).json({ ret: -1, error: '未登录或登录已过期' });
  }
  next();
}

// ==================== 配置系统（持久化到 config.json） ====================
const CONFIG_PATH = path.resolve(process.env.LB_CONFIG_PATH || path.join(__dirname, 'config.json'));
// QQ 统计使用追加式文本存储，不再把几千个 QQ 号反复写回 config.json。
const QQ_STATS_DIR = path.resolve(process.env.LB_QQ_STATS_DIR || path.join(path.dirname(CONFIG_PATH), 'qq-stats'));
const QQ_ALL_PATH = path.join(QQ_STATS_DIR, 'all-qq.txt');
const QQ_TOTAL_PATH = path.join(QQ_STATS_DIR, 'total.count');
// 仅用于临时排障的独立路由配置；文件不存在或 enabled=false 时完全不生效。
// 密钥仅保存在运行目录的 debug-route.json，不写入管理配置、日志或响应。
const DEBUG_ROUTE_PATH = path.resolve(process.env.LB_DEBUG_ROUTE_PATH || path.join(__dirname, 'debug-route.json'));
// 一次性节点引导配置：用于把已验证节点安全加入现有分组，不覆盖整个 config.json。
const NODE_BOOTSTRAP_PATH = path.resolve(process.env.LB_NODE_BOOTSTRAP_PATH || path.join(__dirname, 'node-bootstrap.json'));
const MAX_REQUEST_BODY_BYTES = Math.max(1024, parseInt(process.env.LB_MAX_REQUEST_BODY_BYTES, 10) || 10 * 1024 * 1024);

const DEFAULT_CONFIG = {
  port: parseInt(process.env.LB_PORT) || 8888,
  frp_port: parseInt(process.env.LB_FRP_PORT) || 7000,
  admin_password: process.env.LB_ADMIN_PASSWORD || '',
  agent_token: process.env.LB_AGENT_TOKEN || '',
  hc_interval: parseInt(process.env.LB_HC_INTERVAL) || 5000,
  hc_timeout: parseInt(process.env.LB_HC_TIMEOUT) || 8000,
  tunnel_timeout: parseInt(process.env.LB_TUNNEL_TIMEOUT) || 30000,
  // 用户后端可能需要数秒初始化；转发请求的等待上限不得低于 60 秒。
  request_timeout: parseInt(process.env.LB_REQUEST_TIMEOUT) || 120000,
  max_log: parseInt(process.env.LB_MAX_LOG) || 500,
  page_title: process.env.LB_PAGE_TITLE || '负载均衡管理面板',
  bark_key: process.env.LB_BARK_KEY || '',
  monitor_interval: parseInt(process.env.LB_MONITOR_INTERVAL) || 30000, // 监控检查间隔
  persist_stats: true, // 重启后保留统计数据（QQ 统计等）
  version_rewrite_enabled: false, // 是否开启 ver 参数改写
  version_rewrite_target: '9.2.70', // 改写目标版本
  auto_backup_enabled: true, // 自动备份开关
  auto_backup_interval: 21600000, // 自动备份间隔（默认 6 小时）
  max_backups: 30, // 最多保留备份数
  retry_400_enabled: true, // 后端返回 400 时自动重试
  retry_400_max: 2,        // 同一节点最大重试次数
  retry_400_max_backends: 3, // 换节点最多尝试几个
  retry_502_enabled: true, // 后端返回 429/502/504 或连接/传输失败时自动重试
  retry_502_max: 2,        // 同一节点最大重试次数
  retry_502_max_backends: 3, // 换节点最多尝试几个
};

let CONFIG = { ...DEFAULT_CONFIG };
let hcTimer = null;      // 健康检查定时器
let statsTimer = null;   // 统计推送定时器
let debugRoute = null;

function loadConfig() {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      const data = fs.readFileSync(CONFIG_PATH, 'utf8');
      CONFIG = { ...DEFAULT_CONFIG, ...JSON.parse(data) };
      console.log(`  📋 已加载配置文件 ${CONFIG_PATH}`);
    } else {
      saveConfig();
    }
  } catch (e) {
    console.error(`  ⚠️ 配置文件读取失败，使用默认配置: ${e.message}`);
  }
}

function saveConfig() {
  try {
    const dir = path.dirname(CONFIG_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const tempPath = `${CONFIG_PATH}.tmp-${process.pid}`;
    fs.writeFileSync(tempPath, JSON.stringify(CONFIG, null, 2), { encoding: 'utf8', mode: 0o640 });
    fs.renameSync(tempPath, CONFIG_PATH);
    return true;
  } catch (e) {
    console.error(`  ❌ 配置文件写入失败: ${e.message}`);
    return false;
  }
}

function loadDebugRoute() {
  debugRoute = null;
  try {
    if (!fs.existsSync(DEBUG_ROUTE_PATH)) return;
    const data = JSON.parse(fs.readFileSync(DEBUG_ROUTE_PATH, 'utf8'));
    if (!data.enabled || typeof data.token !== 'string' || data.token.length < 32) return;
    if (typeof data.url !== 'string' || !/^https?:\/\//i.test(data.url)) return;
    debugRoute = {
      token: data.token,
      url: data.url,
      tag: String(data.tag || 'debug-route').slice(0, 100),
      query_to_json_enabled: !!data.query_to_json_enabled,
      post_to_get_enabled: !!data.post_to_get_enabled
    };
    console.log(`  🧪 已启用仅调试路由 → ${debugRoute.tag}`);
  } catch (e) {
    console.error(`  ⚠️ 调试路由配置无效，已忽略: ${e.message}`);
  }
}

/** 仅匹配持有运行期密钥的排障请求；请求头在转发前删除。 */
function selectDebugRoute(req) {
  if (!debugRoute) return null;
  const provided = String(req.headers['x-lb-debug-route'] || '');
  const expected = Buffer.from(debugRoute.token, 'utf8');
  const actual = Buffer.from(provided, 'utf8');
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) return null;
  delete req.headers['x-lb-debug-route'];
  return {
    id: `debug:${crypto.createHash('sha256').update(debugRoute.url).digest('hex').slice(0, 16)}`,
    type: 'http', url: debugRoute.url, tag: debugRoute.tag, group: '__debug__',
    alive: true, connections: 0, responseTime: 0, totalRequests: 0, successRequests: 0, failRequests: 0,
    query_to_json_enabled: debugRoute.query_to_json_enabled,
    post_to_get_enabled: debugRoute.post_to_get_enabled,
    _debugRoute: true
  };
}

function ensureAdminPassword() {
  if (CONFIG.admin_password) return false;
  CONFIG.admin_password = crypto.randomBytes(18).toString('base64url');
  console.log(`  🔐 首次启动已生成管理员密码，请从本次启动日志中保存: ${CONFIG.admin_password}`);
  return true;
}

const CONFIG_MUTABLE_KEYS = [
  'agent_token', 'hc_interval', 'hc_timeout', 'tunnel_timeout', 'max_log', 'frp_port',
  'request_timeout',
  'admin_password', 'page_title', 'bark_key', 'monitor_interval', 'persist_stats',
  'version_rewrite_enabled', 'version_rewrite_target', 'auto_backup_enabled',
  'auto_backup_interval', 'max_backups', 'retry_400_enabled', 'retry_400_max',
  'retry_400_max_backends', 'cors_origins',
  'retry_502_enabled', 'retry_502_max', 'retry_502_max_backends'
];
const CONFIG_CLIENT_KEYS = [
  'port', 'frp_port', 'agent_token', 'hc_interval', 'hc_timeout', 'tunnel_timeout',
  'request_timeout',
  'max_log', 'page_title', 'monitor_interval', 'persist_stats', 'version_rewrite_enabled',
  'version_rewrite_target', 'auto_backup_enabled', 'auto_backup_interval', 'max_backups',
  'retry_400_enabled', 'retry_400_max', 'retry_400_max_backends', 'cors_origins',
  'retry_502_enabled', 'retry_502_max', 'retry_502_max_backends'
];

function getClientConfig() {
  const result = {};
  for (const key of CONFIG_CLIENT_KEYS) {
    if (CONFIG[key] !== undefined) result[key] = CONFIG[key];
  }
  return result;
}

// 转发等待时间与健康检查时间分离。旧配置仍可用 tunnel_timeout 作为回退值，
// 但不会允许管理面板误把 5~6 秒的后端初始化当成超时。
const MIN_REQUEST_TIMEOUT = 60 * 1000;
const MAX_REQUEST_TIMEOUT = 10 * 60 * 1000;
function getForwardTimeout() {
  const configured = Number(CONFIG.request_timeout || CONFIG.tunnel_timeout);
  if (!Number.isFinite(configured)) return 120 * 1000;
  return Math.max(MIN_REQUEST_TIMEOUT, Math.min(MAX_REQUEST_TIMEOUT, configured));
}

function getTunnelConnectTimeout() {
  const configured = Number(CONFIG.tunnel_timeout);
  if (!Number.isFinite(configured)) return 30 * 1000;
  return Math.max(10 * 1000, Math.min(120 * 1000, configured));
}

// ==================== 分组 & 路由规则 ====================
// groups: { name: { algorithm, description } }
// rules:  [{ id, path, group, priority }]
// 这些数据存储在 CONFIG 中持久化

const DEFAULT_GROUPS = { 'default': { algorithm: 'round-robin', description: '默认分组（未匹配规则的请求）' } };
let groups = { ...DEFAULT_GROUPS };
let rules = [];
let ruleIdCounter = 1;
let sortedRules = [];

function initGroupsAndRules() {
  groups = CONFIG.groups ? { ...DEFAULT_GROUPS, ...CONFIG.groups } : { ...DEFAULT_GROUPS };
  rules = CONFIG.rules || [];
  ruleIdCounter = rules.length > 0 ? Math.max(...rules.map(r => r.id)) + 1 : 1;
  updateSortedRules();
  // 确保 default 分组始终存在
  if (!groups['default']) groups['default'] = { algorithm: 'round-robin', description: '默认分组' };
  syncConfigGroupsRules();
}

function syncConfigGroupsRules() {
  CONFIG.groups = groups;
  CONFIG.rules = rules;
  saveConfig();
}

function updateSortedRules() {
  sortedRules = [...rules].sort((a, b) => (b.priority || 0) - (a.priority || 0));
}

const RULE_MATCH_TYPES = new Set(['prefix', 'query', 'json', 'keyword', 'header', 'method']);

function readJsonField(body, keyPath) {
  let value = body;
  for (const key of keyPath.split('.')) {
    if (value == null || typeof value !== 'object') return undefined;
    value = value[key];
  }
  return value;
}

function useMatchedRule(req, rule) {
  req._lbMatchedRule = rule;
  return rule.group;
}

/** 按优先级匹配路径、参数、JSON、关键词、请求头和方法，返回分组名。 */
function matchGroup(req) {
  const url = req.url || '/';
  const qIdx = url.indexOf('?');
  const pathOnly = qIdx >= 0 ? url.slice(0, qIdx) : url;
  const queryStr = qIdx >= 0 ? url.slice(qIdx + 1) : '';
  let decodedUrl = url;
  try { decodedUrl = decodeURIComponent(url); } catch (_) {}
  let jsonText = '';
  if (req.body && typeof req.body === 'object') {
    try { jsonText = JSON.stringify(req.body).slice(0, 65536).toLowerCase(); } catch (_) {}
  }
  const headerText = Object.entries(req.headers || {})
    .map(([key, value]) => `${key}:${Array.isArray(value) ? value.join(',') : value}`).join('\n').slice(0, 16384).toLowerCase();

  for (const rule of sortedRules) {
    if (rule.matchType === 'query') {
      // query 类型: rule.path 格式为 /path?key=value
      const qi = rule.path.indexOf('?');
      if (qi === -1) continue;
      const rulePath = rule.path.slice(0, qi);
      const ruleQuery = rule.path.slice(qi + 1);
      if (!pathOnly.startsWith(rulePath)) continue;
      const params = queryStr.split('&');
      const matched = params.some(p => p === ruleQuery || p.startsWith(ruleQuery + '='));
      if (matched) return useMatchedRule(req, rule);
    } else if (rule.matchType === 'json') {
      // json 类型: /path:key.subkey=value
      const colon = rule.path.indexOf(':');
      if (colon === -1) continue;
      const rulePath = rule.path.slice(0, colon);
      const expr = rule.path.slice(colon + 1);
      const eq = expr.indexOf('=');
      if (eq === -1 || !pathOnly.startsWith(rulePath)) continue;
      if (String(readJsonField(req.body, expr.slice(0, eq))) === expr.slice(eq + 1)) return useMatchedRule(req, rule);
    } else if (rule.matchType === 'keyword') {
      const keyword = rule.path.trim().toLowerCase();
      if (keyword && (decodedUrl.toLowerCase().includes(keyword) || headerText.includes(keyword) || jsonText.includes(keyword))) return useMatchedRule(req, rule);
    } else if (rule.matchType === 'header') {
      const separator = rule.path.indexOf('=');
      if (separator === -1) continue;
      const name = rule.path.slice(0, separator).trim().toLowerCase();
      const expected = rule.path.slice(separator + 1).trim().toLowerCase();
      const actual = req.headers?.[name];
      if (name && expected && String(Array.isArray(actual) ? actual.join(',') : actual || '').toLowerCase().includes(expected)) return useMatchedRule(req, rule);
    } else if (rule.matchType === 'method') {
      const methods = rule.path.split(',').map(value => value.trim().toUpperCase());
      if (methods.includes(String(req.method || '').toUpperCase())) return useMatchedRule(req, rule);
    } else if (url.startsWith(rule.path)) {
      // prefix 类型（默认）: 在完整 URL（含查询串）上做前缀匹配
      return useMatchedRule(req, rule);
    }
  }
  return 'default';
}

/**
 * 改写 ver 参数为指定目标版本。
 * 支持：
 *   - 查询参数:  ver=xxx → ver=<target>
 *   - JSON body: "ver":"xxx" → "ver":"<target>"
 *   - form-urlencoded: ver=xxx → ver=<target>
 * 返回改写后的 Buffer 或原 Buffer（无需改写时）。
 */
function rewriteVersion(rawBuffer, contentType) {
  if (!CONFIG.version_rewrite_enabled || !rawBuffer || rawBuffer.length === 0) return rawBuffer;
  const target = CONFIG.version_rewrite_target || '9.2.70';
  const ct = String(contentType || '').toLowerCase();
  let text;
  try { text = rawBuffer.toString('utf8'); } catch (_) { return rawBuffer; }
  if (!text.includes('ver=') && !/["']ver["']/.test(text)) return rawBuffer;
  let newText;
  if (ct.includes('application/json')) {
    newText = text.replace(/"ver"\s*:\s*"[^"]*"/g, `"ver":"${target}"`);
  } else {
    newText = text.replace(/(ver=)[^&"'\s]*/g, `$1${target}`);
  }
  if (newText === text) return rawBuffer;
  return Buffer.from(newText, 'utf8');
}

/** 获取分组的算法 */
function getGroupAlgorithm(groupName) {
  return (groups[groupName] || groups['default']).algorithm;
}

/** 节点可同时属于多个分组；group 保留为主分组以兼容旧配置和旧客户端。 */
function backendGroupNames(backend) {
  const raw = Array.isArray(backend?.groups) ? backend.groups : [backend?.group || 'default'];
  const names = [...new Set(raw.map(name => String(name || '').trim()).filter(name => name && groups[name]))];
  return names.length ? names : ['default'];
}

function setBackendGroups(backend, names) {
  const normalized = [...new Set((Array.isArray(names) ? names : [names]).map(name => String(name || '').trim()))]
    .filter(name => name && groups[name]);
  backend.groups = normalized.length ? normalized : ['default'];
  backend.group = backend.groups[0];
  return backend.groups;
}

function validateBackendGroups(value) {
  if (!Array.isArray(value)) value = [value];
  if (value.length < 1 || value.length > 100) return { error: '请至少选择 1 个分组' };
  const names = [...new Set(value.map(name => String(name || '').trim()).filter(Boolean))];
  if (!names.length) return { error: '请至少选择 1 个分组' };
  const unknown = names.find(name => !groups[name]);
  if (unknown) return { error: `分组不存在: ${unknown}` };
  return { names };
}

function backendInGroup(backend, groupName) {
  return backendGroupNames(backend).includes(groupName);
}

/** 获取分组内所有在线的后端 */
function getAliveBackendsInGroup(groupName, excludeIds) {
  return Array.from(backends.values())
    .filter(b => b.alive && !b.disabled)
    .filter(b => backendInGroup(b, groupName))
    .filter(b => !excludeIds || !excludeIds.has(b.id));
}

// ==================== 算法定义 ====================
const ALGORITHMS = {
  'round-robin':           { name: '轮询',             description: '依次循环选择后端节点，平均分配请求',               icon: '🔄' },
  'weighted-round-robin':  { name: '加权轮询',         description: '根据权重比例分配请求，权重越高承担越多流量',       icon: '⚖️' },
  'least-connections':     { name: '最少连接',         description: '选择当前活跃连接数最少的节点',                   icon: '🔗' },
  'ip-hash':               { name: 'IP哈希',           description: '根据客户端IP哈希值选择节点，同IP分配到同节点',      icon: '📍' },
  'random':                { name: '随机',             description: '从可用节点中随机选择一个',                       icon: '🎲' },
  'least-response-time':   { name: '最少响应时间',     description: '选择平均响应时间最短的节点',                     icon: '⚡' }
};

// ==================== 核心数据结构 ====================
const backends = new Map();         // id → backend object（HTTP 或 Tunnel）
let currentAlgorithm = 'round-robin';    // 默认算法（同时作为 default 分组的算法）
const pendingRequests = new Map();  // requestId → { backendId, resolve, reject, timer }
const requestLogs = [];
const retryRequests = new Map();    // reqId → { reason, budgets, triedBackendIds }

// ==================== 自动重试（400 / 431 / 429 / 502 / 504 / 连接失败） ====================
// 统一重试预算结构: { reason:'400'|'502', budgets:{400:{same,backends},502:{same,backends}}, tried*:Set }
// budgets[r].same = 同一节点最多重试次数；budgets[r].backends = 最多换节点次数
function retryBudgets() {
  return {
    400: {
      same: CONFIG.retry_400_enabled ? (CONFIG.retry_400_max || 2) : 0,
      backends: CONFIG.retry_400_enabled ? (CONFIG.retry_400_max_backends || 3) - 1 : 0,
    },
    502: {
      same: CONFIG.retry_502_enabled ? (CONFIG.retry_502_max || 2) : 0,
      backends: CONFIG.retry_502_enabled ? (CONFIG.retry_502_max_backends || 3) - 1 : 0,
    },
  };
}
function anyRetryEnabled() {
  return !!(CONFIG.retry_400_enabled || CONFIG.retry_502_enabled);
}
function retryAllowed(reason) {
  return reason === '400' ? !!CONFIG.retry_400_enabled : !!CONFIG.retry_502_enabled;
}

/** 管理日志只保留路径和查询参数数量，避免 buffer/sign 等大字段泄露或刷屏。 */
function displayRequestPath(url) {
  const text = String(url || '/');
  const queryIndex = text.indexOf('?');
  if (queryIndex === -1) return text;
  const query = text.slice(queryIndex + 1);
  const count = query ? query.split('&').filter(Boolean).length : 0;
  return `${text.slice(0, queryIndex) || '/'}?…${count ? `(${count})` : ''}`;
}
function retryReasonForStatus(statusCode) {
  return statusCode === 400 ? '400' : '502';
}
function isRetryableUpstreamStatus(statusCode) {
  return statusCode === 400 || statusCode === 431 || statusCode === 429 || statusCode === 502 || statusCode === 504;
}
/** QSign 常以 HTTP 200 包装业务错误；把其中可重试的 code 视为对应上游状态。 */
function getRetryableResponseStatus(statusCode, body) {
  if (isRetryableUpstreamStatus(statusCode)) return statusCode;
  if (statusCode < 200 || statusCode >= 300 || !body || body.length === 0) return null;
  try {
    const payload = JSON.parse(Buffer.isBuffer(body) ? body.toString('utf8') : String(body));
    const code = Number(payload?.code);
    return isRetryableUpstreamStatus(code) ? code : null;
  } catch (_) {
    return null;
  }
}
function retrySameMax(reason) {
  return reason === '400' ? (CONFIG.retry_400_max || 2) : (CONFIG.retry_502_max || 2);
}
function isSuccessfulStatus(statusCode) {
  return statusCode >= 200 && statusCode < 400;
}
function normalizeBackendWeight(value) {
  const parsed = Number.parseInt(value, 10);
  return Number.isInteger(parsed) ? Math.min(10000, Math.max(1, parsed)) : 1;
}
const MAX_SHOWN_LOGS = 200; // 日志前端最多展示量，但后端全量保留
const stats = {
  totalRequests: 0, successRequests: 0, failRequests: 0,
  historyRequests: new Array(60).fill(0),
  historyResponseTime: new Array(60).fill(0),
  lastMinute: new Date().getMinutes(),
  shownLogIndex: 0
};
const wsSubscribers = new Set();    // 管理页面前端 WebSocket 订阅者

// RPS 以进入代理入口的真实请求计数；不把重试和日志刷新当成新请求。
const recentRequestTimes = [];
let recentRequestHead = 0;
function pruneRequestTimes(now) {
  const cutoff = now - 1000;
  while (recentRequestHead < recentRequestTimes.length && recentRequestTimes[recentRequestHead] <= cutoff) recentRequestHead++;
  if (recentRequestHead > 4096 && recentRequestHead * 2 >= recentRequestTimes.length) {
    recentRequestTimes.splice(0, recentRequestHead);
    recentRequestHead = 0;
  }
}
function recordIncomingRequest() {
  const now = Date.now();
  recentRequestTimes.push(now);
  pruneRequestTimes(now);
}
function calcRps() {
  pruneRequestTimes(Date.now());
  return recentRequestTimes.length - recentRequestHead;
}

// 持久化后端节点（所有类型）
function saveBackends() {
  const list = [];
  for (const [, b] of backends) {
    // HTTP 后端完整保存；tunnel/frp 保存配置以便重连时恢复偏好
    if (b.type === 'http') {
      list.push({ id: b.id, type: b.type, url: b.url, weight: b.weight, tag: b.tag || '', group: backendGroupNames(b)[0], groups: backendGroupNames(b), disable_health_check: !!b.disable_health_check, query_to_json_enabled: !!b.query_to_json_enabled, post_to_get_enabled: !!b.post_to_get_enabled, disabled: !!b.disabled, createdAt: b.createdAt });
    } else {
      // tunnel / frp：保存偏好配置（ID 会变，用 tag 匹配恢复）
      list.push({ type: b.type, tag: b.tag || '', weight: b.weight || 1, group: backendGroupNames(b)[0], groups: backendGroupNames(b), disable_health_check: !!b.disable_health_check, query_to_json_enabled: !!b.query_to_json_enabled, post_to_get_enabled: !!b.post_to_get_enabled, disabled: !!b.disabled, _preference: true });
    }
  }
  CONFIG._backends = list;
  saveConfig();
}
function loadBackends() {
  const list = CONFIG._backends || [];
  for (const b of list) {
    if (b.type === 'http' && b.url) {
      const backend = {
        id: b.id, type: 'http', url: b.url, weight: normalizeBackendWeight(b.weight), tag: b.tag || '',
        alive: !b.disabled, connections: 0, responseTime: 0,
        totalRequests: 0, successRequests: 0, failRequests: 0,
        disable_health_check: !!b.disable_health_check, query_to_json_enabled: !!b.query_to_json_enabled, post_to_get_enabled: !!b.post_to_get_enabled,
        disabled: !!b.disabled,
        createdAt: b.createdAt || Date.now(), lastCheck: Date.now()
      };
      setBackendGroups(backend, b.groups || b.group || 'default');
      backends.set(b.id, backend);
    }
  }
  // 保存 tunnel/frp 偏好配置供 Agent 重连时恢复
  CONFIG._backend_prefs = list.filter(b => b._preference);
  console.log(`  📦 已恢复 ${backends.size} 个后端节点`);
}

function normalizeBackendUrl(url) {
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host}${parsed.pathname.replace(/\/+$/, '') || '/'}`;
  } catch (_) {
    return '';
  }
}

/**
 * 仅在运行目录存在 enabled=true 的 node-bootstrap.json 时执行一次节点配置合并。
 * 正常模式只更新同 URL 节点；紧急恢复模式可显式清除全部节点的格式转换并停用目标节点。
 */
function applyNodeBootstrap() {
  try {
    if (!fs.existsSync(NODE_BOOTSTRAP_PATH)) return false;
    const data = JSON.parse(fs.readFileSync(NODE_BOOTSTRAP_PATH, 'utf8'));
    const removeRuleKeys = Array.isArray(data.removeBootstrapRules) ? new Set(data.removeBootstrapRules.map(String)) : null;
    if (removeRuleKeys && removeRuleKeys.size > 0) {
      const before = rules.length;
      rules = rules.filter(rule => !removeRuleKeys.has(String(rule._bootstrapKey || '')));
      updateSortedRules();
      CONFIG.groups = groups;
      CONFIG.rules = rules;
      saveBackends();
      console.log(`  ✅ 已移除 ${before - rules.length} 条固定节点规则`);
      return true;
    }
    if (data.resetAllFormatTransforms) {
      for (const item of backends.values()) {
        if (item.type !== 'http') continue;
        item.query_to_json_enabled = false;
        item.post_to_get_enabled = false;
      }
    }
    const targetUrlForRecovery = normalizeBackendUrl(data.url);
    if (data.disableTarget && targetUrlForRecovery) {
      const target = Array.from(backends.values()).find(item => item.type === 'http' && normalizeBackendUrl(item.url) === targetUrlForRecovery);
      if (target) {
        target.disabled = true;
        target.alive = false;
        target.query_to_json_enabled = false;
        target.post_to_get_enabled = false;
      }
      CONFIG.groups = groups;
      CONFIG.rules = rules;
      saveBackends();
      console.log(`  ✅ 节点恢复已生效: 已清除格式转换${target ? `，并停用 ${target.tag || target.url}` : ''}`);
      return true;
    }
    const normalizedUrl = data.enabled ? normalizeBackendUrl(data.url) : '';
    const groupName = String(data.group || '').trim();
    if (!normalizedUrl || !groupName) return false;
    if (!groups[groupName]) groups[groupName] = { algorithm: 'weighted-round-robin', description: '' };

    let backend = Array.from(backends.values()).find(item => item.type === 'http' && normalizeBackendUrl(item.url) === normalizedUrl);
    if (!backend) {
      backend = {
        id: uuidv4(), type: 'http', url: data.url, weight: normalizeBackendWeight(data.weight),
        tag: String(data.tag || '').slice(0, 100), group: groupName, groups: [groupName],
        alive: true, connections: 0, responseTime: 0, totalRequests: 0, successRequests: 0, failRequests: 0,
        disable_health_check: !!data.disable_health_check,
        query_to_json_enabled: !!data.query_to_json_enabled,
        post_to_get_enabled: !!data.post_to_get_enabled,
        disabled: false, createdAt: Date.now(), lastCheck: Date.now()
      };
      backends.set(backend.id, backend);
    } else {
      setBackendGroups(backend, data.groups || groupName);
      backend.weight = normalizeBackendWeight(data.weight ?? backend.weight);
      backend.tag = String(data.tag || backend.tag || '').slice(0, 100);
      backend.disable_health_check = !!data.disable_health_check;
      backend.query_to_json_enabled = !!data.query_to_json_enabled;
      backend.post_to_get_enabled = !!data.post_to_get_enabled;
      if (backend.query_to_json_enabled) backend.post_to_get_enabled = false;
      backend.disabled = false;
      backend.alive = true;
      backend.lastCheck = Date.now();
    }
    const bootstrapRules = Array.isArray(data.rules) ? data.rules : [];
    for (const spec of bootstrapRules) {
      const key = String(spec.key || '').trim();
      const matchType = String(spec.matchType || 'prefix').trim();
      const rulePath = String(spec.path || '').trim();
      const targetGroup = String(spec.group || groupName).trim();
      const targetUrl = normalizeBackendUrl(spec.backendUrl || data.url);
      if (!key || !RULE_MATCH_TYPES.has(matchType) || !rulePath || !groups[targetGroup] || !targetUrl) continue;
      const ruleData = {
        _bootstrapKey: key,
        matchType,
        path: rulePath,
        group: targetGroup,
        priority: Number.isFinite(Number(spec.priority)) ? Number(spec.priority) : 0,
        backendUrl: targetUrl
      };
      const existing = rules.find(rule => rule._bootstrapKey === key);
      if (existing) Object.assign(existing, ruleData);
      else rules.push({ id: `bootstrap:${key}`, ...ruleData });
    }
    updateSortedRules();
    CONFIG.groups = groups;
    CONFIG.rules = rules;
    saveBackends();
    console.log(`  ✅ 节点引导已生效: ${backend.tag || backend.url} → ${groupName}`);
    return true;
  } catch (e) {
    console.error(`  ⚠️ 节点引导配置无效，已忽略: ${e.message}`);
    return false;
  }
}

// ==================== FRPS（标准 frpc TLS 协议） ====================
// frp v0.52+ 默认启用 TLS 加密控制连接
const frpControlConns = new Map();
const frpWorkWaiters = new Map();
let frpsServer = null;
let frpsTlsOptions = null;

function getTlsOptions() {
  if (frpsTlsOptions !== null) return frpsTlsOptions;
  const certDir = path.join(__dirname, 'certs');
  // 1) PEM 格式证书（openssl 生成）
  const keyPath = path.join(certDir, 'frps.key');
  const certPath = path.join(certDir, 'frps.crt');
  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    frpsTlsOptions = { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) };
    console.log(`  [FRPS] 加载证书: ${certPath}`);
    return frpsTlsOptions;
  }
  // 2) PFX 格式（PowerShell 生成）
  const pfxPath = path.join(certDir, 'frps.pfx');
  if (fs.existsSync(pfxPath)) {
    try {
      const ctx = tls.createSecureContext({ pfx: fs.readFileSync(pfxPath), passphrase: 'frps' });
      // extract key/cert from context - just pass pfx directly
      frpsTlsOptions = { pfx: fs.readFileSync(pfxPath), passphrase: 'frps' };
      console.log(`  [FRPS] 加载 PFX: ${pfxPath}`);
      return frpsTlsOptions;
    } catch (e) {
      console.error(`  [FRPS] PFX 加载失败: ${e.message}`);
    }
  }
  // 3) 尝试 openssl 自动生成
  try {
    const { execSync } = require('child_process');
    if (!fs.existsSync(certDir)) fs.mkdirSync(certDir, { recursive: true });
    execSync(`openssl req -x509 -newkey rsa:2048 -keyout "${keyPath}" -out "${certPath}" -days 3650 -nodes -subj "/CN=frps"`, { timeout: 15000, stdio: 'pipe' });
    frpsTlsOptions = { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) };
    console.log(`  [FRPS] openssl 证书已生成`);
    return frpsTlsOptions;
  } catch (e) { /* openssl not available */ }
  // 4) 无证书，降级纯 TCP
  frpsTlsOptions = false;
  return false;
}

function sendFrpMsg(socket, obj) {
  const payload = Buffer.from(msgpack.encode(obj));
  const header = Buffer.alloc(4);
  header.writeInt32BE(payload.length, 0);
  if (!socket.destroyed && socket.writable) {
    socket.write(Buffer.concat([header, payload]));
  }
}

function logFrp(msg) {
  console.log(`  [FRPS ${new Date().toLocaleTimeString()}] ${msg}`);
}

function handleFrpConnection(socket, initialChunk) {
  socket.setKeepAlive(true, 30000);
  socket.setNoDelay(true);
  socket.resume();
  let buf = Buffer.alloc(0);
  let isControl = false;
  let ctrlProxyName = null;
  let ctrlRunId = null;
  let idleTimer = null;

  function resetIdle() {
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      logFrp(`${ctrlProxyName || 'unknown'} 空闲超时断开`);
      socket.destroy();
    }, 300000);
  }
  resetIdle();

  socket.on('data', (chunk) => {
    resetIdle();
    buf = Buffer.concat([buf, chunk]);
    if (buf.length > 1048576) { logFrp('消息过大，断开'); socket.destroy(); return; }

    while (buf.length >= 4) {
      const msgLen = buf.readInt32BE(0);
      if (msgLen <= 0 || msgLen > 524288) {
        // 打印原始字节帮助排查
        const hex = buf.slice(0, Math.min(16, buf.length)).toString('hex');
        logFrp(`非法消息长度 ${msgLen}，首字节: ${hex}，断开`);
        socket.destroy(); return;
      }
      if (buf.length < 4 + msgLen) break;

      const msgData = buf.slice(4, 4 + msgLen);
      buf = buf.slice(4 + msgLen);

      let msg;
      try { msg = msgpack.decode(msgData); } catch (e) {
        logFrp(`msgpack 解码失败: ${e.message}`);
        socket.destroy(); return;
      }

      if (!isControl && msg.version && msg.hostname !== undefined) {
        isControl = true;
        if (CONFIG.agent_token && msg.privilege_key !== CONFIG.agent_token) {
          logFrp(`认证失败: ${msg.hostname}`);
          sendFrpMsg(socket, { version: '', run_id: '', error: 'token invalid' });
          socket.end(); return;
        }
        ctrlRunId = uuidv4();
        sendFrpMsg(socket, { version: '0.58.0', run_id: ctrlRunId, error: '' });
        logFrp(`已连接: ${msg.hostname} (${msg.os}/${msg.arch}) v${msg.version}`);
        return;
      }

      if (isControl && msg.proxy_name) {
        ctrlProxyName = msg.proxy_name;
        let g = msg.group || msg.group_key || 'default';
        if (!groups[g]) groups[g] = { algorithm: 'round-robin', description: g };
        // 恢复保存的偏好配置
        const frpPrefs = (CONFIG._backend_prefs || []).find(p => p.type === 'frp' && p.tag === ctrlProxyName);
        const backendId = uuidv4();
        const backend = {
          id: backendId, type: 'frp', tag: ctrlProxyName,
          weight: normalizeBackendWeight(frpPrefs?.weight), query_to_json_enabled: !!frpPrefs?.query_to_json_enabled, post_to_get_enabled: !!frpPrefs?.post_to_get_enabled,
          alive: !(frpPrefs?.disabled), connections: 0, responseTime: 0,
          totalRequests: 0, successRequests: 0, failRequests: 0,
          disable_health_check: frpPrefs?.disable_health_check || false,
          disabled: frpPrefs?.disabled || false,
          createdAt: Date.now(), lastCheck: Date.now(),
          remoteAddress: socket.remoteAddress || 'unknown',
          connectedAt: Date.now(), frpProxyName: ctrlProxyName
        };
        setBackendGroups(backend, frpPrefs?.groups || frpPrefs?.group || g);
        if (frpPrefs) console.log(`  📋 恢复 ${ctrlProxyName} 偏好: group=${backend.group} hc=${backend.disable_health_check ? 'off' : 'on'}`);
        backends.set(backendId, backend);
        frpControlConns.set(ctrlProxyName, { socket, backendId, group: g });
        sendFrpMsg(socket, { proxy_name: ctrlProxyName, error: '' });
        broadcast({ type: 'backend_added', backend });
        const connLog = { id: uuidv4(), time: new Date().toLocaleTimeString(), method: 'FRPC', path: ctrlProxyName,
          sourceIp: backend.remoteAddress, backend: `frp:${ctrlProxyName}`, backendTag: ctrlProxyName, type: 'frp',
          group: g, algorithm: 'frp-connect', responseTime: 0, statusCode: 200, success: true };
        requestLogs.push(connLog);
        if (requestLogs.length > CONFIG.max_log) requestLogs.shift();
        broadcast({ type: 'new_log', log: connLog });
        logFrp(`代理注册: ${ctrlProxyName} -> ${g}`);
        return;
      }

      if (isControl && Object.keys(msg).length === 0) { sendFrpMsg(socket, {}); return; }

      if (!isControl && msg.run_id) {
        let paired = false;
        for (const waiters of frpWorkWaiters.values()) {
          if (waiters.length > 0) {
            const w = waiters.shift();
            clearTimeout(w.timer);
            w.resolve(socket);
            paired = true;
            break;
          }
        }
        if (!paired) socket.destroy();
        return;
      }

      logFrp(`未知消息: ${JSON.stringify(msg).slice(0, 120)}`);
    }
  });

  socket.on('close', () => {
    if (idleTimer) clearTimeout(idleTimer);
    if (ctrlProxyName && frpControlConns.has(ctrlProxyName)) {
      const info = frpControlConns.get(ctrlProxyName);
      if (backends.has(info.backendId)) {
        backends.delete(info.backendId);
        broadcast({ type: 'backend_removed', id: info.backendId, tag: ctrlProxyName });
      }
      frpControlConns.delete(ctrlProxyName);
      const waiters = frpWorkWaiters.get(ctrlProxyName) || [];
      for (const w of waiters) { clearTimeout(w.timer); try { w.reject(new Error('frpc 断开')); } catch(_){} }
      frpWorkWaiters.delete(ctrlProxyName);
      const discLog = { id: uuidv4(), time: new Date().toLocaleTimeString(), method: 'FRPC', path: ctrlProxyName,
        sourceIp: 'unknown', backend: `frp:${ctrlProxyName}`, backendTag: ctrlProxyName, type: 'frp',
        group: '-', algorithm: 'frp-disconnect', responseTime: 0, statusCode: 0, success: false };
      requestLogs.push(discLog);
      if (requestLogs.length > CONFIG.max_log) requestLogs.shift();
      broadcast({ type: 'new_log', log: discLog });
      logFrp(`断开: ${ctrlProxyName}`);
    }
  });

  socket.on('error', (err) => { logFrp(`错误: ${err.message}`); socket.destroy(); });

  if (initialChunk && initialChunk.length > 0) {
    setImmediate(() => socket.emit('data', initialChunk));
  }
}

// ==================== FRP HTTP 转发 ====================
function decodeChunkedBody(body) {
  const chunks = [];
  let offset = 0;
  while (offset < body.length) {
    const lineEnd = body.indexOf('\r\n', offset);
    if (lineEnd < 0) return null;
    const sizeText = body.subarray(offset, lineEnd).toString('ascii').split(';', 1)[0].trim();
    const size = Number.parseInt(sizeText, 16);
    if (!Number.isFinite(size) || size < 0) return null;
    offset = lineEnd + 2;
    if (size === 0) {
      // 允许 trailers；只要完整的空行已经到达即可结束。
      const trailerEnd = body.indexOf('\r\n', offset);
      if (trailerEnd < 0) return null;
      return Buffer.concat(chunks);
    }
    if (offset + size + 2 > body.length) return null;
    chunks.push(body.subarray(offset, offset + size));
    if (body[offset + size] !== 0x0d || body[offset + size + 1] !== 0x0a) return null;
    offset += size + 2;
  }
  return null;
}

/**
 * 解析 FRP work_conn 上的单个 HTTP 响应。
 * 返回 null 表示还没收齐，避免把慢初始化或 TCP 分片误判为失败。
 */
function parseRawHttpResponse(buffer, requestMethod, ended) {
  const separator = Buffer.from('\r\n\r\n');
  const headerEnd = buffer.indexOf(separator);
  if (headerEnd < 0) return null;
  const headerLines = buffer.subarray(0, headerEnd).toString('latin1').split('\r\n');
  const statusMatch = (headerLines[0] || '').match(/^HTTP\/\d\.\d\s+(\d{3})/);
  if (!statusMatch) return { error: 'invalid_status' };
  const statusCode = Number.parseInt(statusMatch[1], 10);
  const headers = {};
  for (const line of headerLines.slice(1)) {
    const sep = line.indexOf(':');
    if (sep <= 0) continue;
    const key = line.slice(0, sep).trim().toLowerCase();
    const value = line.slice(sep + 1).trim();
    if (key === 'set-cookie') headers[key] = [...(headers[key] || []), value];
    else headers[key] = headers[key] ? `${headers[key]}, ${value}` : value;
  }
  const bodyStart = headerEnd + 4;
  if (requestMethod === 'HEAD' || (statusCode >= 100 && statusCode < 200) || [204, 304].includes(statusCode)) {
    return { statusCode, headers, body: Buffer.alloc(0) };
  }
  const body = buffer.subarray(bodyStart);
  const transferEncoding = String(headers['transfer-encoding'] || '').toLowerCase();
  if (transferEncoding.includes('chunked')) {
    const decoded = decodeChunkedBody(body);
    return decoded ? { statusCode, headers, body: decoded } : null;
  }
  const length = Number.parseInt(headers['content-length'], 10);
  if (Number.isInteger(length) && length >= 0) {
    if (body.length < length) return null;
    return { statusCode, headers, body: body.subarray(0, length) };
  }
  // 没有长度信息时只能依赖对端 FIN；在 FIN 之前继续等待，避免截断响应。
  return ended ? { statusCode, headers, body } : null;
}

function forwardViaFrp(req, res, backend, retryState) {
  req._lbBackendId = backend.id;
  prepareForwardRequest(req);
  const proxyName = backend.frpProxyName;
  const ctrl = frpControlConns.get(proxyName);
  if (!retryState) retryState = { budgets: retryBudgets(), triedIds: new Set() };
  retryState.triedIds.add(backend.id);

  // 502/504/传输失败：先重试当前 frp 节点，耗尽后再换节点。
  const failover502 = (workSocket, note) => {
    if (!CONFIG.retry_502_enabled) return false;
    const b = retryState.budgets['502'];
    if (b.same > 0) {
      b.same--;
      try { workSocket && workSocket.destroy(); } catch (_) {}
      console.log(`  🔄 [502 重试·FRP·${note}·同节点] ${req.method} ${req.url} → ${backend.tag}  (剩余 ${b.same} 次)`);
      forwardViaFrp(req, res, backend, retryState);
      return true;
    }
    if (b.backends > 0) {
      const nb = selectBackend(req, req._lbGroup || 'default', retryState.triedIds);
      if (nb && nb.type === 'frp') {
        b.backends--;
        b.same = CONFIG.retry_502_max || 2;
        try { workSocket && workSocket.destroy(); } catch (_) {}
        console.log(`  🔄 [502 重试·FRP·${note}·换节点] ${req.method} ${req.url} ${backend.tag} → ${nb.tag}  (还可换 ${b.backends} 个)`);
        forwardViaFrp(req, res, nb, retryState);
        return true;
      }
    }
    return false;
  };

  if (!ctrl || !ctrl.socket.writable) {
    if (failover502(null, '控制连接不可用')) return;
    return res.status(502).json({ ret: -1, error: 'frpc 控制连接不可用' });
  }
  const startTime = Date.now();
  backend.connections = (backend.connections || 0) + 1;

  const timer = setTimeout(() => {
    const idx = (frpWorkWaiters.get(proxyName) || []).findIndex(w => w.timer === timer);
    if (idx >= 0) { const w = frpWorkWaiters.get(proxyName)[idx]; w.reject(new Error('work_conn 超时')); frpWorkWaiters.get(proxyName).splice(idx, 1); }
  }, getTunnelConnectTimeout());

  const p = new Promise((resolve, reject) => {
    if (!frpWorkWaiters.has(proxyName)) frpWorkWaiters.set(proxyName, []);
    frpWorkWaiters.get(proxyName).push({ resolve, reject, timer });
  });

  // 请求 frpc 建立一个 work_conn
  sendFrpMsg(ctrl.socket, {
    proxy_name: proxyName,
    src_addr: req.socket?.remoteAddress || '127.0.0.1',
    dst_addr: '127.0.0.1',
    src_port: 0, dst_port: 0, error: ''
  });

  p.then(workSocket => {
    clearTimeout(timer);
    const responseTimer = setTimeout(() => {
      try { workSocket.destroy(new Error('FRP 后端响应超时')); } catch (_) {}
    }, getForwardTimeout());
    // 构建原始 HTTP 请求并写入 work_conn
    const urlObj = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathAndQuery = urlObj.pathname + urlObj.search;
    const lines = [];
    lines.push(`${req.method} ${pathAndQuery} HTTP/1.1`);
    lines.push(`Host: ${req.headers.host || 'localhost'}`);
    for (const [k, v] of Object.entries(req.headers)) {
      const lk = k.toLowerCase();
      if (lk === 'host' || lk === 'connection' || lk === 'upgrade' || lk === 'transfer-encoding') continue;
      if (Array.isArray(v)) lines.push(`${k}: ${v.join(', ')}`);
      else lines.push(`${k}: ${v}`);
    }
    const headStr = lines.join('\r\n') + '\r\n\r\n';
    workSocket.write(headStr);
    if (req._lbForwardBody && req._lbForwardBody.length > 0) workSocket.write(req._lbForwardBody);
    workSocket.end();

    // 读取响应：TCP 可能分片，必须等到 Content-Length/chunked/FIN 明确完成。
    let respBuf = Buffer.alloc(0);
    let settled = false;
    const finishResponse = (parsed) => {
      if (settled) return;
      settled = true;
      clearTimeout(responseTimer);
      const rt = Date.now() - startTime;
      backend.connections = Math.max(0, (backend.connections || 0) - 1);
      backend.responseTime = backend.responseTime ? Math.round(backend.responseTime * 0.7 + rt * 0.3) : rt;

      if (res.writableEnded || res.destroyed) {
        workSocket.destroy();
        return;
      }

      if (!parsed || parsed.error) {
        if (failover502(workSocket, '解析失败')) return;
        const log = recordLog(req, backend, { success: false, responseTime: rt, statusCode: 502 });
        broadcast({ type: 'new_log', log });
        return res.status(502).json({ ret: -1, error: 'frp 响应解析失败' });
      }
      const { statusCode, headers, body } = parsed;

      // ── 400/431/429/502/504 自动重试（FRP，先同节点再换节点） ──
      if (isRetryableUpstreamStatus(statusCode)) {
        const reason = retryReasonForStatus(statusCode);
        if (retryAllowed(reason)) {
          const b = retryState.budgets[reason];
          if (b.same > 0) {
            b.same--;
            console.log(`  🔄 [${statusCode} 重试·FRP·同节点] ${req.method} ${req.url} → ${backend.tag}  (剩余 ${b.same} 次)`);
            backend.connections = Math.max(0, (backend.connections || 0) - 1);
            workSocket.destroy();
            return forwardViaFrp(req, res, backend, retryState);
          }
          if (b.backends > 0) {
            const newBackend = selectBackend(req, req._lbGroup || 'default', retryState.triedIds);
            if (newBackend && newBackend.type === 'frp') {
              b.backends--;
              b.same = retrySameMax(reason);
              console.log(`  🔄 [${statusCode} 重试·FRP·换节点] ${req.method} ${req.url}  ${backend.tag} → ${newBackend.tag}  (还可换 ${b.backends} 个)`);
              backend.connections = Math.max(0, (backend.connections || 0) - 1);
              workSocket.destroy();
              return forwardViaFrp(req, res, newBackend, retryState);
            }
          }
        }
      }

      // 设置响应头；传输层头由 Node 根据 body 重新生成，避免把 chunk 标记透传。
      for (const [k, v] of Object.entries(headers)) {
        if (k !== 'transfer-encoding' && k !== 'connection' && k !== 'keep-alive') {
          try { res.setHeader(k, v); } catch (_) {}
        }
      }
      try {
        res.setHeader('x-lb-node', `frp:${proxyName}`);
        res.setHeader('x-lb-group', req._lbGroup || 'default');
        res.setHeader('x-lb-algorithm', req._lbAlgo || getGroupAlgorithm(req._lbGroup || 'default'));
        res.setHeader('x-lb-response-time', `${rt}ms`);
      } catch (_) {}
      res.status(statusCode).end(body);

      const log = recordLog(req, backend, { success: isSuccessfulStatus(statusCode), responseTime: rt, statusCode });
      broadcast({ type: 'new_log', log });
      workSocket.destroy();
    };
    const tryFinish = (ended = false) => {
      if (settled) return;
      const parsed = parseRawHttpResponse(respBuf, req.method, ended);
      // 有 Content-Length/chunked 时无需等待连接关闭，可以及时回写客户端。
      if (parsed) finishResponse(parsed);
    };
    workSocket.on('data', chunk => {
      respBuf = Buffer.concat([respBuf, chunk]);
      tryFinish(false);
    });
    workSocket.on('end', () => tryFinish(true));
    workSocket.on('error', () => {
      if (settled) return;
      settled = true;
      clearTimeout(responseTimer);
      backend.connections = Math.max(0, (backend.connections || 0) - 1);
      const rt = Date.now() - startTime;
      if (failover502(workSocket, 'work_conn 错误')) return;
      const log = recordLog(req, backend, { success: false, responseTime: rt, statusCode: 502 });
      broadcast({ type: 'new_log', log });
      try { res.status(502).json({ ret: -1, error: 'frp work_conn 错误' }); } catch (_) {}
    });
  }).catch(err => {
    clearTimeout(timer);
    backend.connections = Math.max(0, (backend.connections || 0) - 1);
    const rt = Date.now() - startTime;
    if (failover502(null, '隧道失败')) return;
    const log = recordLog(req, backend, { success: false, responseTime: rt, statusCode: 504 });
    broadcast({ type: 'new_log', log });
    if (!res.writableEnded && !res.destroyed) {
      try { res.status(504).json({ ret: -1, error: 'frp 隧道失败', message: err.message }); } catch (_) {}
    }
  });
}

// ==================== HTTP 代理 ====================
const proxy = httpProxy.createProxyServer({
  proxyTimeout: 120000, timeout: 120000, changeOrigin: true
});

proxy.on('error', (err, req, res) => {
  // 清理重试追踪
  if (req._lbReqId) retryRequests.delete(req._lbReqId);
  if (res && typeof res.writeHead === 'function') {
    try {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ret: -1, error: '代理错误', message: err.message }));
    } catch (_) {}
  }
});

// 注入被 express.json() / urlencoded 消费的 body，转发时还原
proxy.on('proxyReq', (proxyReq, req) => {
  if (req._lbOriginalBody) {
    if (Buffer.isBuffer(req._lbOriginalBody)) {
      proxyReq.setHeader('content-length', req._lbOriginalBody.length);
      proxyReq.write(req._lbOriginalBody);
      proxyReq.end();
    } else if (req._lbOriginalBody.pipe) {
      req._lbOriginalBody.pipe(proxyReq);
    }
  }
});

/** 为一次重试选择下一个 HTTP 目标：始终先同节点，耗尽后才换节点。 */
function pickHttpRetryTarget(origReq, retryInfo, reason) {
  // 调试路由必须始终固定到指定节点，绝不能回落到正常用户的节点池。
  if (origReq._lbDebugRoute) return null;
  if (!retryInfo || !retryInfo.budgets) return null;
  const budget = retryInfo.budgets[reason];
  if (!budget || !retryAllowed(reason)) return null;
  const currentBackend = backends.get(origReq._lbBackendId);
  const canSame = !!(currentBackend && currentBackend.type === 'http' && currentBackend.url);

  if (budget.same > 0 && canSame) {
    budget.same--;
    return { target: currentBackend.url, switched: false };
  }
  // 命中固定节点规则时，不能把节点专属格式转换发送给其他节点。
  if (normalizeBackendUrl(origReq._lbMatchedRule?.backendUrl || '')) return null;
  if (budget.backends > 0) {
    const group = origReq._lbGroup || 'default';
    const newBackend = selectBackend(origReq, group, retryInfo.triedBackendIds);
    if (newBackend && newBackend.type === 'http' && newBackend.url) {
      retryInfo.triedBackendIds.add(newBackend.id);
      budget.backends--;
      budget.same = retrySameMax(reason);
      if (currentBackend) currentBackend.connections = Math.max(0, (currentBackend.connections || 0) - 1);
      origReq._lbBackendId = newBackend.id;
      newBackend.connections = (newBackend.connections || 0) + 1;
      return { target: newBackend.url, switched: true };
    }
  }
  return null;
}

function appendQueryString(url, query) {
  if (!query) return url;
  if (!url.includes('?')) return `${url}?${query}`;
  return `${url}${url.endsWith('?') || url.endsWith('&') ? '' : '&'}${query}`;
}

/** 合并 POST Body 的 Query；同名参数以 Body 为准，避免大字段（如 buffer）重复两次。 */
function mergeBodyQueryIntoUrl(url, bodyQuery) {
  if (!bodyQuery) return url;
  const queryIndex = url.indexOf('?');
  if (queryIndex === -1 || queryIndex === url.length - 1) return appendQueryString(url, bodyQuery);
  const current = new URLSearchParams(url.slice(queryIndex + 1));
  const incoming = new URLSearchParams(bodyQuery);
  const incomingKeys = new Set();
  for (const [key] of incoming) incomingKeys.add(key);
  if (![...incomingKeys].some(key => current.has(key))) return appendQueryString(url, bodyQuery);
  for (const key of incomingKeys) current.delete(key);
  for (const [key, value] of incoming) current.append(key, value);
  return `${url.slice(0, queryIndex)}?${current.toString()}`;
}

/** 将 JSON 或 form 请求体转换成 URL Query；无法安全转换的二进制体返回 null。 */
function bodyToQuery(body, contentType) {
  if (!body || body.length === 0) return '';
  const text = Buffer.isBuffer(body) ? body.toString('utf8') : String(body);
  const ct = String(contentType || '').toLowerCase();
  if (ct.includes('application/x-www-form-urlencoded')) return text;
  // 部分旧客户端未带 Content-Type，或误标成 JSON，但实际 body 是标准 form。
  // 仅识别 key=value&... 形态，不能识别时仍保持原请求，避免误转二进制/文本协议。
  if (!text.trimStart().startsWith('{') && /^[^=&\s]+=[\s\S]*$/.test(text)) return text;
  if (!ct.includes('application/json') && !text.trimStart().startsWith('{')) return null;
  let value;
  try { value = JSON.parse(text); } catch (_) { return null; }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const params = new URLSearchParams();
  for (const [key, item] of Object.entries(value)) {
    const values = Array.isArray(item) ? item : [item];
    for (const entry of values) {
      if (entry === undefined) continue;
      params.append(key, entry && typeof entry === 'object' ? JSON.stringify(entry) : String(entry));
    }
  }
  return params.toString();
}

function paramsToPayload(params) {
  const payload = {};
  for (const [key, value] of params) {
    if (Object.prototype.hasOwnProperty.call(payload, key)) {
      payload[key] = Array.isArray(payload[key]) ? [...payload[key], value] : [payload[key], value];
    } else {
      payload[key] = value;
    }
  }
  return payload;
}

/** 仅接受非空的标准 form 内容，避免把二进制或普通文本误转成 JSON。 */
function formBodyToPayload(body) {
  if (!body || body.length === 0) return null;
  const text = (Buffer.isBuffer(body) ? body : Buffer.from(body)).toString('utf8').trim();
  if (!text || text.startsWith('{') || text.startsWith('[') || !text.includes('=')) return null;
  const params = new URLSearchParams(text);
  if ([...params].length === 0) return null;
  return paramsToPayload(params);
}

/** 按当前目标节点恢复并准备转发请求；两种请求形态转换均为节点级选项。 */
function prepareForwardRequest(req) {
  if (!req._lbSourceRequest) {
    req._lbSourceRequest = {
      // 转发源必须保留原始 URL；日志显示时才使用 displayRequestPath，不能混用。
      url: req.url,
      method: req.method,
      headers: { ...req.headers },
      body: req._lbOriginalBody ? Buffer.from(req._lbOriginalBody) : (req._rawBody ? Buffer.from(req._rawBody) : null)
    };
  }
  const source = req._lbSourceRequest;
  const sourceUrl = source.url;
  req.url = sourceUrl;
  req.method = source.method;
  req.headers = { ...source.headers };
  req._lbOriginalBody = source.body ? Buffer.from(source.body) : null;
  req._lbForwardBody = req._lbOriginalBody;

  const backend = backends.get(req._lbBackendId) || req._lbBackend;
  req._lbAppliedTransform = null;
  const preserveOriginal = !!(backend && req._lbOriginalFormatBackendIds?.has(backend.id));
  const queryIndex = sourceUrl.indexOf('?');
  if (!preserveOriginal && backend?.query_to_json_enabled) {
    let payload = null;
    let transform = null;
    if (queryIndex !== -1 && queryIndex !== sourceUrl.length - 1) {
      try {
        const search = new URL(sourceUrl, 'http://lb.local').searchParams;
        if ([...search].length > 0) {
          payload = paramsToPayload(search);
          transform = 'query_to_json';
        }
      } catch (_) {}
    } else if (String(source.method).toUpperCase() === 'POST') {
      payload = formBodyToPayload(source.body);
      if (payload) transform = 'form_to_json';
    }
    if (payload) {
      const body = Buffer.from(JSON.stringify(payload));
      req.url = queryIndex >= 0 ? (sourceUrl.slice(0, queryIndex) || '/') : sourceUrl;
      req.method = 'POST';
      delete req.headers['transfer-encoding'];
      req.headers['content-type'] = 'application/json';
      req.headers['content-length'] = String(body.length);
      req._lbOriginalBody = body;
      req._lbForwardBody = body;
      req._lbAppliedTransform = transform;
    }
  }

  if (!preserveOriginal && backend?.post_to_get_enabled && String(req.method).toUpperCase() === 'POST') {
    const query = bodyToQuery(req._lbForwardBody, req.headers['content-type']);
    if (query !== null) {
      req.url = mergeBodyQueryIntoUrl(req.url, query);
      req.method = 'GET';
      delete req.headers['transfer-encoding'];
      delete req.headers['content-type'];
      delete req.headers['content-length'];
      req._lbOriginalBody = null;
      req._lbForwardBody = null;
      req._lbAppliedTransform = 'post_to_get';
    }
  }
}

/** 转换格式被上游拒绝时，先用原始请求形态在同一节点回退一次。 */
function retryOriginalFormat(req, realRes, retryInfo, reqId, statusCode) {
  const backend = backends.get(req._lbBackendId) || req._lbBackend;
  if (!backend || backend.type !== 'http' || !backend.url || !req._lbAppliedTransform) return false;
  // 该节点明确要求 GET 时，绝不因失败回退为 POST；POST 是不兼容的协议形态。
  if (req._lbAppliedTransform === 'post_to_get') return false;
  if (!req._lbOriginalFormatBackendIds) req._lbOriginalFormatBackendIds = new Set();
  if (req._lbOriginalFormatBackendIds.has(backend.id)) return false;
  req._lbOriginalFormatBackendIds.add(backend.id);
  console.log(`  ↩️  [${statusCode} 格式回退] ${req._lbAppliedTransform} → 原始请求  ${req.method} ${displayRequestPath(req.url)} → ${backend.url}`);
  retryHttpRequest(req, realRes, backend.url, retryInfo, reqId);
  return true;
}

/** 用原生 http.request 重新发送请求到指定 target（400/431/429/502/504 自动重试用） */
function retryHttpRequest(origReq, realRes, target, retryInfo, reqId) {
  prepareForwardRequest(origReq);
  const targetUrl = new URL(target);
  const isHttps = targetUrl.protocol === 'https:';
  const mod = isHttps ? require('https') : require('http');

  const headers = { ...origReq.headers };
  // 删除 hop-by-hop 头
  delete headers['host'];
  delete headers['connection'];
  delete headers['transfer-encoding'];
  delete headers['content-length'];
  headers['host'] = targetUrl.host;
  if (origReq._lbOriginalBody) {
    const body = Buffer.isBuffer(origReq._lbOriginalBody) ? origReq._lbOriginalBody : Buffer.from(origReq._lbOriginalBody);
    headers['content-length'] = body.length;
  }

  const startTime = Date.now();
  const upstreamReq = mod.request({
    hostname: targetUrl.hostname,
    port: targetUrl.port || (isHttps ? 443 : 80),
    path: origReq.url,
    method: origReq.method,
    headers,
    timeout: CONFIG.tunnel_timeout || 30000,
  }, (upstreamRes) => {
    const chunks = [];
    upstreamRes.on('data', chunk => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    upstreamRes.on('end', () => {
      const body = Buffer.concat(chunks);
      const retryStatus = getRetryableResponseStatus(upstreamRes.statusCode, body);
      if (retryStatus && retryOriginalFormat(origReq, realRes, retryInfo, reqId, retryStatus)) return;
      if (retryStatus) {
        const reason = retryReasonForStatus(retryStatus);
        const next = pickHttpRetryTarget(origReq, retryInfo, reason);
        if (next && next.target) {
          const tag = next.switched ? '换节点' : '同节点';
          const remain = next.switched
            ? `还可换 ${retryInfo.budgets[reason].backends} 个`
            : `剩余 ${retryInfo.budgets[reason].same} 次`;
          console.log(`  🔄 [${retryStatus} 重试·${tag}] ${origReq.method} ${displayRequestPath(origReq.url)} → ${next.target}  (${remain})`);
          return retryHttpRequest(origReq, realRes, next.target, retryInfo, reqId);
        }
      }
      sendBufferedUpstreamToClient(upstreamRes, body, realRes, origReq, Date.now() - startTime);
      finalizeRetriedRequest(origReq, retryStatus || upstreamRes.statusCode, Date.now() - (origReq._lbStartTime || startTime));
      if (reqId) retryRequests.delete(reqId);
    });
    upstreamRes.on('error', () => {
      try { upstreamRes.resume(); } catch (_) {}
    });
  });

  upstreamReq.on('error', (err) => {
    console.log(`  ⚠️  [重试请求] ${target} 失败: ${err.message}`);
    const next = pickHttpRetryTarget(origReq, retryInfo, '502');
    if (next && next.target) {
      const tag = next.switched ? '换节点' : '同节点';
      const remain = next.switched
        ? `还可换 ${retryInfo.budgets['502'].backends} 个`
        : `剩余 ${retryInfo.budgets['502'].same} 次`;
      console.log(`  🔄 [502 重试·${tag}] ${origReq.method} ${displayRequestPath(origReq.url)} → ${next.target}  (${remain})`);
      return retryHttpRequest(origReq, realRes, next.target, retryInfo, reqId);
    }
    try { realRes.status(502).json({ ret: -1, error: '重试失败', message: err.message }); } catch (_) {}
    finalizeRetriedRequest(origReq, 502, Date.now() - (origReq._lbStartTime || startTime));
    if (reqId) retryRequests.delete(reqId);
  });

  // 写 body
  if (origReq._lbOriginalBody) {
    const body = Buffer.isBuffer(origReq._lbOriginalBody) ? origReq._lbOriginalBody : Buffer.from(origReq._lbOriginalBody);
    upstreamReq.write(body);
  }
  upstreamReq.end();
}

function finalizeRetriedRequest(origReq, statusCode, responseTime) {
  if (origReq._lbRetryFinalized) return;
  origReq._lbRetryFinalized = true;
  const backend = backends.get(origReq._lbBackendId) || origReq._lbBackend;
  if (backend) {
    backend.connections = Math.max(0, (backend.connections || 0) - 1);
    if (responseTime > 0) {
      backend.responseTime = backend.responseTime
        ? Math.round(backend.responseTime * 0.7 + responseTime * 0.3)
        : responseTime;
    }
  }
  updateHttpLogOutcome(origReq, statusCode, responseTime);
}

function updateHttpLogOutcome(req, statusCode, responseTime) {
  const logEntry = req._lbLogEntry;
  if (!logEntry) return;
  const success = isSuccessfulStatus(statusCode);
  if (logEntry.success !== success) {
    if (success) {
      stats.failRequests = Math.max(0, stats.failRequests - 1);
      stats.successRequests++;
    } else {
      stats.successRequests = Math.max(0, stats.successRequests - 1);
      stats.failRequests++;
    }
    const countedBackend = backends.get(req._lbLogBackendId);
    if (countedBackend) {
      if (success) {
        countedBackend.failRequests = Math.max(0, (countedBackend.failRequests || 0) - 1);
        countedBackend.successRequests = (countedBackend.successRequests || 0) + 1;
      } else {
        countedBackend.successRequests = Math.max(0, (countedBackend.successRequests || 0) - 1);
        countedBackend.failRequests = (countedBackend.failRequests || 0) + 1;
      }
    }
  }
  logEntry.success = success;
  logEntry.responseTime = responseTime;
  logEntry.statusCode = statusCode;
  broadcast({ type: 'update_log', log: logEntry });
}

/** 把上游响应写回客户端（带 LB 标记头） */
function sendUpstreamToClient(upstreamRes, realRes, origReq, rt) {
  const headers = { ...upstreamRes.headers };
  delete headers['transfer-encoding'];
  delete headers['connection'];
  // 加 LB 标识头
  try {
    if (!realRes.headersSent) {
      const backend = backends.get(origReq._lbBackendId) || origReq._lbBackend;
      if (backend) realRes.setHeader('x-lb-node', backend.url || backend.tag || 'unknown');
      realRes.setHeader('x-lb-group', origReq._lbGroup || 'default');
      realRes.setHeader('x-lb-algorithm', origReq._lbAlgo || getGroupAlgorithm(origReq._lbGroup || 'default'));
      realRes.setHeader('x-lb-response-time', `${rt}ms`);
    }
  } catch (_) {}
  realRes.writeHead(upstreamRes.statusCode, headers);
  upstreamRes.pipe(realRes);
}

function sendBufferedUpstreamToClient(upstreamRes, body, realRes, origReq, rt) {
  const headers = { ...upstreamRes.headers };
  delete headers['transfer-encoding'];
  delete headers['connection'];
  try {
    if (!realRes.headersSent) {
      const backend = backends.get(origReq._lbBackendId) || origReq._lbBackend;
      if (backend) realRes.setHeader('x-lb-node', backend.url || backend.tag || 'unknown');
      realRes.setHeader('x-lb-group', origReq._lbGroup || 'default');
      realRes.setHeader('x-lb-algorithm', origReq._lbAlgo || getGroupAlgorithm(origReq._lbGroup || 'default'));
      realRes.setHeader('x-lb-response-time', `${rt}ms`);
    }
  } catch (_) {}
  try {
    realRes.writeHead(upstreamRes.statusCode, headers);
    realRes.end(body);
  } catch (_) {}
}

/** 创建缓冲响应包装器 — 收集后端响应，决定是否重试后再发送给客户端
 *  writeHead / write / end 全部拦截为 no-op，避免 http-proxy 直接写 realRes。
 *  data 通过 pipe 写入 chunks；end 时触发 done 回调供 proxyRes handler 决策。
 */
function createBufferedRes(realRes) {
  const buf = { status: 200, headers: {}, chunks: [] };
  let doneCallback = null;
  let flushed = false;
  const wrapper = new Writable({
    write(chunk, encoding, callback) {
      if (chunk) buf.chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding));
      callback();
    }
  });
  wrapper._buf = buf;
  wrapper._realRes = realRes;
  wrapper.writeHead = function writeHead(status, headers) {
    buf.status = status;
    if (headers && typeof headers === 'object') Object.assign(buf.headers, headers);
    return wrapper;
  };
  wrapper.setHeader = function setHeader(k, v) {
    buf.headers[String(k).toLowerCase()] = v;
    return wrapper;
  };
  wrapper.getHeader = function getHeader(k) { return buf.headers[String(k).toLowerCase()]; };
  wrapper.removeHeader = function removeHeader(k) { delete buf.headers[String(k).toLowerCase()]; };
  wrapper.onDone = function onDone(cb) {
    doneCallback = typeof cb === 'function' ? cb : null;
    return wrapper;
  };
  wrapper.flush = function flush() {
    if (flushed) return;
    flushed = true;
    const body = Buffer.concat(buf.chunks);
    try {
      if (!realRes.headersSent) realRes.writeHead(buf.status, buf.headers);
      if (!realRes.writableEnded) realRes.end(body);
    } catch (_) {}
  };
  wrapper.on('finish', () => {
    const cb = doneCallback;
    doneCallback = null;
    if (cb) {
      try { cb(); } catch (error) { wrapper.emit('error', error); }
    }
  });
  Object.defineProperty(wrapper, 'finished', { enumerable: true, get: () => wrapper.writableFinished });
  Object.defineProperty(wrapper, 'headersSent', { enumerable: true, get: () => false });
  // http-proxy 用 `res.statusCode = ...` 属性赋值写状态码（不调用 writeHead），需同步捕获
  Object.defineProperty(wrapper, 'statusCode', {
    configurable: true,
    get() { return buf.status; },
    set(value) { if (Number.isInteger(value) && value >= 100 && value <= 599) buf.status = value; }
  });
  return wrapper;
}

proxy.on('proxyRes', (proxyRes, req, res) => {
  const startTime = req._lbStartTime || Date.now();
  const responseTime = Date.now() - startTime;
  const backendId = req._lbBackendId;
  const logEntry = req._lbLogEntry;
  const reqId = req._lbReqId;
  const retryInfo = reqId ? retryRequests.get(reqId) : null;
  const isBufferedRes = res._buf !== undefined;

  // ── 缓冲模式下的 400/431/429/502/504 自动重试（先同节点，再换节点） ──
  if (isBufferedRes && retryInfo && isRetryableUpstreamStatus(proxyRes.statusCode)) {
    const reason = retryReasonForStatus(proxyRes.statusCode);
    if (retryOriginalFormat(req, res._realRes, retryInfo, reqId, proxyRes.statusCode)) {
      proxyRes.resume();
      return;
    }
    if (retryAllowed(reason)) {
      const next = pickHttpRetryTarget(req, retryInfo, reason);
      if (next && next.target) {
        const tag = next.switched ? '换节点' : '同节点';
        const remain = next.switched
          ? `还可换 ${retryInfo.budgets[reason].backends} 个`
          : `剩余 ${retryInfo.budgets[reason].same} 次`;
        console.log(`  🔄 [${proxyRes.statusCode} 重试·${tag}] ${req.method} ${displayRequestPath(req.url)} → ${next.target}  (${remain})`);
        // 静默消费旧响应
        proxyRes.on('data', () => {});
        proxyRes.resume();
        // 用原生 http.request 重新发请求（避免 http-proxy 在同一 req 上重用的状态问题）
        retryHttpRequest(req, res._realRes, next.target, retryInfo, reqId);
        return;
      }
    }
  }

  // ── 正常路径 ──
  if (backendId && (backends.has(backendId) || req._lbBackend)) {
    const b = backends.get(backendId) || req._lbBackend;
    b.responseTime = b.responseTime ? Math.round(b.responseTime * 0.7 + responseTime * 0.3) : responseTime;
    b.connections = Math.max(0, (b.connections || 0) - 1);
    if (logEntry) {
      updateHttpLogOutcome(req, proxyRes.statusCode, responseTime);
    }
    // 更新 stats 响应时间
    if (responseTime > 0) {
      const idx = stats.historyResponseTime.length - 1;
      const prev = stats.historyResponseTime[idx] || 0;
      stats.historyResponseTime[idx] = prev + (responseTime - prev) / stats.historyRequests[idx];
    }
    try {
      if (isBufferedRes || !res.headersSent) {
        res.setHeader('x-lb-node', b.url || b.tag || 'unknown');
        res.setHeader('x-lb-group', req._lbGroup || 'default');
        res.setHeader('x-lb-algorithm', req._lbAlgo || getGroupAlgorithm(req._lbGroup || 'default'));
        res.setHeader('x-lb-response-time', `${responseTime}ms`);
      }
    } catch (_) {}
  }
  // 缓冲模式：http-proxy 的 pipe 会调 bufferedRes.end()，触发 onDone 回调后再 flush
  if (isBufferedRes) {
    res.onDone(() => {
      const finalResponseTime = Date.now() - (req._lbStartTime || startTime);
      const retryStatus = getRetryableResponseStatus(proxyRes.statusCode, Buffer.concat(res._buf.chunks));
      if (retryStatus && retryInfo) {
        if (retryOriginalFormat(req, res._realRes, retryInfo, reqId, retryStatus)) return;
        const reason = retryReasonForStatus(retryStatus);
        if (retryAllowed(reason)) {
          const next = pickHttpRetryTarget(req, retryInfo, reason);
          if (next && next.target) {
            const tag = next.switched ? '换节点' : '同节点';
            const remain = next.switched
              ? `还可换 ${retryInfo.budgets[reason].backends} 个`
              : `剩余 ${retryInfo.budgets[reason].same} 次`;
            console.log(`  🔄 [业务 code ${retryStatus} 重试·${tag}] ${req.method} ${displayRequestPath(req.url)} → ${next.target}  (${remain})`);
            retryHttpRequest(req, res._realRes, next.target, retryInfo, reqId);
            return;
          }
        }
      }
      // 响应体结束才是完整耗时，包含下载和前面的重试时间。
      updateHttpLogOutcome(req, retryStatus || proxyRes.statusCode, finalResponseTime);
      res.flush();
      if (reqId) retryRequests.delete(reqId);
    });
    return;
  }
  // 清理重试追踪
  if (reqId) retryRequests.delete(reqId);
});

// ==================== 负载均衡算法（支持按分组选择） ====================

let rrCounters = {};
let wrrStates = {};

function resetGroupAlgoState(group) {
  delete rrCounters[group];
  delete wrrStates[group];
}

function roundRobin(group, excludeIds) {
  const alive = getAliveBackendsInGroup(group, excludeIds);
  if (alive.length === 0) return null;
  if (!rrCounters[group]) rrCounters[group] = 0;
  const idx = rrCounters[group] % alive.length;
  rrCounters[group]++;
  return alive[idx];
}

function weightedRoundRobin(group, excludeIds) {
  const alive = getAliveBackendsInGroup(group, excludeIds);
  if (alive.length === 0) return null;
  if (alive.length === 1) return alive[0];
  const total = alive.reduce((s, b) => s + (b.weight || 1), 0);
  if (!wrrStates[group]) wrrStates[group] = {};
  const st = wrrStates[group];
  for (const b of alive) st[b.id] = (st[b.id] || 0) + (b.weight || 1);
  let sel = alive[0], maxCur = -Infinity;
  for (const b of alive) { if (st[b.id] > maxCur) { maxCur = st[b.id]; sel = b; } }
  st[sel.id] -= total;
  return sel;
}

function leastConnections(group, excludeIds) {
  const alive = getAliveBackendsInGroup(group, excludeIds);
  if (alive.length === 0) return null;
  return alive.reduce((a, b) => (a.connections || 0) < (b.connections || 0) ? a : b);
}

function ipHash(req, group, excludeIds) {
  const alive = getAliveBackendsInGroup(group, excludeIds);
  if (alive.length === 0) return null;
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.socket?.remoteAddress || req.connection?.remoteAddress || '127.0.0.1';
  let hash = 0;
  for (let i = 0; i < ip.length; i++) { hash = ((hash << 5) - hash) + ip.charCodeAt(i); hash |= 0; }
  return alive[Math.abs(hash) % alive.length];
}

function random(group, excludeIds) {
  const alive = getAliveBackendsInGroup(group, excludeIds);
  if (alive.length === 0) return null;
  return alive[Math.floor(Math.random() * alive.length)];
}

function leastResponseTime(group, excludeIds) {
  const alive = getAliveBackendsInGroup(group, excludeIds);
  if (alive.length === 0) return null;
  return alive.reduce((a, b) => (a.responseTime || Infinity) < (b.responseTime || Infinity) ? a : b);
}

function selectBackend(req, groupName, excludeIds) {
  const algo = getGroupAlgorithm(groupName);
  switch (algo) {
    case 'round-robin':          return roundRobin(groupName, excludeIds);
    case 'weighted-round-robin': return weightedRoundRobin(groupName, excludeIds);
    case 'least-connections':    return leastConnections(groupName, excludeIds);
    case 'ip-hash':              return ipHash(req, groupName, excludeIds);
    case 'random':               return random(groupName, excludeIds);
    case 'least-response-time':  return leastResponseTime(groupName, excludeIds);
    default:                     return roundRobin(groupName, excludeIds);
  }
}

/** 路由规则可选固定到同分组某 HTTP 节点；节点不可用时仍回退至分组调度。 */
function selectRuleBackend(rule, groupName) {
  const configuredUrl = normalizeBackendUrl(rule?.backendUrl || '');
  if (!configuredUrl) return null;
  return Array.from(backends.values()).find(backend =>
    backend.type === 'http'
    && backend.alive
    && !backend.disabled
    && backendInGroup(backend, groupName)
    && normalizeBackendUrl(backend.url) === configuredUrl
  ) || null;
}

// ==================== 健康检查 ====================
function healthCheck() {
  for (const [, backend] of backends) {
    if (backend.disabled || backend._hcPending) continue;
    if (backend.disable_health_check) {
      // 用户主动禁用了健康检查 — 始终视为 alive
      if (!backend.alive) {
        backend.alive = true;
        backend.lastCheck = Date.now();
      }
      continue;
    }
    if (backend.type === 'tunnel') {
      if (!backend.ws || backend.ws.readyState !== WebSocket.OPEN) setDead(backend);
      continue;
    }
    if (backend.type === 'frp') {
      const ctrl = frpControlConns.get(backend.frpProxyName);
      if (!ctrl || !ctrl.socket || ctrl.socket.destroyed) setDead(backend);
      continue;
    }
    // HTTP 类型健康检查
    const isHttps = backend.url.startsWith('https');
    const mod = isHttps ? https : http;
    let u;
    try { u = new URL(backend.url); } catch { continue; }

    backend._hcPending = true;
    const req = mod.get(u, { agent: false }, (res) => {
      clearTimeout(timer);
      res.resume();
      backend._hcPending = false;
      backend.lastCheck = Date.now();
      // 只有连接错误才判死；任何 HTTP 响应（哪怕 400/404）都认为 alive
      // 因为后端可能只接受 POST，GET 会返 400 但实际是好的
      if (!backend.alive) {
        backend.alive = true;
        backend.lastCheck = Date.now();
        broadcast({ type: 'backend_recovered', id: backend.id, url: backend.url, tag: backend.tag });
      }
    });
    const timer = setTimeout(() => {
      req.destroy(new Error('Health check timeout'));
    }, CONFIG.hc_timeout);
    req.on('error', (err) => {
      clearTimeout(timer);
      backend._hcPending = false;
      backend.lastCheck = Date.now();
      // 只在连续 3 次失败后才标 dead（更宽容）
      backend._hcFails = (backend._hcFails || 0) + 1;
      if (backend._hcFails >= 3) {
        setDead(backend);
      }
    });
    req.on('response', () => { backend._hcFails = 0; });
  }
}

function setDead(b) {
  if (b.alive) { b.alive = false; b.lastCheck = Date.now(); broadcast({ type: 'backend_down', id: b.id, url: b.url || b.tag, tag: b.tag }); }
}

// ==================== 统计与日志 ====================

const qqStats = {
  totalUnique: 0,           // 总去重 QQ 数
  todayUnique: 0,           // 今日去重 QQ 数
  recentQQs: new Set(),     // 今日 QQ Set
  qqHistory: new Array(60).fill(0),  // 近 60 秒秒级新增 QQ 数
  lastQqMinute: new Date().getMinutes(),
  totalRequests: 0,         // 包含 QQ 参数的请求总数
};

// 持久化/恢复 QQ 统计：all-qq.txt 只追加，total.count 很小，当前日独立去重。
const qqPersistence = {
  allQQs: new Set(),
  dayKey: '',
  pending: new Map(),
  flushTimer: null,
  loaded: false,
};

function qqDayKey(date = new Date()) {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

function qqDayPath(dayKey) {
  return path.join(QQ_STATS_DIR, `${dayKey}.txt`);
}

function validQQValue(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 30 && !/[\r\n]/.test(value);
}

function readQqLines(filePath) {
  try {
    if (!fs.existsSync(filePath)) return [];
    return fs.readFileSync(filePath, 'utf8').split(/\r?\n/).filter(validQQValue);
  } catch (_) {
    return [];
  }
}

function queueQqLine(filePath, qq) {
  if (!validQQValue(qq)) return;
  const lines = qqPersistence.pending.get(filePath) || [];
  lines.push(qq);
  qqPersistence.pending.set(filePath, lines);
  if (!qqPersistence.flushTimer) {
    qqPersistence.flushTimer = setTimeout(() => {
      qqPersistence.flushTimer = null;
      flushQqStats();
    }, 1000);
  }
}

function flushQqStats() {
  if (!CONFIG.persist_stats) return;
  try {
    fs.mkdirSync(QQ_STATS_DIR, { recursive: true });
    for (const [filePath, lines] of qqPersistence.pending) {
      if (!lines.length) continue;
      fs.appendFileSync(filePath, `${lines.join('\n')}\n`, 'utf8');
      qqPersistence.pending.delete(filePath);
    }
    qqPersistence.pending.clear();
    const tempPath = `${QQ_TOTAL_PATH}.tmp-${process.pid}`;
    fs.writeFileSync(tempPath, `${qqStats.totalUnique}\n`, 'utf8');
    fs.renameSync(tempPath, QQ_TOTAL_PATH);
  } catch (error) { console.error(`  ⚠️ QQ 统计保存失败（待写数据已保留）: ${error.message}`); }
}

function rolloverQqDay() {
  const currentDay = qqDayKey();
  if (qqPersistence.dayKey === currentDay) return;
  qqPersistence.dayKey = currentDay;
  qqStats.recentQQs.clear();
  qqStats.todayUnique = 0;
  qqStats.qqHistory.fill(0);
  qqStats.lastQqMinute = new Date().getMinutes();
  if (!CONFIG.persist_stats || !qqPersistence.loaded) return;
  for (const qq of readQqLines(qqDayPath(currentDay))) qqStats.recentQQs.add(qq);
  qqStats.todayUnique = qqStats.recentQQs.size;
}

function saveQqStats() {
  // 只刷追加队列和一个小计数文件，不触碰 config.json。
  flushQqStats();
}

function loadQqStats() {
  try {
    fs.mkdirSync(QQ_STATS_DIR, { recursive: true });
    for (const qq of readQqLines(QQ_ALL_PATH)) qqPersistence.allQQs.add(qq);
    const storedTotal = Number.parseInt(fs.existsSync(QQ_TOTAL_PATH) ? fs.readFileSync(QQ_TOTAL_PATH, 'utf8') : '0', 10) || 0;
    qqStats.totalUnique = Math.max(storedTotal, qqPersistence.allQQs.size);
    qqPersistence.dayKey = qqDayKey();
    for (const qq of readQqLines(qqDayPath(qqPersistence.dayKey))) qqStats.recentQQs.add(qq);

    // 一次性兼容旧版本：把 config.json 中的 _qq_stats 迁移到追加式文件，然后删除大数组。
    const legacy = CONFIG._qq_stats;
    if (legacy && Array.isArray(legacy.qqSet)) {
      const newAll = [];
      const newToday = [];
      for (const raw of legacy.qqSet) {
        const qq = String(raw);
        if (!validQQValue(qq)) continue;
        if (!qqPersistence.allQQs.has(qq)) {
          qqPersistence.allQQs.add(qq);
          newAll.push(qq);
        }
        // 旧数据没有日期时只能确认历史总数，不能冒充今天的访问。
        if (legacy.dayKey === qqPersistence.dayKey && !qqStats.recentQQs.has(qq)) {
          qqStats.recentQQs.add(qq);
          newToday.push(qq);
        }
      }
      if (newAll.length) fs.appendFileSync(QQ_ALL_PATH, `${newAll.join('\n')}\n`, 'utf8');
      if (newToday.length) fs.appendFileSync(qqDayPath(qqPersistence.dayKey), `${newToday.join('\n')}\n`, 'utf8');
      qqStats.totalUnique = Math.max(qqStats.totalUnique, Number(legacy.totalUnique) || 0, qqPersistence.allQQs.size);
      delete CONFIG._qq_stats;
      saveConfig();
    }
    qqStats.todayUnique = qqStats.recentQQs.size;
    fs.writeFileSync(QQ_TOTAL_PATH, `${qqStats.totalUnique}\n`, 'utf8');
    qqPersistence.loaded = true;
  } catch (error) {
    console.error(`  ⚠️ QQ 统计恢复失败: ${error.message}`);
  }
}

const qqDayTimer = setInterval(rolloverQqDay, 60000);
qqDayTimer.unref();

/** 请求样本缓存（用于调试 QQ 提取） */
const requestSamples = [];
const MAX_SAMPLES = 50;

/** 记录一个请求样本（用来自查） */
function sampleRequest(req, foundQQ) {
  if (requestSamples.length >= MAX_SAMPLES) return;
  try {
    requestSamples.push({
      time: new Date().toLocaleTimeString(),
      url: req.url,
      method: req.method,
      query: req.query ? `${Object.keys(req.query).length} 个参数` : null,
      body: req.body && typeof req.body === 'object' ? `${Object.keys(req.body).length} 个字段` : null,
      hasQQ: !!foundQQ,
      headers: JSON.stringify({
        'content-type': req.headers['content-type'],
        'x-forwarded-for': req.headers['x-forwarded-for'],
      })
    });
  } catch (_) {}
}

/**
 * 从请求中提取 QQ 号 —— 超轻量。
 * 支持格式：?qq=xxx / ?uin=xxx 以及 JSON body 中的 qq / uin 字段。
 *
 * 使用多重检测策略以确保最大兼容性。
 */
function extractQQ(req) {
  // 1) Express 已解析的 req.query（最快路径，永远可用）
  try {
    if (req.query) {
      if (req.query.qq != null && req.query.qq !== '') return String(req.query.qq);
      if (req.query.uin != null && req.query.uin !== '') return String(req.query.uin);
    }
  } catch (_) {}

  // 2) 原始 URL 手动扫描（兼容任意格式）
  try {
    const url = req.url || '';
    const qIdx = url.indexOf('?');
    if (qIdx >= 0) {
      let qs = url.slice(qIdx + 1);
      try { qs = decodeURIComponent(qs); } catch (_2) {}
      const pairs = qs.split('&');
      for (const pair of pairs) {
        const eqIdx = pair.indexOf('=');
        if (eqIdx > 0) {
          const key = pair.slice(0, eqIdx);
          const val = pair.slice(eqIdx + 1);
          if ((key === 'qq' || key === 'uin') && val.length > 0 && val.length <= 30) {
            return val;
          }
        }
      }
    }
  } catch (_) {}

  // 3) JSON body 中的 qq / uin（只读已解析的 body，不触发解析）
  try {
    const body = req.body;
    if (body && typeof body === 'object' && !Array.isArray(body)) {
      if (body.qq != null) return String(body.qq);
      if (body.uin != null) return String(body.uin);
      // 嵌套：data.qq, data.uin
      if (typeof body.data === 'object' && body.data) {
        if (body.data.qq != null) return String(body.data.qq);
        if (body.data.uin != null) return String(body.data.uin);
      }
    }
  } catch (_) {}

  return null;
}

/** 记录一个 QQ 号（去重） */
function recordQQ(qq) {
  if (!qq) return;
  // 限长防滥用
  if (!validQQValue(qq)) return;

  rolloverQqDay();

  if (!qqStats.recentQQs.has(qq)) {
    qqStats.recentQQs.add(qq);
    const globalNew = !qqPersistence.allQQs.has(qq);
    if (globalNew) qqStats.totalUnique++;
    if (globalNew) qqPersistence.allQQs.add(qq);
    qqStats.todayUnique = qqStats.recentQQs.size;

    if (CONFIG.persist_stats && qqPersistence.loaded) {
      if (globalNew) {
        qqPersistence.allQQs.add(qq);
        queueQqLine(QQ_ALL_PATH, qq);
      }
      queueQqLine(qqDayPath(qqPersistence.dayKey), qq);
    }

    // 秒级统计（用于图表）
    const curMin = new Date().getMinutes();
    if (curMin !== qqStats.lastQqMinute) {
      qqStats.lastQqMinute = curMin;
      qqStats.qqHistory.push(0);
      if (qqStats.qqHistory.length > 60) qqStats.qqHistory.shift();
    }
    const idx = qqStats.qqHistory.length - 1;
    qqStats.qqHistory[idx]++;

  }
  qqStats.totalRequests++;
}

function recordLog(req, backend, opts = {}) {
  const { success, responseTime, statusCode, deferBroadcast = false } = opts;
  const now = new Date();
  // 不记录 favicon.ico
  if (req.url === '/favicon.ico' || req.url === '/robots.txt') return null;

  // 轻量提取 QQ 统计（沿已有请求路径，无额外开销）
  const qq = extractQQ(req);
  if (qq) recordQQ(qq);
  sampleRequest(req, qq);

  const curMin = now.getMinutes();
  if (curMin !== stats.lastMinute) {
    stats.lastMinute = curMin;
    stats.historyRequests.push(0); stats.historyResponseTime.push(0);
    if (stats.historyRequests.length > 60) stats.historyRequests.shift();
    if (stats.historyResponseTime.length > 60) stats.historyResponseTime.shift();
  }
  stats.totalRequests++;
  if (success) stats.successRequests++; else stats.failRequests++;
  // 节流后定时更新 showedLogIndex，供前端全量拉取
  if (stats.totalRequests % 50 === 0) stats.shownLogIndex = stats.totalRequests;
  const idx = stats.historyRequests.length - 1;
  stats.historyRequests[idx]++;
  if (responseTime > 0) {
    const prev = stats.historyResponseTime[idx] || 0;
    stats.historyResponseTime[idx] = prev + (responseTime - prev) / stats.historyRequests[idx];
  }
  if (backend) {
    backend.totalRequests = (backend.totalRequests || 0) + 1;
    if (success) backend.successRequests = (backend.successRequests || 0) + 1;
    else backend.failRequests = (backend.failRequests || 0) + 1;
  }
  const groupName = req._lbGroup || 'default';
  const groupAlgo = getGroupAlgorithm(groupName);
  const logEntry = {
    id: uuidv4(), time: now.toLocaleTimeString(),
    method: req.method, path: displayRequestPath(req.url), fullPath: req.url,
    sourceIp: (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket?.remoteAddress || req.connection?.remoteAddress || 'unknown',
    backend: backend ? (backend.type === 'tunnel' ? `🔌 ${backend.tag}` : backend.url) : '无可用节点',
    backendTag: backend?.tag || '-', type: backend?.type || 'none',
    group: groupName, algorithm: ALGORITHMS[groupAlgo]?.name || groupAlgo, responseTime: responseTime || 0,
    statusCode: statusCode || (success ? 200 : 502), success: success !== false
  };
  requestLogs.push(logEntry);
  if (requestLogs.length > CONFIG.max_log) requestLogs.shift();
  // 日志节流：每秒超过一定量的请求不逐个发 ws 推送
  if (!deferBroadcast && stats.totalRequests - stats.shownLogIndex < 100) {
    broadcast({ type: 'new_log', log: logEntry });
  }
  return logEntry;
}

// ==================== WebSocket 广播（管理前端） ====================
function broadcast(message) {
  if (!wsSubscribers.size) return;
  const msg = JSON.stringify(message);
  for (const ws of wsSubscribers) {
    if (ws.readyState !== WebSocket.OPEN) continue;
    // 慢客户端不能无限积压管理消息；重连后 init 会恢复完整状态。
    if (ws.bufferedAmount > 1024 * 1024) { ws.terminate(); continue; }
    try { ws.send(msg); } catch (_) {}
  }
}

// ==================== 隧道转发 ====================

function forwardViaTunnel(req, res, backend, retryState) {
  req._lbBackendId = backend.id;
  prepareForwardRequest(req);
  const requestId = uuidv4();
  const startTime = Date.now();
  let clientAborted = false;
  if (!retryState) retryState = { budgets: retryBudgets(), triedIds: new Set() };
  retryState.triedIds.add(backend.id);
  backend.connections = (backend.connections || 0) + 1;

  // 502/504/传输失败：先重试当前隧道节点，耗尽后再换节点。
  const failover502 = (note) => {
    if (!CONFIG.retry_502_enabled) return false;
    const b = retryState.budgets['502'];
    if (b.same > 0) {
      b.same--;
      console.log(`  🔄 [502 重试·隧道·${note}·同节点] ${req.method} ${req.url} → ${backend.tag}  (剩余 ${b.same} 次)`);
      forwardViaTunnel(req, res, backend, retryState);
      return true;
    }
    if (b.backends > 0) {
      const nb = selectBackend(req, req._lbGroup || 'default', retryState.triedIds);
      if (nb && nb.type === 'tunnel') {
        b.backends--;
        b.same = CONFIG.retry_502_max || 2;
        console.log(`  🔄 [502 重试·隧道·${note}·换节点] ${req.method} ${req.url} ${backend.tag} → ${nb.tag}  (还可换 ${b.backends} 个)`);
        forwardViaTunnel(req, res, nb, retryState);
        return true;
      }
    }
    return false;
  };

  // Express 已经消费了请求流，直接使用捕获的原始 body，避免在
  // readableEnded 后再次监听 data/end 导致隧道请求永久等待。
  const sendRequest = () => {
    const body = req._lbForwardBody && req._lbForwardBody.length > 0 ? req._lbForwardBody.toString('utf8') : '';
    const timer = setTimeout(() => {
      const pend = pendingRequests.get(requestId);
      if (pend) { pend.reject(new Error('隧道请求超时')); pendingRequests.delete(requestId); }
    }, getForwardTimeout());

    const p = new Promise((resolve, reject) => {
      pendingRequests.set(requestId, { backendId: backend.id, resolve, reject, timer });
    });

    const abortPending = () => {
      clientAborted = true;
      const pend = pendingRequests.get(requestId);
      if (!pend) return;
      clearTimeout(pend.timer);
      pendingRequests.delete(requestId);
      pend.reject(new Error('客户端已断开'));
    };
    req.once('aborted', abortPending);
    res.once('close', () => { if (!res.writableEnded) abortPending(); });

    try {
      backend.ws.send(JSON.stringify({
        type: 'request', id: requestId,
        method: req.method, path: req.url,
        headers: req.headers, body: body || undefined, timeoutMs: getForwardTimeout()
      }));
    } catch (err) {
      clearTimeout(timer); pendingRequests.delete(requestId);
      backend.connections = Math.max(0, (backend.connections || 0) - 1);
      if (failover502('发送失败')) return;
      const log = recordLog(req, backend, { success: false, responseTime: Date.now() - startTime, statusCode: 502 });
      broadcast({ type: 'new_log', log });
      return res.status(502).json({ ret: -1, error: '隧道发送失败', message: err.message });
    }

    p.then(response => {
      clearTimeout(timer);
      const rt = Date.now() - startTime;
      backend.connections = Math.max(0, (backend.connections || 0) - 1);

      if (clientAborted || res.writableEnded || res.destroyed) return;
      backend.responseTime = backend.responseTime ? Math.round(backend.responseTime * 0.7 + rt * 0.3) : rt;

      // ── 400/431/429/502/504 自动重试（先同节点，再换节点） ──
      if (isRetryableUpstreamStatus(response.statusCode)) {
        const reason = retryReasonForStatus(response.statusCode);
        if (retryAllowed(reason)) {
          const b = retryState.budgets[reason];
          if (b.same > 0) {
            b.same--;
            console.log(`  🔄 [${response.statusCode} 重试·隧道·同节点] ${req.method} ${req.url} → ${backend.tag}  (剩余 ${b.same} 次)`);
            return forwardViaTunnel(req, res, backend, retryState);
          }
          if (b.backends > 0) {
            const newBackend = selectBackend(req, req._lbGroup || 'default', retryState.triedIds);
            if (newBackend && newBackend.type === 'tunnel') {
              b.backends--;
              b.same = retrySameMax(reason);
              console.log(`  🔄 [${response.statusCode} 重试·隧道·换节点] ${req.method} ${req.url}  ${backend.tag} → ${newBackend.tag}  (还可换 ${b.backends} 个)`);
              return forwardViaTunnel(req, res, newBackend, retryState);
            }
          }
        }
      }

      const respHeaders = response.headers || {};
      for (const [k, v] of Object.entries(respHeaders)) {
        if (k.toLowerCase() !== 'transfer-encoding' && k.toLowerCase() !== 'connection') {
          try { res.setHeader(k, v); } catch (_) {}
        }
      }
      try {
        res.setHeader('x-lb-node', `tunnel:${backend.tag}`);
        res.setHeader('x-lb-group', req._lbGroup || 'default');
        res.setHeader('x-lb-algorithm', req._lbAlgo || getGroupAlgorithm(req._lbGroup || 'default'));
        res.setHeader('x-lb-response-time', `${rt}ms`);
      } catch (_) {}

      res.status(response.statusCode || 200);
      res.end(response.body || '');

      const statusCode = response.statusCode || 200;
      const log = recordLog(req, backend, { success: isSuccessfulStatus(statusCode), responseTime: rt, statusCode });
      broadcast({ type: 'new_log', log });
    }).catch(err => {
      clearTimeout(timer);
      backend.connections = Math.max(0, (backend.connections || 0) - 1);
      const rt = Date.now() - startTime;
      if (!clientAborted && failover502('隧道请求失败')) return;
      const log = recordLog(req, backend, { success: false, responseTime: rt, statusCode: 504 });
      broadcast({ type: 'new_log', log });
      if (!clientAborted && !res.writableEnded && !res.destroyed) {
        try { res.status(504).json({ ret: -1, error: '隧道请求失败', message: err.message }); } catch (_) {}
      }
    });
  };
  if (req.readableEnded) sendRequest();
  else req.once('end', sendRequest);
}

// ==================== Express 应用 ====================
const app = express();

app.disable('x-powered-by');
// 默认不向任意站点开放管理 API；如确实需要跨域，显式设置 LB_CORS_ORIGIN。
app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    const allowed = String(process.env.LB_CORS_ORIGIN || CONFIG.cors_origins || '')
      .split(',').map(value => value.trim()).filter(Boolean);
    return callback(null, allowed.includes(origin));
  }
}));

// 捕获原始 body 供 HTTP/FRP/Tunnel 转发使用，同时限制未解析请求体的内存占用。
app.use((req, res, next) => {
  const chunks = [];
  let size = 0;
  let tooLarge = false;
  req.on('data', chunk => {
    size += chunk.length;
    if (size <= MAX_REQUEST_BODY_BYTES) chunks.push(chunk);
    else tooLarge = true;
  });
  req.on('end', () => {
    req._bodyTooLarge = tooLarge;
    req._rawBody = tooLarge ? Buffer.alloc(0) : Buffer.concat(chunks);
  });
  next();
});
app.use(express.json({ limit: `${MAX_REQUEST_BODY_BYTES}b` }));
app.use(express.urlencoded({ extended: false, limit: `${MAX_REQUEST_BODY_BYTES}b` }));
app.use((req, res, next) => {
  if (req._bodyTooLarge) return res.status(413).json({ ret: -1, error: '请求体过大' });
  next();
});

// ─── API 路由 ──────────────────────────────────────
const apiRouter = express.Router();

// 只暴露无敏感信息的存活探针，供 systemd/监控使用。
app.get('/healthz', (req, res) => res.status(200).json({ ok: true, status: 'ok' }));

// 登录接口（无需认证）
apiRouter.post('/login', (req, res) => {
  const ip = getClientIp(req);
  const fail = loginFails.get(ip);
  if (fail && fail.count >= LOGIN_MAX_TRIES && Date.now() - fail.lastFail < LOGIN_LOCKOUT_MS) {
    return res.status(429).json({ ret: -1, error: '登录过于频繁，请60秒后重试' });
  }
  const { password } = req.body;
  if (password !== CONFIG.admin_password) {
    if (!fail || Date.now() - fail.lastFail > LOGIN_LOCKOUT_MS) loginFails.set(ip, { count: 1, lastFail: Date.now() });
    else { fail.count++; fail.lastFail = Date.now(); }
    return res.status(401).json({ ret: -1, error: '密码错误' });
  }
  loginFails.delete(ip);
  const token = createToken({
    ip,
    ua: (req.headers['user-agent'] || '').slice(0, 200),
    name: (req.body.name || '').slice(0, 50) || (req.headers['user-agent'] || '').slice(0, 30)
  });
  res.json({ ret: 0, token, expiresIn: TOKEN_TTL_MS });
});

// 其余 API 需要认证
apiRouter.use(requireAdmin);

apiRouter.post('/self-reload', (req, res) => {
  if (CONFIG.persist_stats) saveQqStats();
  res.json({ ret: 0, message: '正在重启...' });
  console.log('  🔄 收到已认证的 self-reload 请求');
  setTimeout(() => process.exit(0), 1000);
});

apiRouter.get('/stats', (req, res) => {
  const aliveBackends = Array.from(backends.values()).filter(b => b.alive).length;
  res.json({ ret: 0, data: { ...stats, currentRps: calcRps(), totalBackends: backends.size, aliveBackends, currentAlgorithm, groups: Object.keys(groups) } });
});
apiRouter.get('/qqstats', (req, res) => {
  res.json({ ret: 0, data: {
    totalUnique: qqStats.totalUnique,
    todayUnique: qqStats.todayUnique,
    totalRequests: qqStats.totalRequests,
    qqHistory: qqStats.qqHistory
  }});
});
apiRouter.get('/qqdebug', (req, res) => {
  res.json({ ret: 0, data: {
    totalRequests: stats.totalRequests,
    qqTotalRequests: qqStats.totalRequests,
    qqTotalUnique: qqStats.totalUnique,
    samples: [...requestSamples],
    sampleCount: requestSamples.length,
    maxSamples: MAX_SAMPLES,
  }});
});

apiRouter.get('/backends', (req, res) => {
  const list = Array.from(backends.values()).map(b => {
    const base = {
      id: b.id, type: b.type, weight: b.weight, tag: b.tag || '',
      group: backendGroupNames(b)[0], groups: backendGroupNames(b),
      alive: b.alive, connections: b.connections || 0,
      responseTime: Math.round(b.responseTime || 0),
      totalRequests: b.totalRequests || 0, successRequests: b.successRequests || 0, failRequests: b.failRequests || 0,
      disable_health_check: !!b.disable_health_check,
      query_to_json_enabled: !!b.query_to_json_enabled,
      post_to_get_enabled: !!b.post_to_get_enabled,
      disabled: !!b.disabled,
      createdAt: b.createdAt, lastCheck: b.lastCheck
    };
    if (b.type === 'http') { base.url = b.url; }
    if (b.type === 'tunnel') { base.remoteAddress = b.remoteAddress || 'unknown'; base.connectedAt = b.connectedAt; }
    return base;
  });
  res.json({ ret: 0, data: list });
});

apiRouter.post('/backends', (req, res) => {
  const { url, weight = 1, tag = '', group: groupName = 'default', disable_health_check = false, query_to_json_enabled = false, post_to_get_enabled = false } = req.body;
  if (!url) return res.status(400).json({ ret: -1, error: '请输入后端地址' });
  if (!url.startsWith('http://') && !url.startsWith('https://'))
    return res.status(400).json({ ret: -1, error: '地址须以 http:// 或 https:// 开头' });
  const selection = validateBackendGroups(req.body.groups !== undefined ? req.body.groups : groupName);
  if (selection.error) return res.status(400).json({ ret: -1, error: selection.error });
  for (const [, b] of backends) { if (b.type === 'http' && b.url === url) return res.status(400).json({ ret: -1, error: '该地址已存在' }); }
  const id = uuidv4();
  const backend = {
    id, type: 'http', url, weight: normalizeBackendWeight(weight), tag: tag || '',
    alive: true, connections: 0, responseTime: 0,
    totalRequests: 0, successRequests: 0, failRequests: 0,
    disable_health_check: !!disable_health_check, query_to_json_enabled: !!query_to_json_enabled && !post_to_get_enabled, post_to_get_enabled: !!post_to_get_enabled,
    createdAt: Date.now(), lastCheck: Date.now()
  };
  setBackendGroups(backend, selection.names);
  backends.set(id, backend);
  saveBackends();  // 持久化 HTTP 后端
  broadcast({ type: 'backend_added', backend });
  res.json({ ret: 0, data: backend });
});

apiRouter.put('/backends/:id', (req, res) => {
  if (!backends.has(req.params.id)) return res.status(404).json({ ret: -1, error: '后端不存在' });
  const b = backends.get(req.params.id);
  let selectedGroups = null;
  if (req.body.groups !== undefined || req.body.group !== undefined) {
    const selection = validateBackendGroups(req.body.groups !== undefined ? req.body.groups : req.body.group);
    if (selection.error) return res.status(400).json({ ret: -1, error: selection.error });
    selectedGroups = selection.names;
  }
  if (req.body.url !== undefined && b.type === 'http') b.url = req.body.url;
  if (req.body.weight !== undefined) b.weight = normalizeBackendWeight(req.body.weight);
  if (req.body.disable_health_check !== undefined) b.disable_health_check = !!req.body.disable_health_check;
  if (req.body.query_to_json_enabled !== undefined) {
    b.query_to_json_enabled = !!req.body.query_to_json_enabled;
    if (b.query_to_json_enabled) b.post_to_get_enabled = false;
  }
  if (req.body.post_to_get_enabled !== undefined) {
    b.post_to_get_enabled = !!req.body.post_to_get_enabled;
    if (b.post_to_get_enabled) b.query_to_json_enabled = false;
  }
  if (req.body.disabled !== undefined) b.disabled = !!req.body.disabled;
  if (req.body.tag !== undefined) b.tag = req.body.tag || '';
  if (selectedGroups) setBackendGroups(b, selectedGroups);
  saveBackends();
  broadcast({ type: 'backend_updated', backend: b });
  res.json({ ret: 0, data: b });
});

apiRouter.put('/backends/:id/tag', (req, res) => {
  if (!backends.has(req.params.id)) return res.status(404).json({ ret: -1, error: '后端不存在' });
  const b = backends.get(req.params.id);
  b.tag = req.body.tag || '';
  broadcast({ type: 'backend_updated', backend: b });
  res.json({ ret: 0, data: b });
});

// 手动把后端标记为 alive（清掉「离线」状态 + 自动关闭健康检查）
apiRouter.post('/backends/:id/revive', (req, res) => {
  if (!backends.has(req.params.id)) return res.status(404).json({ ret: -1, error: '后端不存在' });
  const b = backends.get(req.params.id);
  b.alive = true;
  b._hcFails = 0;
  b.lastCheck = Date.now();
  // 同时关闭健康检查，避免 5 秒后又被自动标死
  b.disable_health_check = true;
  saveBackends();
  broadcast({ type: 'backend_recovered', id: b.id, url: b.url, tag: b.tag });
  broadcast({ type: 'backend_updated', backend: b });
  res.json({ ret: 0, message: '已恢复在线，健康检查已自动关闭（状态：在线-免检）', data: b });
});

apiRouter.delete('/backends/:id', (req, res) => {
  if (!backends.has(req.params.id)) return res.status(404).json({ ret: -1, error: '后端不存在' });
  const b = backends.get(req.params.id);
  if (b.type === 'tunnel') {
    try { b.ws.close(); } catch (_) {}
  }
  backends.delete(req.params.id);
  if (b.type === 'http') saveBackends();
  broadcast({ type: 'backend_removed', id: req.params.id, url: b.url || b.tag, tag: b.tag });
  res.json({ ret: 0, message: '已删除' });
});

apiRouter.get('/algorithm', (req, res) => {
  const groupName = req.query.group || 'default';
  const algo = getGroupAlgorithm(groupName);
  res.json({ ret: 0, data: { algorithm: algo, info: ALGORITHMS[algo], group: groupName } });
});

apiRouter.put('/algorithm', (req, res) => {
  const { algorithm, group: groupName = 'default' } = req.body;
  if (!ALGORITHMS[algorithm]) return res.status(400).json({ ret: -1, error: `未知算法: ${algorithm}` });
  if (!groups[groupName]) return res.status(400).json({ ret: -1, error: `分组不存在: ${groupName}` });
  groups[groupName].algorithm = algorithm;
  if (groupName === 'default') currentAlgorithm = algorithm;
  resetGroupAlgoState(groupName);
  syncConfigGroupsRules();
  broadcast({ type: 'algorithm_changed', algorithm, group: groupName });
  res.json({ ret: 0, data: { algorithm, info: ALGORITHMS[algorithm], group: groupName } });
});

apiRouter.get('/algorithms', (req, res) => {
  res.json({ ret: 0, data: ALGORITHMS });
});

// ─── 分组管理 ───────────────────────────────────────
apiRouter.get('/groups', (req, res) => {
  res.json({ ret: 0, data: groups });
});

apiRouter.put('/groups', (req, res) => {
  const { name, algorithm, description } = req.body;
  if (!name) return res.status(400).json({ ret: -1, error: '请指定分组名称' });
  if (name === 'default' && algorithm && !ALGORITHMS[algorithm]) return res.status(400).json({ ret: -1, error: `未知算法: ${algorithm}` });
  if (!groups[name]) groups[name] = { algorithm: algorithm || 'round-robin', description: description || '' };
  if (algorithm) { groups[name].algorithm = algorithm; resetGroupAlgoState(name); }
  if (description !== undefined) groups[name].description = description;
  if (name === 'default') currentAlgorithm = groups[name].algorithm;
  syncConfigGroupsRules();
  broadcast({ type: 'groups_updated', groups });
  res.json({ ret: 0, data: groups });
});

apiRouter.delete('/groups/:name', (req, res) => {
  if (req.params.name === 'default') return res.status(400).json({ ret: -1, error: '不能删除默认分组' });
  if (!groups[req.params.name]) return res.status(404).json({ ret: -1, error: '分组不存在' });
  delete groups[req.params.name];
  // 从节点成员关系中移除该分组；没有剩余分组的节点回到 default。
  for (const [, b] of backends) setBackendGroups(b, backendGroupNames(b).filter(name => name !== req.params.name));
  saveBackends();
  syncConfigGroupsRules();
  broadcast({ type: 'groups_updated', groups });
  res.json({ ret: 0, message: '已删除', data: groups });
});

// ─── 路由规则管理 ───────────────────────────────────
apiRouter.get('/rules', (req, res) => {
  res.json({ ret: 0, data: sortedRules });
});

apiRouter.post('/rules', (req, res) => {
  const { path: rulePath, group, priority = 0, matchType = 'prefix' } = req.body;
  if (!rulePath) return res.status(400).json({ ret: -1, error: '请指定路径匹配规则' });
  if (!group) return res.status(400).json({ ret: -1, error: '请指定目标分组' });
  if (!groups[group]) return res.status(400).json({ ret: -1, error: `分组不存在: ${group}` });
  if (!RULE_MATCH_TYPES.has(matchType)) return res.status(400).json({ ret: -1, error: 'matchType 不支持' });
  const rule = { id: ruleIdCounter++, path: rulePath, group, priority: parseInt(priority) || 0, matchType };
  rules.push(rule);
  updateSortedRules();
  syncConfigGroupsRules();
  broadcast({ type: 'rules_updated', rules });
  res.json({ ret: 0, data: rule });
});

apiRouter.delete('/rules/:id', (req, res) => {
  const idx = rules.findIndex(r => r.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ ret: -1, error: '规则不存在' });
  rules.splice(idx, 1);
  updateSortedRules();
  syncConfigGroupsRules();
  broadcast({ type: 'rules_updated', rules });
  res.json({ ret: 0, message: '已删除' });
});

apiRouter.put('/rules/:id', (req, res) => {
  const idx = rules.findIndex(r => r.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ ret: -1, error: '规则不存在' });
  const { path: rulePath, group, priority, matchType } = req.body;
  if (matchType && !RULE_MATCH_TYPES.has(matchType)) return res.status(400).json({ ret: -1, error: 'matchType 不支持' });
  if (group && !groups[group]) return res.status(400).json({ ret: -1, error: `分组不存在: ${group}` });
  if (rulePath !== undefined) rules[idx].path = rulePath;
  if (group !== undefined) rules[idx].group = group;
  if (priority !== undefined) rules[idx].priority = parseInt(priority) || 0;
  if (matchType !== undefined) rules[idx].matchType = matchType;
  updateSortedRules();
  syncConfigGroupsRules();
  broadcast({ type: 'rules_updated', rules });
  res.json({ ret: 0, data: rules[idx] });
});

// ─── 预配置 Agent 代理 ───────────────────────────────
let proxyPresets = [];
apiRouter.get('/proxies', (req, res) => {
  proxyPresets = CONFIG.proxy_presets || [];
  res.json({ ret: 0, data: proxyPresets });
});
apiRouter.post('/proxies', (req, res) => {
  const { name, group: g, groupKey, localPort } = req.body;
  if (!name) return res.status(400).json({ ret: -1, error: '请输入 Agent 名称' });
  proxyPresets = CONFIG.proxy_presets || [];
  proxyPresets.push({ name, group: g || 'default', groupKey: groupKey || '', localPort: parseInt(localPort) || 0 });
  CONFIG.proxy_presets = proxyPresets; saveConfig();
  broadcast({ type: 'proxies_updated', proxies: proxyPresets });
  res.json({ ret: 0, data: proxyPresets });
});
apiRouter.delete('/proxies/:name', (req, res) => {
  proxyPresets = (CONFIG.proxy_presets || []).filter(p => p.name !== req.params.name);
  CONFIG.proxy_presets = proxyPresets; saveConfig();
  broadcast({ type: 'proxies_updated', proxies: proxyPresets });
  res.json({ ret: 0, data: proxyPresets });
});
apiRouter.get('/config', (req, res) => {
  res.json({ ret: 0, data: { ...getClientConfig(), groups, rules } });
});

// 导出完整配置（备份用）
apiRouter.get('/config/export', (req, res) => {
  const backendsList = [];
  for (const [, b] of backends) {
    if (b.type === 'http') {
      backendsList.push({ id: b.id, type: b.type, url: b.url, weight: b.weight, tag: b.tag || '', group: backendGroupNames(b)[0], groups: backendGroupNames(b), disable_health_check: !!b.disable_health_check, query_to_json_enabled: !!b.query_to_json_enabled, post_to_get_enabled: !!b.post_to_get_enabled, createdAt: b.createdAt });
    }
  }
  const exportData = {
    version: 1,
    exportedAt: new Date().toISOString(),
    // Deliberately omit admin password, HMAC secret, deploy/agent secrets,
    // sessions and QQ identifiers from downloaded backups.
    config: Object.fromEntries(Object.entries(getClientConfig()).filter(([key]) => key !== 'agent_token')),
    groups,
    rules,
    backends: backendsList
  };
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="lb-config-${new Date().toISOString().slice(0,10)}.json"`);
  res.send(JSON.stringify(exportData, null, 2));
});

// 导入配置（恢复备份）
apiRouter.post('/config/import', (req, res) => {
  const data = req.body;
  if (!data || typeof data !== 'object') return res.status(400).json({ ret: -1, error: '数据格式错误' });

  // 只恢复非敏感的可配置项；认证材料和运行时状态不能由备份覆盖。
  if (data.config && typeof data.config === 'object') {
    const importable = CONFIG_MUTABLE_KEYS.filter(key => !['admin_password', 'agent_token', 'bark_key'].includes(key));
    for (const key of importable) {
      if (data.config[key] !== undefined) CONFIG[key] = data.config[key];
    }
  }
  // 恢复分组
  if (data.groups && typeof data.groups === 'object' && !Array.isArray(data.groups)) {
    for (const [name, value] of Object.entries(data.groups).slice(0, 100)) {
      if (!/^[\w.-]{1,64}$/u.test(name) || !value || typeof value !== 'object') continue;
      if (value.algorithm && !ALGORITHMS[value.algorithm]) continue;
      groups[name] = { algorithm: value.algorithm || 'round-robin', description: String(value.description || '').slice(0, 200) };
    }
  }
  // 恢复规则
  if (Array.isArray(data.rules) && data.rules.length <= 500) {
    const importedRules = data.rules.filter(rule => rule && typeof rule === 'object'
      && typeof rule.path === 'string' && rule.path.length <= 500
      && typeof rule.group === 'string' && groups[rule.group]
      && RULE_MATCH_TYPES.has(rule.matchType || 'prefix'))
      .map(rule => ({
        id: Number.isInteger(rule.id) ? rule.id : ruleIdCounter++,
        path: rule.path,
        group: rule.group,
        priority: Number.parseInt(rule.priority, 10) || 0,
        matchType: rule.matchType || 'prefix'
      }));
    rules.length = 0;
    rules.push(...importedRules);
    ruleIdCounter = rules.length > 0 ? Math.max(...rules.map(r => r.id)) + 1 : 1;
    updateSortedRules();
  }
  // 恢复后端
  if (Array.isArray(data.backends) && data.backends.length <= 200) {
    for (const [, b] of backends) { if (b.type === 'http') backends.delete(b.id); }
    for (const b of data.backends) {
      const selection = b && validateBackendGroups(b.groups || b.group || 'default');
      if (b && typeof b.url === 'string' && /^https?:\/\//i.test(b.url) && !selection.error) {
        const id = b.id || uuidv4();
        const backend = {
          id, type: 'http', url: b.url, weight: normalizeBackendWeight(b.weight), tag: String(b.tag || '').slice(0, 100),
          alive: true, connections: 0, responseTime: 0,
          totalRequests: 0, successRequests: 0, failRequests: 0,
          disable_health_check: !!b.disable_health_check, query_to_json_enabled: !!b.query_to_json_enabled, post_to_get_enabled: !!b.post_to_get_enabled,
          createdAt: b.createdAt || Date.now(), lastCheck: Date.now()
        };
        setBackendGroups(backend, selection.names);
        backends.set(id, backend);
      }
    }
  }
  saveConfig();
  saveBackends();
  saveSessions();
  broadcast({ type: 'config_updated', config: getClientConfig() });
  broadcast({ type: 'groups_updated', groups });
  broadcast({ type: 'rules_updated', rules });
  res.json({ ret: 0, message: '配置已导入' });
});

// 活动会话管理（多设备登录）
apiRouter.get('/sessions', (req, res) => {
  const currentToken = (req.headers.authorization || '').replace('Bearer ', '');
  const now = Date.now();
  const list = Array.from(activeSessions.entries())
    .map(([token, s]) => ({
      token: token.slice(0, 10) + '...' + token.slice(-6),
      tokenFull: token,
      id: s.id,
      ip: s.ip,
      ua: s.ua,
      name: s.name,
      createdAt: s.createdAt,
      lastActive: s.lastActive,
      exp: s.exp,
      isCurrent: token === currentToken
    }))
    .filter(s => now < s.exp)
    .sort((a, b) => b.lastActive - a.lastActive);
  res.json({ ret: 0, data: list });
});

apiRouter.delete('/sessions/:token', (req, res) => {
  // token 在 URL 里可能需要还原（用户拿到的 token 已经被截断了）
  const full = decodeURIComponent(req.params.token);
  let removed = false;
  for (const t of activeSessions.keys()) {
    if (t === full || t.startsWith(full.slice(0, 10)) && t.endsWith(full.slice(-6))) {
      activeSessions.delete(t);
      removed = true;
      break;
    }
  }
  if (removed) {
    saveSessions();
    res.json({ ret: 0, message: '已注销该设备' });
  } else {
    res.status(404).json({ ret: -1, error: '会话不存在' });
  }
});

apiRouter.post('/logout', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  removeToken(token);
  res.json({ ret: 0, message: '已退出登录' });
});

apiRouter.put('/config', (req, res) => {
  const previousConfig = CONFIG;
  const nextConfig = { ...CONFIG };
  for (const key of CONFIG_MUTABLE_KEYS) {
    if (req.body[key] !== undefined) {
      if (key === 'admin_password' && (typeof req.body[key] !== 'string' || req.body[key].length < 8 || req.body[key].length > 200)) {
        return res.status(400).json({ ret: -1, error: '管理员密码长度必须为 8-200 位' });
      }
      if (key === 'request_timeout') {
        const value = Number.parseInt(req.body[key], 10);
        if (!Number.isInteger(value) || value < MIN_REQUEST_TIMEOUT || value > MAX_REQUEST_TIMEOUT) {
          return res.status(400).json({ ret: -1, error: 'request_timeout 必须在 60000-600000ms 之间' });
        }
        nextConfig[key] = value;
      } else if (['hc_interval', 'hc_timeout', 'tunnel_timeout', 'monitor_interval', 'auto_backup_interval'].includes(key)) {
        const value = Number.parseInt(req.body[key], 10);
        if (!Number.isInteger(value) || value < 1000 || value > 7 * 24 * 3600 * 1000) return res.status(400).json({ ret: -1, error: `${key} 数值范围无效` });
        nextConfig[key] = value;
      } else if (['max_log', 'max_backups', 'retry_400_max', 'retry_400_max_backends', 'retry_502_max', 'retry_502_max_backends'].includes(key)) {
        const value = Number.parseInt(req.body[key], 10);
        if (!Number.isInteger(value) || value < 1 || value > 10000) return res.status(400).json({ ret: -1, error: `${key} 数值范围无效` });
        nextConfig[key] = value;
      } else if (key === 'page_title' || key === 'version_rewrite_target' || key === 'cors_origins') {
        if (typeof req.body[key] !== 'string' || req.body[key].length > 500) return res.status(400).json({ ret: -1, error: `${key} 格式无效` });
        nextConfig[key] = req.body[key];
      } else {
        nextConfig[key] = req.body[key];
      }
    }
  }
  CONFIG = nextConfig;
  if (!saveConfig()) {
    CONFIG = previousConfig;
    return res.status(500).json({ ret: -1, error: '配置写入失败，未应用修改' });
  }
  applyForwardTimeouts();
  restartHealthCheck();
  if (req.body.auto_backup_enabled !== undefined || req.body.auto_backup_interval !== undefined) startAutoBackup();
  if (req.body.monitor_interval !== undefined || req.body.bark_key !== undefined) startMonitor();
  if (req.body.frp_port !== undefined) startFrpsServer();
  broadcast({ type: 'config_updated', config: getClientConfig() });
  res.json({ ret: 0, message: '配置已更新', data: getClientConfig() });
});

apiRouter.get('/logs', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, CONFIG.max_log);
  res.json({ ret: 0, data: [...requestLogs].reverse().slice(0, limit) });
});

apiRouter.get('/overview', (req, res) => {
  const backendList = Array.from(backends.values()).map(b => {
    const base = {
      id: b.id, type: b.type, weight: b.weight, tag: b.tag || '',
      group: backendGroupNames(b)[0], groups: backendGroupNames(b),
      alive: b.alive, connections: b.connections || 0,
      responseTime: Math.round(b.responseTime || 0),
      totalRequests: b.totalRequests || 0, successRequests: b.successRequests || 0, failRequests: b.failRequests || 0,
      disable_health_check: !!b.disable_health_check,
      query_to_json_enabled: !!b.query_to_json_enabled,
      post_to_get_enabled: !!b.post_to_get_enabled,
      disabled: !!b.disabled,
      createdAt: b.createdAt, lastCheck: b.lastCheck
    };
    if (b.type === 'http') { base.url = b.url; }
    if (b.type === 'tunnel') { base.remoteAddress = b.remoteAddress || 'unknown'; base.connectedAt = b.connectedAt; }
    return base;
  });
  res.json({
    ret: 0, data: {
      stats: { ...stats, currentRps: calcRps(), totalBackends: backends.size, aliveBackends: backendList.filter(b => b.alive).length, currentAlgorithm },
      qqStats: {
        totalUnique: qqStats.totalUnique,
        todayUnique: qqStats.todayUnique,
        totalRequests: qqStats.totalRequests,
        qqHistory: qqStats.qqHistory
      },
      page_title: CONFIG.page_title || '负载均衡管理面板',
      algorithm: { name: currentAlgorithm, info: ALGORITHMS[currentAlgorithm] },
      groups, rules: sortedRules,
      backends: backendList, logs: [...requestLogs].reverse().slice(0, 30)
    }
  });
});

app.use('/api', apiRouter);

// ─── 静态文件 ───────────────────────────────────────
const publicPath = path.join(__dirname, 'public');
app.get('/', (req, res) => res.sendFile(path.join(publicPath, 'index.html')));
app.use('/css', express.static(path.join(publicPath, 'css')));
app.use('/js', express.static(path.join(publicPath, 'js')));
app.use('/lib', express.static(path.join(publicPath, 'lib')));

// ─── 代理/隧道转发入口 ──────────────────────────────
function handleProxyRequest(req, res) {
  // 浏览器自动请求，不转发也不记录
  if (req.url === '/favicon.ico' || req.url === '/robots.txt') {
    return res.status(204).end();
  }
  recordIncomingRequest();
  const debugBackend = selectDebugRoute(req);
  const groupName = debugBackend ? '__debug__' : matchGroup(req);
  req._lbGroup = groupName;
  const groupAlgo = req._lbAlgo = debugBackend ? 'debug' : getGroupAlgorithm(groupName);
  const ruleBackend = debugBackend ? null : selectRuleBackend(req._lbMatchedRule, groupName);
  const backend = debugBackend || ruleBackend || selectBackend(req, groupName);
  if (!backend) {
    recordLog(req, null, { success: false, responseTime: 0, statusCode: 502 });
    // 让分组里所有 dead 后端都记一次失败（健康检查可能没及时）
    const peers = getAliveBackendsInGroup(groupName);
    if (peers.length === 0) {
      // 分组里没有任何 alive 后端，列出该分组所有后端并全部算失败
      const allInGroup = Array.from(backends.values()).filter(b => backendInGroup(b, groupName));
      for (const b of allInGroup) b.failRequests = (b.failRequests || 0) + 1;
    }
      return res.status(502).json({ ret: -1, error: `[${groupName}] 没有可用的后端节点`, lb: { group: { name: groupName, algorithm: groupAlgo } } });
  }
  req._lbBackendId = backend.id;
  req._lbBackend = backend;
  req._lbDebugRoute = !!debugBackend;
  if (backend.type === 'tunnel') {
    prepareForwardRequest(req);
    return forwardViaTunnel(req, res, backend);
  }
  if (backend.type === 'frp') {
    prepareForwardRequest(req);
    return forwardViaFrp(req, res, backend);
  }
  // HTTP 代理
  req._lbStartTime = Date.now();
  req._lbBackendId = backend.id;
  req._lbGroup = groupName;
  // 初始化失败重试追踪（400 与 431/429/502/504 各自独立预算，先同节点重试，不行再换节点）
  const needsBufferedResponse = anyRetryEnabled() || !!backend.query_to_json_enabled || !!backend.post_to_get_enabled;
  if (needsBufferedResponse) {
    req._lbReqId = uuidv4();
    retryRequests.set(req._lbReqId, {
      budgets: retryBudgets(),
      triedBackendIds: new Set([backend.id])
    });
  }
  backend.connections = (backend.connections || 0) + 1;
  const logEntry = recordLog(req, backend, { success: true, responseTime: 0, deferBroadcast: true });
  req._lbLogEntry = logEntry;
  req._lbLogBackendId = backend.id;
  // 重新注入请求体（应用 ver 改写）
  if (req._rawBody && req._rawBody.length > 0) {
    // 优先用原始 body（保留 urlencoded 格式）
    let raw = req._rawBody;
    if (CONFIG.version_rewrite_enabled) {
      const rewritten = rewriteVersion(raw, req.headers['content-type']);
      if (rewritten !== raw) {
        logEntry.rewritten = true;
        raw = rewritten;
      }
    }
    req.headers['content-length'] = Buffer.byteLength(raw);
    req._lbOriginalBody = raw;
  } else if (req.body && typeof req.body === 'object' && Object.keys(req.body).length > 0) {
    const bodyStr = JSON.stringify(req.body);
    req.headers['content-length'] = Buffer.byteLength(bodyStr);
    req._lbOriginalBody = Buffer.from(bodyStr);
  }
  prepareForwardRequest(req);
  // 日志同时保留入口原始方法和实际发给节点的方法，避免把节点转换误看成客户端请求变化。
  logEntry.forwardMethod = req.method;
  logEntry.forwardPath = displayRequestPath(req.url);
  logEntry.forwardFullPath = req.url;
  logEntry.transform = req._lbAppliedTransform || null;
  if (stats.totalRequests - stats.shownLogIndex < 100) broadcast({ type: 'new_log', log: logEntry });
  // 使用缓冲响应包装器（支持失败重试）或直接转发
  const targetRes = needsBufferedResponse ? createBufferedRes(res) : res;
  proxy.web(req, targetRes, {
    target: backend.url,
    // http-proxy 的默认 30 秒会误伤慢初始化接口；这里与隧道等待上限统一。
    proxyTimeout: getForwardTimeout(),
    timeout: getForwardTimeout()
  }, err => {
    const reqId = req._lbReqId;
    // 连接/传输失败 → 若启用 502/504 重试且有预算，先同节点重试，预算耗尽才换节点
    const canRetryConn = !!(targetRes._buf && reqId && CONFIG.retry_502_enabled && !res.headersSent && !res.writableEnded);
    if (canRetryConn) {
      const retryInfo = retryRequests.get(reqId);
      const next = retryInfo ? pickHttpRetryTarget(req, retryInfo, '502') : null;
      if (next && next.target) {
        const tag = next.switched ? '换节点' : '同节点';
        const remain = next.switched
          ? `还可换 ${retryInfo.budgets['502'].backends} 个`
          : `剩余 ${retryInfo.budgets['502'].same} 次`;
        console.log(`  🔄 [502 重试·${tag}] ${req.method} ${req.url} → ${next.target}  (${remain}) 原后端错误: ${err.message}`);
        retryHttpRequest(req, res, next.target, retryInfo, reqId);
        return;
      }
    }
    // 无法重试（或预算耗尽）→ 记录失败并按原样返回 502
    backend.connections = Math.max(0, (backend.connections || 0) - 1);
    const rt = Date.now() - req._lbStartTime;
    updateHttpLogOutcome(req, 502, rt);
    // 更新 stats.historyResponseTime（recordLog 初始传入 0 不会更新）
    if (rt > 0) {
      const idx = stats.historyResponseTime.length - 1;
      const prev = stats.historyResponseTime[idx] || 0;
      stats.historyResponseTime[idx] = prev + (rt - prev) / stats.historyRequests[idx];
      backend.responseTime = backend.responseTime ? Math.round(backend.responseTime * 0.7 + rt * 0.3) : rt;
    }
    if (!res.headersSent && !res.writableEnded) {
      try { res.status(502).json({ ret: -1, error: '代理错误', message: err.message }); } catch (_) {}
    }
    if (reqId) retryRequests.delete(reqId);
  });
}

app.use(handleProxyRequest);

// Normalize JSON/urlencoded parser failures to the API contract instead of
// returning Express' HTML error page.
function recoverMislabelledFormRequest(req, error) {
  if (!error || error.type !== 'entity.parse.failed') return null;
  const requestPath = String(req.originalUrl || req.url || '').split('?')[0];
  if (requestPath === '/api' || requestPath.startsWith('/api/')) return null;
  if (!String(req.headers?.['content-type'] || '').toLowerCase().includes('application/json')) return null;
  const raw = Buffer.isBuffer(req._rawBody) && req._rawBody.length > 0
    ? req._rawBody
    : (error.body ? Buffer.from(error.body) : null);
  const body = formBodyToPayload(raw);
  if (!body || !Object.prototype.hasOwnProperty.call(body, 'ver') || !Object.prototype.hasOwnProperty.call(body, 'cmd')) return null;
  return { raw, body };
}

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  if (error && (error.type === 'entity.too.large' || error.status === 413)) {
    return res.status(413).json({ ret: -1, error: '请求体过大' });
  }
  const recovered = recoverMislabelledFormRequest(req, error);
  if (recovered) {
    // 某些旧客户端错误地标注 application/json，却发送 ver=...&cmd=...；
    // 只在代理入口恢复，管理 API 仍严格校验 JSON。
    req.headers['content-type'] = 'application/x-www-form-urlencoded';
    req.headers['content-length'] = String(recovered.raw.length);
    req._rawBody = recovered.raw;
    req._lbOriginalBody = recovered.raw;
    req.body = recovered.body;
    return handleProxyRequest(req, res);
  }
  return res.status(400).json({ ret: -1, error: '请求格式无效' });
});

function startFrpsServer() {
  // FRPS 已集成到 rawServer 中，无需额外端口
  console.log(`  [FRPS] frps 与 HTTP 共用 7878 (TLS+明文自动检测)`);
}

// ==================== HTTP 服务器（协议嗅探） ====================
// 底层 raw TCP server：首字节检测 FRPS vs HTTP
const rawServer = net.createServer((socket) => {
  socket.pause();

  socket.once('data', (chunk) => {
    socket.pause();

    const isHttp = chunk && chunk.length > 0 && chunk[0] >= 0x41 && chunk[0] <= 0x5A;
    const isTls = chunk && chunk.length > 0 && chunk[0] === 0x16;

    if (isHttp) {
      socket.unshift(chunk);
      httpServer.emit('connection', socket);
      socket.resume();
      return;
    }

    // FRPS
    const tlsOpts = getTlsOptions();
    logFrp(`${isTls ? 'TLS' : '明文'} ${socket.remoteAddress}`);
    if (isTls && tlsOpts) {
      socket.unshift(chunk);
      try { handleFrpConnection(new tls.TLSSocket(socket, { isServer: true, allowHalfOpen: false, ...tlsOpts }), Buffer.alloc(0)); }
      catch (e) { socket.destroy(); }
    } else {
      socket.resume();
      handleFrpConnection(socket, chunk);
    }
  });

  socket.resume(); // 恢复读取，等待第一个数据包

  // 3 秒没数据 → HTTP 放行
  const fallback = setTimeout(() => {
    if (socket.listenerCount('data') > 0) {
      socket.removeAllListeners('data');
      httpServer.emit('connection', socket);
      socket.resume();
    }
  }, 3000);
  socket.once('close', () => clearTimeout(fallback));
});

// Express 内嵌在 httpServer 中
const httpServer = http.createServer(app);

function applyForwardTimeouts() {
  const timeout = getForwardTimeout();
  // Node 层也不能用 30 秒默认值提前掐断慢初始化请求。
  httpServer.requestTimeout = timeout;
  httpServer.timeout = timeout;
  httpServer.headersTimeout = Math.max(120000, timeout);
}

// WebSocket 升级：在 HTTP 层处理，绕过 Express
httpServer.on('upgrade', (request, socket, head) => {
  const u = new URL(request.url, `http://${request.headers.host}`);
  const { pathname } = u;
  if (pathname === '/ws') {
    const protocol = (request.headers['sec-websocket-protocol'] || '').split(',')[0].trim();
    const token = protocol || u.searchParams.get('token') || '';
    if (!verifyToken(token)) { socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); socket.destroy(); return; }
    adminWss.handleUpgrade(request, socket, head, (ws) => adminWss.emit('connection', ws, request));
  } else if (pathname === '/agent') {
    agentWss.handleUpgrade(request, socket, head, (ws) => agentWss.emit('connection', ws, request));
  } else {
    socket.destroy();
  }
});

// ==================== WebSocket（管理前端推送） ====================
const adminWss = new WebSocket.Server({ noServer: true });
adminWss.on('connection', (ws) => {
  wsSubscribers.add(ws);
  const backendList = Array.from(backends.values()).map(b => {
    const base = {
      id: b.id, type: b.type, weight: b.weight, tag: b.tag || '',
      group: backendGroupNames(b)[0], groups: backendGroupNames(b),
      alive: b.alive, connections: b.connections || 0,
      responseTime: Math.round(b.responseTime || 0),
      totalRequests: b.totalRequests || 0, successRequests: b.successRequests || 0, failRequests: b.failRequests || 0,
      disable_health_check: !!b.disable_health_check,
      query_to_json_enabled: !!b.query_to_json_enabled,
      post_to_get_enabled: !!b.post_to_get_enabled,
      disabled: !!b.disabled
    };
    if (b.type === 'http') { base.url = b.url; }
    if (b.type === 'tunnel') base.remoteAddress = b.remoteAddress || 'unknown';
    return base;
  });
  ws.send(JSON.stringify({
    type: 'init', data: {
      stats: { ...stats, currentRps: calcRps(), totalBackends: backends.size, aliveBackends: backendList.filter(b => b.alive).length, currentAlgorithm },
      qqStats: { totalUnique: qqStats.totalUnique, todayUnique: qqStats.todayUnique, totalRequests: qqStats.totalRequests, qqHistory: qqStats.qqHistory },
      page_title: CONFIG.page_title || '负载均衡管理面板',
      algorithm: { name: currentAlgorithm, info: ALGORITHMS[currentAlgorithm] },
      algorithms: ALGORITHMS, groups, rules: sortedRules,
      backends: backendList, logs: [...requestLogs].reverse().slice(0, 30)
    }
  }));
  ws.on('close', () => wsSubscribers.delete(ws));
  ws.on('error', () => wsSubscribers.delete(ws));
});

// ==================== WebSocket（Agent 隧道连接） ====================
const agentWss = new WebSocket.Server({ noServer: true });
agentWss.on('connection', (ws, req) => {
  let agentId = null;
  let agentTag = 'unknown';

  const msgHandler = (data) => {
    try {
      const msg = JSON.parse(data.toString());
      if (msg.type === 'register') {
        // Token 鉴权（如果设置了 AGENT_AUTH_TOKEN）
        if (CONFIG.agent_token && msg.token !== CONFIG.agent_token) {
          ws.send(JSON.stringify({ type: 'error', message: '认证失败: token 无效' }));
          ws.close(4001, '认证失败');
          return;
        }
        agentId = uuidv4();
        agentTag = msg.tag || `agent-${agentId.slice(0, 8)}`;
        // 分组：Agent 指定 > groupKey 匹配预配置 > 默认；管理端偏好可恢复为多分组。
        let agentGroup = msg.group || 'default';
        if (!msg.group && msg.groupKey) {
          const preset = (CONFIG.proxy_presets || []).find(p => p.groupKey === msg.groupKey);
          if (preset) agentGroup = preset.group || 'default';
        }
        if (!groups[agentGroup]) agentGroup = 'default';
        // 恢复保存的偏好配置（weight/group/disable_health_check）
        const prefs = (CONFIG._backend_prefs || []).find(p => p.type === 'tunnel' && p.tag === agentTag);
        const backend = {
          id: agentId, type: 'tunnel', ws,
          tag: agentTag, weight: normalizeBackendWeight(prefs?.weight ?? msg.weight), query_to_json_enabled: !!prefs?.query_to_json_enabled, post_to_get_enabled: !!prefs?.post_to_get_enabled,
          alive: !(prefs?.disabled), connections: 0, responseTime: 0,
          totalRequests: 0, successRequests: 0, failRequests: 0,
          disable_health_check: prefs?.disable_health_check || false,
          disabled: prefs?.disabled || false,
          createdAt: Date.now(), lastCheck: Date.now(),
          remoteAddress: req.socket?.remoteAddress || 'unknown',
          connectedAt: Date.now()
        };
        setBackendGroups(backend, prefs?.groups || prefs?.group || msg.groups || agentGroup);
        if (prefs) console.log(`  📋 恢复 ${agentTag} 偏好: group=${backend.group} weight=${backend.weight} hc=${backend.disable_health_check ? 'off' : 'on'}`);
        backends.set(agentId, backend);
        ws.send(JSON.stringify({ type: 'registered', id: agentId, status: 'ok' }));
        broadcast({ type: 'backend_added', backend });
        // 记录连接日志
        const connLog = { id: uuidv4(), time: new Date().toLocaleTimeString(), method: 'AGENT', path: agentTag,
          sourceIp: backend.remoteAddress, backend: `🔌 ${agentTag}`, backendTag: agentTag, type: 'tunnel',
          group: agentGroup, algorithm: 'connect', responseTime: 0, statusCode: 200, success: true };
        requestLogs.push(connLog);
        if (requestLogs.length > CONFIG.max_log) requestLogs.shift();
        broadcast({ type: 'new_log', log: connLog });
        console.log(`  ✅ Agent 已连接: ${agentTag} (${backend.remoteAddress}) → 分组: ${agentGroup}`);
        return;
      }
      if (msg.type === 'response' && agentId) {
        const pend = pendingRequests.get(msg.id);
        if (pend) { clearTimeout(pend.timer); pend.resolve(msg); pendingRequests.delete(msg.id); }
        return;
      }
      if (msg.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong' }));
        return;
      }
    } catch (e) { /* ignore bad messages */ }
  };

  const closeHandler = () => {
    if (agentId) {
      // 清理该 Agent 所有待处理请求
      for (const [rid, pend] of pendingRequests) {
        if (pend.backendId === agentId) {
          clearTimeout(pend.timer);
          pend.reject(new Error('Agent disconnected'));
          pendingRequests.delete(rid);
        }
      }
      backends.delete(agentId);
      broadcast({ type: 'backend_removed', id: agentId, tag: agentTag });
      // 记录断开日志
      const discLog = { id: uuidv4(), time: new Date().toLocaleTimeString(), method: 'AGENT', path: agentTag,
        sourceIp: 'unknown', backend: `🔌 ${agentTag}`, backendTag: agentTag, type: 'tunnel',
        group: '-', algorithm: 'disconnect', responseTime: 0, statusCode: 0, success: false };
      requestLogs.push(discLog);
      if (requestLogs.length > CONFIG.max_log) requestLogs.shift();
      broadcast({ type: 'new_log', log: discLog });
      console.log(`  ❌ Agent 断开: ${agentTag}`);
    }
  };

  ws.on('message', msgHandler);
  ws.on('close', closeHandler);
  ws.on('error', closeHandler);

  // 10 秒内未注册则断开
  const regTimer = setTimeout(() => {
    if (!agentId) { ws.close(); }
  }, 10000);
  ws.once('message', () => clearTimeout(regTimer));
});

// ==================== 定时推送统计（管理前端） ====================
  statsTimer = setInterval(() => {
  if (!wsSubscribers.size) { calcRps(); return; }
  const backendList = Array.from(backends.values());
  const aliveBackends = backendList.filter(b => b.alive).length;
  broadcast({
    type: 'stats_update', data: {
      stats: { ...stats, currentRps: calcRps(), totalBackends: backends.size, aliveBackends, currentAlgorithm },
      qqStats: { totalUnique: qqStats.totalUnique, todayUnique: qqStats.todayUnique, totalRequests: qqStats.totalRequests, qqHistory: qqStats.qqHistory },
      page_title: CONFIG.page_title || '负载均衡管理面板',
      groups, rules: sortedRules,
      backends: backendList.map(b => {
        const base = {
          id: b.id, type: b.type, weight: b.weight, tag: b.tag || '',
          group: backendGroupNames(b)[0], groups: backendGroupNames(b),
          alive: b.alive, connections: b.connections || 0,
          responseTime: Math.round(b.responseTime || 0),
          totalRequests: b.totalRequests || 0, successRequests: b.successRequests || 0, failRequests: b.failRequests || 0,
          disable_health_check: !!b.disable_health_check,
          query_to_json_enabled: !!b.query_to_json_enabled,
          post_to_get_enabled: !!b.post_to_get_enabled,
          disabled: !!b.disabled,
          lastCheck: b.lastCheck
        };
        if (b.type === 'http') { base.url = b.url; }
        if (b.type === 'tunnel') base.remoteAddress = b.remoteAddress || 'unknown';
        return base;
      })
    }
  });
}, 1000);

// ==================== Bark 离线推送监控 ====================
// 公开版本不内置任何真实服务器地址；需要监控时通过配置或环境变量注入。
function loadMonitorServers() {
  const raw = process.env.LB_MONITOR_SERVERS_JSON || '';
  let value = raw;
  if (raw) {
    try { value = JSON.parse(raw); } catch (_) { value = []; }
  } else {
    value = CONFIG.monitor_servers;
  }
  if (!Array.isArray(value)) return [];
  return value.filter(server => server && typeof server.name === 'string'
    && typeof server.host === 'string' && server.host.length > 0
    && Number.isInteger(Number(server.port)) && Number(server.port) > 0 && Number(server.port) < 65536)
    .map(server => ({ name: server.name.slice(0, 80), host: server.host, port: Number(server.port) }));
}
let MONITOR_SERVERS = [];

function getSelfName() {
  const ips = Object.values(require('os').networkInterfaces()).flat()
    .filter(i => i.family === 'IPv4' && !i.internal).map(i => i.address);
  for (const s of MONITOR_SERVERS)
    if (ips.some(ip => ip === s.host)) return s.name;
  return 'relay';
}
let SELF_NAME = 'relay';

const _monitorStatus = {};
for (const s of MONITOR_SERVERS) _monitorStatus[s.host] = false;

function sendBark(title, body) {
  const key = CONFIG.bark_key;
  if (!key) return;
  const url = `https://api.day.app/${key}/${encodeURIComponent(title)}/${encodeURIComponent(body)}?isArchive=1`;
  https.get(url, (res) => {
    let data = '';
    res.on('data', d => data += d);
    res.on('end', () => {
      try { const r = JSON.parse(data); if (r.code !== 200) console.log('  [BARK] ⚠️', r.message); }
      catch (_) {}
    });
  }).on('error', () => {});
}

// ==================== 自动备份系统 ====================
const BACKUP_DIR = path.join(__dirname, 'backups');
let backupTimer = null;

if (!fs.existsSync(BACKUP_DIR)) {
  try { fs.mkdirSync(BACKUP_DIR, { recursive: true }); } catch (_) {}
}

function listBackupFiles() {
  try {
    return fs.readdirSync(BACKUP_DIR)
      .filter(f => f.startsWith('lb-config-') && f.endsWith('.json'))
      .map(f => {
        const full = path.join(BACKUP_DIR, f);
        const stat = fs.statSync(full);
        return { filename: f, size: stat.size, mtime: stat.mtime.getTime() };
      })
      .sort((a, b) => b.mtime - a.mtime);
  } catch (_) { return []; }
}

function makeBackupSnapshot() {
  const backendsList = [];
  for (const [, b] of backends) {
    if (b.type === 'http') backendsList.push({ id: b.id, type: b.type, url: b.url, weight: b.weight, tag: b.tag || '', group: backendGroupNames(b)[0], groups: backendGroupNames(b), disable_health_check: !!b.disable_health_check, createdAt: b.createdAt });
  }
  const sessionsList = Array.from(activeSessions.entries()).map(([token, s]) => ({ token, ...s }));
  return {
    version: 1,
    exportedAt: new Date().toISOString(),
    auto: true,
    config: CONFIG,
    groups,
    rules,
    backends: backendsList,
    sessions: sessionsList
  };
}

function doAutoBackup(notify = true) {
  try {
    const snap = makeBackupSnapshot();
    const filename = `lb-config-${new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)}.json`;
    fs.writeFileSync(path.join(BACKUP_DIR, filename), JSON.stringify(snap, null, 2), 'utf8');
    pruneOldBackups();
    if (notify) sendBark('📦 配置已自动备份', `${filename} 已保存，可从管理面板下载`);
    console.log(`  [BACKUP] 已保存 ${filename}`);
    return filename;
  } catch (e) {
    console.error(`  [BACKUP] 失败: ${e.message}`);
    return null;
  }
}

function pruneOldBackups() {
  const maxBackups = CONFIG.max_backups || 30;
  const files = listBackupFiles();
  if (files.length > maxBackups) {
    const toDelete = files.slice(maxBackups);
    for (const f of toDelete) {
      try { fs.unlinkSync(path.join(BACKUP_DIR, f.filename)); } catch (_) {}
    }
  }
}

function startAutoBackup() {
  if (backupTimer) clearInterval(backupTimer);
  if (!CONFIG.auto_backup_enabled) return;
  const interval = CONFIG.auto_backup_interval || 6 * 3600 * 1000; // 默认 6 小时
  backupTimer = setInterval(() => doAutoBackup(true), interval);
  console.log(`  [BACKUP] 自动备份已启用，间隔 ${(interval/3600000).toFixed(1)} 小时`);
}

// 备份列表 API
apiRouter.get('/backups', (req, res) => {
  res.json({ ret: 0, data: listBackupFiles() });
});

// 立即备份
apiRouter.post('/backups/create', (req, res) => {
  const filename = doAutoBackup(false);
  if (filename) res.json({ ret: 0, message: '已备份', filename });
  else res.status(500).json({ ret: -1, error: '备份失败' });
});

// 下载备份
apiRouter.get('/backups/:filename', (req, res) => {
  const safeName = req.params.filename.replace(/[^a-zA-Z0-9._-]/g, '');
  if (!safeName || !safeName.startsWith('lb-config-') || !safeName.endsWith('.json')) {
    return res.status(400).json({ ret: -1, error: '非法文件名' });
  }
  const full = path.join(BACKUP_DIR, safeName);
  if (!fs.existsSync(full)) return res.status(404).json({ ret: -1, error: '备份不存在' });
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${safeName}"`);
  res.send(fs.readFileSync(full, 'utf8'));
});

// 删除备份
apiRouter.delete('/backups/:filename', (req, res) => {
  const safeName = req.params.filename.replace(/[^a-zA-Z0-9._-]/g, '');
  if (!safeName || !safeName.startsWith('lb-config-') || !safeName.endsWith('.json')) {
    return res.status(400).json({ ret: -1, error: '非法文件名' });
  }
  try { fs.unlinkSync(path.join(BACKUP_DIR, safeName)); res.json({ ret: 0 }); }
  catch (e) { res.status(404).json({ ret: -1, error: '备份不存在' }); }
});

function checkMonitorTarget(server) {
  return new Promise((resolve) => {
    const req = http.request({
      hostname: server.host, port: server.port, path: '/healthz',
      method: 'GET', timeout: 8000,
    }, (res) => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => {
        try { resolve(res.statusCode === 200 && JSON.parse(body).ok === true ? 'online' : 'error'); }
        catch (_) { resolve('error'); }
      });
    });
    req.on('timeout', () => { req.destroy(); resolve('timeout'); });
    req.on('error', () => resolve('offline'));
    req.end();
  });
}

async function runMonitorCheck() {
  for (const server of MONITOR_SERVERS) {
    if (server.name === SELF_NAME) continue;
    const status = await checkMonitorTarget(server);
    const wasOffline = _monitorStatus[server.host];
    const isOffline = status !== 'online';
    if (isOffline && !wasOffline) {
      _monitorStatus[server.host] = true;
      const msg = `${server.name} (${server.host}:${server.port}) 离线！`;
      console.log(`  [MONITOR] ❌ ${msg}`);
      sendBark(`⚠️ ${server.name} 离线`, msg);
    } else if (!isOffline && wasOffline) {
      _monitorStatus[server.host] = false;
      const msg = `${server.name} (${server.host}:${server.port}) 已恢复`;
      console.log(`  [MONITOR] ✅ ${msg}`);
      sendBark(`✅ ${server.name} 恢复`, msg);
    }
  }
}

let monitorTimer = null;
function startMonitor() {
  if (monitorTimer) clearInterval(monitorTimer);
  MONITOR_SERVERS = loadMonitorServers();
  SELF_NAME = getSelfName();
  if (!CONFIG.bark_key) { console.log('  [MONITOR] Bark Key 未配置，跳过在线监控'); return; }
  runMonitorCheck();
  monitorTimer = setInterval(runMonitorCheck, CONFIG.monitor_interval || 30000);
  console.log(`  [MONITOR] 在线监控已启动，间隔 ${((CONFIG.monitor_interval || 30000) / 1000)}s`);
}

// ==================== 启动 ====================
loadConfig();
loadDebugRoute();
applyForwardTimeouts();
const generatedAdminPassword = ensureAdminPassword();
const newSecret = initAdminSecret();
initGroupsAndRules();
loadBackends();
applyNodeBootstrap();
if (CONFIG.persist_stats) loadQqStats();
loadSessions();  // 恢复活动会话
if (newSecret || generatedAdminPassword) saveConfig(); // 首次生成认证材料，持久化

function restartHealthCheck() {
  if (hcTimer) clearInterval(hcTimer);
  hcTimer = setInterval(healthCheck, CONFIG.hc_interval);
}
  restartHealthCheck();
setTimeout(healthCheck, 2000);
startFrpsServer();
startMonitor();
startAutoBackup();

rawServer.listen(CONFIG.port, () => {
  const port = CONFIG.port;
  console.log(`\n`);
  console.log(`  ╔══════════════════════════════════════════════╗`);
  console.log(`  ║      🔀  HTTP 负载均衡器 v2.0（内置 frps）   ║`);
  console.log(`  ╚══════════════════════════════════════════════╝`);
  console.log(`\n`);
  console.log(`  📡 HTTP/FRPS   : ${port}`);
  console.log(`  🌐 管理面板    : http://localhost:${port}/`);
  console.log(`  🔧 API 接口    : http://localhost:${port}/api/`);
  console.log(`  📊 实时推送    : ws://localhost:${port}/ws`);
  console.log(`\n`);
  console.log(`  🚇 隧道连接: 2种方式`);
  console.log(`    [1] WS Agent: node agent.js --server ws://... --target http://...`);
  console.log(`    [2] 标准frpc: frpc -c frpc.toml 连接 tcp://你的服务器:${port}`);
  console.log(`\n`);
  console.log(`  ⚙️  默认算法   : ${ALGORITHMS[currentAlgorithm].name}`);
  console.log(`  🗂️  后端分组   : ${Object.keys(groups).join(', ')}`);
  console.log(`  📋 路由规则   : ${rules.length} 条`);
  console.log(`  🖥️  后端节点   : ${backends.size} 个（可混合 HTTP直连 + 隧道Agent）`);
  console.log(`\n`);
  console.log(`  ── 分组路由 ──`);
  for (const [gName, g] of Object.entries(groups)) {
    const algo = ALGORITHMS[g.algorithm]?.name || g.algorithm;
    const backendCount = Array.from(backends.values()).filter(b => backendInGroup(b, gName)).length;
    console.log(`    📁 ${gName.padEnd(12)} ${algo.padEnd(10)} ${g.description || ''}`);
    console.log(`       后端 ${backendCount} 个`);
  }
  if (rules.length > 0) {
    console.log(`\n  ── 路由规则 ──`);
    for (const r of sortedRules) {
      console.log(`    ${r.path.padEnd(20)} → ${r.group.padEnd(12)} (优先级: ${r.priority})`);
    }
  }
  console.log(`\n`);
  console.log(`  ── 管理模式 ──`);
  console.log(`    🌐 HTTP 直连  : 通过管理面板 / API 添加`);
  console.log(`    🔌 隧道 Agent : node agent.js -s ws://localhost:${port}/agent -t http://localhost:3000 -n 标签`);
  console.log(`    📱 管理面板   : http://localhost:${port}/`);
  console.log(`\n`);
  console.log(`  ── 后台配置全在网页端操作 ──`);
  console.log(`\n`);
});
rawServer.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\n  ⚠️  端口 ${CONFIG.port} 被占用，等待 3s 重试...`);
    setTimeout(() => rawServer.listen(CONFIG.port), 3000);
    return;
  }
  console.error(`\n  ❌ 服务器启动失败: ${err.message}`);
  process.exit(1);
});

// 优雅关闭：收到 SIGTERM/SIGINT 时保存统计、释放端口再退出
process.on('SIGTERM', () => {
  if (CONFIG.persist_stats) saveQqStats();
  setTimeout(() => process.exit(0), 2000);
  if (rawServer) rawServer.close(() => process.exit(0));
});
process.on('SIGINT', () => {
  if (CONFIG.persist_stats) saveQqStats();
  setTimeout(() => process.exit(0), 2000);
  if (rawServer) rawServer.close(() => process.exit(0));
});
