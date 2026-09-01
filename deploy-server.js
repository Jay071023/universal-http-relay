'use strict';

/**
 * Cross-platform deployment receiver.
 *
 * Protocol: newline-delimited JSON over TCP. The receiver authenticates every
 * connection, stages every file, commits the complete batch atomically, and
 * only then performs the requested service restart. The same authenticated
 * channel exposes only fixed status/health/restart/reload controls; it never
 * executes arbitrary remote Shell commands.
 *
 * Linux/systemd:
 *   DEPLOY_TOKEN=... DEPLOY_SERVICE_MANAGER=systemd \
 *   DEPLOY_SERVICE_NAME=qq-load-balancer.service node deploy-server.js
 *
 * Standalone Windows/Linux:
 *   DEPLOY_TOKEN=... DEPLOY_SERVICE_MANAGER=pidfile node deploy-server.js
 */

const fs = require('fs');
const path = require('path');
const net = require('net');
const http = require('http');
const crypto = require('crypto');
const { spawn, execFile } = require('child_process');

const args = process.argv.slice(2);
function getArg(name) {
  const index = args.indexOf(name);
  return index >= 0 && index + 1 < args.length ? args[index + 1] : null;
}

const PORT = parsePort(getArg('--port') || process.env.DEPLOY_PORT || '7879', 7879);
const HOST = getArg('--host') || process.env.DEPLOY_BIND || '0.0.0.0';
const BASE_DIR = path.resolve(process.env.DEPLOY_BASE_DIR || __dirname);
// 生产环境必须由安装器或管理员显式生成并注入随机 Token。
// 不提供弱默认值，避免公开源码复制部署后暴露控制面。
const TOKEN = String(getArg('--token') || process.env.DEPLOY_TOKEN || '');
const ALLOW_ANONYMOUS = process.env.DEPLOY_ALLOW_ANONYMOUS === '1';
const MAX_FILE_BYTES = parseSize(process.env.DEPLOY_MAX_FILE_BYTES, 32 * 1024 * 1024);
const MAX_FRAME_BYTES = Math.max(1024 * 1024, parseSize(process.env.DEPLOY_MAX_FRAME_BYTES, Math.ceil(MAX_FILE_BYTES * 1.37) + 64 * 1024));
const MAX_BATCH_FILES = parseCount(process.env.DEPLOY_MAX_BATCH_FILES, 200);
const MAX_BATCH_BYTES = parseSize(process.env.DEPLOY_MAX_BATCH_BYTES, 128 * 1024 * 1024);
const MAX_CONNECTIONS = parseCount(process.env.DEPLOY_MAX_CONNECTIONS, 20);
const MAX_QUEUED_MESSAGES = parseCount(process.env.DEPLOY_MAX_QUEUED_MESSAGES, 100);
const IDLE_TIMEOUT_MS = parseCount(process.env.DEPLOY_IDLE_TIMEOUT_MS, 120000);
const RESTART_TIMEOUT_MS = parseCount(process.env.DEPLOY_RESTART_TIMEOUT_MS, 30000);
const HEALTH_TIMEOUT_MS = parseCount(process.env.DEPLOY_HEALTH_TIMEOUT_MS, 15000);
const BACKUP_LIMIT = parseCount(process.env.DEPLOY_BACKUP_LIMIT, 10);
const STAGING_DIR = path.join(BASE_DIR, '.deploy-staging');
const BACKUP_DIR = path.join(BASE_DIR, '.deploy-backups');
const PID_FILE = path.resolve(process.env.LB_PID_FILE || path.join(BASE_DIR, 'lb-server.pid'));
const LB_PORT = parsePort(process.env.LB_PORT || '8888', 8888);
const RESTART_MODE = String(process.env.DEPLOY_SERVICE_MANAGER || (process.platform === 'linux' ? 'systemd' : 'pidfile')).toLowerCase();
const SERVICE_NAME = process.env.DEPLOY_SERVICE_NAME || 'qq-load-balancer.service';
const PROCESS_NAME = process.env.DEPLOY_PROCESS_NAME || 'lb-server';

function parsePort(value, fallback) {
  const port = Number.parseInt(value, 10);
  return Number.isInteger(port) && port > 0 && port < 65536 ? port : fallback;
}

function parseCount(value, fallback) {
  const count = Number.parseInt(value, 10);
  return Number.isInteger(count) && count > 0 ? count : fallback;
}

function parseSize(value, fallback) {
  if (!value) return fallback;
  const match = String(value).trim().match(/^(\d+)(kb|mb|gb)?$/i);
  if (!match) return fallback;
  const multiplier = { kb: 1024, mb: 1024 * 1024, gb: 1024 * 1024 * 1024 }[(match[2] || '').toLowerCase()] || 1;
  return Math.max(1024, Number(match[1]) * multiplier);
}

function log(level, message) {
  console.log(`[${new Date().toISOString()}] [${level}] ${message}`);
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function ensureDirectory(directory) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o750 });
}

function relativeTarget(relPath) {
  if (typeof relPath !== 'string' || relPath.length === 0 || relPath.length > 240) {
    throw new Error('非法文件路径');
  }
  if (relPath.includes('\0') || relPath.includes('\\') || /^[a-zA-Z]:/.test(relPath) || relPath.startsWith('/')) {
    throw new Error('文件路径必须是安全的相对 POSIX 路径');
  }
  const normalized = path.posix.normalize(relPath);
  if (normalized === '.' || normalized === '..' || normalized.startsWith('../') || normalized.includes('/../')) {
    throw new Error('拒绝路径穿越');
  }
  const fullPath = path.resolve(BASE_DIR, ...normalized.split('/'));
  const relative = path.relative(BASE_DIR, fullPath);
  if (!relative || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error('拒绝路径穿越');
  }

  // Do not follow an existing symlink at any path component. This closes the
  // common "safe-looking path points outside the root" upload bypass.
  let current = BASE_DIR;
  for (const part of relative.split(path.sep)) {
    current = path.join(current, part);
    if (fs.existsSync(current) && fs.lstatSync(current).isSymbolicLink()) {
      throw new Error('拒绝写入符号链接路径');
    }
  }
  return { normalized, fullPath };
}

function stageTarget(stageRoot, relPath) {
  const { normalized } = relativeTarget(relPath);
  const fullPath = path.resolve(stageRoot, ...normalized.split('/'));
  const relative = path.relative(stageRoot, fullPath);
  if (!relative || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error('暂存路径越界');
  }
  return { normalized, fullPath };
}

function decodeContent(content) {
  if (typeof content !== 'string') throw new Error('文件内容必须是 base64 字符串');
  const maxBase64Length = Math.ceil(MAX_FILE_BYTES / 3) * 4 + 4;
  if (content.length > maxBase64Length || content.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(content)) {
    throw new Error('非法或过大的 base64 文件内容');
  }
  const buffer = Buffer.from(content, 'base64');
  if (buffer.length > MAX_FILE_BYTES) throw new Error(`文件超过大小限制（${MAX_FILE_BYTES} bytes）`);
  return buffer;
}

function cleanupDirectory(directory) {
  try { fs.rmSync(directory, { recursive: true, force: true }); } catch (error) { log('WARN', `清理目录失败 ${directory}: ${error.message}`); }
}

function backupExisting(targetPath, backupPath) {
  if (!fs.existsSync(targetPath)) return false;
  const stat = fs.lstatSync(targetPath);
  if (stat.isSymbolicLink() || !stat.isFile()) throw new Error(`目标不是普通文件: ${targetPath}`);
  ensureDirectory(path.dirname(backupPath));
  fs.copyFileSync(targetPath, backupPath);
  return true;
}

function removeFileIfPresent(filePath) {
  try {
    if (fs.existsSync(filePath)) {
      const stat = fs.lstatSync(filePath);
      if (stat.isDirectory() && !stat.isSymbolicLink()) fs.rmSync(filePath, { recursive: true, force: true });
      else fs.rmSync(filePath, { force: true });
    }
  } catch (_) {}
}

function commitBatch(batch) {
  const backupRoot = path.join(BACKUP_DIR, batch.id);
  const committed = [];
  ensureDirectory(backupRoot);
  try {
    for (const file of batch.files.values()) {
      const target = relativeTarget(file.path).fullPath;
      const backup = path.join(backupRoot, ...file.path.split('/'));
      const hadOriginal = backupExisting(target, backup);
      ensureDirectory(path.dirname(target));
      if (!fs.existsSync(file.stagePath)) throw new Error(`暂存文件不存在: ${file.path}`);
      // rename within the same filesystem prevents readers from observing a
      // partially-written source file. Windows needs the existing target removed first.
      if (process.platform === 'win32' && fs.existsSync(target)) removeFileIfPresent(target);
      fs.renameSync(file.stagePath, target);
      committed.push({ path: file.path, target, backup, hadOriginal });
    }
    cleanupDirectory(batch.stageRoot);
    pruneBackups();
    return { id: batch.id, files: [...batch.files.keys()] };
  } catch (error) {
    log('ERROR', `批量提交失败，开始回滚: ${error.message}`);
    for (const item of committed.reverse()) {
      removeFileIfPresent(item.target);
      if (item.hadOriginal && fs.existsSync(item.backup)) {
        ensureDirectory(path.dirname(item.target));
        fs.copyFileSync(item.backup, item.target);
      }
    }
    cleanupDirectory(batch.stageRoot);
    cleanupDirectory(backupRoot);
    throw error;
  }
}

function pruneBackups() {
  ensureDirectory(BACKUP_DIR);
  const entries = fs.readdirSync(BACKUP_DIR, { withFileTypes: true })
    .filter(entry => entry.isDirectory())
    .map(entry => {
      const fullPath = path.join(BACKUP_DIR, entry.name);
      return { fullPath, mtime: fs.statSync(fullPath).mtimeMs };
    })
    .sort((a, b) => b.mtime - a.mtime);
  for (const entry of entries.slice(BACKUP_LIMIT)) cleanupDirectory(entry.fullPath);
}

function runCommand(command, commandArgs, timeoutMs) {
  return new Promise((resolve, reject) => {
    const child = execFile(command, commandArgs, { cwd: BASE_DIR, timeout: timeoutMs, windowsHide: true }, (error, stdout, stderr) => {
      if (error) {
        const detail = String(stderr || stdout || error.message).trim().slice(-1000);
        reject(new Error(detail || error.message));
        return;
      }
      resolve(String(stdout || '').trim());
    });
    child.once('error', reject);
  });
}

function processExists(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; } catch (error) { return error.code === 'EPERM'; }
}

function readPid() {
  try {
    const pid = Number.parseInt(fs.readFileSync(PID_FILE, 'utf8').trim(), 10);
    return processExists(pid) ? pid : null;
  } catch (_) { return null; }
}

function waitForProcessExit(pid, timeoutMs) {
  return new Promise((resolve) => {
    const deadline = Date.now() + timeoutMs;
    const check = () => {
      if (!processExists(pid) || Date.now() >= deadline) return resolve(!processExists(pid));
      setTimeout(check, 100);
    };
    check();
  });
}

function checkHealth() {
  return new Promise((resolve) => {
    const request = http.get({ hostname: '127.0.0.1', port: LB_PORT, path: '/healthz', timeout: HEALTH_TIMEOUT_MS }, (response) => {
      response.resume();
      response.once('end', () => resolve(response.statusCode === 200));
    });
    request.once('timeout', () => { request.destroy(); resolve(false); });
    request.once('error', () => resolve(false));
  });
}

async function waitForHealth() {
  const deadline = Date.now() + HEALTH_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (await checkHealth()) return true;
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  return false;
}

async function restartWithSystemd() {
  await runCommand('systemctl', ['restart', SERVICE_NAME], RESTART_TIMEOUT_MS);
  if (!(await waitForHealth())) throw new Error(`服务已重启但健康检查未通过: ${SERVICE_NAME}`);
  return { manager: 'systemd', service: SERVICE_NAME };
}

async function restartWithPm2() {
  await runCommand('pm2', ['restart', PROCESS_NAME], RESTART_TIMEOUT_MS);
  if (!(await waitForHealth())) throw new Error(`PM2 已执行重启但健康检查未通过: ${PROCESS_NAME}`);
  return { manager: 'pm2', process: PROCESS_NAME };
}

async function restartWithPidfile() {
  const oldPid = readPid();
  if (oldPid && oldPid !== process.pid) {
    try { process.kill(oldPid, 'SIGTERM'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
    if (!(await waitForProcessExit(oldPid, 10000))) throw new Error(`旧服务未在超时内退出（PID ${oldPid}）`);
  }
  const lbPath = path.join(BASE_DIR, 'lb-server.js');
  if (!fs.existsSync(lbPath)) throw new Error('lb-server.js 不存在');
  const child = spawn(process.execPath, [lbPath], {
    cwd: BASE_DIR,
    detached: true,
    stdio: 'ignore',
    windowsHide: true,
    env: { ...process.env, LB_PORT: String(LB_PORT), LB_PID_FILE: PID_FILE }
  });
  child.unref();
  if (!(await waitForHealth())) throw new Error(`新服务健康检查未通过（PID ${child.pid}）`);
  return { manager: 'pidfile', pid: child.pid };
}

async function restartLbServer() {
  if (RESTART_MODE === 'none') return { manager: 'none' };
  if (RESTART_MODE === 'systemd') return restartWithSystemd();
  if (RESTART_MODE === 'pm2') return restartWithPm2();
  if (RESTART_MODE === 'pidfile') return restartWithPidfile();
  throw new Error(`未知部署重启模式: ${RESTART_MODE}`);
}

function createBatch() {
  const id = `${Date.now().toString(36)}-${crypto.randomBytes(6).toString('hex')}`;
  const stageRoot = path.join(STAGING_DIR, id);
  ensureDirectory(stageRoot);
  return { id, stageRoot, files: new Map(), bytes: 0 };
}

async function handleConnection(socket) {
  const clientAddr = `${socket.remoteAddress || 'unknown'}:${socket.remotePort || 0}`;
  let authenticated = ALLOW_ANONYMOUS;
  let buffer = Buffer.alloc(0);
  let processing = false;
  let closed = false;
  let batch = null;
  const queue = [];

  function sendJson(payload) {
    if (!closed && !socket.destroyed && socket.writable) {
      try { socket.write(`${JSON.stringify(payload)}\n`); } catch (_) {}
    }
  }

  function closeConnection() {
    if (closed) return;
    closed = true;
    if (batch) cleanupDirectory(batch.stageRoot);
    batch = null;
    try { socket.destroy(); } catch (_) {}
  }

  async function handleMessage(message) {
    if (!message || typeof message !== 'object' || Array.isArray(message)) throw new Error('消息必须是 JSON 对象');
    if (!authenticated) {
      if (message.type !== 'auth' || !safeEqual(message.token || '', TOKEN)) {
        sendJson({ type: 'error', message: '认证失败' });
        closeConnection();
        return;
      }
      authenticated = true;
      sendJson({ type: 'auth_ok', protocol: 2 });
      return;
    }

    switch (message.type) {
      case 'file': {
        if (!batch) batch = createBatch();
        if (batch.files.size >= MAX_BATCH_FILES) throw new Error(`批量文件数超过限制（${MAX_BATCH_FILES}）`);
        const target = relativeTarget(message.path);
        if (batch.files.has(target.normalized)) throw new Error(`批量中重复文件: ${target.normalized}`);
        const content = decodeContent(message.content);
        if (batch.bytes + content.length > MAX_BATCH_BYTES) throw new Error(`批量总大小超过限制（${MAX_BATCH_BYTES} bytes）`);
        const staged = stageTarget(batch.stageRoot, target.normalized);
        ensureDirectory(path.dirname(staged.fullPath));
        fs.writeFileSync(staged.fullPath, content, { mode: 0o640 });
        batch.files.set(target.normalized, { path: target.normalized, stagePath: staged.fullPath, size: content.length });
        batch.bytes += content.length;
        log('INFO', `${clientAddr} 暂存 ${target.normalized} (${content.length} bytes)`);
        sendJson({ type: 'file_ok', path: target.normalized, size: content.length });
        break;
      }
      case 'batch_done': {
        if (!batch || batch.files.size === 0) throw new Error('没有可提交的文件');
        const committed = commitBatch(batch);
        batch = null;
        sendJson({ type: 'done', files: committed.files });
        log('INFO', `${clientAddr} 批量提交完成，共 ${committed.files.length} 个文件`);
        break;
      }
      case 'restart': {
        if (message.service !== 'lb-server') throw new Error(`未知服务: ${message.service || ''}`);
        sendJson({ type: 'restart_ack', message: '正在重启 lb-server...' });
        const result = await restartLbServer();
        sendJson({ type: 'restart_ok', ...result });
        log('INFO', `${clientAddr} 热更新完成: ${JSON.stringify(result)}`);
        break;
      }
      case 'command': {
        const command = String(message.command || '').toLowerCase();
        if (!['status', 'health', 'restart', 'reload'].includes(command)) {
          throw new Error(`不支持的控制命令: ${command || '(empty)'}`);
        }
        if (command === 'status') {
          sendJson({ type: 'command_ok', command, data: {
            pid: process.pid,
            deployPort: PORT,
            baseDir: BASE_DIR,
            restartMode: RESTART_MODE,
            service: SERVICE_NAME,
            process: PROCESS_NAME,
            uptime: Math.round(process.uptime()),
          }});
          break;
        }
        if (command === 'health') {
          sendJson({ type: 'command_ok', command, data: { healthy: await checkHealth(), lbPort: LB_PORT } });
          break;
        }
        sendJson({ type: 'command_ack', command, message: '正在执行受控服务重启...' });
        const result = await restartLbServer();
        sendJson({ type: 'command_ok', command, data: { ...result, operation: 'restart' } });
        log('INFO', `${clientAddr} 控制命令 ${command}: ${JSON.stringify(result)}`);
        break;
      }
      case 'ping':
        sendJson({ type: 'pong' });
        break;
      default:
        throw new Error(`未知消息类型: ${message.type || ''}`);
    }
  }

  async function drainQueue() {
    if (processing || closed) return;
    processing = true;
    while (queue.length > 0 && !closed) {
      const message = queue.shift();
      try { await handleMessage(message); }
      catch (error) {
        log('WARN', `${clientAddr} 请求失败: ${error.message}`);
        sendJson({ type: 'error', message: error.message });
        if (message.type === 'file' || message.type === 'batch_done') closeConnection();
      }
    }
    processing = false;
  }

  socket.setNoDelay(true);
  socket.setTimeout(IDLE_TIMEOUT_MS, () => {
    log('WARN', `${clientAddr} 空闲超时`);
    closeConnection();
  });
  socket.on('data', (chunk) => {
    if (closed) return;
    buffer = Buffer.concat([buffer, chunk]);
    if (buffer.length > MAX_FRAME_BYTES && buffer.indexOf(0x0a) < 0) {
      sendJson({ type: 'error', message: '请求帧过大' });
      closeConnection();
      return;
    }
    let newline;
    while ((newline = buffer.indexOf(0x0a)) >= 0) {
      if (newline > MAX_FRAME_BYTES) {
        sendJson({ type: 'error', message: '请求帧过大' });
        closeConnection();
        return;
      }
      const line = buffer.subarray(0, newline).toString('utf8').trim();
      buffer = buffer.subarray(newline + 1);
      if (!line) continue;
       try {
         if (queue.length >= MAX_QUEUED_MESSAGES) {
           sendJson({ type: 'error', message: '请求队列已满' });
           closeConnection();
           return;
         }
         queue.push(JSON.parse(line));
       }
      catch (_) { sendJson({ type: 'error', message: 'Invalid JSON' }); closeConnection(); return; }
    }
    void drainQueue();
  });
  socket.on('close', () => { closed = true; if (batch) cleanupDirectory(batch.stageRoot); batch = null; log('CONN', `连接断开: ${clientAddr}`); });
  socket.on('error', (error) => { log('WARN', `Socket 错误 (${clientAddr}): ${error.message}`); });

  sendJson({ type: 'hello', protocol: 2, authRequired: !ALLOW_ANONYMOUS });
  log('CONN', `新连接: ${clientAddr}`);
}

if (!ALLOW_ANONYMOUS && !TOKEN) {
  console.error('DEPLOY_TOKEN 未配置，拒绝以不安全模式启动部署服务。');
  process.exit(1);
}

ensureDirectory(STAGING_DIR);
ensureDirectory(BACKUP_DIR);
pruneBackups();

let activeConnections = 0;
const server = net.createServer((socket) => {
  if (activeConnections >= MAX_CONNECTIONS) {
    socket.end(JSON.stringify({ type: 'error', message: '部署服务当前连接数已满' }) + '\n');
    return;
  }
  activeConnections++;
  socket.once('close', () => { activeConnections = Math.max(0, activeConnections - 1); });
  void handleConnection(socket);
});
server.on('error', (error) => {
  log('ERROR', `部署服务启动失败: ${error.message}`);
  process.exit(1);
});
server.listen(PORT, HOST, () => {
  log('INFO', `部署服务已启动 ${HOST}:${PORT}`);
  log('INFO', `工作目录: ${BASE_DIR}`);
  log('INFO', `认证: ${ALLOW_ANONYMOUS ? '显式匿名兼容模式' : 'Token（必需）'}`);
  log('INFO', `热更新: ${RESTART_MODE}${RESTART_MODE === 'systemd' ? ` (${SERVICE_NAME})` : ''}`);
});

process.on('SIGTERM', () => server.close(() => process.exit(0)));
process.on('SIGINT', () => server.close(() => process.exit(0)));
