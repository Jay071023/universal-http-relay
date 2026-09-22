'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { execFile, spawn } = require('node:child_process');
const { promisify } = require('node:util');
const { test, after } = require('node:test');
const WebSocket = require('ws');

const execFileAsync = promisify(execFile);
const ROOT = path.resolve(__dirname, '..');
const deployServerPath = path.join(ROOT, 'deploy-server.js');
const controlPath = path.join(ROOT, 'control.js');
const realServerPath = path.join(ROOT, 'lb-server-real.js');
const children = new Set();

after(async () => {
  for (const child of children) {
    if (!child.killed) child.kill('SIGTERM');
  }
  await Promise.all([...children].map(child => new Promise(resolve => {
    if (child.exitCode !== null) return resolve();
    child.once('exit', resolve);
    setTimeout(() => { try { child.kill('SIGKILL'); } catch (_) {} resolve(); }, 5000);
  })));
});

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'qq-lb-test-'));
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
  });
}

async function waitUntil(check, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await check()) return;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error('等待测试进程超时');
}

async function startDeploy(baseDir, token, extra = {}) {
  const port = await freePort();
  const childEnv = { ...process.env, DEPLOY_BASE_DIR: baseDir, ...extra };
  if (token === null) delete childEnv.DEPLOY_TOKEN;
  else childEnv.DEPLOY_TOKEN = token;
  const child = spawn(process.execPath, [deployServerPath, '--host', '127.0.0.1', '--port', String(port)], {
    cwd: ROOT,
    env: { ...childEnv, DEPLOY_SERVICE_MANAGER: 'none' },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  child._testOutput = '';
  child.stdout.on('data', chunk => { child._testOutput += chunk.toString(); });
  child.stderr.on('data', chunk => { child._testOutput += chunk.toString(); });
  children.add(child);
  await waitUntil(async () => {
    try {
      const socket = net.createConnection({ host: '127.0.0.1', port });
      await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
      socket.destroy();
      return true;
    } catch (_) { return false; }
  });
  return { child, port };
}

function protocolClient(port) {
  const socket = net.createConnection({ host: '127.0.0.1', port });
  let buffer = Buffer.alloc(0);
  const queue = [];
  const waiters = [];
  let socketError = null;
  socket.on('data', chunk => {
    buffer = Buffer.concat([buffer, chunk]);
    let index;
    while ((index = buffer.indexOf(0x0a)) >= 0) {
      const line = buffer.subarray(0, index).toString('utf8').trim();
      buffer = buffer.subarray(index + 1);
      if (!line) continue;
      const message = JSON.parse(line);
      const waiter = waiters.shift();
      if (waiter) waiter.resolve(message);
      else queue.push(message);
    }
  });
  socket.on('error', error => {
    socketError = error;
    while (waiters.length) waiters.shift().reject(error);
  });
  return {
    async ready() {
      await new Promise((resolve, reject) => {
        if (socket.readyState === 'open') return resolve();
        socket.once('connect', resolve);
        socket.once('error', reject);
      });
    },
    send(message) { socket.write(`${JSON.stringify(message)}\n`); },
    next(timeoutMs = 5000) {
      if (queue.length) return Promise.resolve(queue.shift());
      if (socketError) return Promise.reject(socketError);
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('协议消息超时')), timeoutMs);
        waiters.push({
          resolve: value => { clearTimeout(timer); resolve(value); },
          reject: error => { clearTimeout(timer); reject(error); }
        });
      });
    },
    close() { socket.destroy(); }
  };
}

async function deployOne(port, token, relativePath, content) {
  const client = protocolClient(port);
  await client.ready();
  assert.deepEqual(await client.next(), { type: 'hello', protocol: 2, authRequired: true });
  client.send({ type: 'auth', token });
  assert.equal((await client.next()).type, 'auth_ok');
  client.send({ type: 'file', path: relativePath, content: Buffer.from(content).toString('base64') });
  const fileOk = await client.next();
  assert.equal(fileOk.type, 'file_ok');
  client.send({ type: 'batch_done', files: [{ path: relativePath }] });
  const done = await client.next();
  assert.equal(done.type, 'done');
  client.close();
}

test('部署协议拒绝错误 token、路径穿越和非法 base64', async () => {
  const dir = tempDir();
  const { port } = await startDeploy(dir, 'correct-token');

  const wrong = protocolClient(port);
  await wrong.ready();
  assert.equal((await wrong.next()).authRequired, true);
  wrong.send({ type: 'auth', token: 'wrong-token' });
  assert.equal((await wrong.next()).type, 'error');
  wrong.close();

  const traversal = protocolClient(port);
  await traversal.ready();
  await traversal.next();
  traversal.send({ type: 'auth', token: 'correct-token' });
  await traversal.next();
  traversal.send({ type: 'file', path: '../outside.txt', content: Buffer.from('blocked').toString('base64') });
  assert.equal((await traversal.next()).type, 'error');
  traversal.close();
  assert.equal(fs.existsSync(path.join(path.dirname(dir), 'outside.txt')), false);

  const invalid = protocolClient(port);
  await invalid.ready();
  await invalid.next();
  invalid.send({ type: 'auth', token: 'correct-token' });
  await invalid.next();
  invalid.send({ type: 'file', path: 'invalid.txt', content: 'not-base64!' });
  assert.equal((await invalid.next()).type, 'error');
  invalid.close();
});

test('未配置部署 token 时拒绝启动部署服务', async () => {
  const dir = tempDir();
  const port = await freePort();
  const child = spawn(process.execPath, [deployServerPath, '--host', '127.0.0.1', '--port', String(port)], {
    cwd: ROOT,
    env: { ...process.env, DEPLOY_BASE_DIR: dir, DEPLOY_SERVICE_MANAGER: 'none', DEPLOY_TOKEN: '' },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let output = '';
  child.stdout.on('data', chunk => { output += chunk.toString(); });
  child.stderr.on('data', chunk => { output += chunk.toString(); });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('部署服务未按预期退出')), 5000);
    child.once('exit', code => { clearTimeout(timer); assert.notEqual(code, 0); resolve(); });
    child.once('error', error => { clearTimeout(timer); reject(error); });
  });
  assert.match(output, /DEPLOY_TOKEN 未配置/);
});

test('初始化脚本为管理员密码和 Agent Token 生成随机值', async () => {
  const dir = tempDir();
  const configPath = path.join(dir, 'config.json');
  const result = await execFileAsync(process.execPath, [path.join(ROOT, 'scripts', 'init-config.js'), configPath], {
    cwd: ROOT, timeout: 10000, maxBuffer: 1024 * 1024
  });
  const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  assert.match(config.admin_password, /^[A-Za-z0-9_-]{20,}$/);
  assert.match(config.agent_token, /^[a-f0-9]{48}$/);
  assert.match(result.stdout, /ADMIN_PASSWORD=/);
  assert.match(result.stdout, /AGENT_TOKEN=/);
});

test('部署批次提交失败会回滚已提交文件并保留成功批次备份', async () => {
  const dir = tempDir();
  fs.writeFileSync(path.join(dir, 'existing.txt'), 'old');
  fs.mkdirSync(path.join(dir, 'blocked'));
  const { port } = await startDeploy(dir, 'batch-token');

  const client = protocolClient(port);
  await client.ready();
  await client.next();
  client.send({ type: 'auth', token: 'batch-token' });
  await client.next();
  client.send({ type: 'file', path: 'existing.txt', content: Buffer.from('new').toString('base64') });
  await client.next();
  client.send({ type: 'file', path: 'blocked', content: Buffer.from('must-fail').toString('base64') });
  await client.next();
  client.send({ type: 'batch_done', files: [] });
  await new Promise(resolve => setTimeout(resolve, 250));
  client.close();
  assert.equal(fs.readFileSync(path.join(dir, 'existing.txt'), 'utf8'), 'old');

  await deployOne(port, 'batch-token', 'existing.txt', 'final');
  assert.equal(fs.readFileSync(path.join(dir, 'existing.txt'), 'utf8'), 'final');
  const backupRoot = path.join(dir, '.deploy-backups');
  assert.equal(fs.readdirSync(backupRoot, { withFileTypes: true }).some(entry => entry.isDirectory()), true);
});

test('帧大小限制阻止无换行大包', async () => {
  const dir = tempDir();
  const { child, port } = await startDeploy(dir, 'frame-token', { DEPLOY_MAX_FRAME_BYTES: '1mb' });
  const socket = net.createConnection({ host: '127.0.0.1', port });
  await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
  socket.write(Buffer.concat([Buffer.alloc(1024 * 1024 + 1024, 0x41), Buffer.from('\n')]));
  await new Promise(resolve => setTimeout(resolve, 500));
  assert.match(child._testOutput, /连接断开/);
  socket.destroy();
});

test('upload.js --no-restart 可向 Linux 接收端完成热更新批次', async () => {
  const dir = tempDir();
  const { port } = await startDeploy(dir, 'upload-token');
  const result = await execFileAsync(process.execPath, [
    path.join(ROOT, 'upload.js'), '--host', '127.0.0.1', '--port', String(port),
    '--token', 'upload-token', '--no-restart', 'lb-server-real.js'
  ], { cwd: ROOT, timeout: 15000, maxBuffer: 2 * 1024 * 1024 });
  assert.match(result.stdout, /成功/);
  assert.equal(fs.existsSync(path.join(dir, 'lb-server-real.js')), true);
});

test('control.js 可用自定义端口查询状态并拒绝任意 Shell', async () => {
  const dir = tempDir();
  const { port } = await startDeploy(dir, 'control-token');
  const common = ['--host', '127.0.0.1', '--port', String(port), '--token', 'control-token'];
  const status = await execFileAsync(process.execPath, [controlPath, ...common, 'status'], { cwd: ROOT, timeout: 15000 });
  assert.match(status.stdout, /status 成功/);
  assert.match(status.stdout, new RegExp(`"deployPort": ${port}`));
  await assert.rejects(
    execFileAsync(process.execPath, [controlPath, ...common, 'shell'], { cwd: ROOT, timeout: 15000 }),
    error => /命令必须是 status、health、restart 或 reload/.test(`${error.message}\n${error.stderr || ''}`)
  );
});

function request(port, requestPath, options = {}, body = '') {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, path: requestPath, method: options.method || 'GET', headers: options.headers || {}, timeout: 15000 }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.once('timeout', () => req.destroy(new Error('HTTP 请求超时')));
    req.once('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

test('管理面板探针公开但管理 API、配置和大请求受到保护', async () => {
  const dir = tempDir();
  const port = await freePort();
  const configPath = path.join(dir, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify({
    port,
    admin_password: 'test-password-123',
    agent_token: 'agent-secret',
    bark_key: 'private-bark-key',
    groups: { default: { algorithm: 'round-robin', description: '' } },
    rules: [],
    _backends: []
  }));
  const child = spawn(process.execPath, [realServerPath], {
    cwd: ROOT,
    env: { ...process.env, LB_PORT: String(port), LB_CONFIG_PATH: configPath, LB_BARK_KEY: '' },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  children.add(child);
  await waitUntil(async () => {
    try { return (await request(port, '/healthz')).status === 200; } catch (_) { return false; }
  });

  const health = await request(port, '/healthz');
  assert.equal(health.status, 200);
  assert.equal(JSON.parse(health.body).ok, true);
  assert.equal((await request(port, '/api/overview')).status, 401);

  const loginBody = JSON.stringify({ password: 'test-password-123' });
  const login = await request(port, '/api/login', {
    method: 'POST', headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(loginBody) }
  }, loginBody);
  assert.equal(login.status, 200);
  const sessionToken = JSON.parse(login.body).token;
  const configResponse = await request(port, '/api/config', { headers: { authorization: `Bearer ${sessionToken}` } });
  const safeConfig = JSON.parse(configResponse.body).data;
  assert.equal(safeConfig.agent_token, 'agent-secret');
  assert.equal(Object.hasOwn(safeConfig, 'admin_password'), false);
  assert.equal(Object.hasOwn(safeConfig, 'bark_key'), false);
  assert.equal(Object.hasOwn(safeConfig, 'admin_secret'), false);
  assert.equal(Object.hasOwn(safeConfig, '_sessions'), false);

  const invalidUpdate = await request(port, '/api/config', {
    method: 'PUT', headers: { authorization: `Bearer ${sessionToken}`, 'content-type': 'application/json' }
  }, JSON.stringify({ hc_interval: 12000, hc_timeout: 1 }));
  assert.equal(invalidUpdate.status, 400);
  const unchanged = JSON.parse((await request(port, '/api/config', { headers: { authorization: `Bearer ${sessionToken}` } })).body).data;
  assert.equal(unchanged.hc_interval, safeConfig.hc_interval, 'invalid batch must not partially apply');

  const largeBody = Buffer.alloc(10 * 1024 * 1024 + 1, 0x61);
  const large = await request(port, '/api/login', {
    method: 'POST', headers: { 'content-type': 'application/json', 'content-length': largeBody.length }
  }, largeBody);
  assert.equal(large.status, 413);
  child.kill('SIGTERM');
});

test('同一后端可加入 9290 和 9350 多个分组并保持旧 group 字段兼容', async () => {
  const upstream = http.createServer((req, res) => res.end(`shared:${req.url}`));
  await new Promise((resolve, reject) => { upstream.once('error', reject); upstream.listen(0, '127.0.0.1', resolve); });
  const dir = tempDir();
  const port = await freePort();
  const configPath = path.join(dir, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify({
    port, admin_password: 'test-password-123',
    groups: {
      default: { algorithm: 'round-robin', description: '' },
      '9290': { algorithm: 'round-robin', description: '' },
      '9350': { algorithm: 'round-robin', description: '' }
    },
    rules: [
      { id: 1, path: '/v9290', group: '9290', priority: 10, matchType: 'prefix' },
      { id: 2, path: '/v9350', group: '9350', priority: 10, matchType: 'prefix' }
    ],
    _backends: [{ id: 'shared-api', type: 'http', url: `http://127.0.0.1:${upstream.address().port}`, group: '9290', groups: ['9290', '9350'], weight: 3, disable_health_check: true }]
  }));
  const child = spawn(process.execPath, [realServerPath], {
    cwd: ROOT, env: { ...process.env, LB_PORT: String(port), LB_CONFIG_PATH: configPath }, stdio: ['ignore', 'pipe', 'pipe']
  });
  children.add(child);
  try {
    await waitUntil(async () => { try { return (await request(port, '/healthz')).status === 200; } catch (_) { return false; } });
    assert.equal((await request(port, '/v9290')).body, 'shared:/v9290');
    assert.equal((await request(port, '/v9350')).body, 'shared:/v9350');

    const loginBody = JSON.stringify({ password: 'test-password-123' });
    const login = await request(port, '/api/login', { method: 'POST', headers: { 'content-type': 'application/json' } }, loginBody);
    const token = JSON.parse(login.body).token;
    const headers = { authorization: `Bearer ${token}`, 'content-type': 'application/json' };
    const invalid = await request(port, '/api/backends/shared-api', { method: 'PUT', headers }, JSON.stringify({ weight: 99, groups: ['9290', 'missing'] }));
    assert.equal(invalid.status, 400);
    let backend = JSON.parse((await request(port, '/api/backends', { headers })).body).data.find(item => item.id === 'shared-api');
    assert.equal(backend.weight, 3, 'invalid group update must not partially change other fields');
    assert.deepEqual(backend.groups, ['9290', '9350']);
    assert.equal(backend.group, '9290');

    const update = await request(port, '/api/backends/shared-api', { method: 'PUT', headers }, JSON.stringify({ groups: ['9350', '9290'] }));
    assert.equal(update.status, 200);
    backend = JSON.parse((await request(port, '/api/backends', { headers })).body).data.find(item => item.id === 'shared-api');
    assert.deepEqual(backend.groups, ['9350', '9290']);
    assert.equal(backend.group, '9350');
    const persisted = JSON.parse(fs.readFileSync(configPath, 'utf8'))._backends.find(item => item.id === 'shared-api');
    assert.deepEqual(persisted.groups, ['9350', '9290']);
  } finally {
    child.kill('SIGTERM');
    await new Promise(resolve => upstream.close(resolve));
  }
});

test('HTTP 缓冲响应可正常 pipe，且完成后推送真实耗时', async () => {
  const upstream = http.createServer((req, res) => {
    setTimeout(() => res.writeHead(200, { 'content-type': 'text/plain' }).end('buffered-ok'), 20);
  });
  await new Promise((resolve, reject) => { upstream.once('error', reject); upstream.listen(0, '127.0.0.1', resolve); });
  const upstreamPort = upstream.address().port;
  const dir = tempDir();
  const lbPort = await freePort();
  const configPath = path.join(dir, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify({
    port: lbPort,
    admin_password: 'test-password-123',
    request_timeout: 60000,
    retry_400_enabled: true,
    groups: { default: { algorithm: 'round-robin', description: '' } },
    rules: [], _backends: [{ id: 'buffered-http', type: 'http', url: 'http://127.0.0.1:' + upstreamPort, group: 'default', weight: 1 }]
  }));
  const child = spawn(process.execPath, [realServerPath], {
    cwd: ROOT,
    env: { ...process.env, LB_PORT: String(lbPort), LB_CONFIG_PATH: configPath },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  child._testOutput = '';
  child.stdout.on('data', chunk => { child._testOutput += chunk.toString(); });
  child.stderr.on('data', chunk => { child._testOutput += chunk.toString(); });
  children.add(child);
  const sockets = new Set();
  try {
    await waitUntil(async () => {
      try { return (await request(lbPort, '/healthz')).status === 200; } catch (_) { return false; }
    });
    const loginBody = JSON.stringify({ password: 'test-password-123' });
    const login = await request(lbPort, '/api/login', {
      method: 'POST', headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(loginBody) }
    }, loginBody);
    assert.equal(login.status, 200);
    const token = JSON.parse(login.body).token;
    const ws = new WebSocket('ws://127.0.0.1:' + lbPort + '/ws?token=' + encodeURIComponent(token));
    sockets.add(ws);
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('管理 WebSocket 连接超时')), 5000);
      ws.once('open', () => { clearTimeout(timer); resolve(); });
      ws.once('error', error => { clearTimeout(timer); reject(error); });
    });
    const logEvent = new Promise((resolve, reject) => {
      let logId = null;
      const timer = setTimeout(() => reject(new Error('未收到 HTTP 日志耗时更新')), 5000);
      ws.on('message', data => {
        let message;
        try { message = JSON.parse(data.toString()); } catch (_) { return; }
        if (message.type === 'new_log' && message.log?.path === '/buffered-response') logId = message.log.id;
        if (message.type === 'update_log' && message.log?.id === logId && message.log.responseTime > 0) {
          clearTimeout(timer);
          resolve(message.log);
        }
      });
    });
    const response = await request(lbPort, '/buffered-response');
    assert.equal(response.status, 200);
    assert.equal(response.body, 'buffered-ok');
    const log = await logEvent;
    assert.ok(log.responseTime >= 20);
    assert.doesNotMatch(child._testOutput, /dest\.on is not a function/);
  } finally {
    for (const ws of sockets) { try { ws.close(); } catch (_) {} }
    await new Promise(resolve => upstream.close(resolve));
    if (!child.killed) child.kill('SIGTERM');
  }
});

test('HTTP 转发会等待慢初始化响应，不会在 5-6 秒时提前切换或丢弃', async () => {
  const upstream = http.createServer((req, res) => {
    if (req.url === '/healthz') return res.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}');
    setTimeout(() => res.end('initialized-ok'), 6500);
  });
  await new Promise((resolve, reject) => { upstream.once('error', reject); upstream.listen(0, '127.0.0.1', resolve); });
  const upstreamPort = upstream.address().port;
  const dir = tempDir();
  const lbPort = await freePort();
  const configPath = path.join(dir, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify({
    port: lbPort,
    admin_password: 'test-password-123',
    request_timeout: 60000,
    retry_400_enabled: false,
    groups: { default: { algorithm: 'round-robin', description: '' } },
    rules: [],
    _backends: [{ id: 'slow-http', type: 'http', url: `http://127.0.0.1:${upstreamPort}`, group: 'default', weight: 1 }]
  }));
  const child = spawn(process.execPath, [realServerPath], {
    cwd: ROOT,
    env: { ...process.env, LB_PORT: String(lbPort), LB_CONFIG_PATH: configPath },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  children.add(child);
  try {
    await waitUntil(async () => {
      try { return (await request(lbPort, '/healthz')).status === 200; } catch (_) { return false; }
    });
    const startedAt = Date.now();
    const response = await request(lbPort, '/slow-initialize');
    const elapsed = Date.now() - startedAt;
    assert.equal(response.status, 200);
    assert.equal(response.body, 'initialized-ok');
    assert.ok(elapsed >= 6000, `响应提前结束: ${elapsed}ms`);
  } finally {
    await new Promise(resolve => upstream.close(resolve));
    if (!child.killed) child.kill('SIGTERM');
  }
});

test('HTTP 502 响应自动重试（同节点）后成功', async () => {
  let hits = 0;
  const upstream = http.createServer((req, res) => {
    if (req.url === '/healthz') return res.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}');
    hits++;
    if (hits === 1) { res.writeHead(502, { 'content-type': 'text/plain' }); return res.end('first-502'); }
    res.writeHead(200, { 'content-type': 'text/plain' }).end('ok-after-retry');
  });
  await new Promise((resolve, reject) => { upstream.once('error', reject); upstream.listen(0, '127.0.0.1', resolve); });
  const upstreamPort = upstream.address().port;
  const dir = tempDir();
  const lbPort = await freePort();
  const configPath = path.join(dir, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify({
    port: lbPort,
    admin_password: 'test-password-123',
    request_timeout: 60000,
    groups: { default: { algorithm: 'round-robin', description: '' } },
    rules: [],
    _backends: [{ id: 'same-502', type: 'http', url: `http://127.0.0.1:${upstreamPort}`, group: 'default', weight: 1, disable_health_check: true }]
  }));
  const child = spawn(process.execPath, [realServerPath], {
    cwd: ROOT,
    env: { ...process.env, LB_PORT: String(lbPort), LB_CONFIG_PATH: configPath },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  child._testOutput = '';
  child.stdout.on('data', chunk => { child._testOutput += chunk.toString(); });
  child.stderr.on('data', chunk => { child._testOutput += chunk.toString(); });
  children.add(child);
  try {
    await waitUntil(async () => {
      try { return (await request(lbPort, '/healthz')).status === 200; } catch (_) { return false; }
    });
    const response = await request(lbPort, '/retry-502-same');
    assert.equal(response.status, 200);
    assert.equal(response.body, 'ok-after-retry');
    assert.ok(hits >= 2, `应至少命中后端两次，实际 ${hits}`);
    assert.match(child._testOutput, /\[502 重试·同节点\]/);
  } finally {
    await new Promise(resolve => upstream.close(resolve));
    if (!child.killed) child.kill('SIGTERM');
  }
});

test('HTTP 504 响应自动重试（同节点）后成功', async () => {
  let hits = 0;
  const upstream = http.createServer((req, res) => {
    if (req.url === '/healthz') return res.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}');
    hits++;
    if (hits === 1) return res.writeHead(504, { 'content-type': 'text/plain' }).end('first-504');
    res.writeHead(200, { 'content-type': 'text/plain' }).end('ok-after-retry');
  });
  await new Promise((resolve, reject) => { upstream.once('error', reject); upstream.listen(0, '127.0.0.1', resolve); });
  const upstreamPort = upstream.address().port;
  const dir = tempDir();
  const lbPort = await freePort();
  const configPath = path.join(dir, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify({
    port: lbPort,
    admin_password: 'test-password-123',
    request_timeout: 60000,
    retry_502_enabled: true,
    retry_502_max: 1,
    groups: { default: { algorithm: 'round-robin', description: '' } },
    rules: [],
    _backends: [{ id: 'same-504', type: 'http', url: `http://127.0.0.1:${upstreamPort}`, group: 'default', weight: 1, disable_health_check: true }]
  }));
  const child = spawn(process.execPath, [realServerPath], {
    cwd: ROOT,
    env: { ...process.env, LB_PORT: String(lbPort), LB_CONFIG_PATH: configPath },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  child._testOutput = '';
  child.stdout.on('data', chunk => { child._testOutput += chunk.toString(); });
  child.stderr.on('data', chunk => { child._testOutput += chunk.toString(); });
  children.add(child);
  try {
    await waitUntil(async () => {
      try { return (await request(lbPort, '/healthz')).status === 200; } catch (_) { return false; }
    });
    const response = await request(lbPort, '/retry-504-same');
    assert.equal(response.status, 200);
    assert.equal(response.body, 'ok-after-retry');
    assert.equal(hits, 2);
    assert.match(child._testOutput, /\[504 重试·同节点\]/);
  } finally {
    await new Promise(resolve => upstream.close(resolve));
    if (!child.killed) child.kill('SIGTERM');
  }
});

test('HTTP 200 包装的 QSign code=400 也会重试后返回签名结果', async () => {
  let hits = 0;
  const upstream = http.createServer((req, res) => {
    if (req.url === '/healthz') return res.writeHead(200).end('ok');
    hits++;
    if (hits === 1) return res.writeHead(200, { 'content-type': 'application/json' }).end('{"code":400,"errmsg":"请求失败"}');
    res.writeHead(200, { 'content-type': 'application/json' }).end('{"code":0,"data":{"sign":"signed-value"}}');
  });
  await new Promise((resolve, reject) => { upstream.once('error', reject); upstream.listen(0, '127.0.0.1', resolve); });
  const dir = tempDir();
  const lbPort = await freePort();
  const configPath = path.join(dir, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify({
    port: lbPort,
    admin_password: 'test-password-123',
    retry_400_enabled: true,
    retry_400_max: 1,
    groups: { default: { algorithm: 'round-robin', description: '' } },
    rules: [],
    _backends: [{ id: 'qsign-code-400', type: 'http', url: `http://127.0.0.1:${upstream.address().port}`, group: 'default', weight: 1, disable_health_check: true }]
  }));
  const child = spawn(process.execPath, [realServerPath], {
    cwd: ROOT,
    env: { ...process.env, LB_PORT: String(lbPort), LB_CONFIG_PATH: configPath },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  children.add(child);
  try {
    await waitUntil(async () => {
      try { return (await request(lbPort, '/healthz')).status === 200; } catch (_) { return false; }
    });
    const response = await request(lbPort, '/sign?cmd=test');
    assert.equal(response.status, 200);
    assert.deepEqual(JSON.parse(response.body), { code: 0, data: { sign: 'signed-value' } });
    assert.equal(hits, 2);
  } finally {
    await new Promise(resolve => upstream.close(resolve));
    if (!child.killed) child.kill('SIGTERM');
  }
});

test('HTTP 429 qsign busy 自动重试（同节点）后成功', async () => {
  let hits = 0;
  const upstream = http.createServer((req, res) => {
    if (req.url === '/healthz') return res.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}');
    hits++;
    if (hits === 1) return res.writeHead(429, { 'content-type': 'application/json' }).end('{"code":429,"msg":"qsign is busy"}');
    res.writeHead(200, { 'content-type': 'application/json' }).end('{"code":0,"msg":"ok"}');
  });
  await new Promise((resolve, reject) => { upstream.once('error', reject); upstream.listen(0, '127.0.0.1', resolve); });
  const dir = tempDir();
  const lbPort = await freePort();
  const configPath = path.join(dir, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify({
    port: lbPort,
    admin_password: 'test-password-123',
    retry_502_enabled: true,
    retry_502_max: 1,
    groups: { default: { algorithm: 'round-robin', description: '' } },
    rules: [],
    _backends: [{ id: 'same-429', type: 'http', url: `http://127.0.0.1:${upstream.address().port}`, group: 'default', weight: 1, disable_health_check: true }]
  }));
  const child = spawn(process.execPath, [realServerPath], {
    cwd: ROOT,
    env: { ...process.env, LB_PORT: String(lbPort), LB_CONFIG_PATH: configPath },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  child._testOutput = '';
  child.stdout.on('data', chunk => { child._testOutput += chunk.toString(); });
  child.stderr.on('data', chunk => { child._testOutput += chunk.toString(); });
  children.add(child);
  try {
    await waitUntil(async () => {
      try { return (await request(lbPort, '/healthz')).status === 200; } catch (_) { return false; }
    });
    const response = await request(lbPort, '/retry-429-same');
    assert.equal(response.status, 200);
    assert.equal(JSON.parse(response.body).code, 0);
    assert.equal(hits, 2);
    assert.match(child._testOutput, /\[429 重试·同节点\]/);
  } finally {
    await new Promise(resolve => upstream.close(resolve));
    if (!child.killed) child.kill('SIGTERM');
  }
});

test('HTTP 重试耗尽时仍返回上游的 504 响应体', async () => {
  let hits = 0;
  const upstream = http.createServer((req, res) => {
    if (req.url === '/healthz') return res.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}');
    hits++;
    res.writeHead(504, { 'content-type': 'text/plain' }).end('upstream-timeout-body');
  });
  await new Promise((resolve, reject) => { upstream.once('error', reject); upstream.listen(0, '127.0.0.1', resolve); });
  const upstreamPort = upstream.address().port;
  const dir = tempDir();
  const lbPort = await freePort();
  const configPath = path.join(dir, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify({
    port: lbPort,
    admin_password: 'test-password-123',
    request_timeout: 60000,
    retry_502_enabled: true,
    retry_502_max: 1,
    groups: { default: { algorithm: 'round-robin', description: '' } },
    rules: [],
    _backends: [{ id: 'exhausted-504', type: 'http', url: `http://127.0.0.1:${upstreamPort}`, group: 'default', weight: 1, disable_health_check: true }]
  }));
  const child = spawn(process.execPath, [realServerPath], {
    cwd: ROOT,
    env: { ...process.env, LB_PORT: String(lbPort), LB_CONFIG_PATH: configPath },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  children.add(child);
  try {
    await waitUntil(async () => {
      try { return (await request(lbPort, '/healthz')).status === 200; } catch (_) { return false; }
    });
    const response = await request(lbPort, '/retry-504-exhausted');
    assert.equal(response.status, 504);
    assert.equal(response.body, 'upstream-timeout-body');
    assert.equal(hits, 2);
  } finally {
    await new Promise(resolve => upstream.close(resolve));
    if (!child.killed) child.kill('SIGTERM');
  }
});

test('每秒请求数按最近一秒的真实入口请求计算', async () => {
  const upstream = http.createServer((req, res) => {
    if (req.url === '/healthz') return res.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}');
    res.writeHead(200, { 'content-type': 'text/plain' }).end('ok');
  });
  await new Promise((resolve, reject) => { upstream.once('error', reject); upstream.listen(0, '127.0.0.1', resolve); });
  const upstreamPort = upstream.address().port;
  const dir = tempDir();
  const lbPort = await freePort();
  const configPath = path.join(dir, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify({
    port: lbPort,
    admin_password: 'test-password-123',
    request_timeout: 60000,
    retry_400_enabled: false,
    retry_502_enabled: false,
    groups: { default: { algorithm: 'round-robin', description: '' } },
    rules: [],
    _backends: [{ id: 'rps-upstream', type: 'http', url: `http://127.0.0.1:${upstreamPort}`, group: 'default', weight: 1, disable_health_check: true }]
  }));
  const child = spawn(process.execPath, [realServerPath], {
    cwd: ROOT,
    env: { ...process.env, LB_PORT: String(lbPort), LB_CONFIG_PATH: configPath },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  children.add(child);
  try {
    await waitUntil(async () => {
      try { return (await request(lbPort, '/healthz')).status === 200; } catch (_) { return false; }
    });
    const loginBody = JSON.stringify({ password: 'test-password-123' });
    const login = await request(lbPort, '/api/login', {
      method: 'POST', headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(loginBody) }
    }, loginBody);
    const token = JSON.parse(login.body).token;
    const burst = await Promise.all(Array.from({ length: 6 }, (_, index) => request(lbPort, `/rps-${index}`)));
    assert.ok(burst.every(response => response.status === 200));
    const statsResponse = await request(lbPort, '/api/stats', { headers: { authorization: `Bearer ${token}` } });
    assert.ok(JSON.parse(statsResponse.body).data.currentRps >= 6);
  } finally {
    await new Promise(resolve => upstream.close(resolve));
    if (!child.killed) child.kill('SIGTERM');
  }
});

test('节点级 Query→JSON 只转换已开启节点，关键词规则可匹配请求头', async () => {
  const defaultRequests = [];
  const convertedRequests = [];
  const defaultUpstream = http.createServer((req, res) => {
    if (req.url === '/healthz') return res.writeHead(200).end('ok');
    defaultRequests.push({ method: req.method, url: req.url });
    res.writeHead(200, { 'content-type': 'text/plain' }).end('default');
  });
  const convertedUpstream = http.createServer((req, res) => {
    if (req.url === '/healthz') return res.writeHead(200).end('ok');
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      convertedRequests.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString('utf8') });
      res.writeHead(200, { 'content-type': 'text/plain' }).end('converted');
    });
  });
  await Promise.all([defaultUpstream, convertedUpstream].map(server => new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); })));
  const dir = tempDir();
  const lbPort = await freePort();
  const configPath = path.join(dir, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify({
    port: lbPort,
    admin_password: 'test-password-123',
    retry_400_enabled: false,
    retry_502_enabled: false,
    groups: { default: { algorithm: 'round-robin', description: '' }, convert: { algorithm: 'round-robin', description: '' } },
    rules: [
      { id: 1, path: 'android', group: 'convert', priority: 20, matchType: 'keyword' },
      { id: 2, path: '/convert', group: 'convert', priority: 10, matchType: 'prefix' }
    ],
    _backends: [
      { id: 'default-query', type: 'http', url: `http://127.0.0.1:${defaultUpstream.address().port}`, group: 'default', weight: 1, disable_health_check: true },
      { id: 'convert-query', type: 'http', url: `http://127.0.0.1:${convertedUpstream.address().port}`, group: 'convert', weight: 1, query_to_json_enabled: true, disable_health_check: true }
    ]
  }));
  const child = spawn(process.execPath, [realServerPath], {
    cwd: ROOT,
    env: { ...process.env, LB_PORT: String(lbPort), LB_CONFIG_PATH: configPath },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  children.add(child);
  try {
    await waitUntil(async () => {
      try { return (await request(lbPort, '/healthz')).status === 200; } catch (_) { return false; }
    });
    assert.equal((await request(lbPort, '/plain?foo=one')).body, 'default');
    assert.equal((await request(lbPort, '/convert/task?ver=9.2.90&foo=one&tag=a&tag=b')).body, 'converted');
    assert.equal((await request(lbPort, '/header-keyword', { headers: { 'x-client': 'android-app' } })).body, 'converted');
    assert.deepEqual(defaultRequests, [{ method: 'GET', url: '/plain?foo=one' }]);
    assert.equal(convertedRequests[0].method, 'POST');
    assert.equal(convertedRequests[0].url, '/convert/task');
    assert.equal(convertedRequests[0].headers['content-type'], 'application/json');
    assert.deepEqual(JSON.parse(convertedRequests[0].body), { ver: '9.2.90', foo: 'one', tag: ['a', 'b'] });
    assert.equal(convertedRequests[1].method, 'GET');
    assert.equal(convertedRequests[1].url, '/header-keyword');
  } finally {
    await Promise.all([defaultUpstream, convertedUpstream].map(server => new Promise(resolve => server.close(resolve))));
    if (!child.killed) child.kill('SIGTERM');
  }
});

test('节点级 Query→JSON 被拒绝时会回退为原始 Query，不依赖常规重试开关', async () => {
  const received = [];
  const upstream = http.createServer((req, res) => {
    if (req.url === '/healthz') return res.writeHead(200).end('ok');
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      received.push({ method: req.method, url: req.url, contentType: req.headers['content-type'], body: Buffer.concat(chunks).toString('utf8') });
      if (req.headers['content-type'] === 'application/json') {
        return res.writeHead(200, { 'content-type': 'application/json' }).end('{"code":400,"errmsg":"JSON 不支持"}');
      }
      res.writeHead(200, { 'content-type': 'application/json' }).end('{"code":0,"data":{"sign":"query-sign"}}');
    });
  });
  await new Promise((resolve, reject) => { upstream.once('error', reject); upstream.listen(0, '127.0.0.1', resolve); });
  const dir = tempDir();
  const lbPort = await freePort();
  const configPath = path.join(dir, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify({
    port: lbPort,
    admin_password: 'test-password-123',
    retry_400_enabled: false,
    retry_502_enabled: false,
    groups: { default: { algorithm: 'round-robin', description: '' } },
    rules: [],
    _backends: [{ id: 'query-fallback', type: 'http', url: `http://127.0.0.1:${upstream.address().port}`, group: 'default', weight: 1, query_to_json_enabled: true, disable_health_check: true }]
  }));
  const child = spawn(process.execPath, [realServerPath], {
    cwd: ROOT,
    env: { ...process.env, LB_PORT: String(lbPort), LB_CONFIG_PATH: configPath },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  children.add(child);
  try {
    await waitUntil(async () => {
      try { return (await request(lbPort, '/healthz')).status === 200; } catch (_) { return false; }
    });
    const response = await request(lbPort, '/sign?ver=9.2.90&cmd=wtlogin.login');
    assert.equal(response.status, 200);
    assert.deepEqual(JSON.parse(response.body), { code: 0, data: { sign: 'query-sign' } });
    assert.deepEqual(received, [
      { method: 'POST', url: '/sign', contentType: 'application/json', body: '{"ver":"9.2.90","cmd":"wtlogin.login"}' },
      { method: 'GET', url: '/sign?ver=9.2.90&cmd=wtlogin.login', contentType: undefined, body: '' }
    ]);
  } finally {
    await new Promise(resolve => upstream.close(resolve));
    if (!child.killed) child.kill('SIGTERM');
  }
});

test('节点级 POST→GET 会将 JSON 参数合并到 Query 并移除请求体', async () => {
  const received = [];
  const upstream = http.createServer((req, res) => {
    if (req.url === '/healthz') return res.writeHead(200).end('ok');
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      received.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString('utf8') });
      res.writeHead(200, { 'content-type': 'text/plain' }).end('get-ok');
    });
  });
  await new Promise((resolve, reject) => { upstream.once('error', reject); upstream.listen(0, '127.0.0.1', resolve); });
  const dir = tempDir();
  const lbPort = await freePort();
  const configPath = path.join(dir, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify({
    port: lbPort,
    admin_password: 'test-password-123',
    retry_400_enabled: false,
    retry_502_enabled: false,
    groups: { default: { algorithm: 'round-robin', description: '' } },
    rules: [],
    _backends: [{ id: 'post-to-get', type: 'http', url: `http://127.0.0.1:${upstream.address().port}`, group: 'default', weight: 1, post_to_get_enabled: true, disable_health_check: true }]
  }));
  const child = spawn(process.execPath, [realServerPath], {
    cwd: ROOT,
    env: { ...process.env, LB_PORT: String(lbPort), LB_CONFIG_PATH: configPath },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  children.add(child);
  try {
    await waitUntil(async () => {
      try { return (await request(lbPort, '/healthz')).status === 200; } catch (_) { return false; }
    });
    const body = JSON.stringify({ ver: '9.2.90', uin: '13131', cmd: 'wtlogin.login', seq: '12371', tag: ['a', 'b'] });
    const response = await request(lbPort, '/sign?guid=device-guid&ver=old-version', {
      method: 'POST', headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) }
    }, body);
    assert.equal(response.status, 200);
    assert.equal(response.body, 'get-ok');
    assert.equal(received.length, 1);
    assert.equal(received[0].method, 'GET');
    assert.equal(received[0].body, '');
    assert.equal(received[0].headers['content-type'], undefined);
    const params = new URL(`http://test${received[0].url}`).searchParams;
    assert.equal(params.get('guid'), 'device-guid');
    assert.equal(params.get('ver'), '9.2.90');
    assert.deepEqual(params.getAll('ver'), ['9.2.90']);
    assert.equal(params.get('uin'), '13131');
    assert.equal(params.get('cmd'), 'wtlogin.login');
    assert.deepEqual(params.getAll('tag'), ['a', 'b']);
  } finally {
    await new Promise(resolve => upstream.close(resolve));
    if (!child.killed) child.kill('SIGTERM');
  }
});

test('HTTP 连接被拒先同节点重试再换节点后成功', async () => {
  const goodHits = [];
  const good = http.createServer((req, res) => {
    if (req.url === '/healthz') return res.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}');
    goodHits.push(1);
    res.writeHead(200, { 'content-type': 'text/plain' }).end('switch-ok');
  });
  await new Promise((resolve, reject) => { good.once('error', reject); good.listen(0, '127.0.0.1', resolve); });
  const goodPort = good.address().port;
  const deadPort = await freePort(); // 无人监听 → ECONNREFUSED
  const dir = tempDir();
  const lbPort = await freePort();
  const configPath = path.join(dir, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify({
    port: lbPort,
    admin_password: 'test-password-123',
    request_timeout: 60000,
    retry_502_enabled: true,
    retry_502_max: 2,
    retry_502_max_backends: 3,
    groups: { default: { algorithm: 'round-robin', description: '' } },
    rules: [],
    _backends: [
      { id: 'dead-refused', type: 'http', url: `http://127.0.0.1:${deadPort}`, group: 'default', weight: 1, disable_health_check: true },
      { id: 'good-live', type: 'http', url: `http://127.0.0.1:${goodPort}`, group: 'default', weight: 1, disable_health_check: true }
    ]
  }));
  const child = spawn(process.execPath, [realServerPath], {
    cwd: ROOT,
    env: { ...process.env, LB_PORT: String(lbPort), LB_CONFIG_PATH: configPath },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  child._testOutput = '';
  child.stdout.on('data', chunk => { child._testOutput += chunk.toString(); });
  child.stderr.on('data', chunk => { child._testOutput += chunk.toString(); });
  children.add(child);
  try {
    await waitUntil(async () => {
      try { return (await request(lbPort, '/healthz')).status === 200; } catch (_) { return false; }
    });
    const response = await request(lbPort, '/retry-502-switch');
    assert.equal(response.status, 200);
    assert.equal(response.body, 'switch-ok');
    assert.equal(goodHits.length, 1);
    const sameRetryAt = child._testOutput.indexOf('[502 重试·同节点]');
    const switchRetryAt = child._testOutput.indexOf('[502 重试·换节点]');
    assert.ok(sameRetryAt >= 0, `未发生同节点重试: ${child._testOutput}`);
    assert.ok(switchRetryAt > sameRetryAt, `未在同节点重试后换节点: ${child._testOutput}`);
  } finally {
    await new Promise(resolve => good.close(resolve));
    if (!child.killed) child.kill('SIGTERM');
  }
});

test('关闭 502 重试时原样返回 502，不自动重试', async () => {
  let hits = 0;
  const upstream = http.createServer((req, res) => {
    if (req.url === '/healthz') return res.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}');
    hits++;
    res.writeHead(502, { 'content-type': 'text/plain' }).end('always-502');
  });
  await new Promise((resolve, reject) => { upstream.once('error', reject); upstream.listen(0, '127.0.0.1', resolve); });
  const upstreamPort = upstream.address().port;
  const dir = tempDir();
  const lbPort = await freePort();
  const configPath = path.join(dir, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify({
    port: lbPort,
    admin_password: 'test-password-123',
    request_timeout: 60000,
    retry_502_enabled: false,
    groups: { default: { algorithm: 'round-robin', description: '' } },
    rules: [],
    _backends: [{ id: 'always-502', type: 'http', url: `http://127.0.0.1:${upstreamPort}`, group: 'default', weight: 1, disable_health_check: true }]
  }));
  const child = spawn(process.execPath, [realServerPath], {
    cwd: ROOT,
    env: { ...process.env, LB_PORT: String(lbPort), LB_CONFIG_PATH: configPath },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  child._testOutput = '';
  child.stdout.on('data', chunk => { child._testOutput += chunk.toString(); });
  child.stderr.on('data', chunk => { child._testOutput += chunk.toString(); });
  children.add(child);
  try {
    await waitUntil(async () => {
      try { return (await request(lbPort, '/healthz')).status === 200; } catch (_) { return false; }
    });
    const response = await request(lbPort, '/no-502-retry');
    assert.equal(response.status, 502);
    assert.equal(response.body, 'always-502');
    assert.equal(hits, 1, `不应重试，命中次数应为 1，实际 ${hits}`);
    assert.doesNotMatch(child._testOutput, /\[502 重试/);
  } finally {
    await new Promise(resolve => upstream.close(resolve));
    if (!child.killed) child.kill('SIGTERM');
  }
});
