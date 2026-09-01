/**
 * Agent 隧道客户端（相当于 frpc）
 *
 * 运行在你的后端服务器上，通过 WebSocket 连接到负载均衡器，
 * 负载均衡器会将 HTTP 请求通过隧道转发过来。
 *
 * 用法:
 *   node agent.js --server ws://你的服务器:7878/agent --target http://localhost:3000 --tag 我的API
 *
 * 简写:
 *   node agent.js -s ws://localhost:7878/agent -t http://localhost:3000 -n 节点1 -w 2
 */

const WebSocket = require('ws');
const http = require('http');
const https = require('https');

// ── 参数解析 ───────────────────────────────────────
const args = {};
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '-s' || a === '--server') args.server = argv[++i];
  else if (a === '-t' || a === '--target') args.target = argv[++i];
  else if (a === '-n' || a === '--tag' || a === '--name') args.tag = argv[++i];
  else if (a === '-w' || a === '--weight') args.weight = parseInt(argv[++i]) || 1;
  else if (a.startsWith('--')) args[a.slice(2)] = argv[i + 1] && !argv[i + 1].startsWith('-') ? argv[i + 1] : true;
}

const SERVER_URL = args.server || process.env.LB_SERVER || 'ws://localhost:7878/agent';
const TARGET_URL = args.target || process.env.LB_TARGET || 'http://localhost:8080';
const TAG = args.tag || args.name || process.env.LB_TAG || `agent-${require('os').hostname()}`;
const WEIGHT = args.weight || parseInt(process.env.LB_WEIGHT) || 1;
const AGENT_GROUP = args.group || process.env.LB_GROUP || 'default';
const GROUP_KEY = args.groupKey || args['group-key'] || process.env.LB_GROUPKEY || '';
const AUTH_TOKEN = args.token || process.env.LB_TOKEN || '';
const DEFAULT_REQUEST_TIMEOUT = 120000;
const MIN_REQUEST_TIMEOUT = 60000;
const MAX_REQUEST_TIMEOUT = 10 * 60 * 1000;
const REQUEST_TIMEOUT = Math.max(MIN_REQUEST_TIMEOUT, Math.min(MAX_REQUEST_TIMEOUT,
  parseInt(args.timeout || process.env.LB_REQUEST_TIMEOUT, 10) || DEFAULT_REQUEST_TIMEOUT));
const RECONNECT_DELAY = 3000;
const PING_INTERVAL = 15000;

let ws = null;
let registered = false;
let reconnectTimer = null;
let pingTimer = null;
let agentId = null;

// ── 连接 ───────────────────────────────────────────
function connect() {
  if (ws) { try { ws.close(); } catch (_) {} }

  console.log(`\n  🔌 Agent 隧道客户端`);
  console.log(`  ─────────────────────────────`);
  console.log(`  🎯 服务器   : ${SERVER_URL}`);
  console.log(`  🏠 本地目标  : ${TARGET_URL}`);
  console.log(`  🏷️  标签     : ${TAG}`);
  console.log(`  ⚖️  权重     : ${WEIGHT}`);
  console.log(`  📁 分组     : ${AGENT_GROUP}`);
  if (GROUP_KEY) console.log(`  🔑 组密钥   : ${GROUP_KEY}`);
  if (AUTH_TOKEN) console.log(`  🔑 认证     : 已启用`);
  console.log(`  ─────────────────────────────\n`);

  ws = new WebSocket(SERVER_URL);

  ws.on('open', () => {
    console.log(`  ✅ 已连接到负载均衡器 ${SERVER_URL}`);
    registered = false;
    // 注册
    ws.send(JSON.stringify({ type: 'register', tag: TAG, name: TAG, weight: WEIGHT, group: AGENT_GROUP, groupKey: GROUP_KEY || undefined, token: AUTH_TOKEN || undefined }));
    // 启动心跳
    startPing();
  });

  ws.on('message', async (data) => {
    try {
      const msg = JSON.parse(data.toString());

      if (msg.type === 'registered') {
        agentId = msg.id;
        registered = true;
        console.log(`  ✅ 注册成功，Agent ID: ${agentId.slice(0, 8)}...\n`);
        return;
      }

      if (msg.type === 'pong') return;

      if (msg.type === 'request') {
        handleRequest(msg).catch(err => {
          console.error(`  ❌ 请求处理失败: ${err.message}`);
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
              type: 'response', id: msg.id,
              statusCode: 502, headers: { 'content-type': 'text/plain' },
              body: `Proxy error: ${err.message}`
            }));
          }
        });
        return;
      }
    } catch (e) {
      console.error(`  ⚠️ 消息解析错误: ${e.message}`);
    }
  });

  ws.on('close', () => {
    console.log(`  ⚠️ 连接断开，${RECONNECT_DELAY / 1000}秒后重连...`);
    stopPing();
    registered = false;
    reconnectTimer = setTimeout(connect, RECONNECT_DELAY);
  });

  ws.on('error', (err) => {
    console.error(`  ❌ WebSocket 错误: ${err.message}`);
    ws.close();
  });
}

// ── 处理请求 ───────────────────────────────────────
async function handleRequest(msg) {
  const { id, method = 'GET', path = '/', headers = {}, body } = msg;
  const urlObj = new URL(path, TARGET_URL);
  const isHttps = TARGET_URL.startsWith('https');
  const mod = isHttps ? https : http;

  console.log(`  📩 ${method} ${path}`);

  return new Promise((resolve, reject) => {
    let responseSent = false;
    const sendResponse = payload => {
      if (responseSent) return;
      responseSent = true;
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'response', id, ...payload }));
    };
    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || (isHttps ? 443 : 80),
      path: urlObj.pathname + urlObj.search,
      method: method,
      headers: { ...headers },
       // 后端可能需要 5~6 秒初始化；超时是最后兜底，不用于快速切换节点。
       timeout: Math.max(MIN_REQUEST_TIMEOUT, Math.min(MAX_REQUEST_TIMEOUT, parseInt(msg.timeoutMs, 10) || REQUEST_TIMEOUT)),
      rejectUnauthorized: false
    };

    // 清理不需要转发的头
    delete options.headers['host'];
    delete options.headers['x-lb-node'];
    delete options.headers['x-lb-algorithm'];
    delete options.headers['x-lb-response-time'];
    delete options.headers['connection'];
    delete options.headers['upgrade'];
    delete options.headers['sec-websocket-key'];
    delete options.headers['sec-websocket-version'];
    delete options.headers['sec-websocket-extensions'];

    const req = mod.request(options, (res) => {
      const respChunks = [];
      res.on('data', chunk => { respChunks.push(chunk); });
      res.on('end', () => {
        const respBody = Buffer.concat(respChunks).toString('utf8');
        const respHeaders = {};
        for (const [k, v] of Object.entries(res.headers)) {
          if (k !== 'transfer-encoding' && k !== 'connection') {
            respHeaders[k] = Array.isArray(v) ? v.join(', ') : v;
          }
        }

        sendResponse({ statusCode: res.statusCode, headers: respHeaders, body: respBody });
        resolve();
      });
    });

    req.on('error', (err) => {
      console.error(`  ❌ 本地请求失败: ${err.message}`);
      sendResponse({ statusCode: 502, headers: { 'content-type': 'text/plain' }, body: `Upstream error: ${err.message}` });
      resolve(); // 不 reject 防止上层未捕获
    });

    req.on('timeout', () => {
      req.destroy();
      console.error(`  ⏰ 本地请求超时`);
      sendResponse({ statusCode: 504, headers: { 'content-type': 'text/plain' }, body: 'Upstream timeout' });
      resolve();
    });

    if (body) req.write(body);
    req.end();
  });
}

// ── 心跳 ───────────────────────────────────────────
function startPing() {
  stopPing();
  pingTimer = setInterval(() => {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'ping' }));
    }
  }, PING_INTERVAL);
}

function stopPing() {
  if (pingTimer) { clearInterval(pingTimer); pingTimer = null; }
}

// ── 优雅关闭 ───────────────────────────────────────
process.on('SIGINT', () => {
  console.log('\n  👋 正在断开连接...');
  stopPing();
  if (reconnectTimer) clearTimeout(reconnectTimer);
  if (ws) { try { ws.close(); } catch (_) {} }
  process.exit(0);
});

process.on('SIGTERM', () => process.emit('SIGINT'));

// ── 启动 ───────────────────────────────────────────
console.log(`\n`);
console.log(`  ╔══════════════════════════════════╗`);
console.log(`  ║   🔌 隧道 Agent v1.0 (frpc 模式)  ║`);
console.log(`  ╚══════════════════════════════════╝`);
connect();
