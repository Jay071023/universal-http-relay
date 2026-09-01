'use strict';

/**
 * Cross-platform hot-update client.
 *
 * Examples:
 *   node upload.js --host 203.0.113.10 --port 7879 --token xxx --all
 *   LB_DEPLOY_TOKEN=xxx node upload.js --host 203.0.113.10 --all
 *   node upload.js --host 203.0.113.10 --token xxx lb-server-real.js public/js/app.js
 */

const net = require('net');
const fs = require('fs');
const path = require('path');

const argv = process.argv.slice(2);
const VALUE_OPTIONS = new Set(['--host', '--port', '--token']);
const hosts = [];
const filesFromArgs = [];
let port = Number.parseInt(process.env.DEPLOY_PORT || '7879', 10) || 7879;
let token = process.env.LB_DEPLOY_TOKEN || process.env.DEPLOY_TOKEN || '';
let uploadAll = false;
let noRestart = false;

for (let i = 0; i < argv.length; i++) {
  const arg = argv[i];
  if (arg === '--all') { uploadAll = true; continue; }
  if (arg === '--no-restart') { noRestart = true; continue; }
  if (VALUE_OPTIONS.has(arg)) {
    const value = argv[++i];
    if (!value || value.startsWith('--')) throw new Error(`${arg} 缺少参数`);
    if (arg === '--host') hosts.push(...value.split(',').map(s => s.trim()).filter(Boolean));
    else if (arg === '--port') port = Number.parseInt(value, 10) || 7879;
    else if (arg === '--token') token = value;
    continue;
  }
  if (arg.startsWith('--')) throw new Error(`未知参数: ${arg}`);
  filesFromArgs.push(arg);
}

const DEFAULT_FILES = [
  'lb-server.js',
  'lb-server-real.js',
  'deploy-server.js',
  'control.js',
  'agent.js',
  'package.json',
  'package-lock.json',
  'ecosystem.config.js',
];
const MAX_UPLOAD_FILE_BYTES = 32 * 1024 * 1024;

function normalizeLocalPath(input) {
  if (typeof input !== 'string' || !input || input.includes('\0')) throw new Error('非法本地文件路径');
  const fullPath = path.resolve(__dirname, input);
  const relative = path.relative(__dirname, fullPath);
  if (!relative || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error(`拒绝上传工作目录外的文件: ${input}`);
  }
  const normalized = relative.split(path.sep).join('/');
  if (normalized.startsWith('.') || normalized.includes('/node_modules/') || normalized.startsWith('node_modules/')) {
    throw new Error(`不允许上传该路径: ${input}`);
  }
  return { relative: normalized, fullPath };
}

function walkPublic(directory, result) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) walkPublic(fullPath, result);
    else if (entry.isFile()) result.push(path.relative(__dirname, fullPath).split(path.sep).join('/'));
  }
}

function collectFiles() {
  const requested = uploadAll ? [...DEFAULT_FILES] : filesFromArgs;
  if (uploadAll && fs.existsSync(path.join(__dirname, 'public'))) walkPublic(path.join(__dirname, 'public'), requested);
  if (requested.length === 0) throw new Error('请指定文件，或使用 --all 上传运行时文件和 public/');

  const unique = [];
  const seen = new Set();
  for (const input of requested) {
    const local = normalizeLocalPath(input);
    if (seen.has(local.relative)) continue;
    const stat = fs.statSync(local.fullPath);
    if (!stat.isFile()) throw new Error(`不是普通文件: ${input}`);
    if (stat.size > MAX_UPLOAD_FILE_BYTES) throw new Error(`文件过大（上限 ${MAX_UPLOAD_FILE_BYTES} bytes）: ${input}`);
    seen.add(local.relative);
    unique.push(local);
  }
  return unique;
}

function connectAndUpload(host, files) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port });
    let lineBuffer = Buffer.alloc(0);
    let fileIndex = 0;
    let authenticated = false;
    let restartRequested = false;
    let settled = false;
    const result = { host, port, status: 'PENDING', files: [], error: null };

    function finish(status, error) {
      if (settled) return;
      settled = true;
      result.status = status;
      result.error = error || null;
      if (status !== 'OK') result.files = files.slice(0, fileIndex).map(file => ({ path: file.relative, status: 'UNKNOWN' }));
      socket.destroy();
      resolve(result);
    }

    function send(message) {
      if (settled || socket.destroyed) return;
      socket.write(`${JSON.stringify(message)}\n`);
    }

    function sendNextFile() {
      if (fileIndex >= files.length) {
        send({ type: 'batch_done', files: files.map(file => ({ path: file.relative })) });
        return;
      }
      const file = files[fileIndex];
      const content = fs.readFileSync(file.fullPath).toString('base64');
      send({ type: 'file', path: file.relative, content });
    }

    function processMessage(message) {
      if (!message || typeof message !== 'object') return finish('FAIL', '服务端返回了无效消息');
      switch (message.type) {
        case 'hello':
          if (message.protocol !== 2) return finish('FAIL', `不兼容的部署服务协议: ${message.protocol || 'unknown'}`);
          if (message.authRequired && !token) return finish('FAIL', '部署服务要求 token，请使用 --token 或 LB_DEPLOY_TOKEN');
          if (message.authRequired) send({ type: 'auth', token });
          else {
            authenticated = true;
            sendNextFile();
          }
          break;
        case 'auth_ok':
          authenticated = true;
          console.log(`  [${host}] 认证成功，开始上传 ${files.length} 个文件...`);
          sendNextFile();
          break;
        case 'file_ok':
          if (!authenticated || fileIndex >= files.length || message.path !== files[fileIndex].relative) {
            return finish('FAIL', '服务端文件确认顺序异常');
          }
          result.files.push({ path: message.path, status: 'OK', size: message.size || 0 });
          fileIndex++;
          sendNextFile();
          break;
        case 'done':
          if (fileIndex !== files.length) return finish('FAIL', '服务端在文件未全部确认前完成批量');
          if (noRestart) return finish('OK');
          restartRequested = true;
          send({ type: 'restart', service: 'lb-server' });
          break;
        case 'restart_ack':
          console.log(`  [${host}] 文件已提交，正在热重启...`);
          break;
        case 'restart_ok':
          if (!restartRequested) return finish('FAIL', '服务端返回了意外的重启结果');
          console.log(`  [${host}] 热更新完成 (${message.manager || 'unknown'})`);
          finish('OK');
          break;
        case 'error':
          finish('FAIL', message.message || '服务端拒绝请求');
          break;
        default:
          // Ignore only unknown informational messages; never advance the state.
          break;
      }
    }

    socket.setTimeout(120000, () => finish('FAIL', '连接超时'));
    socket.on('data', (chunk) => {
      if (settled) return;
      lineBuffer = Buffer.concat([lineBuffer, chunk]);
      let newline;
      while ((newline = lineBuffer.indexOf(0x0a)) >= 0) {
        const line = lineBuffer.subarray(0, newline).toString('utf8').trim();
        lineBuffer = lineBuffer.subarray(newline + 1);
        if (!line) continue;
        try { processMessage(JSON.parse(line)); }
        catch (_) { finish('FAIL', '服务端返回了非法 JSON'); return; }
        if (settled) return;
      }
    });
    socket.on('connect', () => console.log(`[${host}:${port}] 已连接，等待服务端握手...`));
    socket.on('error', error => finish('FAIL', error.message));
    socket.on('close', () => { if (!settled) finish('FAIL', '连接意外关闭'); });
  });
}

async function main() {
  const uniqueHosts = [...new Set(hosts)];
  if (uniqueHosts.length === 0) throw new Error('请指定服务器地址 --host IP[,IP...]');
  if (!token) throw new Error('必须提供部署 token（--token 或 LB_DEPLOY_TOKEN）');
  const files = collectFiles();

  console.log('========================================');
  console.log(`  目标服务器: ${uniqueHosts.length} 台`);
  uniqueHosts.forEach(host => console.log(`    - ${host}:${port}`));
  console.log(`  文件数量  : ${files.length}`);
  console.log(`  上传后重启: ${noRestart ? '否' : '是'}`);
  console.log('========================================\n');

  const results = await Promise.all(uniqueHosts.map(host => connectAndUpload(host, files)));
  let failed = 0;
  console.log('\n========================================');
  console.log('  部署汇总');
  console.log('========================================');
  for (const result of results) {
    if (result.status === 'OK') console.log(`  ✓ ${result.host}:${result.port} — 成功 (${result.files.length}/${files.length} 文件)`);
    else { failed++; console.log(`  ✗ ${result.host}:${result.port} — 失败: ${result.error || '未知错误'}`); }
  }
  console.log('========================================\n');
  if (failed > 0) process.exitCode = 1;
}

main().catch(error => { console.error(`错误: ${error.message}`); process.exitCode = 1; });
