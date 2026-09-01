/**
 * lb-server.js — 启动引导脚本（wrapper）
 *
 * 1. 写 install.log 记录全过程
 * 2. 检测 node_modules，缺失则 npm install
 * 3. 加载 lb-server-real.js
 * 4. 写入 PID 文件，供跨平台部署接收端安全重启本进程
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const LOG_PATH = path.join(__dirname, 'install.log');
const PID_PATH = path.resolve(process.env.LB_PID_FILE || path.join(__dirname, 'lb-server.pid'));
function log(line) {
  const s = `[${new Date().toISOString()}] ${line}\n`;
  try { fs.appendFileSync(LOG_PATH, s); } catch (_) {}
}

log('=== wrapper start ===');
log('node ' + process.version + ' on ' + process.platform + ' ' + process.arch);
log('cwd=' + process.cwd());
log('__dirname=' + __dirname);
log('pid=' + process.ppid + ' (parent deploy-server)');

function checkDeps() {
  const required = [
    '@msgpack/msgpack',
    'http-proxy',
    'ws',
    'express',
    'cors',
    'uuid',
  ];
  const missing = [];
  for (const m of required) {
    try { require.resolve(m, { paths: [__dirname] }); }
    catch (_) { missing.push(m); }
  }
  return missing;
}

const missing = checkDeps();
log('missing deps: ' + (missing.length ? missing.join(', ') : '(none)'));

if (missing.length > 0) {
  log('running npm install...');
  try {
    const installCommand = fs.existsSync(path.join(__dirname, 'package-lock.json'))
      ? 'npm ci --omit=dev --no-audit --no-fund --loglevel=error'
      : 'npm install --omit=dev --no-audit --no-fund --loglevel=error';
    execSync(installCommand, {
      cwd: __dirname,
      stdio: 'pipe',
      timeout: 900000,
      windowsHide: true,
    });
    log('npm install finished');
  } catch (e) {
    log('npm install FAILED: ' + e.message);
    if (e.stderr) log('stderr: ' + e.stderr.toString().slice(-2000));
    if (e.stdout) log('stdout: ' + e.stdout.toString().slice(-2000));
    process.exit(1);
  }
  const stillMissing = checkDeps();
  if (stillMissing.length > 0) {
    log('FATAL: still missing: ' + stillMissing.join(', '));
    process.exit(1);
  }
}

const realPath = path.join(__dirname, 'lb-server-real.js');
if (!fs.existsSync(realPath)) {
  log('FATAL: ' + realPath + ' not found');
  process.exit(1);
}

log('loading lb-server-real.js ...');
try {
  require(realPath);
  log('lb-server-real.js loaded OK');
} catch (e) {
  log('FATAL require failed: ' + e.message);
  log(e.stack || '(no stack)');
  process.exit(1);
}

try {
  fs.writeFileSync(PID_PATH, `${process.pid}\n`, { encoding: 'utf8', mode: 0o640 });
  log('pid file=' + PID_PATH);
  const removePid = () => {
    try {
      if (fs.readFileSync(PID_PATH, 'utf8').trim() === String(process.pid)) fs.unlinkSync(PID_PATH);
    } catch (_) {}
  };
  process.once('exit', removePid);
  process.once('SIGTERM', removePid);
  process.once('SIGINT', removePid);
} catch (e) {
  log('WARN: pid file write failed: ' + e.message);
}

log('=== wrapper done ===');
