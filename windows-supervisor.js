'use strict';

/** Windows supervisor: restart a service after an unexpected exit and keep logs. */
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const args = process.argv.slice(2);
function getArg(name) {
  const index = args.indexOf(name);
  return index >= 0 && index + 1 < args.length ? args[index + 1] : null;
}

const service = getArg('--service');
const port = getArg('--port');
const services = {
  'lb-server': { script: 'lb-server.js', log: 'lb-server.log', pid: 'lb-server.supervisor.pid' },
  'deploy-server': { script: 'deploy-server.js', log: 'deploy-server.log', pid: 'deploy-server.supervisor.pid' },
};
const definition = services[service];
if (!definition) {
  console.error('Usage: node windows-supervisor.js --service lb-server|deploy-server [--port PORT]');
  process.exit(2);
}

const root = __dirname;
const logDir = path.join(root, 'logs');
const logPath = path.join(logDir, definition.log);
const pidPath = path.resolve(process.env.LB_SUPERVISOR_PID_FILE || path.join(root, definition.pid));
const restartDelay = Math.max(1000, Number.parseInt(process.env.LB_RESTART_DELAY_MS || '5000', 10) || 5000);
fs.mkdirSync(logDir, { recursive: true });
fs.writeFileSync(pidPath, `${process.pid}\n`, 'utf8');

let child = null;
let stopping = false;
let restartTimer = null;

function writeLog(message) {
  try { fs.appendFileSync(logPath, `[${new Date().toISOString()}] ${message}\n`, 'utf8'); } catch (_) {}
}

function cleanup() {
  try {
    if (fs.readFileSync(pidPath, 'utf8').trim() === String(process.pid)) fs.unlinkSync(pidPath);
  } catch (_) {}
}

function stopChild() {
  if (!child || child.exitCode !== null) return;
  try { child.kill(); } catch (_) {}
}

function shutdown() {
  if (stopping) return;
  stopping = true;
  if (restartTimer) clearTimeout(restartTimer);
  writeLog('supervisor stopping');
  stopChild();
  const wait = setInterval(() => {
    if (!child || child.exitCode !== null) {
      clearInterval(wait);
      cleanup();
      process.exit(0);
    }
  }, 100);
  setTimeout(() => {
    clearInterval(wait);
    stopChild();
    cleanup();
    process.exit(0);
  }, 5000).unref();
}

function startChild() {
  if (stopping) return;
  const childArgs = [path.join(root, definition.script)];
  if (service === 'deploy-server' && port) childArgs.push('--port', port);
  writeLog(`starting ${service}: ${process.execPath} ${childArgs.join(' ')}`);
  child = spawn(process.execPath, childArgs, {
    cwd: root,
    env: { ...process.env, LB_WINDOWS_SUPERVISED: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  child.stdout.on('data', data => { try { fs.appendFileSync(logPath, data); } catch (_) {} });
  child.stderr.on('data', data => { try { fs.appendFileSync(logPath, data); } catch (_) {} });
  child.on('error', error => writeLog(`child error: ${error.stack || error.message}`));
  // close 同时覆盖正常退出和 spawn 失败，且确保剩余日志已经排空。
  child.on('close', (code, signal) => {
    writeLog(`child exited: code=${code === null ? 'null' : code} signal=${signal || 'none'}`);
    child = null;
    if (stopping) return;
    writeLog(`unexpected exit; restarting in ${restartDelay}ms`);
    restartTimer = setTimeout(startChild, restartDelay);
  });
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
process.on('uncaughtException', error => {
  writeLog(`supervisor fatal: ${error.stack || error.message}`);
  shutdown();
});
process.on('exit', cleanup);

writeLog(`supervisor started: service=${service} pid=${process.pid}`);
startChild();
