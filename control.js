'use strict';

/**
 * 远程受控运维客户端；仅允许固定的受控运维命令，不支持任意 Shell。
 *
 * 示例:
 *   node control.js --host 203.0.113.10 --port 9001 --token xxx status
 *   node control.js --host 203.0.113.10 --port 9001 --token xxx health
 *   node control.js --host 203.0.113.10 --port 9001 --token xxx restart
 */

const net = require('net');

const argv = process.argv.slice(2);
const valueOptions = new Set(['--host', '--port', '--token']);
let hosts = [];
let port = Number.parseInt(process.env.DEPLOY_PORT || '7879', 10) || 7879;
let token = process.env.LB_DEPLOY_TOKEN || process.env.DEPLOY_TOKEN || '';
let command = '';

for (let i = 0; i < argv.length; i++) {
  const arg = argv[i];
  if (valueOptions.has(arg)) {
    const value = argv[++i];
    if (!value || value.startsWith('--')) throw new Error(`${arg} 缺少参数`);
    if (arg === '--host') hosts.push(...value.split(',').map(v => v.trim()).filter(Boolean));
    else if (arg === '--port') port = Number.parseInt(value, 10) || 7879;
    else if (arg === '--token') token = value;
  } else if (arg.startsWith('--')) {
    throw new Error(`未知参数: ${arg}`);
  } else if (!command) {
    command = arg.toLowerCase();
  } else {
    throw new Error(`多余参数: ${arg}`);
  }
}

if (!hosts.length) throw new Error('请指定服务器地址 --host IP[,IP...]');
if (!token) throw new Error('必须提供部署 token（--token 或 LB_DEPLOY_TOKEN）');
if (!['status', 'health', 'restart', 'reload'].includes(command)) {
  throw new Error('命令必须是 status、health、restart 或 reload');
}

function run(host) {
  return new Promise(resolve => {
    const socket = net.createConnection({ host, port });
    let buffer = Buffer.alloc(0);
    let settled = false;

    const finish = result => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ host, port, ...result });
    };
    const send = message => {
      if (!settled && !socket.destroyed) socket.write(`${JSON.stringify(message)}\n`);
    };
    const handle = message => {
      if (message.type === 'hello') {
        if (message.protocol !== 2) return finish({ ok: false, error: `协议不兼容: ${message.protocol || 'unknown'}` });
        if (!message.authRequired) send({ type: 'command', command });
        else send({ type: 'auth', token });
      } else if (message.type === 'auth_ok') {
        send({ type: 'command', command });
      } else if (message.type === 'command_ack') {
        console.log(`[${host}] ${message.message || '命令执行中...'}`);
      } else if (message.type === 'command_ok') {
        const data = message.data || {};
        finish({
          ok: data.ok !== false,
          command: message.command,
          data,
          error: data.ok === false ? '受控运维命令执行失败' : null,
        });
      } else if (message.type === 'error') {
        finish({ ok: false, error: message.message || '服务端拒绝命令' });
      }
    };

    socket.setTimeout(120000, () => finish({ ok: false, error: '连接超时' }));
    socket.on('data', chunk => {
      buffer = Buffer.concat([buffer, chunk]);
      let newline;
      while ((newline = buffer.indexOf(0x0a)) >= 0 && !settled) {
        const line = buffer.subarray(0, newline).toString('utf8').trim();
        buffer = buffer.subarray(newline + 1);
        if (!line) continue;
        try { handle(JSON.parse(line)); }
        catch (_) { finish({ ok: false, error: '服务端返回了非法 JSON' }); }
      }
    });
    socket.on('error', error => finish({ ok: false, error: error.message }));
    socket.on('close', () => { if (!settled) finish({ ok: false, error: '连接意外关闭' }); });
  });
}

(async () => {
  const results = await Promise.all([...new Set(hosts)].map(run));
  let failed = 0;
  for (const result of results) {
    if (result.ok) console.log(`[${result.host}:${result.port}] ${result.command} 成功\n${JSON.stringify(result.data, null, 2)}`);
    else {
      failed++;
      console.error(`[${result.host}:${result.port}] 失败: ${result.error}`);
      if (result.data?.stdout) console.error(result.data.stdout);
      if (result.data?.stderr) console.error(result.data.stderr);
    }
  }
  if (failed) process.exitCode = 1;
})().catch(error => { console.error(`错误: ${error.message}`); process.exitCode = 1; });
