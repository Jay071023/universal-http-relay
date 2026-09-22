'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '..', 'lb-server-real.js'), 'utf8');
test('RPS 保持精确滚动一秒窗口，高流量过期后回收数组', () => {
  let now = 10000;
  const context = vm.createContext({ Date: { now: () => now } });
  vm.runInContext(source.slice(source.indexOf('const recentRequestTimes ='), source.indexOf('// 持久化后端节点')), context);
  const run = code => vm.runInContext(code, context);
  run('for (let i = 0; i < 50000; i++) recordIncomingRequest()');
  now += 999;
  assert.equal(run('calcRps()'), 50000);
  run('recordIncomingRequest()');
  now++;
  assert.equal(run('calcRps()'), 1);
  assert.equal(run('recentRequestTimes.length'), 1);
  now += 1000;
  assert.equal(run('calcRps()'), 0);
});

test('管理广播无人订阅不序列化，慢客户端断开但正常客户端继续收消息', () => {
  let serializations = 0;
  const sent = [];
  let terminated = false;
  const subscribers = new Set();
  const context = vm.createContext({ wsSubscribers: subscribers, WebSocket: { OPEN: 1 },
    JSON: { stringify(value) { serializations++; return JSON.stringify(value); } } });
  vm.runInContext(source.slice(source.indexOf('function broadcast(message)'), source.indexOf('// ==================== 隧道转发')), context);
  vm.runInContext("broadcast({type:'stats_update'})", context);
  assert.equal(serializations, 0);
  subscribers.add({ readyState: 1, bufferedAmount: 2 * 1024 * 1024, terminate() { terminated = true; } });
  subscribers.add({ readyState: 1, bufferedAmount: 0, send(msg) { sent.push(msg); } });
  vm.runInContext("broadcast({type:'stats_update'})", context);
  assert.equal(terminated, true);
  assert.equal(sent.length, 1);
  assert.equal(serializations, 1);
});
// Exercise the actual statistics implementation with a controlled clock and isolated storage.
function fixture(persist, legacy) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lb-stats-regression-'));
  let now = new Date(2026, 8, 20, 23, 59).getTime();
  class Clock extends Date { constructor(...args) { super(...(args.length ? args : [now])); } static now() { return now; } }
  let configWrites = 0;
  const context = vm.createContext({ fs, path, console, process: { pid: process.pid }, Date: Clock, CONFIG: { persist_stats: persist, _qq_stats: legacy },
    QQ_STATS_DIR: dir, QQ_ALL_PATH: path.join(dir, 'all-qq.txt'), QQ_TOTAL_PATH: path.join(dir, 'total.count'),
    setTimeout: () => 1, setInterval: () => ({ unref() {} }), saveConfig: () => { configWrites++; return true; } });
  vm.runInContext(source.slice(source.indexOf('const qqStats ='), source.indexOf('/** 请求样本缓存')), context);
  vm.runInContext(source.slice(source.indexOf('function recordQQ('), source.indexOf('function recordLog(')), context);
  return { dir, run: code => vm.runInContext(code, context), nextDay: () => { now += 86400000; }, writes: () => configWrites,
    close: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

test('QQ 跨天重置今日数量但保留总去重，拒绝换行污染文件', () => {
  const f = fixture(false);
  try {
    f.run("recordQQ('12345'); recordQQ('12345'); recordQQ('bad\\nvalue')");
    assert.equal(f.run('qqStats.totalUnique'), 1);
    f.nextDay(); f.run("recordQQ('12345')");
    assert.equal(f.run('qqStats.totalUnique'), 1);
    assert.equal(f.run('qqStats.todayUnique'), 1);
    assert.equal(f.writes(), 0);
  } finally { f.close(); }
});

test('QQ 迁移不把无日期历史算作今日，新增批量写入不改配置', () => {
  const f = fixture(true, { totalUnique: 2, qqSet: ['11111', '22222'] });
  try {
    f.run('loadQqStats()');
    assert.equal(f.run('qqStats.todayUnique'), 0);
    assert.equal(f.run('qqStats.totalUnique'), 2);
    f.run("recordQQ('11111'); recordQQ('33333'); saveQqStats()");
    assert.equal(f.run('qqStats.totalUnique'), 3);
    assert.equal(f.run('qqStats.todayUnique'), 2);
    assert.equal(f.writes(), 1);
    assert.equal(fs.readFileSync(path.join(f.dir, 'total.count'), 'utf8'), '3\n');
    assert.equal(fs.readFileSync(path.join(f.dir, 'all-qq.txt'), 'utf8'), '11111\n22222\n33333\n');
    f.nextDay(); f.run('rolloverQqDay()');
    assert.equal(f.run('qqStats.todayUnique'), 0);
  } finally { f.close(); }
});
