'use strict';
// Run with Playwright available on NODE_PATH. Uses mocked API/WS, never production.
const { chromium } = require('playwright');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');

(async () => {
  const browser = await chromium.launch({ headless: true, channel: 'msedge' });
  try {
    const page = await browser.newPage({ viewport: { width: 390, height: 844 }, hasTouch: true });
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    page.on('console', msg => { if (msg.type() === 'warning' && msg.text().includes('面板初始化失败')) errors.push(msg.text()); });
    const writes = [];
    let failSave = false;
    await page.addInitScript(() => {
      localStorage.setItem('lb_token', 'test-only');
      window.WebSocket = class { close() {} };
    });
    await page.route('http://lb.test/**', async route => {
      const url = new URL(route.request().url());
      if (url.pathname.startsWith('/api/')) {
        const overview = { stats: {}, qqStats: {}, backends: [
          { id: 'a', url: 'http://one.test', weight: 3, alive: true, type: 'http', group: '9290', groups: ['9290', '9350'] },
          { id: 'b', url: 'http://two.test', weight: 8, alive: false, type: 'http', group: 'default' }
        ], groups: { default: { algorithm: 'round-robin' }, '9290': { algorithm: 'round-robin' }, '9350': { algorithm: 'round-robin' } }, rules: [], logs: [], algorithms: {} };
        if (route.request().method() === 'PUT') {
          writes.push(route.request().postDataJSON());
          return route.fulfill({ json: failSave ? { ret: -1, error: '测试保存失败' } : { ret: 0 } });
        }
        let data = [];
        if (url.pathname === '/api/overview') data = overview;
        if (url.pathname === '/api/config') data = { hc_interval: 5000 };
        return route.fulfill({ json: { ret: 0, data } });
      }
      const file = path.join(root, 'public', url.pathname === '/' ? 'index.html' : url.pathname);
      if (!fs.existsSync(file)) return route.fulfill({ status: 404, body: '' });
      return route.fulfill({ body: fs.readFileSync(file), contentType: file.endsWith('.js') ? 'application/javascript' : file.endsWith('.css') ? 'text/css' : 'text/html' });
    });
    await page.goto('http://lb.test/');
    const weight = page.locator('[data-backend-id="a"] .backend-weight-input');
    await weight.waitFor();
    await page.locator('#loginOverlay').waitFor({ state: 'hidden' });
    assert.equal(await page.evaluate(() => {
      const chart = state.chart, qqChart = state.qqChart;
      renderAll();
      return state.chart === chart && state.qqChart === qqChart;
    }), true, 'overview refresh must reuse charts');
    assert.match(await page.locator('[data-backend-id="a"] .group-picker-cell').innerText(), /9290/);
    assert.match(await page.locator('[data-backend-id="a"] .group-picker-cell').innerText(), /9350/);
    if (process.env.LB_UI_SCREENSHOTS) {
      fs.mkdirSync(process.env.LB_UI_SCREENSHOTS, { recursive: true });
      for (const width of [390, 1440]) {
        await page.setViewportSize({ width, height: 1000 });
        for (const theme of ['light', 'dark']) {
          await page.evaluate(theme => document.documentElement.setAttribute('data-theme', theme), theme);
          await page.waitForTimeout(400);
          await page.screenshot({ path: path.join(process.env.LB_UI_SCREENSHOTS, `${width}-${theme}.png`), animations: 'disabled' });
          const overflow = await page.evaluate(() => ({ width: innerWidth, scroll: document.documentElement.scrollWidth,
            elements: [...document.querySelectorAll('body *')].filter(el => el.getBoundingClientRect().right > innerWidth + 1 && !el.closest('.table-wrapper, .section-nav')).slice(-25).map(el => `${el.tagName}#${el.id}.${el.className}:${Math.round(el.getBoundingClientRect().right)}`) }));
          assert.ok(overflow.scroll <= overflow.width, `${width} ${theme} must not overflow: ${JSON.stringify(overflow)}`);
        }
      }
      await page.setViewportSize({ width: 390, height: 844 });
    }
    await weight.fill('');
    await page.evaluate(() => {
      window.originalWeightInput = document.activeElement;
      for (let i = 0; i < 8; i++) handleWS({ type: 'stats_update', data: { backends: state.backends.map(b => ({ ...b, totalRequests: i })) } });
    });
    assert.equal(await weight.inputValue(), '');
    assert.equal(await page.evaluate(() => document.activeElement === window.originalWeightInput), true);
    await weight.fill('25');
    await weight.press('Enter');
    await page.waitForFunction(() => !weightEdits.has('a'));
    assert.deepEqual(writes.at(-1), { weight: 25 });
    await weight.fill('');
    await weight.press('Enter');
    assert.equal(writes.length, 1, 'empty input must never save weight=1');
    failSave = true;
    await weight.fill('42');
    await weight.press('Enter');
    await page.waitForFunction(() => document.querySelector('[data-backend-id="a"] input').getAttribute('aria-invalid') === 'true');
    await page.evaluate(() => renderBackendTable());
    assert.equal(await weight.inputValue(), '42');
    failSave = false;
    await page.locator('[data-backend-id="a"] .group-picker-cell').click();
    if (process.env.LB_UI_SCREENSHOTS) await page.screenshot({ path: path.join(process.env.LB_UI_SCREENSHOTS, '390-groups-modal.png'), animations: 'disabled' });
    assert.deepEqual(await page.locator('#backendGroupOptions input:checked').evaluateAll(items => items.map(item => item.value)), ['9290', '9350']);
    await page.locator('#backendGroupsModalSave').click();
    assert.deepEqual(writes.at(-1), { groups: ['9290', '9350'] });
    await page.locator('#backendGroupsModal').waitFor({ state: 'hidden' });
    await page.evaluate(() => { state.backendQuery = 'two.test'; renderBackendTable(); });
    assert.equal(await page.locator('#backendTableBody tr').count(), 1);
    assert.match(await page.locator('#backendTableBody .status-badge').innerText(), /离线/);
    const setting = page.locator('#setHcInterval');
    await setting.fill('');
    await page.evaluate(() => renderSettings());
    await page.waitForTimeout(100);
    assert.equal(await setting.inputValue(), '');
    await page.evaluate(() => {
      window.logRenders = 0;
      const original = renderLogs;
      renderLogs = (...args) => { window.logRenders++; original(...args); };
      for (let i = 0; i < 100; i++) handleWS({ type: 'new_log', log: { id: `load-${i}`, path: '/test', method: 'GET', statusCode: 200 } });
    });
    await page.waitForTimeout(350);
    assert.equal(await page.evaluate(() => window.logRenders), 1, '100 log messages must coalesce to one render');
    await page.evaluate(() => showLogin());
    assert.equal(await page.locator('#loginOverlay').isVisible(), true, 'expired token must reveal login');
    assert.deepEqual(errors, []);
    console.log('PASS mobile input identity/focus, empty editing, save, failure drafts, filtered status, settings focus');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
