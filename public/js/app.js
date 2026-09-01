// ==================== 前端应用逻辑 v3.0 ====================

const state = {
  stats: {}, algorithms: {}, algorithm: {}, groups: {}, rules: [],
  backends: [], logs: [], proxyPresets: [],
  qqStats: { totalUnique: 0, todayUnique: 0, totalRequests: 0, qqHistory: [] },
  selectedGroup: 'default',
  editingTagId: null, chart: null, qqChart: null, ws: null, reconnectTimer: null,
  token: localStorage.getItem('lb_token') || null,
  pageTitle: '',
  backendFilter: 'all', backendQuery: '', refreshing: false, lastUpdated: 0,
};

const $ = id => document.getElementById(id);
const dom = {};
['navNodesOnline','navTotalReqs','navAlgorithm','navToggle','navStats','navStatusDot',
 'statTotalRequests','statOnlineNodes','statRps','statAvgResponse',
 'algoGrid','currentAlgoBadge','algoGroupSelector',
 'chartCanvas',
 'backendTableBody','backendEmpty','showAddBackendBtn','addBackendForm',
 'newBackendUrl','newBackendWeight','newBackendTag','newBackendGroup',
 'addBackendBtn','cancelAddBackendBtn',
 'logTableBody','logEmpty','logCount',
 'tagModal','tagModalUrl','tagModalInput','tagModalClose','tagModalCancel','tagModalSave',
 'loginOverlay','loginPassword','loginBtn','loginError','logoutBtn',
 'brandTitle','loginTitle',
 'showAddGroupBtn','addGroupForm','newGroupName','newGroupDesc','newGroupAlgo',
 'addGroupBtn','cancelAddGroupBtn','groupsList',
 'showAddRuleBtn','addRuleForm','newRulePath','newRuleMatchType','newRuleGroup','newRulePriority','rulePathHint',
 'addRuleBtn','cancelAddRuleBtn','rulesList',
  'setAgentToken','setHcInterval','setHcTimeout','setTunnelTimeout','setRequestTimeout','setMaxLog','setFrpPort','saveSettingsBtn','settingsStatus',
 'cfgServerAddr','cfgServerPort','cfgFrpPort','cfgAgentToken','cfgAgentCmd','cfgFrpcCmd','cfgCopyCmd','cfgCopyFrpcCmd',
 'showAddProxyBtn','addProxyForm','newProxyName','newProxyGroup','newProxyPort','newProxyKey',
 'addProxyBtn','cancelAddProxyBtn','proxyList',
 'agentTableBody','agentEmpty',
 'toastContainer','themeToggle',
 'statTotalQq','statTodayQq','statQqRequests',
  'statMaxDaily',
  'qqChartCanvas',
 'setPersistStats',
 'setVersionRewrite','setVersionTarget',
 'sessionsTableBody','sessionsEmpty',
 'setAutoBackup','setBackupInterval','setMaxBackupsLabel',
 'setRetry400','setRetry400Max',
 'setAdminPassword',
  'backupsTableBody','backupsEmpty'
  ,'dashboardGreeting','dashboardSubtext','serviceState','serviceStateDot','serviceStatusText','serviceStatusSub',
  'lastUpdated','refreshOverviewBtn','quickExportBtn','quickBackupBtn','backendSearch','backendVisibleCount',
  'backendCountAll','backendCountOnline','backendCountOffline'
].forEach(id => dom[id] = $(id));

function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

// ==================== Toast 通知系统 ====================
function toast(message, type = 'info', duration = 3000) {
  const icons = { success: '✓', error: '✕', warning: '⚠', info: 'ℹ' };
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.innerHTML = `<span class="toast-icon">${icons[type]||'ℹ'}</span><span class="toast-message">${esc(message)}</span><button class="toast-close" onclick="this.parentElement.classList.add('removing');setTimeout(()=>this.parentElement.remove(),200)">&times;</button>`;
  dom.toastContainer.appendChild(el);
  setTimeout(() => { if (el.isConnected) { el.classList.add('removing'); setTimeout(() => el.remove(), 200); } }, duration);
}

// ==================== 主题切换 ====================
function toggleTheme() {
  const html = document.documentElement;
  const current = html.getAttribute('data-theme');
  const next = current === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', next);
  localStorage.setItem('lb_theme', next);
  // 图表适配主题色
  if (state.chart) {
    const isDark = next === 'dark';
    state.chart.options.scales.y.grid.color = isDark ? 'rgba(255,255,255,.06)' : 'rgba(0,0,0,.04)';
    state.chart.update();
  }
}
dom.themeToggle?.addEventListener('click', toggleTheme);

// ==================== 路由规则提示 ====================
function updateRulePathHint() {
  const hint = dom.rulePathHint;
  if (!hint) return;
  hint.textContent = dom.newRuleMatchType.value === 'query'
    ? '例如 /sign?ver=xxx 仅匹配带该查询参数的请求'
    : dom.newRuleMatchType.value === 'json'
    ? '例如 /sign:ver=xxx 仅匹配请求体 JSON 中 ver=xxx 的请求'
    : '前缀匹配，如 /api/';
}

// ==================== 认证 ====================
function api(path, opts = {}) {
  if (!opts.headers) opts.headers = {};
  if (state.token) opts.headers['Authorization'] = 'Bearer ' + state.token;
  return fetch(path, opts);
}

function doLogin() {
  const pw = dom.loginPassword.value;
  if (!pw) return;
  dom.loginBtn.disabled = true;
  dom.loginBtn.textContent = '验证中...';
  dom.loginError.style.display = 'none';
  api('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: pw }) })
    .then(r => r.json()).then(d => {
      if (d.ret === 0) {
        state.token = d.token;
        localStorage.setItem('lb_token', d.token);
        dom.loginOverlay.style.display = 'none';
        dom.logoutBtn.style.display = '';
        connectWS();
        fetchOverview();
        toast('登录成功', 'success');
      } else {
        dom.loginError.textContent = d.error || '密码错误';
        dom.loginError.style.display = 'block';
      }
    })
    .catch(() => { dom.loginError.textContent = '连接失败'; dom.loginError.style.display = 'block'; })
    .finally(() => { dom.loginBtn.disabled = false; dom.loginBtn.textContent = '登 录'; });
}

function doLogout() {
  api('/api/logout', { method: 'POST' }).catch(() => {}).finally(() => {
    state.token = null;
    localStorage.removeItem('lb_token');
    if (state.ws) { try { state.ws.close(); } catch (_) {} state.ws = null; }
    location.reload();
  });
}

dom.loginBtn.addEventListener('click', doLogin);
dom.loginPassword.addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
dom.logoutBtn.addEventListener('click', doLogout);

// ==================== WebSocket ====================
function connectWS() {
  if (state.ws) { try { state.ws.close(); } catch(_) {} }
  if (!state.token) return;
  const url = `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/ws?token=${encodeURIComponent(state.token)}`;
  state.ws = new WebSocket(url);
  state.ws.onopen = () => setServiceState('online', '实时连接', 'WebSocket 已连接');
  state.ws.onmessage = e => { try { handleWS(JSON.parse(e.data)); } catch(_) {} };
  state.ws.onclose = () => {
    setServiceState('syncing', '轮询模式', '实时通道断开，5 秒后重连');
    state.reconnectTimer = setTimeout(connectWS, 5000);
  };
  state.ws.onerror = () => state.ws.close();
}

function handleWS(msg) {
  if (msg.type === 'init') { Object.assign(state, msg.data); if (msg.data.qqStats) state.qqStats = msg.data.qqStats; if (msg.data.proxy_presets) state.proxyPresets = msg.data.proxy_presets; renderAll(); }
  else if (msg.type === 'proxies_updated') { state.proxyPresets = msg.proxies; renderProxyList(); }
  else if (msg.type === 'stats_update') {
    if (msg.data.stats) Object.assign(state.stats, msg.data.stats);
    if (msg.data.qqStats) Object.assign(state.qqStats, msg.data.qqStats);
    if (msg.data.backends) { state.backends = msg.data.backends; renderBackendTable(); updateBackendStatus(); }
    renderStats(); updateChart(); updateQqChart(); qqStatsDisplay();
  }
  else if (msg.type === 'new_log') { state.logs.unshift(msg.log); if (state.logs.length>200) state.logs.pop(); renderLogs(true); }
  else if (msg.type === 'update_log' && msg.log) {
    const index = state.logs.findIndex(log => log.id === msg.log.id);
    if (index >= 0) state.logs[index] = { ...state.logs[index], ...msg.log };
    else state.logs.unshift(msg.log);
    if (state.logs.length > 200) state.logs.pop();
    renderLogs(false);
  }
  else if (msg.type === 'groups_updated') { if (msg.groups) { state.groups = msg.groups; renderGroups(); renderGroupSelector(); } }
  else if (msg.type === 'rules_updated') { if (msg.rules) { state.rules = msg.rules; renderRules(); } }
  else if (msg.type === 'backend_added' || msg.type === 'backend_removed' || msg.type === 'backend_updated' || msg.type === 'backend_down' || msg.type === 'backend_recovered') { fetchOverview(); }
  else if (msg.type === 'algorithm_changed') { fetchOverview(); }
  else if (msg.type === 'config_updated') { /* handled by settings */ }
  else fetchOverview();
}

// ==================== 数据获取 ====================
async function fetchOverview() {
  if (state.refreshing) return;
  state.refreshing = true;
  setServiceState('syncing', '同步中', '正在读取最新运行状态');
  dom.refreshOverviewBtn?.classList.add('loading');
  try {
    const response = await api('/api/overview?_t=' + Date.now());
    if (response.status === 401) { showLogin(); return; }
    const r = await response.json();
    if (r.ret === 0) {
      Object.assign(state, r.data);
      state.lastUpdated = Date.now();
      const online = r.data?.stats?.aliveBackends || 0;
      const total = r.data?.stats?.totalBackends || 0;
      setServiceState('online', '服务正常', `${online}/${total} 个节点可用`);
      if (dom.lastUpdated) dom.lastUpdated.textContent = '刚刚更新';
    } else {
      setServiceState('warning', '响应异常', r.error || '服务返回了错误');
    }
    if (!state.groups || !state.groups.default) state.groups = { default: { algorithm: 'round-robin', description: '默认分组' } };
    renderAll();
  } catch(_) {
    setServiceState('offline', '服务不可达', '请检查 Node.js、Nginx 或端口');
  } finally {
    state.refreshing = false;
    dom.refreshOverviewBtn?.classList.remove('loading');
  }
}

function setServiceState(kind, title, sub) {
  if (!dom.serviceState) return;
  dom.serviceState.className = `service-state ${kind}`;
  if (dom.serviceStatusText) dom.serviceStatusText.textContent = title;
  if (dom.serviceStatusSub) dom.serviceStatusSub.textContent = sub;
}

function renderAll() { renderStats(); qqStatsDisplay(); renderGroupSelector(); renderAlgorithms(); renderBackendTable(); renderAgentTable(); renderLogs(); renderGroups(); renderRules(); renderSettings(); renderFrpcConfig(); renderProxyList(); initChart(); initQqChart(); fetchSessions(); fetchBackups(); applyTitle(); }

/** 应用页面标题（来自 config.json page_title） */
function applyTitle() {
  const title = state.page_title || state.stats?.page_title || '负载均衡管理面板';
  if (title) {
    document.title = title;
    const el = dom.loginTitle;
    if (el) el.textContent = title;
  }
}

// ==================== 统计 ====================
function renderStats() {
  const s = state.stats || {};
  const online = s.aliveBackends || 0;
  dom.navNodesOnline.textContent = online;
  dom.navTotalReqs.textContent = (s.totalRequests || 0).toLocaleString();
  dom.navStatusDot.className = `nav-stat-dot ${online > 0 ? 'pulse green' : 'red'}`;
  const dfltAlgo = state.groups?.default?.algorithm || '轮询';
  dom.navAlgorithm.textContent = state.algorithms[dfltAlgo]?.name || dfltAlgo;
  dom.statTotalRequests.textContent = (s.totalRequests || 0).toLocaleString();
  dom.statOnlineNodes.innerHTML = `${online} <small>/ ${s.totalBackends || 0}</small>`;
  dom.statRps.textContent = s.currentRps || 0;
  const rt = s.historyResponseTime ? s.historyResponseTime.filter(v=>v>0) : [];
  dom.statAvgResponse.textContent = rt.length ? Math.round(rt.reduce((a,b)=>a+b,0)/rt.length)+'ms' : '0ms';
  if (dom.dashboardGreeting) {
    const hour = new Date().getHours();
    dom.dashboardGreeting.textContent = `${hour < 6 ? '夜深了' : hour < 12 ? '早上好' : hour < 18 ? '下午好' : '晚上好'}，欢迎回到控制台`;
  }
}

// ==================== 算法选择 ====================
function renderGroupSelector() {
  const sel = dom.algoGroupSelector;
  const current = state.selectedGroup || 'default';
  sel.innerHTML = Object.keys(state.groups||{}).map(g => `<option value="${g}" ${g===current?'selected':''}>${g}</option>`).join('');
  sel.onchange = () => { state.selectedGroup = sel.value; renderAlgorithms(); };
}

function renderAlgorithms() {
  const algos = state.algorithms;
  const group = state.selectedGroup || 'default';
  const current = state.groups[group]?.algorithm || 'round-robin';
  dom.currentAlgoBadge.textContent = `${group}: ${algos[current]?.name || current}`;
  dom.algoGrid.innerHTML = Object.entries(algos).map(([k,v]) => `
    <div class="algo-card ${k===current?'active':''}" data-algo="${k}">
      <div class="algo-card-check">✓</div>
      <div class="algo-card-icon">${v.icon||'⚙️'}</div>
      <div class="algo-card-name">${v.name}</div>
      <div class="algo-card-desc">${v.description||''}</div>
    </div>`).join('');
  dom.algoGrid.querySelectorAll('.algo-card').forEach(el => {
    el.addEventListener('click', () => switchAlgorithm(el.dataset.algo));
  });
}

async function switchAlgorithm(algo) {
  const group = state.selectedGroup || 'default';
  try {
    const r = await (await api('/api/algorithm', { method:'PUT',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ algorithm: algo, group })
    })).json();
    if (r.ret === 0) {
      state.groups[group].algorithm = algo;
      if (group === 'default') state.algorithm = r.data;
      renderAlgorithms(); renderStats(); renderGroups();
      toast(`分组「${group}」算法已切换为 ${state.algorithms[algo]?.name||algo}`, 'success');
    }
  } catch(_) {}
}

// ==================== 图表 ====================
function initChart() {
  if (!dom.chartCanvas || typeof Chart === 'undefined') return;
  if (state.chart) { state.chart.destroy(); }
  const labels = Array.from({length:60}, (_,i)=>`${i}s`);
  const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
  const gridColor = isDark ? 'rgba(255,255,255,.06)' : 'rgba(0,0,0,.04)';
  state.chart = new Chart(dom.chartCanvas.getContext('2d'), {
    type: 'line',
    data: {
      labels,
      datasets: [
        { label:'请求数', data:state.stats.historyRequests||[], borderColor:'#6366f1', backgroundColor:'rgba(99,102,241,.1)', fill:true, tension:.3, pointRadius:0, borderWidth:2, yAxisID:'y' },
        { label:'响应时间(ms)', data:state.stats.historyResponseTime||[], borderColor:'#f97316', backgroundColor:'rgba(249,115,22,.1)', fill:true, tension:.3, pointRadius:0, borderWidth:2, yAxisID:'y1' }
      ]
    },
    options: {
      responsive:true, maintainAspectRatio:false, interaction:{mode:'index',intersect:false},
      plugins:{legend:{display:false}},
      scales:{
        x:{display:true,grid:{display:false},ticks:{maxTicksLimit:12,font:{size:10},color:'#94a3b8'}},
        y:{display:true,beginAtZero:true,grid:{color:gridColor},ticks:{font:{size:10},color:'#94a3b8'}},
        y1:{display:true,beginAtZero:true,position:'right',grid:{display:false},ticks:{font:{size:10},color:'#94a3b8'}}
      },
      animation:{duration:300}
    }
  });
}

function updateChart() {
  if (!state.chart) return;
  state.chart.data.datasets[0].data = state.stats.historyRequests || [];
  state.chart.data.datasets[1].data = state.stats.historyResponseTime || [];
  state.chart.update('none');
}

// ==================== QQ 统计 ====================
function qqStatsDisplay() {
  const q = state.qqStats || {};
  dom.statTotalQq.textContent = (q.totalUnique || 0).toLocaleString();
  dom.statTodayQq.textContent = (q.todayUnique || 0).toLocaleString();
  dom.statQqRequests.textContent = (q.totalRequests || 0).toLocaleString();
  // 峰值
  const hist = q.qqHistory || [];
  const peak = hist.length ? Math.max(...hist) : 0;
  const peakIdx = hist.indexOf(peak);
  dom.statMaxDaily.textContent = `${peak.toLocaleString()}/min`;
  dom.statMaxDaily.title = peakIdx >= 0 ? `峰值发生在 ${peakIdx}s` : '';
}

function initQqChart() {
  if (!dom.qqChartCanvas || typeof Chart === 'undefined') return;
  if (state.qqChart) { state.qqChart.destroy(); }
  const labels = Array.from({length:60}, (_,i)=>`${i}s`);
  const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
  const gridColor = isDark ? 'rgba(255,255,255,.06)' : 'rgba(0,0,0,.04)';
  state.qqChart = new Chart(dom.qqChartCanvas.getContext('2d'), {
    type: 'bar',
    data: {
      labels,
      datasets: [
        { label:'新增QQ数', data:state.qqStats.qqHistory||[], backgroundColor:'rgba(236,72,153,.6)', borderColor:'#ec4899', borderWidth:1, borderRadius:2, yAxisID:'y' }
      ]
    },
    options: {
      responsive:true, maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{
        x:{display:true,grid:{display:false},ticks:{maxTicksLimit:12,font:{size:10},color:'#94a3b8'}},
        y:{display:true,beginAtZero:true,grid:{color:gridColor},ticks:{font:{size:10},color:'#94a3b8'}}
      },
      animation:{duration:300}
    }
  });
}

function updateQqChart() {
  if (!state.qqChart) return;
  state.qqChart.data.datasets[0].data = state.qqStats.qqHistory || [];
  state.qqChart.update('none');
}

// ==================== 后端节点管理 ====================
function renderBackendTable() {
  const backends = state.backends || [];
  const query = String(state.backendQuery || '').trim().toLowerCase();
  const filter = state.backendFilter || 'all';
  const filtered = backends.filter(b => {
    const online = !b.disabled && (b.alive || b.disable_health_check);
    if (filter === 'online' && !online) return false;
    if (filter === 'offline' && online) return false;
    if (!query) return true;
    return [b.url, b.tag, b.group, b.remoteAddress, b.type].some(v => String(v || '').toLowerCase().includes(query));
  });
  const onlineCount = backends.filter(b => !b.disabled && (b.alive || b.disable_health_check)).length;
  if (dom.backendCountAll) dom.backendCountAll.textContent = backends.length;
  if (dom.backendCountOnline) dom.backendCountOnline.textContent = onlineCount;
  if (dom.backendCountOffline) dom.backendCountOffline.textContent = backends.length - onlineCount;
  if (dom.backendVisibleCount) dom.backendVisibleCount.textContent = `显示 ${filtered.length} / ${backends.length} 个节点`;
  if (dom.backendEmpty) {
    dom.backendEmpty.style.display = filtered.length ? 'none' : 'block';
    const emptyText = dom.backendEmpty.querySelector('.empty-text');
    if (emptyText) emptyText.textContent = backends.length ? '没有符合当前筛选条件的节点' : '暂无后端节点，请点击上方「添加节点」';
  }
  dom.backendTableBody.innerHTML = filtered.map(b => {
    const isTunnel = b.type === 'tunnel';
    const isFrp = b.type === 'frp';
    const groupOpts = Object.keys(state.groups||{}).map(g => `<option value="${g}" ${(b.group||'default')===g?'selected':''}>${g}</option>`).join('');
    const statusLabel = b.disabled ? '已禁用' : (b.alive ? '在线' : (b.disable_health_check ? '在线(免检)' : '离线'));
    const online = b.disabled ? 'offline' : (b.alive ? 'online' : 'offline');
    const typeBadge = isTunnel ? '<span class="type-badge tunnel">Agent</span>' : (isFrp ? '<span class="type-badge frp">FRP</span>' : '<span class="type-badge http">HTTP</span>');
    const addr = isTunnel ? `<span style="font-size:12px;color:var(--text-secondary)">${esc(b.tag)}</span>` : (isFrp ? `<code style="font-size:12px">frp:${esc(b.tag)}</code>` : `<code style="font-size:12px">${esc(b.url)}</code>`);
    return `<tr data-backend-id="${esc(b.id)}" ${b.disabled?'style="opacity:0.5"':''}>
      <td><span class="status-badge ${online}"><span class="status-dot ${online}"></span>${statusLabel}</span></td>
      <td>${typeBadge}</td>
      <td>${addr}</td>
      <td><select class="form-input" style="width:auto;padding:2px 4px;font-size:11px" onchange="changeBackendGroup('${b.id}',this.value)">${groupOpts}</select></td>
      <td><strong>${b.weight||1}</strong></td>
      <td><span class="tag-display" onclick="openTagModal('${b.id}')"><span class="tag-text">${esc(b.tag||'添加标签')}</span><span class="tag-edit-icon">✏️</span></span></td>
      <td>${b.connections||0}</td>
      <td>${b.responseTime?b.responseTime+'ms':'-'}</td>
      <td>${(b.totalRequests||0).toLocaleString()}</td>
      <td><div style="display:flex;gap:4px;flex-wrap:wrap"><button class="btn-icon" onclick="toggleDisabled('${b.id}', ${b.disabled})" title="${b.disabled?'已禁用，点击启用':'启用此节点'}">${b.disabled?'▶️':'⏸️'}</button>${!b.alive && !b.disabled ? `<button class="btn-icon" onclick="reviveBackend('${b.id}')" title="标记为在线">✅</button>` : ''}<button class="btn-icon" onclick="toggleHealthCheck('${b.id}', ${b.disable_health_check})" title="${b.disable_health_check?'已禁用健康检查，点击启用':'健康检查已启用，点击禁用'}">${b.disable_health_check?'🚫':'💚'}</button><button class="btn-icon" onclick="openTagModal('${b.id}')" title="编辑标签">🏷️</button><button class="btn-icon" onclick="deleteBackend('${b.id}')" title="删除">🗑️</button></div></td>
    </tr>`;
  }).join('');
}

function setBackendFilter(filter) {
  state.backendFilter = filter;
  document.querySelectorAll('[data-backend-filter]').forEach(btn => {
    const active = btn.dataset.backendFilter === filter;
    btn.classList.toggle('active', active);
    btn.setAttribute('aria-pressed', active ? 'true' : 'false');
  });
  renderBackendTable();
}

function refreshOverview() { fetchOverview(); }

dom.backendSearch?.addEventListener('input', e => {
  state.backendQuery = e.target.value;
  renderBackendTable();
});
document.querySelectorAll('[data-backend-filter]').forEach(btn => {
  btn.addEventListener('click', () => setBackendFilter(btn.dataset.backendFilter));
});
dom.refreshOverviewBtn?.addEventListener('click', refreshOverview);
dom.quickExportBtn?.addEventListener('click', exportConfig);
dom.quickBackupBtn?.addEventListener('click', backupNow);
document.addEventListener('keydown', e => {
  if (e.key.toLowerCase() === 'r' && !/input|textarea|select/i.test(e.target.tagName)) {
    e.preventDefault(); refreshOverview();
  }
  if (e.key === '/' && !/input|textarea|select/i.test(e.target.tagName)) {
    e.preventDefault(); dom.backendSearch?.focus();
  }
});

async function reviveBackend(id) {
  const r = await (await api(`/api/backends/${id}/revive`, { method: 'POST' })).json();
  if (r.ret === 0) {
    fetchOverview();
    toast('已恢复在线（健康检查已自动关闭）', 'success');
  }
}

async function toggleHealthCheck(id, currentlyEnabled) {
  // currentlyEnabled = !b.disable_health_check（onclick 传入的是"是否已启用健康检查"）
  const v = !currentlyEnabled;  // 取反得到新的 disable_health_check 值
  const r = await api(`/api/backends/${id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ disable_health_check: v }) });
  const d = await r.json();
  if (d.ret === 0) {
    const b = (state.backends || []).find(x => x.id === id);
    if (b) b.disable_health_check = v;
    renderBackendTable();
    toast(v ? '已禁用健康检查（始终视为在线）' : '已启用健康检查', 'info');
  } else {
    toast('操作失败: ' + (d.error || '未知错误'), 'error');
  }
  fetchOverview();
}

async function toggleDisabled(id, currentDisabled) {
  // currentDisabled 参数实为 "当前 disabled 的反值"，直接反转即可
  const v = !currentDisabled;
  const r = await api(`/api/backends/${id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ disabled: v }) });
  const d = await r.json();
  if (d.ret === 0) {
    const b = (state.backends || []).find(x => x.id === id);
    if (b) { b.disabled = v; b.alive = !v; }
    renderBackendTable();
    toast(v ? '已禁用此节点（不再接收请求）' : '已启用此节点', 'info');
  } else {
    toast(d.error || '操作失败', 'error');
  }
  fetchOverview();
}

async function deleteBackend(id) {
  if (!confirm('确定删除？')) return;
  const r = await (await api(`/api/backends/${id}`,{method:'DELETE'})).json();
  if (r.ret === 0) { fetchOverview(); toast('节点已删除', 'success'); }
}

async function changeBackendGroup(id, group) {
  const r = await (await api(`/api/backends/${id}`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({group})})).json();
  if (r.ret === 0) fetchOverview();
}

function updateBackendStatus() {
  const backends = state.backends || [];
  const rows = dom.backendTableBody.querySelectorAll('tr');
  for (let i = 0; i < Math.min(rows.length, backends.length); i++) {
    const b = backends[i];
    const cells = rows[i].children;
    if (cells[0]) {
      const badge = cells[0].querySelector('.status-badge');
      const dot = cells[0].querySelector('.status-dot');
      if (badge && dot) {
        const cls = b.alive ? 'online' : 'offline';
        badge.className = 'status-badge ' + cls;
        dot.className = 'status-dot ' + cls;
        if (badge.childNodes[1]) badge.childNodes[1].textContent = b.alive ? '在线' : '离线';
      }
    }
    if (cells[6]) cells[6].textContent = b.connections || 0;
    if (cells[7]) cells[7].textContent = b.responseTime ? b.responseTime + 'ms' : '-';
    if (cells[8]) cells[8].textContent = (b.totalRequests || 0).toLocaleString();
  }
}

dom.showAddBackendBtn.addEventListener('click', ()=>{
  dom.addBackendForm.style.display='block';
  dom.newBackendUrl.focus();
  updateGroupDropdown(dom.newBackendGroup);
});
dom.cancelAddBackendBtn.addEventListener('click', ()=>{
  dom.addBackendForm.style.display='none';
  dom.newBackendUrl.value=''; dom.newBackendWeight.value='1'; dom.newBackendTag.value='';
});
dom.addBackendBtn.addEventListener('click', async ()=>{
  const url = dom.newBackendUrl.value.trim();
  if (!url) return toast('请输入后端地址', 'warning');
  if (!url.startsWith('http://')&&!url.startsWith('https://')) return toast('地址须以 http:// 开头', 'warning');
  const r = await (await api('/api/backends',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({url,weight:parseInt(dom.newBackendWeight.value)||1,tag:dom.newBackendTag.value.trim(),group:dom.newBackendGroup.value})})).json();
  if (r.ret===0){ dom.addBackendForm.style.display='none'; dom.newBackendUrl.value=''; dom.newBackendWeight.value='1'; dom.newBackendTag.value=''; fetchOverview(); toast('节点已添加', 'success'); }
  else toast(r.error||'添加失败', 'error');
});

// ==================== 分组管理 ====================
function renderGroups() {
  const gs = state.groups || {};
  const algos = state.algorithms || {};
  dom.groupsList.innerHTML = Object.entries(gs).map(([name, g]) => {
    const bc = (state.backends||[]).filter(b=>(b.group||'default')===name).length;
    const algoName = algos[g.algorithm]?.name || g.algorithm;
    return `<div class="group-card">
      <div class="group-card-info">
        <span class="group-card-name">📁 ${esc(name)}</span>
        <span class="group-card-algo">${algoName}</span>
        <span class="group-card-desc">${esc(g.description||'')}</span>
        <span class="group-card-count">${bc} 个后端</span>
      </div>
      <div style="display:flex;gap:4px;align-items:center">
        ${name!=='default'?`<button class="btn btn-danger btn-xs" onclick="deleteGroup('${name}')">删除</button>`:''}
        <select class="form-input" style="width:auto;padding:2px 6px;font-size:12px" onchange="changeGroupAlgo('${name}',this.value)">
          ${Object.entries(algos).map(([k,v])=>`<option value="${k}" ${k===g.algorithm?'selected':''}>${v.name}</option>`).join('')}
        </select>
      </div>
    </div>`;
  }).join('');
}

async function changeGroupAlgo(name, algo) {
  const r = await (await api('/api/groups',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,algorithm:algo})})).json();
  if (r.ret===0) { state.groups = r.data; renderGroups(); renderAlgorithms(); renderGroupSelector(); toast(`分组「${name}」算法已更新`, 'success'); }
}

async function deleteGroup(name) {
  if (!confirm(`删除分组「${name}」？其中的后端将移回 default 分组`)) return;
  const r = await (await api(`/api/groups/${name}`,{method:'DELETE'})).json();
  if (r.ret===0) { state.groups = r.data; fetchOverview(); toast(`分组「${name}」已删除`, 'success'); }
}

dom.showAddGroupBtn.addEventListener('click', () => {
  dom.addGroupForm.style.display='block';
  dom.newGroupName.focus();
  updateAlgoDropdown(dom.newGroupAlgo);
});
dom.cancelAddGroupBtn.addEventListener('click', ()=>{ dom.addGroupForm.style.display='none'; dom.newGroupName.value=''; dom.newGroupDesc.value=''; });
dom.addGroupBtn.addEventListener('click', async ()=>{
  const name = dom.newGroupName.value.trim();
  if (!name) return toast('请输入分组名称', 'warning');
  const r = await (await api('/api/groups',{method:'PUT',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({name,algorithm:dom.newGroupAlgo.value,description:dom.newGroupDesc.value.trim()})})).json();
  if (r.ret===0) { dom.addGroupForm.style.display='none'; dom.newGroupName.value=''; dom.newGroupDesc.value=''; state.groups=r.data; renderGroups(); renderGroupSelector(); toast('分组已创建', 'success'); }
  else toast(r.error||'创建失败', 'error');
});

// ==================== 路由规则 ====================
function renderRules() {
  const rules = state.rules || [];
  dom.rulesList.innerHTML = rules.length ? rules.map(r => {
    const matchTypeLabel = r.matchType === 'query' ? '查询参数' : r.matchType === 'json' ? 'JSON字段' : '前缀匹配';
    return `<div class="rule-item">
      <div class="rule-item-left">
        <span class="rule-path">${esc(r.path)}</span>
        <span class="rule-arrow">→</span>
        <span class="rule-group">📁 ${esc(r.group)}</span>
      </div>
      <div class="rule-item-right">
        <span class="rule-tag ${r.matchType === 'query' ? 'rule-tag-query' : r.matchType === 'json' ? 'rule-tag-json' : 'rule-tag-prefix'}">${matchTypeLabel}</span>
        <span class="rule-priority">优先级 ${r.priority}</span>
        <button class="btn btn-icon" onclick="editRule(${r.id})" title="编辑">✏️</button>
        <button class="btn btn-danger btn-xs" onclick="deleteRule(${r.id})">删除</button>
      </div>
    </div>`;
  }).join('') : '<div class="empty-state">暂无路由规则，所有请求走 default 分组</div>';
}

async function editRule(id) {
  const r = (state.rules || []).find(x => x.id === id);
  if (!r) return;
  // 填充表单
  dom.newRulePath.value = r.path;
  dom.newRuleMatchType.value = r.matchType || 'prefix';
  updateGroupDropdown(dom.newRuleGroup);
  dom.newRuleGroup.value = r.group;
  dom.newRulePriority.value = r.priority;
  updateRulePathHint();
  dom.addRuleForm.style.display = 'block';
  dom.newRulePath.focus();
  // 替换添加按钮行为为更新
  dom.addRuleBtn._editId = id;
  dom.addRuleBtn.textContent = '更新';
  dom.addRuleBtn.onclick = async () => {
    const path = dom.newRulePath.value.trim();
    if (!path) return toast('请输入路径前缀', 'warning');
    const matchType = dom.newRuleMatchType.value;
    if (matchType === 'query' && !path.includes('?')) return toast('查询参数匹配的路径须包含 ?，例如 /sign?ver=xxx', 'warning');
  if (matchType === 'json' && !path.includes(':')) return toast('JSON字段匹配格式为 /path:key=value，例如 /sign:ver=xxx', 'warning');
    const body = { path, group: dom.newRuleGroup.value, priority: parseInt(dom.newRulePriority.value) || 0, matchType };
    if (r.path === body.path) delete body.path;
    if ((r.matchType || 'prefix') === body.matchType) delete body.matchType;
    if (r.group === body.group) delete body.group;
    if (r.priority === body.priority) delete body.priority;
    if (Object.keys(body).length === 0) { resetRuleForm(); return; }
    const res = await (await api(`/api/rules/${id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })).json();
    if (res.ret === 0) { resetRuleForm(); fetchOverview(); toast('规则已更新', 'success'); }
    else toast(res.error || '更新失败', 'error');
  };
}

function resetRuleForm() {
  dom.addRuleForm.style.display = 'none';
  dom.newRulePath.value = '';
  dom.newRulePriority.value = '10';
  dom.addRuleBtn.textContent = '添加';
  dom.addRuleBtn._editId = null;
  dom.addRuleBtn.onclick = defaultAddRuleHandler;
}

async function defaultAddRuleHandler() {
  const path = dom.newRulePath.value.trim();
  if (!path) return toast('请输入路径前缀', 'warning');
  const matchType = dom.newRuleMatchType.value;
  if (matchType === 'query' && !path.includes('?')) return toast('查询参数匹配的路径须包含 ?，例如 /sign?ver=xxx', 'warning');
  if (matchType === 'json' && !path.includes(':')) return toast('JSON字段匹配格式为 /path:key=value，例如 /sign:ver=xxx', 'warning');
  const r = await (await api('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({path,group:dom.newRuleGroup.value,priority:parseInt(dom.newRulePriority.value)||0,matchType})})).json();
  if (r.ret===0) { dom.addRuleForm.style.display='none'; dom.newRulePath.value=''; dom.newRulePriority.value='10'; fetchOverview(); toast('规则已添加', 'success'); }
  else toast(r.error||'添加失败', 'error');
}

dom.addRuleBtn.onclick = defaultAddRuleHandler;

// 规则表单显示/取消事件
dom.showAddRuleBtn.addEventListener('click', () => {
  resetRuleForm();
  dom.addRuleForm.style.display = 'block';
  dom.newRulePath.focus();
  updateGroupDropdown(dom.newRuleGroup);
  updateRulePathHint();
});
dom.cancelAddRuleBtn.addEventListener('click', resetRuleForm);

// ==================== 系统设置（自动保存失焦） ====================
let settingsAutoSaveDone = false;
function renderSettings() {
  api('/api/config').then(r=>r.json()).then(d=>{
    if (d.ret===0) {
      dom.setAgentToken.value = d.data.agent_token||'';
      dom.setHcInterval.value = d.data.hc_interval||5000;
      dom.setHcTimeout.value = d.data.hc_timeout||3000;
      dom.setTunnelTimeout.value = d.data.tunnel_timeout||30000;
      dom.setRequestTimeout.value = d.data.request_timeout||120000;
      dom.setMaxLog.value = d.data.max_log||500;
      dom.setFrpPort.value = d.data.frp_port||7000;
      ['setAgentToken','setHcInterval','setHcTimeout','setTunnelTimeout','setRequestTimeout','setMaxLog','setFrpPort'].forEach(id => {
        dom[id]._sv = dom[id].value;
      });
      dom.setPersistStats.checked = d.data.persist_stats !== false;
      dom.setVersionRewrite.checked = d.data.version_rewrite_enabled === true;
      dom.setVersionTarget.value = d.data.version_rewrite_target || '9.2.70';
      dom.setAutoBackup.checked = d.data.auto_backup_enabled !== false;
      dom.setBackupInterval.value = String(d.data.auto_backup_interval || 21600000);
      dom.setMaxBackupsLabel.textContent = d.data.max_backups || 30;
      dom.setRetry400.checked = d.data.retry_400_enabled !== false;
      dom.setRetry400Max.value = d.data.retry_400_max || 2;
    }
  });
  if (settingsAutoSaveDone) return;
  settingsAutoSaveDone = true;
  autoSaveSetting(dom.setAgentToken, 'agent_token', v => v.trim());
  autoSaveSetting(dom.setHcInterval, 'hc_interval', v => parseInt(v)||5000);
  autoSaveSetting(dom.setHcTimeout, 'hc_timeout', v => parseInt(v)||3000);
  autoSaveSetting(dom.setTunnelTimeout, 'tunnel_timeout', v => parseInt(v)||30000);
  autoSaveSetting(dom.setRequestTimeout, 'request_timeout', v => Math.max(60000, Math.min(600000, parseInt(v) || 120000)));
  autoSaveSetting(dom.setMaxLog, 'max_log', v => parseInt(v)||500);
  autoSaveSetting(dom.setFrpPort, 'frp_port', v => parseInt(v)||7000);
  // 管理员密码（修改后需重新登录）
  dom.setAdminPassword.addEventListener('change', () => {
    const v = dom.setAdminPassword.value.trim();
    if (!v) return;
    if (v.length < 4) { toast('密码至少 4 位', 'error'); dom.setAdminPassword.value = ''; return; }
    api('/api/config', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ admin_password: v }) })
      .then(r => r.json()).then(d => {
        if (d.ret === 0) { toast('密码已更新，请重新登录', 'success'); dom.setAdminPassword.value = ''; setTimeout(() => location.reload(), 1500); }
        else toast('失败: ' + d.error, 'error');
      });
  });
  dom.saveSettingsBtn.style.display = 'none';
  // persist_stats 开关 — 即时保存
  dom.setPersistStats.addEventListener('change', () => {
    api('/api/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({persist_stats:dom.setPersistStats.checked})})
      .then(r=>r.json()).then(d=>{if(d.ret===0)toast(d.data.persist_stats?'已启用统计持久化':'已关闭统计持久化','info')});
  });
  // ver 改写开关
  dom.setVersionRewrite.addEventListener('change', () => {
    api('/api/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({version_rewrite_enabled:dom.setVersionRewrite.checked})})
      .then(r=>r.json()).then(d=>{if(d.ret===0)toast(d.data.version_rewrite_enabled?'ver 改写已启用 → '+dom.setVersionTarget.value:'ver 改写已关闭','info')});
  });
  // ver 目标版本
  dom.setVersionTarget.addEventListener('blur', () => {
    const v = dom.setVersionTarget.value.trim() || '9.2.70';
    api('/api/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({version_rewrite_target:v})})
      .then(r=>r.json()).then(d=>{if(d.ret===0)toast('ver 目标版本已设为 '+v,'info')});
  });
  // 自动备份开关
  dom.setAutoBackup.addEventListener('change', () => {
    api('/api/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({auto_backup_enabled:dom.setAutoBackup.checked})})
      .then(r=>r.json()).then(d=>{if(d.ret===0)toast(d.data.auto_backup_enabled?'已启用自动备份':'已关闭自动备份','info')});
  });
  // 备份间隔
  dom.setBackupInterval.addEventListener('change', () => {
    const v = parseInt(dom.setBackupInterval.value) || 21600000;
    api('/api/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({auto_backup_interval:v})})
      .then(r=>r.json()).then(d=>{if(d.ret===0)toast('备份间隔已更新','info')});
  });
  // 400 自动重试开关
  dom.setRetry400.addEventListener('change', () => {
    api('/api/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({retry_400_enabled:dom.setRetry400.checked})})
      .then(r=>r.json()).then(d=>{if(d.ret===0)toast(d.data.retry_400_enabled?'400 自动重试已启用':'400 自动重试已关闭','info')});
  });
  // 最大重试次数（即时保存）
  dom.setRetry400Max.addEventListener('change', () => {
    const v = Math.max(1, Math.min(5, parseInt(dom.setRetry400Max.value) || 2));
    dom.setRetry400Max.value = v;
    api('/api/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({retry_400_max:v})})
      .then(r=>r.json()).then(d=>{if(d.ret===0)toast('同节点重试次数已设为 '+v,'info')});
  });
}

function autoSaveSetting(el, key, transform) {
  el.addEventListener('blur', () => {
    const v = transform(el.value);
    if (v === el._sv) return;
    api('/api/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({[key]:v})})
      .then(r=>r.json()).then(d=>{if(d.ret===0){el._sv=v;flashStatus('✅ 已自动保存')}});
  });
}

function flashStatus(text) {
  dom.settingsStatus.textContent = text;
  dom.settingsStatus.style.color = 'var(--success)';
  setTimeout(()=>{ dom.settingsStatus.textContent='已保存'; dom.settingsStatus.style.color=''; }, 2000);
}

// ==================== 日志 ====================
function renderLogs(isNew) {
  const logs = state.logs || [];
  dom.logEmpty.style.display = logs.length ? 'none' : 'block';
  dom.logCount.textContent = `${logs.length}`;
  dom.logTableBody.innerHTML = logs.slice(0,50).map((log,i) => {
    const isAgent = log.method === 'AGENT';
    const isConnect = log.algorithm === 'connect';
    const isDisconnect = log.algorithm === 'disconnect';
    const m = isAgent ? 'agent' : (log.method||'GET').toLowerCase();
    const sc = isConnect ? 'success' : isDisconnect ? 'error' : (log.statusCode>=200&&log.statusCode<300?'success':log.statusCode>=400?'error':'');
    const algoLabel = isConnect ? '上线' : isDisconnect ? '断开' : esc(log.algorithm||'-');
    const statusLabel = isConnect ? 'ON' : isDisconnect ? 'OFF' : (log.statusCode||(log.success?'200':'502'));
    return `<tr class="${i===0&&isNew?'log-row-new':''}">
      <td style="white-space:nowrap;font-size:11px;color:var(--text-secondary)">${esc(log.time)}</td>
      <td>${isAgent ? '<span class="method-badge agent">AGENT</span>' : `<span class="method-badge ${m}">${esc(log.method)}</span>`}</td>
      <td style="max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(log.path)}">${esc(log.path)}</td>
      <td style="font-size:11px;color:var(--text-secondary)">${esc(log.group||'-')}</td>
      <td style="font-size:11px;max-width:120px;overflow:hidden;text-overflow:ellipsis">${esc(log.backend)}</td>
      <td style="font-size:11px">${algoLabel}</td>
      <td><span class="status-code ${sc}">${statusLabel}</span></td>
      <td style="font-size:11px;color:var(--text-secondary)">${log.responseTime?log.responseTime+'ms':'-'}</td>
    </tr>`;
  }).join('');
}

// ==================== 标签编辑弹窗 ====================
function openTagModal(id) {
  const b = (state.backends||[]).find(x=>x.id===id);
  if (!b) return;
  state.editingTagId = id;
  dom.tagModalUrl.value = b.url||b.tag||'';
  dom.tagModalInput.value = b.tag||'';
  dom.tagModal.classList.add('show');
  setTimeout(()=>dom.tagModalInput.focus(),100);
}
function closeTagModal() { dom.tagModal.classList.remove('show'); state.editingTagId=null; }
dom.tagModalClose.addEventListener('click',closeTagModal);
dom.tagModalCancel.addEventListener('click',closeTagModal);
dom.tagModal.addEventListener('click',e=>{if(e.target===dom.tagModal)closeTagModal();});
dom.tagModalSave.addEventListener('click',async()=>{
  const id=state.editingTagId; if(!id)return;
  const r=await(await api(`/api/backends/${id}/tag`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({tag:dom.tagModalInput.value.trim()})})).json();
  if(r.ret===0){closeTagModal();fetchOverview();toast('标签已更新','success');}else toast(r.error||'保存失败','error');
});
dom.tagModalInput.addEventListener('keydown',e=>{if(e.key==='Enter')dom.tagModalSave.click();if(e.key==='Escape')closeTagModal();});

// ==================== 辅助函数 ====================
function updateGroupDropdown(sel) {
  const gs = state.groups||{};
  sel.innerHTML = Object.keys(gs).map(g => `<option value="${g}">${g}</option>`).join('');
}
function updateAlgoDropdown(sel) {
  const algos = state.algorithms||{};
  sel.innerHTML = Object.entries(algos).map(([k,v]) => `<option value="${k}">${v.name}</option>`).join('');
}

// ==================== frpc Agent 配置面板 ====================
function renderFrpcConfig() {
  const host = location.hostname;
  const port = location.port || '8888';
  dom.cfgServerAddr.value = host;
  dom.cfgServerPort.value = port;

  api('/api/config').then(r => r.json()).then(d => {
    if (d.ret === 0) {
      if (d.data.agent_token) dom.cfgAgentToken.value = d.data.agent_token;
      dom.cfgAgentToken._savedVal = d.data.agent_token || '';
      dom.cfgFrpPort.value = d.data.frp_port || 7000;
    }
  }).catch(() => {});

  updateAgentCmd();
  dom.cfgAgentToken.addEventListener('input', updateAgentCmd);
  dom.cfgAgentToken.addEventListener('blur', () => {
    const v = dom.cfgAgentToken.value.trim();
    if (v === dom.cfgAgentToken._savedVal) return;
    api('/api/config', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ agent_token: v }) })
      .then(r => r.json()).then(d => { if (d.ret === 0) dom.cfgAgentToken._savedVal = v; });
  });
  dom.cfgServerAddr.addEventListener('input', updateAgentCmd);
  dom.cfgServerPort.addEventListener('input', updateAgentCmd);
  dom.cfgFrpPort.addEventListener('input', updateAgentCmd);
  dom.cfgCopyCmd.addEventListener('click', () => copyCmd(dom.cfgAgentCmd.textContent, 'WebSocket'));
  dom.cfgCopyFrpcCmd.addEventListener('click', () => copyCmd(dom.cfgFrpcCmd.textContent, 'frpc'));
}

function copyCmd(text, label) {
  if (!text) return;
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(() => toast(`${label}命令已复制`, 'success'));
  } else {
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.left = '-9999px';
    document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); document.body.removeChild(ta);
    toast(`${label}命令已复制`, 'success');
  }
}

function updateAgentCmd() {
  const host = dom.cfgServerAddr.value || location.hostname;
  const port = dom.cfgServerPort.value || '7878';
  const frpPort = dom.cfgFrpPort.value || '7000';
  const token = dom.cfgAgentToken.value.trim();
  const wsUrl = `ws://${host}:${port}/agent`;
  let cmd = `node agent.js -s ${wsUrl} -t http://localhost:8080 -n 节点1`;
  if (token) cmd += ` --token ${token}`;
  cmd += `\n# node agent.js -s ${wsUrl} -t http://localhost:8080 -n 节点1 --group mygroup --groupKey mykey`;
  dom.cfgAgentCmd.textContent = cmd;

  const frpcToml = `serverAddr = "${host}"
serverPort = ${port}
${token ? `auth.token = "${token}"` : '# auth.token = ""'}

[[proxies]]
name = "节点1"
type = "tcp"
localIP = "127.0.0.1"
localPort = 8080
# loadBalancer.group = "mygroup"
# loadBalancer.groupKey = "mykey"`;
  dom.cfgFrpcCmd.textContent = frpcToml;
}

// ─── 预配置代理 ─────────────────────────────────────
function renderProxyList() {
  const presets = state.proxyPresets || [];
  dom.proxyList.innerHTML = presets.length ? presets.map(p => `
    <div class="group-card" style="display:flex;align-items:center;justify-content:space-between">
      <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
        <code style="font-size:13px;background:var(--bg);padding:2px 8px;border-radius:4px">${esc(p.name)}</code>
        <span class="group-badge ${p.group||'default'}">📁 ${esc(p.group||'default')}</span>
        ${p.groupKey ? `<span style="font-size:11px;color:var(--text-secondary)">🔑 ${esc(p.groupKey)}</span>` : ''}
        ${p.localPort ? `<span style="font-size:11px;color:var(--text-secondary)">🔌 :${p.localPort}</span>` : ''}
      </div>
      <button class="btn btn-danger btn-xs" onclick="deleteProxy('${esc(p.name)}')">删除</button>
    </div>
  `).join('') : '<div class="empty-state" style="padding:8px;font-size:13px">暂无预配置代理，添加后 Agent 可通过 groupKey 自动匹配分组</div>';
}

async function deleteProxy(name) {
  if (!confirm(`删除预配置代理「${name}」？`)) return;
  const r = await (await api(`/api/proxies/${encodeURIComponent(name)}`, { method: 'DELETE' })).json();
  if (r.ret === 0) { state.proxyPresets = r.data; renderProxyList(); toast('代理已删除', 'success'); }
}

dom.showAddProxyBtn.addEventListener('click', () => {
  dom.addProxyForm.style.display = 'block';
  updateGroupDropdown(dom.newProxyGroup);
  dom.newProxyName.focus();
});
dom.cancelAddProxyBtn.addEventListener('click', () => {
  dom.addProxyForm.style.display = 'none';
  dom.newProxyName.value = ''; dom.newProxyKey.value = ''; dom.newProxyPort.value = '';
});
dom.addProxyBtn.addEventListener('click', async () => {
  const name = dom.newProxyName.value.trim();
  if (!name) return toast('请输入 Agent 名称', 'warning');
  const r = await (await api('/api/proxies', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name,
      group: dom.newProxyGroup.value,
      groupKey: dom.newProxyKey.value.trim(),
      localPort: parseInt(dom.newProxyPort.value) || 0
    })
  })).json();
  if (r.ret === 0) {
    dom.addProxyForm.style.display = 'none';
    dom.newProxyName.value = ''; dom.newProxyKey.value = ''; dom.newProxyPort.value = '';
    state.proxyPresets = r.data; renderProxyList(); toast('代理已添加', 'success');
  } else { toast(r.error||'添加失败', 'error'); }
});

// ─── Agent 连接表 ────────────────────────────────────
function renderAgentTable() {
  const agents = (state.backends || []).filter(b => b.type === 'tunnel');
  dom.agentEmpty.style.display = agents.length ? 'none' : 'block';
  dom.agentTableBody.innerHTML = agents.map(b => {
    const online = b.alive ? 'online' : 'offline';
    const connTime = b.connectedAt ? new Date(b.connectedAt).toLocaleString() : '-';
    return `<tr>
      <td><span class="status-badge ${online}"><span class="status-dot ${online}"></span>${b.alive ? '已连接' : '离线'}</span></td>
      <td><code style="font-size:12px">${esc(b.tag)}</code></td>
      <td style="font-size:11px;color:var(--text-secondary)">${esc(b.remoteAddress||'unknown')}</td>
      <td>
        <select class="form-input" style="width:auto;padding:2px 4px;font-size:11px" onchange="changeAgentGroup('${b.id}', this.value)">
          ${Object.keys(state.groups||{}).map(g => `<option value="${g}" ${(b.group||'default')===g?'selected':''}>${g}</option>`).join('')}
        </select>
      </td>
      <td><input type="number" value="${b.weight||1}" min="1" max="100" style="width:50px;padding:2px 4px;font-size:11px" onchange="changeAgentWeight('${b.id}', this.value)"></td>
      <td style="font-size:11px;color:var(--text-secondary)">${connTime}</td>
      <td style="font-size:11px">${(b.totalRequests||0).toLocaleString()}</td>
      <td style="font-size:11px;color:var(--text-secondary)">${b.responseTime?b.responseTime+'ms':'-'}</td>
      <td><button class="btn btn-danger btn-xs" onclick="deleteBackend('${b.id}')" title="断开">断开</button></td>
    </tr>`;
  }).join('');
}

async function changeAgentGroup(id, group) {
  const r = await (await api(`/api/backends/${id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ group }) })).json();
  if (r.ret === 0) fetchOverview();
}

async function changeAgentWeight(id, weight) {
  const w = Math.max(1, parseInt(weight) || 1);
  const r = await (await api(`/api/backends/${id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ weight: w }) })).json();
  if (r.ret === 0) fetchOverview();
}

// ==================== 导航栏响应式 ====================
dom.navToggle.addEventListener('click', ()=>dom.navStats.classList.toggle('open'));
document.addEventListener('click', e=>{ if(window.innerWidth<=768 && !e.target.closest('.navbar')) dom.navStats.classList.remove('open'); });
window.addEventListener('resize', ()=>{ if(window.innerWidth>768) dom.navStats.classList.remove('open'); });

// ==================== 启动 ====================
document.addEventListener('DOMContentLoaded', ()=>{
  if (state.token) {
    // 验证 token 是否有效（加 cache-busting 防浏览器缓存旧 200）
    api('/api/overview?_t=' + Date.now()).then(r => {
      if (r.status === 401) {
        state.token = null;
        localStorage.removeItem('lb_token');
        showLogin();
        return null;
      }
      hideLogin();
      connectWS();
      return r.json();
    }).then(d => {
      if (d && d.ret === 0) {
        Object.assign(state, d.data);
        state.lastUpdated = Date.now();
        const online = d.data?.stats?.aliveBackends || 0;
        const total = d.data?.stats?.totalBackends || 0;
        setServiceState('online', '服务正常', `${online}/${total} 个节点可用`);
        if (dom.lastUpdated) dom.lastUpdated.textContent = '刚刚更新';
        renderAll();
      }
    }).catch(() => { showLogin(); });
  } else {
    showLogin();
  }
});

function showLogin() {
  dom.loginOverlay.style.display = 'flex';
  dom.logoutBtn.style.display = 'none';
}
function hideLogin() {
  dom.loginOverlay.style.display = 'none';
  dom.logoutBtn.style.display = '';
}

// ==================== 配置导出/导入（备份用） ====================
function exportConfig() {
  // 直接通过浏览器下载，无需 fetch
  const token = state.token;
  fetch('/api/config/export', { headers: { Authorization: 'Bearer ' + token } })
    .then(r => { if (!r.ok) throw new Error('导出失败'); return r.blob(); })
    .then(blob => {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `lb-config-${new Date().toISOString().slice(0,10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      toast('配置已导出', 'success');
    })
    .catch(err => toast(err.message, 'error'));
}

async function importConfig(event) {
  const file = event.target.files[0];
  if (!file) return;
  if (!confirm(`确认导入 ${file.name}？\n这会覆盖当前所有后端、分组、规则和设置！`)) {
    event.target.value = '';
    return;
  }
  try {
    const text = await file.text();
    const data = JSON.parse(text);
    const r = await (await api('/api/config/import', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    })).json();
    if (r.ret === 0) {
      toast('配置已导入，正在刷新...', 'success');
      setTimeout(() => location.reload(), 1500);
    } else {
      toast(r.error || '导入失败', 'error');
    }
  } catch (e) {
    toast('JSON 解析失败: ' + e.message, 'error');
  }
  event.target.value = '';
}

// ==================== 自动备份管理 ====================
async function fetchBackups() {
  try {
    const r = await (await api('/api/backups')).json();
    if (r.ret !== 0) return;
    const list = r.data || [];
    if (list.length === 0) {
      dom.backupsTableBody.innerHTML = '';
      dom.backupsEmpty.style.display = 'block';
      return;
    }
    dom.backupsEmpty.style.display = 'none';
    dom.backupsTableBody.innerHTML = list.map(b => `<tr>
      <td><span class="backup-filename">${esc(b.filename)}</span></td>
      <td><span class="backup-size">${(b.size/1024).toFixed(1)} KB</span></td>
      <td><span class="backup-time">${new Date(b.mtime).toLocaleString()}</span></td>
      <td><div class="table-actions">
        <button class="btn btn-sm btn-secondary" onclick="downloadBackup('${esc(b.filename)}')">⬇ 下载</button>
        <button class="btn btn-sm btn-danger" onclick="deleteBackup('${esc(b.filename)}')">✕ 删除</button>
      </div></td>
    </tr>`).join('');
  } catch (_) {}
}

function downloadBackup(filename) {
  const token = state.token;
  fetch(`/api/backups/${encodeURIComponent(filename)}`, { headers: { Authorization: 'Bearer ' + token } })
    .then(r => { if (!r.ok) throw new Error('下载失败'); return r.blob(); })
    .then(blob => {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    });
}

async function backupNow() {
  const r = await (await api('/api/backups/create', { method: 'POST' })).json();
  if (r.ret === 0) {
    toast('备份已创建: ' + r.filename, 'success');
    fetchBackups();
  } else {
    toast(r.error || '备份失败', 'error');
  }
}

async function deleteBackup(filename) {
  if (!confirm(`确认删除备份 ${filename}？`)) return;
  const r = await (await api(`/api/backups/${encodeURIComponent(filename)}`, { method: 'DELETE' })).json();
  if (r.ret === 0) { fetchBackups(); toast('已删除', 'success'); }
  else toast(r.error || '删除失败', 'error');
}

// ==================== 多设备会话管理 ====================
async function fetchSessions() {
  try {
    const r = await (await api('/api/sessions')).json();
    if (r.ret !== 0) return;
    const sessions = r.data || [];
    if (sessions.length === 0) {
      dom.sessionsTableBody.innerHTML = '';
      dom.sessionsEmpty.style.display = 'block';
      return;
    }
    dom.sessionsEmpty.style.display = 'none';
    dom.sessionsTableBody.innerHTML = sessions.map(s => {
      const name = s.name || (s.ua || '').slice(0, 40);
      const isCurrent = s.isCurrent;
      const isActive = !isCurrent && (Date.now() - s.lastActive < 5*60*1000);
      const status = isCurrent ? '<span class="session-current">当前设备</span>'
        : (isActive ? '<span class="status-badge online">活跃</span>'
        : '<span class="session-offline">离线</span>');
      return `<tr ${isCurrent?'style="background:var(--success-bg)"':''}>
        <td><span class="session-ua" title="${esc(s.ua||'')}">${esc(name)}</span></td>
        <td><span class="session-ip">${esc(s.ip)}</span></td>
        <td><span class="session-time">${new Date(s.createdAt).toLocaleString()}</span></td>
        <td><span class="session-time">${new Date(s.lastActive).toLocaleString()}</span></td>
        <td>${status}</td>
        <td><div class="table-actions">
          ${isCurrent
            ? '<button class="btn btn-sm btn-secondary" onclick="doLogout()">退出</button>'
            : `<button class="btn btn-sm btn-danger" onclick="revokeSession('${encodeURIComponent(s.tokenFull)}')">✕ 注销</button>`}
        </div></td>
      </tr>`;
    }).join('');
  } catch (_) {}
}

async function revokeSession(tokenFull) {
  if (!confirm('确认注销该设备？')) return;
  const r = await (await api(`/api/sessions/${tokenFull}`, { method: 'DELETE' })).json();
  if (r.ret === 0) {
    toast('已注销该设备', 'success');
    fetchSessions();
  } else {
    toast(r.error || '注销失败', 'error');
  }
}

async function revokeAllOffline() {
  if (!confirm('确认清理所有离线（5 分钟未活跃）会话？')) return;
  const r = await (await api('/api/sessions')).json();
  if (r.ret !== 0) return;
  const offline = (r.data || []).filter(s => !s.isCurrent && (Date.now() - s.lastActive >= 5*60*1000));
  if (offline.length === 0) { toast('没有离线会话', 'info'); return; }
  for (const s of offline) {
    await api(`/api/sessions/${encodeURIComponent(s.tokenFull)}`, { method: 'DELETE' });
  }
  toast(`已清理 ${offline.length} 个离线会话`, 'success');
  fetchSessions();
}
