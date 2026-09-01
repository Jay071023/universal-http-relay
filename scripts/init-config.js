'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const target = path.resolve(process.argv[2] || path.join(__dirname, '..', 'config.json'));
if (fs.existsSync(target)) {
  console.log(`配置已存在，未覆盖: ${target}`);
  process.exit(0);
}

const config = {
  port: Number.parseInt(process.env.LB_PORT || '8888', 10) || 8888,
  frp_port: 7000,
  admin_password: crypto.randomBytes(18).toString('base64url'),
  agent_token: crypto.randomBytes(24).toString('hex'),
  hc_interval: 5000,
  hc_timeout: 8000,
  tunnel_timeout: 30000,
  request_timeout: 120000,
  max_log: 500,
  page_title: '负载均衡管理面板',
  bark_key: '',
  monitor_servers: [],
  monitor_interval: 30000,
  persist_stats: true,
  version_rewrite_enabled: false,
  version_rewrite_target: '9.2.70',
  auto_backup_enabled: true,
  auto_backup_interval: 21600000,
  max_backups: 30,
  retry_400_enabled: true,
  retry_400_max: 2,
  retry_400_max_backends: 3,
  cors_origins: '',
  groups: { default: { algorithm: 'weighted-round-robin', description: '默认分组' } },
  rules: [],
  _backends: []
};

fs.mkdirSync(path.dirname(target), { recursive: true });
fs.writeFileSync(target, `${JSON.stringify(config, null, 2)}\n`, { encoding: 'utf8', mode: 0o640 });
console.log(`ADMIN_PASSWORD=${config.admin_password}`);
console.log(`AGENT_TOKEN=${config.agent_token}`);
