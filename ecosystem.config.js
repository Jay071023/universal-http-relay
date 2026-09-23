/**
 * PM2 生态系统配置 — 生产部署用
 *
 * 用法:
 *   pm2 start ecosystem.config.js          # 启动所有服务
 *   pm2 start ecosystem.config.js --only lb-server   # 只启动负载均衡器
 *   pm2 save                               # 保存进程列表
 *   pm2 startup                            # 设置开机自启
 *   pm2 logs                               # 查看日志
 *   pm2 monit                              # 监控面板
 *
 * 注意: 根据服务器修改 LB_PORT:
 *   Shira → LB_PORT=8888
 *   9L    → LB_PORT=7878
 */

const fs = require('fs');
const path = require('path');
const LB_PORT = parseInt(process.env.LB_PORT) || 8888;

function readEnvFile(filePath) {
  try {
    return Object.fromEntries(fs.readFileSync(filePath, 'utf8').split(/\r?\n/)
      .filter(line => line && !line.trim().startsWith('#'))
      .map(line => {
        const index = line.indexOf('=');
        if (index < 1) return null;
        return [line.slice(0, index).trim(), line.slice(index + 1).trim().replace(/^['"]|['"]$/g, '')];
      }).filter(Boolean));
  } catch (_) { return {}; }
}

const fileEnv = readEnvFile(path.join(__dirname, '.deploy.env'));
const deployToken = process.env.DEPLOY_TOKEN || fileEnv.DEPLOY_TOKEN || '';

module.exports = {
  apps: [
    {
      name: 'lb-server',
      script: 'lb-server.js',
      cwd: __dirname,
      instances: 1,
      exec_mode: 'fork',
      env: {
        NODE_ENV: 'production',
        LB_PORT: LB_PORT,
        LB_PID_FILE: './lb-server.pid',
        LB_MAX_MEMORY_RESTART_MB: '2867',
      },
      max_memory_restart: '2.8G',
      error_file: './logs/lb-error.log',
      out_file: './logs/lb-out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss',
      merge_logs: true,
      max_restarts: 10,
      restart_delay: 4000,
      watch: false,
    },
    {
      name: 'deploy-server',
      script: 'deploy-server.js',
      cwd: __dirname,
      instances: 1,
      exec_mode: 'fork',
      env: {
        NODE_ENV: 'production',
        LB_PORT: LB_PORT,
        DEPLOY_BASE_DIR: process.env.DEPLOY_BASE_DIR || fileEnv.DEPLOY_BASE_DIR || __dirname,
        DEPLOY_BIND: process.env.DEPLOY_BIND || fileEnv.DEPLOY_BIND || '0.0.0.0',
        DEPLOY_PORT: parseInt(process.env.DEPLOY_PORT || fileEnv.DEPLOY_PORT) || 7879,
        DEPLOY_TOKEN: deployToken,
        DEPLOY_SERVICE_MANAGER: process.env.DEPLOY_SERVICE_MANAGER || fileEnv.DEPLOY_SERVICE_MANAGER || 'pm2',
        DEPLOY_PROCESS_NAME: process.env.DEPLOY_PROCESS_NAME || fileEnv.DEPLOY_PROCESS_NAME || 'lb-server',
      },
      max_memory_restart: '200M',
      error_file: './logs/deploy-error.log',
      out_file: './logs/deploy-out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss',
      merge_logs: true,
      max_restarts: 10,
      restart_delay: 4000,
      watch: false,
    },
  ],
};
