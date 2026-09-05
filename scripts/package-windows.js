'use strict';
/**
 * package-windows.js — 打包 Windows 部署版（源码 + 生产依赖）
 *
 * 产出（dist/ 目录）:
 *   universal-http-relay-windows-v<版本>/  解压即用的运行目录
 *   universal-http-relay-windows-v<版本>.zip
 *
 * 目标机要求已安装 Node.js 18+（不打包运行时）。
 * 用法: node scripts/package-windows.js
 */

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const PKG = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const VERSION = PKG.version;
const DIST = path.join(ROOT, 'dist');
const NAME = `universal-http-relay-windows-v${VERSION}`;
const STAGE_PARENT = path.join(DIST, '.staging');
const STAGE = path.join(STAGE_PARENT, NAME);
const ZIP_PATH = path.join(DIST, `${NAME}.zip`);

const TOP_LEVEL_FILES = [
  'lb-server.js', 'lb-server-real.js',
  'deploy-server.js', 'agent.js', 'upload.js', 'control.js',
  'test-backend.js', 'test-frps.js',
  'package.json', 'package-lock.json',
  'ecosystem.config.js', 'config.example.json',
  'README.md',
];
const DIRS = ['public', 'scripts', 'node_modules'];

function cleanDir(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}
function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function stageFiles() {
  console.log(`[1/4] 组装临时目录 ${STAGE}`);
  cleanDir(STAGE_PARENT);
  ensureDir(STAGE);

  for (const file of TOP_LEVEL_FILES) {
    const src = path.join(ROOT, file);
    if (!fs.existsSync(src)) {
      console.warn(`  跳过缺失文件: ${file}`);
      continue;
    }
    fs.copyFileSync(src, path.join(STAGE, file));
    console.log(`  + ${file}`);
  }
  for (const dir of DIRS) {
    const src = path.join(ROOT, dir);
    if (!fs.existsSync(src)) {
      console.warn(`  跳过缺失目录: ${dir}`);
      continue;
    }
    fs.cpSync(src, path.join(STAGE, dir), { recursive: true });
    console.log(`  + ${dir}/`);
  }

  // 运行期/敏感内容一律不打包: config.json、config*.json 备份、certs、backups、logs、
  // *.pid、*.log、健康监控脚本、.deploy.env、deploy-token.txt（首次运行由启动脚本生成）
  writeStartBat();
  writeStopBat();
}

// 注意：批处理输出保持 ASCII，避免中文系统代码页差异导致乱码。
const START_BAT = `@echo off
setlocal
title Universal HTTP Relay - Load Balancer
cd /d "%~dp0"
chcp 65001 >nul

rem ============================================================
rem  启动负载均衡主服务 (lb-server) 与远程部署接收 (deploy-server)
rem  要求: 已安装 Node.js 18+  (https://nodejs.org)
rem
rem  可修改端口:
rem    LB_PORT        WebUI / 转发入口  (默认 8888)
rem    DEPLOY_PORT    远程部署接收端口   (默认 7879)
rem
rem  首次启动会自动:
rem    1) 生成 config.json, 随机 ADMIN_PASSWORD / AGENT_TOKEN (打印在下)
rem    2) 生成 deploy-token.txt (DEPLOY_TOKEN), 是远程热更新的口令
rem ============================================================

set "LB_PORT=8888"
set "DEPLOY_PORT=7879"

where node >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Node.js not found. Please install Node.js 18+ from https://nodejs.org
  echo         then run this script again.
  pause
  exit /b 1
)

set "FIRST_RUN="
if not exist "config.json" (
  echo.
  echo [1/4] First run: generating config.json ...
  if exist "scripts\\init-config.js" (
    node "scripts\\init-config.js"
  ) else (
    echo   (config.json will be auto-created by lb-server)
  )
  echo.
  set "FIRST_RUN=1"
)

if not exist "deploy-token.txt" (
  echo [2/4] Generating deploy token ...
  node -e "require('fs').writeFileSync('deploy-token.txt', require('crypto').randomBytes(24).toString('hex') + String.fromCharCode(10))"
)
for /f "delims=" %%t in (deploy-token.txt) do set "DEPLOY_TOKEN=%%t"

echo [3/4] Stopping previous instances on %LB_PORT% / %DEPLOY_PORT% ...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":%LB_PORT%" ^| findstr LISTENING') do taskkill /F /PID %%a >nul 2>&1
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":%DEPLOY_PORT%" ^| findstr LISTENING') do taskkill /F /PID %%a >nul 2>&1
timeout /t 2 /nobreak >nul

echo [4/4] Starting services ...
start "lb-server" /min node lb-server.js
start "deploy-server" /min node deploy-server.js --port %DEPLOY_PORT%
timeout /t 3 /nobreak >nul

echo.
echo ============================================================
echo   LB Server  : http://localhost:%LB_PORT%/
echo   Deploy Rcv : port %DEPLOY_PORT%
echo   DEPLOY_TOKEN: %DEPLOY_TOKEN%   (keep it secret)
echo ============================================================
echo.
echo  On first run, the ADMIN_PASSWORD shown above is the login
echo  password (also stored in config.json). No username needed.
echo  Change it later in WebUI Settings, or stop with stop-service.bat
echo.
if defined FIRST_RUN (
  start "" http://localhost:%LB_PORT%/
  pause
)
endlocal
`;

function toCrlf(text) {
  return text.replace(/\r?\n/g, '\r\n');
}

function writeStartBat() {
  const dest = path.join(STAGE, '启动服务.bat');
  fs.writeFileSync(dest, toCrlf(START_BAT), { encoding: 'utf8' });
  console.log('  + 启动服务.bat');
}

const STOP_BAT = `@echo off
setlocal
title Stop Universal HTTP Relay
cd /d "%~dp0"
chcp 65001 >nul

set "LB_PORT=8888"
set "DEPLOY_PORT=7879"

echo Stopping lb-server (PID file) ...
if exist "lb-server.pid" (
  for /f "delims=" %%p in (lb-server.pid) do taskkill /F /PID %%p >nul 2>&1
)
echo Stopping listeners on port %LB_PORT% / %DEPLOY_PORT% ...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":%LB_PORT%" ^| findstr LISTENING') do taskkill /F /PID %%a >nul 2>&1
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":%DEPLOY_PORT%" ^| findstr LISTENING') do taskkill /F /PID %%a >nul 2>&1
echo Done. (If a QQ/backend process still holds the port, check netstat.)
pause
`;

function writeStopBat() {
  const dest = path.join(STAGE, '停止服务.bat');
  fs.writeFileSync(dest, toCrlf(STOP_BAT), { encoding: 'utf8' });
  console.log('  + 停止服务.bat');
}

function makeZip() {
  console.log(`[2/4] 压缩为 ${ZIP_PATH}`);
  // -Path '<parent>\*' 让压缩包根目录只含 <NAME> 这一层
  execFileSync('powershell', ['-NoProfile', '-Command',
    `Compress-Archive -Path '${STAGE_PARENT}\\*' -DestinationPath '${ZIP_PATH}' -CompressionLevel Optimal -Force`],
    { stdio: 'inherit' });
}

function listZip() {
  console.log('[3/4] 校验压缩包内容 ...');
  const ps = [
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;",
    "Add-Type -AssemblyName System.IO.Compression.FileSystem;",
    `$z=[System.IO.Compression.ZipFile]::OpenRead('${ZIP_PATH}');`,
    "$z.Entries.FullName;",
    "$z.Dispose()",
  ].join(' ');
  const out = execFileSync('powershell', ['-NoProfile', '-Command', ps], { encoding: 'utf8' }).trim();
  // Compress-Archive 生成的条目用反斜杠分隔，统一转正斜杠便于比对
  const lines = out.split(/\r?\n/).map((l) => l.replace(/\\/g, '/')).filter(Boolean);
  console.log(`  共 ${lines.length} 个条目`);
  const forbidden = ['/config.json', '/certs/', '/backups/', '/deploy-token.txt', '/lb-config-', '/health-monitor.js'];
  const bad = lines.filter((l) => forbidden.some((f) => l.includes(f)));
  if (bad.length) console.warn('  !! 发现可能不该出现的条目:\n  ' + bad.join('\n  '));
  const required = [`${NAME}/lb-server-real.js`, `${NAME}/public/index.html`, `${NAME}/node_modules/express/package.json`, `${NAME}/启动服务.bat`];
  const missing = required.filter((r) => !lines.includes(r));
  if (missing.length) throw new Error('打包缺少必需文件: ' + missing.join(', '));
  console.log('  必需文件校验通过');
}

function finish() {
  // 保留解压即用的运行目录：把 NAME 移出 staging，再清理 staging
  const kept = path.join(DIST, NAME);
  cleanDir(kept);
  fs.renameSync(STAGE, kept);
  cleanDir(STAGE_PARENT);
  console.log('[4/4] 整理产物');
  console.log(`\n完成!\n  运行目录 : ${kept}\n  ZIP      : ${ZIP_PATH}\n`);
}

stageFiles();
makeZip();
listZip();
finish();
