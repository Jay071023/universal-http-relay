$ErrorActionPreference = 'Stop'

$appDir = $PSScriptRoot
$deployListenPort = if ($env:DEPLOY_PORT) { $env:DEPLOY_PORT } else { '7879' }
$node = Get-Command node -ErrorAction SilentlyContinue
$npm = Get-Command npm -ErrorAction SilentlyContinue
if (-not $node -or -not $npm) { throw '请先安装 Node.js 18+。' }

Push-Location $appDir
try {
    npm ci --omit=dev --ignore-scripts
    if (-not (Test-Path (Join-Path $appDir 'config.json'))) {
        node (Join-Path $appDir 'scripts\init-config.js') (Join-Path $appDir 'config.json')
    }
    $deployEnv = Join-Path $appDir '.deploy.env'
    if (-not (Test-Path $deployEnv)) {
        $deployToken = node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))"
        @(
            "DEPLOY_BASE_DIR=$appDir"
            'DEPLOY_BIND=0.0.0.0'
            "DEPLOY_PORT=$deployListenPort"
            "DEPLOY_TOKEN=$deployToken"
            'DEPLOY_SERVICE_MANAGER=pidfile'
            'LB_PORT=8888'
        ) | Set-Content -Path $deployEnv -Encoding utf8
        Write-Host "DEPLOY_TOKEN=$deployToken"
    }
    Write-Host '配置完成。请先启动 lb-server.js，再使用 push.ps1 进行热更新。'
    Write-Host ('部署接收端示例: $env:DEPLOY_TOKEN="..."; node deploy-server.js --port ' + $deployListenPort)
}
finally { Pop-Location }
