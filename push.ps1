$ErrorActionPreference = 'Stop'

$targetHost = Read-Host '目标服务器 IP/域名'
$targetPort = Read-Host '部署端口 [7879]'
if ([string]::IsNullOrWhiteSpace($targetPort)) { $targetPort = '7879' }
$secureToken = Read-Host '部署 Token' -AsSecureString
$tokenPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
try {
    $env:LB_DEPLOY_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($tokenPtr)
    if ([string]::IsNullOrWhiteSpace($env:LB_DEPLOY_TOKEN)) { throw '部署 Token 不能为空，请填写目标服务器安装时生成的随机 Token。' }
    node (Join-Path $PSScriptRoot 'upload.js') --host $targetHost --port $targetPort --all
    if ($LASTEXITCODE -ne 0) { throw "上传失败，退出码 $LASTEXITCODE" }
}
finally {
    if ($tokenPtr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tokenPtr) }
    Remove-Item Env:LB_DEPLOY_TOKEN -ErrorAction SilentlyContinue
}
