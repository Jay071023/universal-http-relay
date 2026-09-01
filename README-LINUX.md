# Universal HTTP Relay Linux 部署包

要求：Node.js 18+、npm。安装脚本适用于使用 systemd 的 Linux 发行版；宝塔也可以用 PM2 直接运行。

## 安装

```bash
tar -xzf qq-load-balancer-linux.tar.gz
cd qq-load-balancer
sudo bash install.sh
```

安装脚本会为管理员密码、Agent Token 和远程部署 Token 分别随机生成。远程部署 Token 保存在 `/etc/qq-load-balancer/deploy.env`，权限为 `0600`；安装完成时只在终端显示一次，请妥善保存。

安装后：

```text
管理面板: http://服务器IP:8888/
热更新端口: 默认 7879，可通过 `DEPLOY_PORT` 或部署接收端的 `--port` 改成任意未占用端口
```

建议防火墙只允许可信来源访问你配置的热更新端口。这个端口具备写入运行时代码和重启服务的能力；项目不提供任意远程 Shell。

## 从本机按 IP 热更新

在包含本部署包源码的目录执行：

```bash
bash push.sh
```

或直接执行（使用安装时生成的随机 Token）：

```bash
LB_DEPLOY_TOKEN='安装时显示的随机Token' node upload.js --host 203.0.113.10 --port 7879 --all
```

Windows 使用 `push.ps1`，也可以使用原有命令形式：

```powershell
node upload.js --host 203.0.113.10 --port 7879 --token 安装时显示的随机Token --all
```

远程控制：

```bash
node control.js --host 203.0.113.10 --port 7879 --token 安装时显示的随机Token status
node control.js --host 203.0.113.10 --port 7879 --token 安装时显示的随机Token health
node control.js --host 203.0.113.10 --port 7879 --token 安装时显示的随机Token restart
```

仅支持 `status`、`health`、`restart`、`reload` 四类固定控制命令，支持自定义端口和多个 IP（逗号分隔）。

更新流程是：服务端认证 → 文件大小/路径校验 → 暂存全部文件 → 原子提交并保留回滚备份 → 重启 `qq-load-balancer.service` → 访问 `/healthz` 验证健康。配置文件、会话、备份、证书和 `node_modules` 不会被 `--all` 上传覆盖。

## 慢初始化接口与请求可靠性

转发请求默认最多等待 120 秒，管理面板允许的范围是 60-600 秒。后端接口如果需要 5-6 秒初始化，负载均衡器会继续等待同一个请求，不会因为健康检查或普通轮询提前切到下一个节点。只有客户端主动断开、连接真正失败，或超过明确的请求等待上限时，才结束该请求并记录原因。

注意：HTTP 请求无法在客户端已经断开后继续“保证送达”；因此服务会区分“客户端取消”“后端响应超时”“后端连接失败”，不会把三者混成普通的节点切换。对有副作用的请求请谨慎开启 400 自动重试，因为重试可能让后端看到多次尝试。

## 宝塔部署

推荐在宝塔「软件商店 → Node.js 版本管理器」安装 Node.js 18+，然后：

1. 将本目录上传到 `/www/wwwroot/qq-load-balancer`，进入目录执行 `npm ci --omit=dev`。
2. 执行 `node scripts/init-config.js` 保存首次输出的管理员密码和 Agent Token。
3. 在宝塔 Node 项目/PM2 中添加 `lb-server.js`，工作目录设为上述目录，监听端口使用配置中的 `8888`。
4. 再添加 `deploy-server.js` 为第二个 PM2 进程，环境变量设置 `DEPLOY_BASE_DIR=/www/wwwroot/qq-load-balancer`、`DEPLOY_BIND=0.0.0.0`、`DEPLOY_PORT=自定义端口`、`DEPLOY_TOKEN=随机长Token`、`DEPLOY_SERVICE_MANAGER=pm2`、`DEPLOY_PROCESS_NAME=lb-server`（如果你在宝塔里给主进程改过名字，这里跟着改）。
5. 宝塔安全组只放行业务端口 `8888` 和热更新端口；热更新端口只允许你的固定公网 IP 访问。需要标准 frpc/FRPS 时，还要按实际协议开放对应端口，并避免只用 Nginx HTTP 代理替代原始 TCP 入口。

如果只需要网页管理和 HTTP 转发，可以在宝塔网站设置中反向代理到 `127.0.0.1:8888`，并开启 WebSocket；如果还要使用同端口的原始 FRP/TCP 协议，建议让 Node/PM2 直接监听该端口，或另行配置 Nginx stream/TCP 转发。

## 常用运维命令

```bash
systemctl status qq-load-balancer.service qq-load-balancer-deploy.service
journalctl -u qq-load-balancer.service -f
journalctl -u qq-load-balancer-deploy.service -f
curl http://127.0.0.1:8888/healthz
```

如果目标机没有 systemd，可将部署接收端设置为 PID 文件模式：

```bash
DEPLOY_TOKEN='自行生成的随机Token' DEPLOY_SERVICE_MANAGER=pidfile LB_PORT=8888 node deploy-server.js
```

独立运行时可将 `DEPLOY_SERVICE_MANAGER` 设为 `none`，然后手动重启 `lb-server.js`；生产环境仍建议使用 PM2/systemd，让热更新完成后能自动恢复服务。

## 发布包边界

发布包只保留运行时源码、管理面板、依赖锁文件、安装/推送脚本和 systemd 模板；不包含生产 `config.json`、QQ 统计、旧配置快照、证书私钥、日志、开发记忆、测试工具或 `node_modules`。
