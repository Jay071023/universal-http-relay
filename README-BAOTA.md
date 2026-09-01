# Universal HTTP Relay 宝塔部署说明

如果需要图文式教学，直接打开同目录的 `BAOTA-DEPLOY-GUIDE.html`；它可以离线打开，也包含给对方 AI 执行的完整提示词。

这是 Node.js + Express 项目，不是 PHP、Java 或 Python 项目。前端是原生 HTML/CSS/JavaScript，不需要 React/Vue 编译。

## PM2 部署

1. 宝塔安装 Node.js 18+，把发布包上传到 `/www/wwwroot/universal-http-relay`。
2. 在目录执行 `npm ci --omit=dev`，再执行 `node scripts/init-config.js`，保存输出的管理员密码和 Agent Token。
3. 用宝塔 Node 项目或 PM2 添加主进程：入口 `lb-server.js`，工作目录为发布包目录。
4. 添加第二个进程：入口 `deploy-server.js`，工作目录相同，环境变量至少包含：

```text
DEPLOY_BASE_DIR=/www/wwwroot/universal-http-relay
DEPLOY_BIND=0.0.0.0
DEPLOY_PORT=7879
DEPLOY_TOKEN=安装时生成的随机Token
DEPLOY_SERVICE_MANAGER=pm2
DEPLOY_PROCESS_NAME=lb-server
```

在宝塔安全组中开放业务端口 `8888` 和你自定义的热更新端口，并把热更新端口限制为本机或你的固定公网 IP。Token 由安装脚本随机生成并显示一次。热更新端口只允许认证后的文件更新、状态查询、健康检查和受控重启，不提供任意 Shell。

## Nginx 反向代理

仅网页管理和 HTTP 转发时，可把网站反向代理到 `http://127.0.0.1:8888` 并开启 WebSocket。若要使用同一个 Node 端口承载原始 FRP/TCP 协议，不要只配置普通 HTTP 反代；应让 PM2 直接监听该端口，或额外使用 Nginx stream/TCP 转发。

## Windows 远程热更新

在本机发布包目录执行 `push.ps1`，输入目标服务器 IP、自定义端口和部署 Token；Linux/macOS 执行 `bash push.sh`。更新会先认证、校验、暂存并原子提交，成功后再重启和健康检查，不会上传目标机的 `config.json`。

远程控制：`node control.js --host 服务器IP --port 自定义端口 --token 部署Token status|health|restart|reload`。

转发请求默认等待 120 秒，管理面板最低允许 60 秒，以覆盖 5-6 秒初始化接口；只有真正超时或连接失败才结束该请求。
