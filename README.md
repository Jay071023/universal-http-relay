# Universal HTTP Relay

通用 Node.js/Express HTTP 转发与负载均衡网关，支持多节点健康检查、Web 管理面板、Linux/宝塔部署，以及认证的原子化远程热更新。

## 特性

- HTTP 直连、WebSocket 管理和可选的 Agent/FRP 通道
- 轮询、加权轮询、最少连接、最快响应等节点选择策略
- 节点健康检查、分组路由、请求日志和实时 WebSocket 面板
- 5～6 秒初始化接口不会被短暂无响应误判；默认请求最长等待 120 秒
- 400 自动重试使用可写流缓冲，不会因响应包装器缺少 `on()` 导致空响应
- 远程更新采用认证、路径校验、暂存、原子提交、备份、重启和 `/healthz` 检查
- 安装时随机生成管理员密码、Agent Token 和远程部署 Token
- 远程控制仅提供固定的 `status / health / restart / reload`，不支持任意 Shell 命令

## 快速开始

要求 Node.js 18+：

```bash
npm ci --omit=dev
node scripts/init-config.js
npm start
```

初始化命令会显示：

```text
ADMIN_PASSWORD=...
AGENT_TOKEN=...
```

浏览器打开 `http://服务器IP:8888/`，后台只有密码，没有用户名。

## 远程热更新

Linux 安装脚本会随机生成并保存 `DEPLOY_TOKEN`；Token 只在安装完成时显示一次。客户端必须显式传入目标服务器安装时生成的 Token：

```bash
node upload.js --host 服务器IP --port 远程端口 --token 安装时生成的Token --all
node control.js --host 服务器IP --port 远程端口 --token 安装时生成的Token status
node control.js --host 服务器IP --port 远程端口 --token 安装时生成的Token health
node control.js --host 服务器IP --port 远程端口 --token 安装时生成的Token restart
```

远程控制端口只提供固定运维动作，不提供任意 Shell。仍应在防火墙/云安全组中把该端口限制为管理 IP。

## 宝塔

详细图文说明请打开 [`BAOTA-DEPLOY-GUIDE.html`](BAOTA-DEPLOY-GUIDE.html)，其中还包含可以交给服务器 AI 的部署提示词。宝塔使用 Node.js 18+ 和 PM2，主进程为 `lb-server.js`，远程控制进程为 `deploy-server.js`。

## 安全边界

不要提交生产 `config.json`、`.deploy.env`、Token、管理员密码、证书私钥、日志、备份、`node_modules` 或本地工作目录。公开仓库只包含示例配置和运行时源码；部署时的凭据由本机/服务器现场生成。

## 许可证

本项目采用 [MIT License](LICENSE)。你可以使用、修改、分发及商用本项目，但须保留原版权和许可证声明。本项目按“原样”提供，不附带任何担保。
