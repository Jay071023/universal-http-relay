#!/usr/bin/env bash
set -Eeuo pipefail

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo "请使用 root 运行: sudo bash install.sh" >&2
  exit 1
fi

APP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
NODE_BIN="$(command -v node || true)"
NPM_BIN="$(command -v npm || true)"
SERVICE_DIR="/etc/qq-load-balancer"
DEPLOY_LISTEN_PORT="${DEPLOY_PORT:-7879}"

if [ -z "$NODE_BIN" ] || [ -z "$NPM_BIN" ]; then
  echo "未找到 node/npm，请先安装 Node.js 18 或更高版本。" >&2
  exit 1
fi
NODE_MAJOR="$("$NODE_BIN" -p "process.versions.node.split('.')[0]")"
if [ "$NODE_MAJOR" -lt 18 ]; then
  echo "Node.js 版本过低，需要 18+，当前为 $NODE_MAJOR。" >&2
  exit 1
fi

if ! id qqlb >/dev/null 2>&1; then
  useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin qqlb
fi

cd "$APP_DIR"
"$NPM_BIN" ci --omit=dev --ignore-scripts

if [ ! -f "$APP_DIR/config.json" ]; then
  CREDENTIALS="$("$NODE_BIN" "$APP_DIR/scripts/init-config.js" "$APP_DIR/config.json")"
  echo "首次配置已生成："
  echo "$CREDENTIALS"
  echo "请保存 ADMIN_PASSWORD 和 AGENT_TOKEN。"
fi

install -d -m 0750 "$SERVICE_DIR"
if [ ! -f "$SERVICE_DIR/deploy.env" ]; then
  DEPLOY_TOKEN="$("$NODE_BIN" -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))")"
  umask 077
  printf '%s\n' \
    "DEPLOY_BASE_DIR=$APP_DIR" \
    "DEPLOY_BIND=0.0.0.0" \
    "DEPLOY_PORT=$DEPLOY_LISTEN_PORT" \
    "DEPLOY_TOKEN=$DEPLOY_TOKEN" \
    "DEPLOY_SERVICE_MANAGER=systemd" \
    "DEPLOY_SERVICE_NAME=qq-load-balancer.service" \
    "DEPLOY_MAX_FILE_BYTES=32mb" \
    "DEPLOY_BACKUP_LIMIT=10" \
    "LB_PORT=8888" \
    > "$SERVICE_DIR/deploy.env"
  chmod 0600 "$SERVICE_DIR/deploy.env"
  echo "DEPLOY_TOKEN=$DEPLOY_TOKEN"
else
  echo "已保留现有部署 token: $SERVICE_DIR/deploy.env"
fi

umask 022
printf '%s\n' "LB_PORT=8888" > "$SERVICE_DIR/lb.env"
chmod 0644 "$SERVICE_DIR/lb.env"

sed -e "s|@APP_DIR@|$APP_DIR|g" -e "s|@NODE_BIN@|$NODE_BIN|g" \
  "$APP_DIR/systemd/qq-load-balancer.service" > /etc/systemd/system/qq-load-balancer.service
sed -e "s|@APP_DIR@|$APP_DIR|g" -e "s|@NODE_BIN@|$NODE_BIN|g" \
  "$APP_DIR/systemd/qq-load-balancer-deploy.service" > /etc/systemd/system/qq-load-balancer-deploy.service

chown -R qqlb:qqlb "$APP_DIR"
chmod 0600 "$SERVICE_DIR/deploy.env"
systemctl daemon-reload
systemctl enable --now qq-load-balancer.service
systemctl enable --now qq-load-balancer-deploy.service

echo
echo "安装完成："
echo "  管理面板: http://服务器IP:8888/"
echo "  热更新端口: $DEPLOY_LISTEN_PORT"
echo "  查看状态: systemctl status qq-load-balancer.service qq-load-balancer-deploy.service"
echo "  查看日志: journalctl -u qq-load-balancer.service -f"
echo "  推送更新: bash push.sh"
echo "请在防火墙仅向可信来源开放 TCP $DEPLOY_LISTEN_PORT，并妥善保管 deploy.env。"
