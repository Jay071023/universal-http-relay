#!/usr/bin/env bash
set -Eeuo pipefail

read -r -p "目标服务器 IP/域名: " TARGET_HOST
read -r -p "部署端口 [7879]: " TARGET_PORT
TARGET_PORT="${TARGET_PORT:-7879}"
read -r -s -p "部署 Token: " LB_DEPLOY_TOKEN
echo
if [ -z "$LB_DEPLOY_TOKEN" ]; then
  echo "部署 Token 不能为空，请填写目标服务器安装时生成的随机 Token。" >&2
  exit 1
fi

if [ -z "$TARGET_HOST" ] || [ -z "$LB_DEPLOY_TOKEN" ]; then
  echo "IP/域名和 Token 都不能为空。" >&2
  exit 1
fi

export LB_DEPLOY_TOKEN
node "$(dirname -- "$0")/upload.js" --host "$TARGET_HOST" --port "$TARGET_PORT" --all
unset LB_DEPLOY_TOKEN
