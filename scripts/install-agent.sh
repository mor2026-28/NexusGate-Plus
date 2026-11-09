#!/usr/bin/env bash
set -Eeuo pipefail

# NexusGate Plus · 受控端 Agent 一键接入脚本 (支持中转机 / 落地机 / 热备容灾机 / 3x-ui 原地平滑接管)
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

MASTER_URL=""
NODE_ID=""
AGENT_TOKEN=""
AGENT_PORT="19090"
TAKEOVER_3XUI="0"
SB_VERSION="${NG_SINGBOX_VERSION:-1.12.23}"
REPO="${NG_REPO:-mor2026-28/NexusGate-Plus}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --master) MASTER_URL="$2"; shift 2 ;;
    --node-id) NODE_ID="$2"; shift 2 ;;
    --token) AGENT_TOKEN="$2"; shift 2 ;;
    --port) AGENT_PORT="$2"; shift 2 ;;
    --takeover-3xui) TAKEOVER_3XUI="1"; shift 1 ;;
    *) shift 1 ;;
  esac
done

[[ -n "$MASTER_URL" && -n "$NODE_ID" && -n "$AGENT_TOKEN" ]] || {
  echo "[错误] 缺少参数！用法: bash install-agent.sh --master <URL> --node-id <ID> --token <TOKEN> [--port 19090] [--takeover-3xui]" >&2
  exit 1
}

echo -e "\033[0;36m[NexusGate-Plus Agent]\033[0m 正在部署超轻量受控端节点 (${NODE_ID})..."

mkdir -p /opt/nexusgate-agent /etc/nexusgate/sing-box /etc/nexusgate/certs

if ! command -v node >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq curl tar ca-certificates openssl nodejs
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl tar ca-certificates openssl nodejs
  fi
fi

if [[ ! -x /usr/local/bin/sing-box ]]; then
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64) SB_ARCH="amd64" ;;
    aarch64|arm64) SB_ARCH="arm64" ;;
    *) SB_ARCH="amd64" ;;
  esac
  TMP_SB="$(mktemp -d)"
  curl -fsSL "https://github.com/SagerNet/sing-box/releases/download/v${SB_VERSION}/sing-box-${SB_VERSION}-linux-${SB_ARCH}.tar.gz" -o "${TMP_SB}/sb.tar.gz"
  tar -xzf "${TMP_SB}/sb.tar.gz" -C "${TMP_SB}" --strip-components=1
  install -m 0755 "${TMP_SB}/sing-box" /usr/local/bin/sing-box
  rm -rf "${TMP_SB}"
fi

curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/agent/nexus-agent.js" -o /opt/nexusgate-agent/nexus-agent.js
chmod 0755 /opt/nexusgate-agent/nexus-agent.js

if [[ "$TAKEOVER_3XUI" == "1" ]]; then
  echo -e "\033[0;33m[平滑接管]\033[0m 正在停止原机 x-ui 服务以释放监听端口，由 Sing-box 零断流接管..."
  systemctl stop x-ui 2>/dev/null || true
  systemctl disable x-ui 2>/dev/null || true
fi

cat >/etc/systemd/system/nexusgate-agent.service <<EOF
[Unit]
Description=NexusGate Plus Cluster Agent (${NODE_ID})
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/env node /opt/nexusgate-agent/nexus-agent.js --master "${MASTER_URL}" --node-id "${NODE_ID}" --token "${AGENT_TOKEN}" --port "${AGENT_PORT}"
Restart=always
RestartSec=3
MemoryMax=64M

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now nexusgate-agent.service
echo -e "\033[0;32m[成功]\033[0m NexusGate Plus Agent (${NODE_ID}) 已启动并连接主控 (${MASTER_URL})！"
