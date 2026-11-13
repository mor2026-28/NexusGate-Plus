#!/usr/bin/env bash
set -Eeuo pipefail

# NexusGate Plus · 受控端 Agent 一键接入脚本 v1.0.7 (支持中转机 / 落地机 / 热备容灾机 / 3x-ui 原地平滑接管)
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

MASTER_URL=""
STANDBY_MASTER_URL=""
NODE_ID=""
AGENT_TOKEN=""
AGENT_PORT="19090"
TAKEOVER_3XUI="0"
SB_VERSION="${NG_SINGBOX_VERSION:-1.12.23}"
REPO="${NG_REPO:-mor2026-28/NexusGate-Plus}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --master) MASTER_URL="$2"; shift 2 ;;
    --standby-master) STANDBY_MASTER_URL="$2"; shift 2 ;;
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

echo -e "\033[0;36m[NexusGate-Plus Agent v1.0.7]\033[0m 正在部署超轻量受控端节点 (${NODE_ID})..."

mkdir -p /opt/nexusgate-agent /etc/nexusgate/sing-box /etc/nexusgate/certs

if ! command -v node >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq curl tar ca-certificates openssl nodejs
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl tar ca-certificates openssl nodejs
  fi
fi

# 1. 自动开启 BBR + FQ + HY2 64MB UDP 缓冲与高并发文件句柄优化
cat >/etc/sysctl.d/99-nexusgate-agent.conf <<'SYSCTL'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_fastopen = 3
fs.file-max = 1048576
SYSCTL
sysctl --system >/dev/null 2>&1 || true

# 2. 自动限制 systemd-journald 日志占用 <= 32MB，防止小硬盘 VPS 爆满
if [[ -d /etc/systemd/journald.conf.d ]] || mkdir -p /etc/systemd/journald.conf.d 2>/dev/null; then
  cat >/etc/systemd/journald.conf.d/nexusgate-agent.conf <<'JCONF'
[Journal]
SystemMaxUse=32M
RuntimeMaxUse=16M
MaxRetentionSec=3day
JCONF
  systemctl restart systemd-journald 2>/dev/null || true
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

if [[ ! -f /etc/nexusgate/sing-box/config.json ]]; then
  cat >/etc/nexusgate/sing-box/config.json <<'SBCFG'
{"log":{"level":"warn"},"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}]}
SBCFG
fi

cat >/etc/systemd/system/nexusgate-singbox.service <<'SBSVC'
[Unit]
Description=NexusGate Plus Sing-box Kernel Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /etc/nexusgate/sing-box/config.json
Restart=always
RestartSec=2
LimitNOFILE=1048576
MemoryMax=256M

[Install]
WantedBy=multi-user.target
SBSVC

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
ExecStart=/usr/bin/env node --max-old-space-size=48 --expose-gc /opt/nexusgate-agent/nexus-agent.js --master "${MASTER_URL}" --standby-master "${STANDBY_MASTER_URL}" --node-id "${NODE_ID}" --token "${AGENT_TOKEN}" --port "${AGENT_PORT}"
Restart=always
RestartSec=3
MemoryMax=64M
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now nexusgate-singbox.service 2>/dev/null || true
systemctl enable --now nexusgate-agent.service
echo -e "\033[0;32m[成功]\033[0m NexusGate Plus Agent v1.0.7 (${NODE_ID}) 已启动并连接主控 (${MASTER_URL})！"
