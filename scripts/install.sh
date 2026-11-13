#!/usr/bin/env bash
set -Eeuo pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
cyan='\033[0;36m'
plain='\033[0m'

REPO="${NG_REPO:-mor2026-28/NexusGate-Plus}"
BRANCH="${NG_BRANCH:-main}"
SB_VERSION="${NG_SINGBOX_VERSION:-1.12.23}"
INSTALL_DIR="/opt/nexusgate"
DATA_DIR="/var/lib/nexusgate"
CONF_DIR="/etc/nexusgate"
RAW_SOURCE="${BASH_SOURCE[0]:-$0}"
if [[ -f "$RAW_SOURCE" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "$RAW_SOURCE")" 2>/dev/null && pwd || echo "")"
else
  SCRIPT_DIR=""
fi

die() { echo -e "${red}[错误]${plain} $*" >&2; exit 1; }
info() { echo -e "${cyan}[NexusGate Plus]${plain} $*"; }
ok() { echo -e "${green}[成功]${plain} $*"; }
warn() { echo -e "${yellow}[提示]${plain} $*"; }

[[ "${EUID}" -eq 0 ]] || die "请使用 root 权限运行此安装脚本 (sudo -i)"

gen_random_str() {
  local len="${1:-16}"
  local excl="${2:-}"
  if command -v node >/dev/null 2>&1; then
    node -e '
      const crypto = require("crypto");
      const len = Math.max(4, Number(process.argv[1]) || 16);
      const excl = String(process.argv[2] || "");
      const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
      const lower = "abcdefghijkmnopqrstuvwxyz";
      const digits = "2345678901";
      const all = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
      for (let a = 0; a < 10; a++) {
        const b = crypto.randomBytes(len * 2);
        const c = [
          upper[b[0] % upper.length],
          upper[b[1] % upper.length],
          lower[b[2] % lower.length],
          lower[b[3] % lower.length],
          digits[b[4] % digits.length],
          digits[b[5] % digits.length]
        ];
        for (let i = 6; i < len; i++) c.push(all[b[i] % all.length]);
        for (let i = c.length - 1; i > 0; i--) {
          const j = b[len + i] % (i + 1);
          [c[i], c[j]] = [c[j], c[i]];
        }
        const s = c.slice(0, len).join("");
        if (!excl || (s !== excl && !s.includes(excl))) {
          process.stdout.write(s);
          process.exit(0);
        }
      }
      process.stdout.write(crypto.randomBytes(len).toString("base64url").replace(/[^a-zA-Z0-9]/g, "").slice(0, len));
    ' "$len" "$excl" 2>/dev/null && return 0
  fi
  local out=""
  out="$(head -c 256 /dev/urandom 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c "$len" || true)"
  if [[ ${#out} -lt "$len" ]]; then
    out="$(openssl rand -hex 32 2>/dev/null | head -c "$len" || echo "Ng9kP2mX8vQ4rL7wB5")"
  fi
  printf '%s' "$out"
}

gen_random_port() {
  if command -v node >/dev/null 2>&1; then
    node -e 'process.stdout.write(String(require("crypto").randomInt(15000, 60001)))' 2>/dev/null && return 0
  fi
  shuf -i 15000-60000 -n 1 2>/dev/null || echo $(( (RANDOM % 45000) + 15000 ))
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|x64|amd64) echo "amd64" ;;
    aarch64|arm64|armv8*) echo "arm64" ;;
    armv7*|arm) echo "armv7" ;;
    *) die "不支持的 CPU 架构: $(uname -m)" ;;
  esac
}

install_dependencies() {
  info "正在检查并安装轻量系统依赖 (curl, tar, openssl, sqlite3, python3, cron, nodejs)..."
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq || true
    apt-get install -y -qq ca-certificates curl tar openssl sqlite3 python3 cron socat
    if ! command -v node >/dev/null 2>&1 || (( $(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0) < 18 )); then
      info "安装 Node.js 20 LTS 运行时..."
      curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1 || true
      apt-get install -y -qq nodejs
    fi
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q ca-certificates curl tar openssl sqlite python3 cronie socat nodejs
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q ca-certificates curl tar openssl sqlite python3 cronie socat nodejs
  elif command -v apk >/dev/null 2>&1; then
    apk update && apk add --no-cache ca-certificates curl tar openssl sqlite python3 dcron socat nodejs
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm ca-certificates curl tar openssl sqlite python cronie socat nodejs
  fi

  command -v node >/dev/null 2>&1 || die "Node.js 安装失败，请先安装 Node.js >= 18"
}

install_singbox_binary() {
  local arch
  arch="$(detect_arch)"
  local ver="${SB_VERSION#v}"
  local tarball="sing-box-${ver}-linux-${arch}.tar.gz"
  local url="https://github.com/SagerNet/sing-box/releases/download/v${ver}/${tarball}"

  if [[ -x /usr/local/bin/sing-box ]]; then
    local sb_ver_line=""
    sb_ver_line="$(/usr/local/bin/sing-box version 2>/dev/null | head -n 1 || true)"
    if [[ -n "$sb_ver_line" ]]; then
      info "检测到已安装 Sing-box: ${sb_ver_line}"
      return 0
    fi
    warn "检测到 /usr/local/bin/sing-box 无法正常返回版本，正在重新下载安装..."
  fi

  info "正在下载官方 Sing-box v${ver} (${arch}) 轻量内核..."
  local tmp
  tmp="$(mktemp -d /tmp/ng-sb.XXXXXX)"
  if curl -fL --retry 3 --connect-timeout 15 "$url" -o "$tmp/$tarball"; then
    tar -xzf "$tmp/$tarball" -C "$tmp" --strip-components=1
    install -m 0755 "$tmp/sing-box" /usr/local/bin/sing-box
    ok "Sing-box v${ver} 内核安装完成 ($(/usr/local/bin/sing-box version 2>/dev/null | head -n 1 || echo '/usr/local/bin/sing-box'))"
  else
    warn "自动下载 Sing-box Release 失败，稍后可在面板或执行 ng 手动切换版本"
  fi
  rm -rf -- "$tmp"
}

download_panel_source() {
  local tmp
  tmp="$(mktemp -d /tmp/nexusgate-src.XXXXXX)"
  trap 'rm -rf -- "$tmp"' RETURN

  local local_src=""
  if [[ -n "$SCRIPT_DIR" && -f "${SCRIPT_DIR}/server.js" && -f "${SCRIPT_DIR}/public/app.js" && "${SCRIPT_DIR}" != "${INSTALL_DIR}" ]]; then
    local_src="${SCRIPT_DIR}"
  elif [[ -n "$SCRIPT_DIR" && -f "${SCRIPT_DIR}/../server.js" && -f "${SCRIPT_DIR}/../public/app.js" ]]; then
    local cand_parent
    cand_parent="$(cd "${SCRIPT_DIR}/.." && pwd)"
    [[ "$cand_parent" != "$INSTALL_DIR" ]] && local_src="$cand_parent"
  elif [[ -f "./server.js" && -f "./public/app.js" ]]; then
    local_src="$(pwd)"
  fi

  mkdir -p "$INSTALL_DIR"
  if [[ -n "$local_src" ]]; then
    local real_src real_dst
    real_src="$(cd "$local_src" && pwd)"
    real_dst="$(cd "$INSTALL_DIR" && pwd)"
    if [[ "$real_src" != "$real_dst" ]]; then
      info "检测到本地源码目录 (${real_src})，直接复制安装..."
      cp -a "${real_src}/." "$INSTALL_DIR/"
    else
      info "当前位于安装目录 (${INSTALL_DIR})，使用本地源码进行配置..."
    fi
  else
    info "正在从 GitHub (${REPO}@${BRANCH}) 下载最新面板源码..."
    curl -fL --retry 3 "https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz" -o "$tmp/source.tar.gz"
    tar -xzf "$tmp/source.tar.gz" -C "$INSTALL_DIR" --strip-components=1
  fi

  rm -rf "$INSTALL_DIR/data" 2>/dev/null || true
  [[ -f "$INSTALL_DIR/server.js" ]] || die "安装包不完整，未找到 server.js"
}

enable_bbr_and_hy2_tuning() {
  info "正在优化内核网络参数与系统日志限额 (启用 BBR + FQ + HY2 64MB 缓冲 + Journald 64MB 自动轮转)..."
  modprobe tcp_bbr 2>/dev/null || true
  mkdir -p /etc/sysctl.d /etc/systemd/journald.conf.d
  cat > /etc/sysctl.d/99-nexusgate-acceleration.conf <<'EOF'
# NexusGate Sing-box BBR + FQ + HY2 Kernel Tuning
fs.file-max = 2097152
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 250000
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 10240 65535
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 2097152
net.core.wmem_default = 2097152
EOF
  sysctl --system >/dev/null 2>&1 || true

  cat > /etc/systemd/journald.conf.d/99-nexusgate.conf <<'EOF'
[Journal]
SystemMaxUse=64M
SystemMaxFileSize=16M
RuntimeMaxUse=32M
MaxRetentionSec=7day
EOF
  systemctl restart systemd-journald 2>/dev/null || true
  journalctl --vacuum-size=32M >/dev/null 2>&1 || true
}

configure_panel() {
  mkdir -p "$DATA_DIR" "$CONF_DIR/sing-box" "$CONF_DIR/certs" /root/cert
  chmod 0700 "$DATA_DIR" "$CONF_DIR"

  systemctl stop nexusgate.service nexusgate-singbox.service 2>/dev/null || true
  pkill -9 -f "sing-box run" 2>/dev/null || true

  local pub_ip=""
  pub_ip="$(curl -fsSL4 --max-time 5 https://api.ipify.org 2>/dev/null || curl -fsSL4 --max-time 5 https://ip.sb 2>/dev/null || hostname -I | awk '{print $1}')"
  pub_ip="$(echo "$pub_ip" | tr -d '\r\n ')"

  cat > "${CONF_DIR}/nexusgate.env" <<EOF
NODE_ENV=production
NG_DATA_FILE=${DATA_DIR}/nexusgate.json
NG_SINGBOX_BIN=/usr/local/bin/sing-box
NG_SINGBOX_CONFIG=${CONF_DIR}/sing-box/config.json
EOF
  chmod 0600 "${CONF_DIR}/nexusgate.env"
  rm -rf /etc/nexusgate/certs/www.bing.com /root/cert/www.bing.com 2>/dev/null || true

  local keep_existing="n"
  if [[ -s "${DATA_DIR}/nexusgate.json" ]]; then
    keep_existing="y"
    if [[ -r /dev/tty && "${NG_NONINTERACTIVE:-0}" != "1" ]]; then
      echo ""
      read -t 6 -r -p "检测到本机已存在面板数据与配置，是否保留现有端口、安全路径与账号密码（仅升级面板程序）？[Y/n (回车或6秒后默认保留，输入 n 重新生成随机账密与端口)]: " keep_existing </dev/tty || true
    fi
  fi

  local panel_port="" admin_user="" admin_pass="" base_path=""
  if [[ "${keep_existing:-Y}" =~ ^[Yy]?$ && -s "${DATA_DIR}/nexusgate.json" ]]; then
    info "已保留现有面板端口、安全路径、管理员账号密码与全部节点数据！"
    NG_DATA_FILE="${DATA_DIR}/nexusgate.json" node "$INSTALL_DIR/server.js" --issue-selfsigned "www.apple.com" "$pub_ip" >/dev/null 2>&1 || true
    local cur_info
    cur_info="$(NG_DATA_FILE="${DATA_DIR}/nexusgate.json" node "$INSTALL_DIR/server.js" --show-info-json)"
    admin_user="$(echo "$cur_info" | node -e 'const d=JSON.parse(require("fs").readFileSync(0,"utf8"));process.stdout.write(String(d.username||""))')"
    admin_pass="$(echo "$cur_info" | node -e 'const d=JSON.parse(require("fs").readFileSync(0,"utf8"));process.stdout.write(String(d.initialPassword||"（已保留原密码，如需重置可执行 ng 选 6）"))')"
    panel_port="$(echo "$cur_info" | node -e 'const d=JSON.parse(require("fs").readFileSync(0,"utf8"));process.stdout.write(String(d.port||""))')"
    base_path="$(echo "$cur_info" | node -e 'const d=JSON.parse(require("fs").readFileSync(0,"utf8"));process.stdout.write(String(d.basePath||"/"))')"
  else
    local default_port default_user default_pass default_path
    default_port="$(gen_random_port)"
    default_user="ng_$(gen_random_str 10)"
    default_pass="$(gen_random_str 18 "$default_user")"
    default_path="/$(gen_random_str 16)/"

    panel_port="$default_port"
    admin_user="$default_user"
    admin_pass="$default_pass"
    base_path="$default_path"

    if [[ -r /dev/tty && "${NG_NONINTERACTIVE:-0}" != "1" ]]; then
      echo ""
      echo -e "${cyan}=== NexusGate Plus · 枢门集群 v1.0.7 已生成本机专属高强度随机登录凭据 ===${plain}"
      echo -e "  • 随机面板端口 : ${yellow}${default_port}${plain}"
      echo -e "  • 随机管理账号 : ${green}${default_user}${plain}"
      echo -e "  • 随机高强密码 : ${green}${default_pass}${plain} (18位大小写字母+数字高强度混合)"
      echo -e "  • 随机安全路径 : ${yellow}${default_path}${plain} (16位防扫描安全根路径)"
      local use_custom="n"
      read -t 8 -r -p "是否直接使用以上随机高强度配置？[Y/n (直接回车或8秒后自动使用随机配置，输入 n 可手动自定义)]: " use_custom </dev/tty || true
      if [[ "${use_custom:-Y}" =~ ^[Nn]$ ]]; then
        read -r -p "请输入自定义面板端口 [默认随机: ${default_port}]: " input_port </dev/tty || true
        [[ -n "${input_port:-}" ]] && panel_port="${input_port//[^0-9]/}"

        read -r -p "请输入自定义管理员账号 [默认随机: ${default_user}]: " input_user </dev/tty || true
        [[ -n "${input_user:-}" ]] && admin_user="$(echo "$input_user" | tr -d '\r\n ')"

        read -r -p "请输入自定义管理员密码 [默认随机 18 位: ${default_pass}]: " input_pass </dev/tty || true
        [[ -n "${input_pass:-}" ]] && admin_pass="$(echo "$input_pass" | tr -d '\r\n ')"
        if [[ "$admin_pass" == "$admin_user" ]]; then
          warn "检测到输入的密码与账号相同，已自动为您生成独立 18 位高强度随机密码！"
          admin_pass="$(gen_random_str 18 "$admin_user")"
        fi

        read -r -p "请输入自定义面板安全路径 [默认随机: ${default_path}]: " input_path </dev/tty || true
        [[ -n "${input_path:-}" ]] && base_path="$(echo "$input_path" | tr -d '\r\n ')"
      fi
    fi

    local init_json
    init_json="$(NG_DATA_FILE="${DATA_DIR}/nexusgate.json" node "$INSTALL_DIR/server.js" --init-panel "$panel_port" "$admin_user" "$admin_pass" "$base_path" "$pub_ip")"
    admin_user="$(echo "$init_json" | node -e 'const d=JSON.parse(require("fs").readFileSync(0,"utf8"));process.stdout.write(String(d.username||""))')"
    admin_pass="$(echo "$init_json" | node -e 'const d=JSON.parse(require("fs").readFileSync(0,"utf8"));process.stdout.write(String(d.password||""))')"
    panel_port="$(echo "$init_json" | node -e 'const d=JSON.parse(require("fs").readFileSync(0,"utf8"));process.stdout.write(String(d.port||""))')"
    base_path="$(echo "$init_json" | node -e 'const d=JSON.parse(require("fs").readFileSync(0,"utf8"));process.stdout.write(String(d.basePath||"/"))')"
  fi

  if [[ -f /etc/x-ui/x-ui.db || -f /root/3xui_backup.tar.gz ]]; then
    local found_xui="/etc/x-ui/x-ui.db"
    [[ ! -f "$found_xui" && -f /root/3xui_backup.tar.gz ]] && found_xui="/root/3xui_backup.tar.gz"
    warn "检测到本机已存在备份数据 (${found_xui})！"
    local do_mig="y"
    if [[ -r /dev/tty && "${NG_NONINTERACTIVE:-0}" != "1" ]]; then
      read -t 10 -r -p "是否立即执行备份迁移恢复全部入站节点、中转出站、分流规则与证书？[Y/n]: " do_mig </dev/tty || true
    fi
    if [[ "${do_mig:-y}" =~ ^[Yy]?$ ]]; then
      NG_DATA_FILE="${DATA_DIR}/nexusgate.json" node "$INSTALL_DIR/server.js" --migrate-3xui "$found_xui" merge || warn "自动迁移可在登录面板后通过【备份迁移】页面操作"
    fi
  fi

  if [[ -x /root/.acme.sh/acme.sh ]]; then
    /root/.acme.sh/acme.sh --install-cronjob >/dev/null 2>&1 || true
    systemctl enable --now cron 2>/dev/null || systemctl enable --now crond 2>/dev/null || true
  fi

  NG_DATA_FILE="${DATA_DIR}/nexusgate.json" node "$INSTALL_DIR/server.js" --open-firewall >/dev/null 2>&1 || true

  install -m 0644 "$INSTALL_DIR/systemd/nexusgate.service" /etc/systemd/system/nexusgate.service
  install -m 0644 "$INSTALL_DIR/systemd/nexusgate-singbox.service" /etc/systemd/system/nexusgate-singbox.service
  install -m 0755 "$INSTALL_DIR/nexusgate.sh" /usr/local/bin/nexusgate
  ln -sf /usr/local/bin/nexusgate /usr/local/bin/ng
  if [[ ! -e /usr/local/bin/x-ui ]]; then
    ln -sf /usr/local/bin/nexusgate /usr/local/bin/x-ui
  fi

  local info_json login_url cert_domain
  info_json="$(NG_DATA_FILE="${DATA_DIR}/nexusgate.json" node "$INSTALL_DIR/server.js" --show-info-json)"
  login_url="$(echo "$info_json" | node -e 'const d=JSON.parse(require("fs").readFileSync(0,"utf8"));process.stdout.write(String(d.url||""))' 2>/dev/null || echo "")"
  cert_domain="$(echo "$info_json" | node -e 'const d=JSON.parse(require("fs").readFileSync(0,"utf8"));process.stdout.write(String(d.defaultNodeTlsDomain||""))' 2>/dev/null || echo "")"

  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    systemctl daemon-reload
    systemctl reset-failed nexusgate.service nexusgate-singbox.service 2>/dev/null || true
    systemctl enable --now nexusgate.service
    systemctl restart nexusgate.service
    systemctl enable --now nexusgate-singbox.service || true
    systemctl restart nexusgate-singbox.service || true
  else
    pkill -f "node.*$INSTALL_DIR/server.js" 2>/dev/null || true
    nohup env NG_DATA_FILE="${DATA_DIR}/nexusgate.json" MALLOC_ARENA_MAX=2 node --expose-gc --max-semi-space-size=8 --max-old-space-size=256 "$INSTALL_DIR/server.js" >/var/log/nexusgate.log 2>&1 &
  fi

  echo ""
  echo -e "${green}==================================================================${plain}"
  echo -e "${green} 🎉 NexusGate Plus · 枢门集群 v1.0.7 安装成功！${plain}"
  echo -e "${green}==================================================================${plain}"
  echo -e " 访问地址   : ${cyan}${login_url}${plain}"
  echo -e " 登录账号   : ${green}${admin_user}${plain}"
  echo -e " 登录密码   : ${green}${admin_pass}${plain}"
  echo -e " 面板端口   : ${yellow}${panel_port}${plain}"
  echo -e " 安全路径   : ${yellow}${base_path}${plain}"
  echo -e " 证书域名   : ${green}${cert_domain}${plain}"
  echo -e " 内核加速   : ${green}已开启 BBR + FQ + HY2 64MB UDP 缓冲优化${plain}"
  echo -e " SSH 命令   : 输入 ${cyan}ng${plain} 或 ${cyan}nexusgate${plain} 呼出管理菜单"
  echo -e "${green}==================================================================${plain}"
}

install_dependencies
install_singbox_binary
enable_bbr_and_hy2_tuning
download_panel_source
configure_panel
