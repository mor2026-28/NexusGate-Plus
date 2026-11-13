#!/usr/bin/env bash
set -Eeuo pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
cyan='\033[0;36m'
plain='\033[0m'

REPO="${NG_REPO:-mor2026-28/NexusGate-Plus}"
BRANCH="${NG_BRANCH:-main}"
INSTALL_DIR="/opt/nexusgate"
DATA_FILE="${NG_DATA_FILE:-/var/lib/nexusgate/nexusgate.json}"

die() { echo -e "${red}[错误]${plain} $*" >&2; exit 1; }
info() { echo -e "${cyan}[NexusGate Plus]${plain} $*"; }
ok() { echo -e "${green}[成功]${plain} $*"; }
warn() { echo -e "${yellow}[提示]${plain} $*"; }

need_root() { [[ "${EUID}" -eq 0 ]] || die "请使用 root 权限运行此命令"; }

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
  head -c 256 /dev/urandom 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c "$len" || true
}

pause_return() {
  if [[ -r /dev/tty ]]; then
    echo ""
    read -r -p "按回车键返回主菜单..." _ </dev/tty || true
  fi
}

panel_status_text() {
  if systemctl is-active --quiet nexusgate.service 2>/dev/null || pgrep -f "node.*$INSTALL_DIR/server.js" >/dev/null 2>&1; then
    echo -e "${green}运行中${plain}"
  else
    echo -e "${red}已停止${plain}"
  fi
}

autostart_status_text() {
  if systemctl is-enabled --quiet nexusgate.service 2>/dev/null; then
    echo -e "${green}是${plain}"
  else
    echo -e "${yellow}否${plain}"
  fi
}

singbox_status_text() {
  local ver=""
  if [[ -x /usr/local/bin/sing-box ]]; then
    ver="$(/usr/local/bin/sing-box version 2>/dev/null | head -n 1 | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?' | head -n 1 || true)"
  fi
  local ver_tag="${ver:+v${ver}}"
  ver_tag="${ver_tag:-已安装}"
  if systemctl is-active --quiet nexusgate-singbox.service 2>/dev/null || pgrep -f "sing-box run" >/dev/null 2>&1; then
    echo -e "${green}运行中 (${ver_tag})${plain}"
  else
    echo -e "${yellow}已停止 (${ver:-未安装})${plain}"
  fi
}

bbr_status_text() {
  local cc qd
  cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo 'cubic')"
  qd="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo 'pfifo')"
  if [[ "$cc" == "bbr" ]]; then
    echo -e "${green}${cc} + ${qd} (已加速)${plain}"
  else
    echo -e "${yellow}${cc} + ${qd}${plain}"
  fi
}

show_info() {
  echo ""
  echo -e "${cyan}──────────────────────── 当前面板配置与访问地址 ────────────────────────${plain}"
  NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --show-info
  echo -e "${cyan}────────────────────────────────────────────────────────────────────────${plain}"
}

cleanup_memory_and_logs() {
  need_root
  info "正在清理系统日志、临时文件并释放内存..."
  mkdir -p /etc/systemd/journald.conf.d
  cat > /etc/systemd/journald.conf.d/99-nexusgate.conf <<'EOF'
[Journal]
SystemMaxUse=64M
SystemMaxFileSize=16M
RuntimeMaxUse=32M
MaxRetentionSec=7day
EOF
  systemctl restart systemd-journald 2>/dev/null || true
  journalctl --vacuum-size=32M >/dev/null 2>&1 || true
  NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --cleanup-memory || true
  sync && echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
  ok "系统日志已收缩至 32MB 以内，临时缓存与可回收内存已释放！"
}

change_account() {
  need_root
  local rand_u="ng_$(gen_random_str 10)"
  local rand_p="$(gen_random_str 18 "$rand_u")"
  local u="" p=""
  read -r -p "请输入新的管理员账号 [直接回车使用高强度随机账号 ${rand_u}]: " u </dev/tty
  u="${u:-$rand_u}"
  read -r -p "请输入新的管理员密码 [直接回车使用 18 位高强度随机密码 ${rand_p}]: " p </dev/tty
  p="${p:-$rand_p}"
  if [[ "$p" == "$u" ]]; then
    warn "检测到密码与账号相同，已自动为您生成独立的 18 位高强度随机密码！"
    p="$(gen_random_str 18 "$u")"
  fi
  systemctl stop nexusgate.service 2>/dev/null || true
  NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --set-account "$u" "$p"
  systemctl start nexusgate.service 2>/dev/null || true
  echo ""
  echo -e "${green}  管理员账号 : ${u}${plain}"
  echo -e "${green}  管理员密码 : ${p}${plain}"
  show_info
}

change_path() {
  need_root
  local rand_str
  rand_str="$(gen_random_str 16)"
  local bp=""
  read -r -p "请输入新的面板安全根路径 [直接回车使用 16 位随机路径 /${rand_str}/ ]: " bp </dev/tty
  bp="${bp:-/$rand_str/}"
  systemctl stop nexusgate.service 2>/dev/null || true
  NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --set-path "$bp"
  systemctl start nexusgate.service 2>/dev/null || true
  ok "面板安全访问路径已更新！(单 IP+端口 已禁止访问，请使用下方完整地址)"
  show_info
}

reset_settings() {
  need_root
  read -r -p "确定要重置面板端口(2053)与访问根路径(/)为默认设置吗？(不会删除节点数据) [y/N]: " c </dev/tty
  [[ "$c" =~ ^[Yy]$ ]] || return 0
  systemctl stop nexusgate.service 2>/dev/null || true
  NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --reset-settings
  systemctl start nexusgate.service 2>/dev/null || true
  ok "面板设置已重置！"
  show_info
}

change_port() {
  need_root
  local rand_port=$(( (RANDOM % 45000) + 15000 ))
  local p=""
  read -r -p "请输入新的面板端口 [直接回车使用随机端口 ${rand_port}]: " p </dev/tty
  p="${p:-$rand_port}"
  systemctl stop nexusgate.service 2>/dev/null || true
  NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --set-port "$p"
  NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --open-firewall >/dev/null 2>&1 || true
  systemctl start nexusgate.service 2>/dev/null || true
  ok "面板端口已更改为: ${p}"
  show_info
}

ensure_acme() {
  if [[ ! -x ~/.acme.sh/acme.sh ]]; then
    info "正在安装 acme.sh 证书管理工具..."
    apt-get install -y -qq socat cron 2>/dev/null || dnf install -y -q socat cronie 2>/dev/null || yum install -y -q socat cronie 2>/dev/null || true
    curl -fsSL https://get.acme.sh | sh
  fi
  ~/.acme.sh/acme.sh --upgrade --auto-upgrade >/dev/null 2>&1 || true
  ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  ~/.acme.sh/acme.sh --install-cronjob >/dev/null 2>&1 || true
  systemctl enable --now cron 2>/dev/null || systemctl enable --now crond 2>/dev/null || true
}

ssl_cert_menu() {
  need_root
  while true; do
    echo ""
    echo -e "${cyan}──────────────── SSL 证书管理 (申请后自动设为面板与节点默认证书) ────────────────${plain}"
    echo -e "  ${green}1.${plain} 获取 SSL 证书 (ACME 域名 80 端口 HTTP-01 模式，自动绑定面板与节点)"
    echo -e "  ${green}2.${plain} 获取 Let's Encrypt IP 短期证书 (无需域名，直接为公网 IP 签发受信任证书)"
    echo -e "  ${green}3.${plain} 无域名一键生成 10 年自签 SSL 证书 (含公网 IP，自动绑定面板与节点)"
    echo -e "  ${green}4.${plain} 撤销已申请的 ACME 证书"
    echo -e "  ${green}5.${plain} 强制更新 / 续签 ACME 证书"
    echo -e "  ${green}6.${plain} 自定义证书路径 (或直接绑定 /root/cert/ 下已有证书)"
    echo -e "  ${green}7.${plain} 显示本机现有证书列表 (/root/cert & /etc/nexusgate/certs)"
    echo -e "  ${green}8.${plain} 关闭面板 HTTPS (恢复为 HTTP 访问)"
    echo -e "  ${green}0.${plain} 返回主菜单"
    read -r -p "请选择一个选项 [0-8]: " sub </dev/tty
    case "$sub" in
      1)
        ensure_acme
        local domain="" email="" port80=""
        read -r -p "请输入已解析到本机的域名: " domain </dev/tty
        domain="$(echo "$domain" | tr -d '\r\n ')"
        [[ -n "$domain" ]] || die "域名不能为空"
        read -r -p "请输入通知邮箱 (可留空): " email </dev/tty || true
        read -r -p "HTTP 验证监听端口 [默认 80]: " port80 </dev/tty || true
        port80="${port80:-80}"
        [[ -n "$email" ]] && ~/.acme.sh/acme.sh --register-account -m "$email" >/dev/null 2>&1 || true
        mkdir -p "/root/cert/${domain}" "/etc/nexusgate/certs/${domain}"
        ~/.acme.sh/acme.sh --issue -d "$domain" --standalone --httpport "$port80" --force || true
        ~/.acme.sh/acme.sh --installcert -d "$domain" \
          --key-file "/root/cert/${domain}/privkey.pem" \
          --fullchain-file "/root/cert/${domain}/fullchain.pem"
        cp -f "/root/cert/${domain}/fullchain.pem" "/etc/nexusgate/certs/${domain}/fullchain.pem"
        cp -f "/root/cert/${domain}/privkey.pem" "/etc/nexusgate/certs/${domain}/privkey.pem"
        systemctl stop nexusgate.service 2>/dev/null || true
        rm -rf /etc/nexusgate/certs/www.bing.com /root/cert/www.bing.com 2>/dev/null || true
        NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --set-cert "/root/cert/${domain}/fullchain.pem" "/root/cert/${domain}/privkey.pem" "$domain"
        systemctl start nexusgate.service 2>/dev/null || true
        systemctl restart nexusgate-singbox.service 2>/dev/null || true
        ok "域名 ${domain} 证书申请成功，已同时设为面板 HTTPS 与全部 TLS 节点默认证书！"
        show_info
        ;;
      2)
        ensure_acme
        local pub_ip=""
        pub_ip="$(curl -fsSL4 --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
        read -r -p "请输入本机公网 IPv4 [默认 ${pub_ip}]: " input_ip </dev/tty || true
        pub_ip="${input_ip:-$pub_ip}"
        mkdir -p "/root/cert/ip" "/etc/nexusgate/certs/${pub_ip}"
        ~/.acme.sh/acme.sh --issue -d "$pub_ip" --standalone --server letsencrypt --certificate-profile shortlived --days 6 --httpport 80 --force
        ~/.acme.sh/acme.sh --installcert -d "$pub_ip" \
          --key-file "/root/cert/ip/privkey.pem" \
          --fullchain-file "/root/cert/ip/fullchain.pem" || true
        systemctl stop nexusgate.service 2>/dev/null || true
        NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --set-cert "/root/cert/ip/fullchain.pem" "/root/cert/ip/privkey.pem" "$pub_ip"
        systemctl start nexusgate.service 2>/dev/null || true
        systemctl restart nexusgate-singbox.service 2>/dev/null || true
        ok "IP 短期受信任证书签发成功并已绑定至面板与节点！"
        show_info
        ;;
      3)
        local sni="" pub_ip=""
        pub_ip="$(curl -fsSL4 --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
        read -r -p "请输入自签伪装域名 SNI [直接回车默认 www.apple.com]: " sni </dev/tty || true
        sni="${sni:-www.apple.com}"
        systemctl stop nexusgate.service 2>/dev/null || true
        NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --issue-selfsigned "$sni" "$pub_ip" --force
        systemctl start nexusgate.service 2>/dev/null || true
        systemctl restart nexusgate-singbox.service 2>/dev/null || true
        ok "10 年自签 SSL 证书已生成，并已同步绑定至面板 HTTPS 与 Sing-box 节点默认证书！"
        show_info
        ;;
      4)
        local d=""
        read -r -p "请输入要撤销的域名或 IP: " d </dev/tty
        ~/.acme.sh/acme.sh --revoke -d "$d" && ~/.acme.sh/acme.sh --remove -d "$d"
        rm -rf "/root/cert/${d}" "/etc/nexusgate/certs/${d}"
        ok "证书 ${d} 已撤销"
        ;;
      5)
        ~/.acme.sh/acme.sh --cron --force
        systemctl restart nexusgate.service nexusgate-singbox.service 2>/dev/null || true
        ok "已完成强制续签检查"
        ;;
      6)
        local cf="" kf="" dm=""
        read -r -p "请输入公钥证书路径 (如 /root/cert/example.com/fullchain.pem): " cf </dev/tty
        read -r -p "请输入私钥文件路径 (如 /root/cert/example.com/privkey.pem): " kf </dev/tty
        read -r -p "请输入对应域名标识: " dm </dev/tty || true
        [[ -f "$cf" && -f "$kf" ]] || die "证书或私钥文件不存在"
        systemctl stop nexusgate.service 2>/dev/null || true
        NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --set-cert "$cf" "$kf" "$dm"
        systemctl start nexusgate.service 2>/dev/null || true
        systemctl restart nexusgate-singbox.service 2>/dev/null || true
        ok "自定义证书已成功绑定至面板 HTTPS 与节点默认证书！"
        show_info
        ;;
      7)
        echo -e "${cyan}--- 已发现的证书目录 ---${plain}"
        find /root/cert /etc/nexusgate/certs -maxdepth 2 -name "*.pem" 2>/dev/null || echo "暂无证书文件"
        ;;
      8)
        systemctl stop nexusgate.service 2>/dev/null || true
        NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --set-cert "" ""
        systemctl start nexusgate.service 2>/dev/null || true
        ok "已关闭面板 HTTPS，现在可通过 HTTP 访问面板！"
        show_info
        ;;
      0) break ;;
      *) warn "无效选项" ;;
    esac
  done
}

cf_ssl_cert() {
  need_root
  ensure_acme
  echo -e "${cyan}──────────────── Cloudflare DNS API 申请 SSL 证书 ────────────────${plain}"
  local domain="" mode=""
  read -r -p "请输入要申请的域名: " domain </dev/tty
  domain="$(echo "$domain" | tr -d '\r\n ')"
  [[ -n "$domain" ]] || die "域名不能为空"
  echo -e "  ${green}1.${plain} 使用 Cloudflare API Token (推荐，Zone:DNS:Edit 权限)"
  echo -e "  ${green}2.${plain} 使用 Cloudflare Global API Key + 注册邮箱"
  read -r -p "请选择验证方式 [1-2]: " mode </dev/tty
  if [[ "$mode" == "2" ]]; then
    local cf_key="" cf_email=""
    read -r -p "请输入 CF Global API Key: " cf_key </dev/tty
    read -r -p "请输入 CF 账号邮箱: " cf_email </dev/tty
    export CF_Key="$cf_key"
    export CF_Email="$cf_email"
  else
    local cf_token=""
    read -r -p "请输入 CF API Token: " cf_token </dev/tty
    export CF_Token="$cf_token"
  fi
  mkdir -p "/root/cert/${domain}" "/etc/nexusgate/certs/${domain}"
  ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$domain" --force || true
  ~/.acme.sh/acme.sh --installcert -d "$domain" \
    --key-file "/root/cert/${domain}/privkey.pem" \
    --fullchain-file "/root/cert/${domain}/fullchain.pem"
  cp -f "/root/cert/${domain}/fullchain.pem" "/etc/nexusgate/certs/${domain}/fullchain.pem"
  cp -f "/root/cert/${domain}/privkey.pem" "/etc/nexusgate/certs/${domain}/privkey.pem"
  systemctl stop nexusgate.service 2>/dev/null || true
  rm -rf /etc/nexusgate/certs/www.bing.com /root/cert/www.bing.com 2>/dev/null || true
  NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --set-cert "/root/cert/${domain}/fullchain.pem" "/root/cert/${domain}/privkey.pem" "$domain"
  systemctl start nexusgate.service 2>/dev/null || true
  systemctl restart nexusgate-singbox.service 2>/dev/null || true
  ok "Cloudflare SSL 证书申请成功，已自动绑定至面板与全部 TLS 节点！"
  show_info
}

bbr_menu() {
  need_root
  while true; do
    echo ""
    echo -e "${cyan}──────────────── BBR + FQ 与 HY2 UDP 内核加速管理 ────────────────${plain}"
    echo -e "  当前状态: $(bbr_status_text)"
    echo -e "  ${green}1.${plain} 启用 BBR + FQ + Hysteria 2 (64MB UDP 缓冲) 全套内核加速 [推荐]"
    echo -e "  ${green}2.${plain} 仅启用 BBR + FQ TCP 拥塞控制加速"
    echo -e "  ${green}3.${plain} 禁用自定义加速 (恢复系统默认配置)"
    echo -e "  ${green}0.${plain} 返回主菜单"
    read -r -p "请输入选项 [0-3]: " b </dev/tty
    case "$b" in
      1)
        modprobe tcp_bbr 2>/dev/null || true
        cat > /etc/sysctl.d/99-nexusgate-acceleration.conf <<'EOF'
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
        ok "已成功开启 BBR + FQ + HY2 64MB UDP 高速缓冲区内核加速！"
        ;;
      2)
        modprobe tcp_bbr 2>/dev/null || true
        cat > /etc/sysctl.d/99-nexusgate-acceleration.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
        sysctl --system >/dev/null 2>&1 || true
        ok "已启用 BBR + FQ！"
        ;;
      3)
        rm -f /etc/sysctl.d/99-nexusgate-acceleration.conf
        sysctl --system >/dev/null 2>&1 || true
        ok "已移除自定义内核加速配置"
        ;;
      0) break ;;
      *) warn "无效选项" ;;
    esac
  done
}

firewall_menu() {
  need_root
  echo -e "${cyan}──────────────── 防火墙端口管理 (支持 Debian/Ubuntu/CentOS) ────────────────${plain}"
  echo -e "  ${green}1.${plain} 一键自动放行面板端口与所有 Sing-box 节点端口"
  echo -e "  ${green}2.${plain} 手动放行指定端口 (TCP + UDP)"
  echo -e "  ${green}3.${plain} 查看当前防火墙状态与监听端口"
  echo -e "  ${green}0.${plain} 返回主菜单"
  local f=""
  read -r -p "请选择 [0-3]: " f </dev/tty
  case "$f" in
    1)
      NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --open-firewall
      ok "面板与所有节点端口已全部放行！"
      ;;
    2)
      local mp=""
      read -r -p "请输入要放行的端口号: " mp </dev/tty
      if command -v ufw >/dev/null 2>&1; then
        ufw allow "${mp}/tcp" >/dev/null 2>&1 || true
        ufw allow "${mp}/udp" >/dev/null 2>&1 || true
      fi
      if command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="${mp}/tcp" >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port="${mp}/udp" >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
      fi
      if command -v iptables >/dev/null 2>&1; then
        iptables -C INPUT -p tcp --dport "$mp" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$mp" -j ACCEPT 2>/dev/null || true
        iptables -C INPUT -p udp --dport "$mp" -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport "$mp" -j ACCEPT 2>/dev/null || true
      fi
      ok "端口 ${mp} (TCP+UDP) 已放行"
      ;;
    3)
      echo -e "${cyan}--- 1. 防火墙规则状态 ---${plain}"
      if command -v ufw >/dev/null 2>&1; then
        ufw status verbose || true
      elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --list-all || true
      elif command -v iptables >/dev/null 2>&1; then
        iptables -L INPUT -n --line-numbers | head -n 30 || true
      else
        echo "当前系统未安装额外主机防火墙拦截器 (默认全端口直通)"
      fi
      echo ""
      echo -e "${cyan}--- 2. 当前本机正在监听的面板与 Sing-box 节点端口 ---${plain}"
      ss -tulnp 2>/dev/null | grep -E "sing-box|node|Local" || ss -tuln 2>/dev/null | head -n 25 || true
      ;;
  esac
}

ip_limit_menu() {
  need_root
  echo -e "${cyan}──────────────── IP 与设备数量限制 / Fail2ban 管理 ────────────────${plain}"
  echo -e "  • 节点同时在线公网 IP 数限制与同时在线设备数限制：可在 Web 面板【入站节点管理 -> 编辑节点】中独立设置。"
  echo -e "  ${green}1.${plain} 安装并启用 SSH 与面板防爆破组件 (Fail2ban)"
  echo -e "  ${green}2.${plain} 查看 Fail2ban 状态"
  echo -e "  ${green}0.${plain} 返回主菜单"
  local il=""
  read -r -p "请选择 [0-2]: " il </dev/tty
  if [[ "$il" == "1" ]]; then
    apt-get install -y -qq fail2ban 2>/dev/null || dnf install -y -q fail2ban 2>/dev/null || yum install -y -q fail2ban 2>/dev/null || true
    systemctl enable --now fail2ban 2>/dev/null || true
    ok "Fail2ban 已安装并启动"
  elif [[ "$il" == "2" ]]; then
    systemctl status fail2ban --no-pager 2>/dev/null || true
  fi
}

update_geo_files() {
  need_root
  info "正在更新 Sing-box 本地 GeoIP / Geosite 规则集文件..."
  mkdir -p /etc/nexusgate/sing-box/rulesets
  curl -fL --retry 2 "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs" -o /etc/nexusgate/sing-box/rulesets/geosite-cn.srs || true
  curl -fL --retry 2 "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs" -o /etc/nexusgate/sing-box/rulesets/geoip-cn.srs || true
  curl -fL --retry 2 "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs" -o /etc/nexusgate/sing-box/rulesets/geosite-category-ads-all.srs || true
  systemctl restart nexusgate-singbox.service 2>/dev/null || true
  ok "Geo 分流规则文件更新完成！"
}

run_speedtest() {
  info "正在运行网络带宽与延迟测试..."
  if command -v speedtest >/dev/null 2>&1; then
    speedtest
  else
    curl -fsSL https://install.speedtest.net/app/cli/install.deb.sh 2>/dev/null | bash >/dev/null 2>&1 || true
    apt-get install -y -qq speedtest 2>/dev/null || true
    if command -v speedtest >/dev/null 2>&1; then
      speedtest
    else
      curl -Lso- bench.sh | bash
    fi
  fi
}

switch_singbox_version() {
  need_root
  local ver=""
  read -r -p "请输入要切换的 Sing-box 版本号 [默认 1.12.23]: " ver </dev/tty
  ver="${ver:-1.12.23}"
  ver="${ver#v}"
  local arch="amd64"
  case "$(uname -m)" in
    aarch64|arm64) arch="arm64" ;;
    armv7*) arch="armv7" ;;
  esac
  local tmp
  tmp="$(mktemp -d /tmp/ng-sb-up.XXXXXX)"
  local url="https://github.com/SagerNet/sing-box/releases/download/v${ver}/sing-box-${ver}-linux-${arch}.tar.gz"
  info "正在下载 ${url} ..."
  curl -fL --retry 3 "$url" -o "$tmp/sb.tar.gz"
  tar -xzf "$tmp/sb.tar.gz" -C "$tmp" --strip-components=1
  install -m 0755 "$tmp/sing-box" /usr/local/bin/sing-box
  rm -rf -- "$tmp"
  systemctl restart nexusgate-singbox.service 2>/dev/null || true
  ok "Sing-box 内核已成功切换至: $(/usr/local/bin/sing-box version | head -n 1)"
}

migrate_3xui() {
  need_root
  local default_db="/etc/x-ui/x-ui.db"
  [[ ! -f "$default_db" && -f /root/3xui_backup.tar.gz ]] && default_db="/root/3xui_backup.tar.gz"
  local db_path=""
  read -r -p "请输入备份数据库或通用备份包路径 [默认 ${default_db}]: " db_path </dev/tty || true
  db_path="${db_path:-$default_db}"
  systemctl stop nexusgate.service nexusgate-singbox.service 2>/dev/null || true
  pkill -9 -f "sing-box run" 2>/dev/null || true
  NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --migrate-3xui "$db_path" merge
  if [[ -x /root/.acme.sh/acme.sh ]]; then
    /root/.acme.sh/acme.sh --install-cronjob >/dev/null 2>&1 || true
    systemctl enable --now cron 2>/dev/null || systemctl enable --now crond 2>/dev/null || true
  fi
  NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --open-firewall >/dev/null 2>&1 || true
  systemctl reset-failed nexusgate.service nexusgate-singbox.service 2>/dev/null || true
  systemctl start nexusgate.service 2>/dev/null || true
  systemctl restart nexusgate-singbox.service 2>/dev/null || true
}

update_panel() {
  need_root
  info "正在从 GitHub (${REPO}@${BRANCH}) 更新 NexusGate 面板与脚本..."
  local tmp
  tmp="$(mktemp -d /tmp/ng-update.XXXXXX)"
  curl -fL --retry 3 "https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz" -o "$tmp/src.tar.gz"
  systemctl stop nexusgate.service nexusgate-singbox.service 2>/dev/null || true
  pkill -9 -f "sing-box run" 2>/dev/null || true
  mkdir -p "$INSTALL_DIR"
  tar -xzf "$tmp/src.tar.gz" -C "$INSTALL_DIR" --strip-components=1
  install -m 0644 "$INSTALL_DIR/systemd/nexusgate.service" /etc/systemd/system/nexusgate.service
  install -m 0644 "$INSTALL_DIR/systemd/nexusgate-singbox.service" /etc/systemd/system/nexusgate-singbox.service
  install -m 0755 "$INSTALL_DIR/nexusgate.sh" /usr/local/bin/nexusgate
  ln -sf /usr/local/bin/nexusgate /usr/local/bin/ng
  rm -rf -- "$tmp" /etc/nexusgate/certs/www.bing.com /root/cert/www.bing.com 2>/dev/null || true

  mkdir -p /etc/systemd/journald.conf.d
  cat > /etc/systemd/journald.conf.d/99-nexusgate.conf <<'EOF'
[Journal]
SystemMaxUse=64M
SystemMaxFileSize=16M
RuntimeMaxUse=32M
MaxRetentionSec=7day
EOF
  systemctl restart systemd-journald 2>/dev/null || true
  journalctl --vacuum-size=32M >/dev/null 2>&1 || true
  systemctl daemon-reload 2>/dev/null || true
  systemctl reset-failed nexusgate.service nexusgate-singbox.service 2>/dev/null || true

  if [[ -x /root/.acme.sh/acme.sh ]]; then
    /root/.acme.sh/acme.sh --install-cronjob >/dev/null 2>&1 || true
  fi

  NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --issue-selfsigned >/dev/null 2>&1 || true
  NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --open-firewall >/dev/null 2>&1 || true
  systemctl start nexusgate.service 2>/dev/null || true
  systemctl restart nexusgate-singbox.service 2>/dev/null || true
  ok "NexusGate Plus 面板与管理脚本已更新至 v1.0.7，所有节点与 Sing-box 内核已重新加载生效！"
  show_info
  if [[ -r /dev/tty ]]; then
    pause_return
    exec /usr/local/bin/nexusgate
  fi
}

uninstall_panel() {
  need_root
  read -r -p "确定要卸载 NexusGate 面板吗？[y/N]: " confirm </dev/tty
  [[ "$confirm" =~ ^[Yy]$ ]] || return 0
  systemctl stop nexusgate.service nexusgate-singbox.service 2>/dev/null || true
  systemctl disable nexusgate.service nexusgate-singbox.service 2>/dev/null || true
  rm -f /etc/systemd/system/nexusgate.service /etc/systemd/system/nexusgate-singbox.service
  systemctl daemon-reload 2>/dev/null || true
  rm -rf "$INSTALL_DIR" /usr/local/bin/nexusgate /usr/local/bin/ng
  ok "NexusGate 面板已卸载（数据备份保留在 /var/lib/nexusgate）"
  exit 0
}

show_menu() {
  clear 2>/dev/null || true
  echo -e "
  ${cyan}╔════════════════════════════════════════════════════════════════╗${plain}
  ${cyan}║${plain}     ${green}         NexusGate Plus · 枢门集群 面板管理脚本 (v1.0.7)         ${plain}      ${cyan}║${plain}
  ${cyan}║${plain}     ${yellow}全协议节点编排 · BBR+FQ+HY2 加速 · ACME 证书联动${plain}          ${cyan}║${plain}
  ${cyan}╚════════════════════════════════════════════════════════════════╝${plain}
  ${green}0.${plain} 退出脚本
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ${green}1.${plain} 安装面板
  ${green}2.${plain} 更新面板 (从 GitHub 拉取最新代码并自动重启生效)
  ${green}3.${plain} 备份 / 导出面板数据
  ${green}4.${plain} 自定义 / 切换 Sing-box 内核版本
  ${green}5.${plain} 卸载面板
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ${green}6.${plain} 重置用户名、密码 (默认生成18位高强度密码)
  ${green}7.${plain} 修改访问路径 (默认生成16位随机安全路径)
  ${green}8.${plain} 重置面板设置 (恢复默认端口与路径)
  ${green}9.${plain} 修改面板端口
  ${green}10.${plain} 查看当前面板配置与访问地址 (端口 / 安全路径 / 证书 / 节点统计)
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ${green}11.${plain} 启动面板与 Sing-box
  ${green}12.${plain} 关闭面板与 Sing-box
  ${green}13.${plain} 重启面板与 Sing-box
  ${green}14.${plain} 检查面板与 Sing-box 状态
  ${green}15.${plain} 查看面板与 Sing-box 日志
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ${green}16.${plain} 启用开机自启
  ${green}17.${plain} 禁用开机自启
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ${green}18.${plain} SSL 证书管理 (自动绑定面板与节点 / ACME / IP证书 / 自签)
  ${green}19.${plain} Cloudflare SSL 证书 (CF DNS API 申请)
  ${green}20.${plain} IP 与设备数限制 / 防爆破管理
  ${green}21.${plain} 防火墙端口管理 (自动放行面板与所有节点端口)
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ${green}22.${plain} 启用 BBR + FQ / HY2 UDP 高速内核加速
  ${green}23.${plain} 更新 Geo 分流规则文件
  ${green}24.${plain} Speedtest 测速工具
  ${green}25.${plain} 一键备份迁移 (导入 x-ui.db / 通用备份包恢复全部节点与证书)
  ${green}26.${plain} 一键清理系统日志与释放内存
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  面板状态: $(panel_status_text)
  开机启动: $(autostart_status_text)
  内核状态: $(singbox_status_text)
  网络加速: $(bbr_status_text)
"
  local choice=""
  read -r -p "请输入选项 [0-26]: " choice </dev/tty || exit 0
  case "$choice" in
    0) exit 0 ;;
    1) bash "$INSTALL_DIR/install.sh" ;;
    2) update_panel ; pause_return ;;
    3) NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --export-backup "/root/nexusgate-master-backup-$(date +%F).zip" && ok "已成功导出全集群完整备份至 /root/nexusgate-master-backup-$(date +%F).zip (含全部中转机、落地机与证书)" ; pause_return ;;
    4) switch_singbox_version ; pause_return ;;
    5) uninstall_panel ;;
    6) change_account ; pause_return ;;
    7) change_path ; pause_return ;;
    8) reset_settings ; pause_return ;;
    9) change_port ; pause_return ;;
    10) show_info ; pause_return ;;
    11) systemctl start nexusgate.service nexusgate-singbox.service && ok "已启动" ; pause_return ;;
    12) systemctl stop nexusgate.service nexusgate-singbox.service && ok "已停止" ; pause_return ;;
    13) pkill -9 -f "sing-box run" 2>/dev/null || true ; systemctl reset-failed nexusgate.service nexusgate-singbox.service 2>/dev/null || true ; systemctl restart nexusgate.service nexusgate-singbox.service && ok "已重启" ; pause_return ;;
    14) systemctl status nexusgate.service nexusgate-singbox.service --no-pager || true ; pause_return ;;
    15) journalctl -u nexusgate.service -u nexusgate-singbox.service -n 80 --no-pager || true ; pause_return ;;
    16) systemctl enable nexusgate.service nexusgate-singbox.service && ok "已启用开机自启" ; pause_return ;;
    17) systemctl disable nexusgate.service nexusgate-singbox.service && ok "已禁用开机自启" ; pause_return ;;
    18) ssl_cert_menu ;;
    19) cf_ssl_cert ; pause_return ;;
    20) ip_limit_menu ; pause_return ;;
    21) firewall_menu ; pause_return ;;
    22) bbr_menu ;;
    23) update_geo_files ; pause_return ;;
    24) run_speedtest ; pause_return ;;
    25) migrate_3xui ; pause_return ;;
    26) cleanup_memory_and_logs ; pause_return ;;
    *) warn "请输入有效数字 [0-26]" ; sleep 1 ;;
  esac
}

if [[ $# -gt 0 ]]; then
  case "$1" in
    start) systemctl start nexusgate.service nexusgate-singbox.service ;;
    stop) systemctl stop nexusgate.service nexusgate-singbox.service ;;
    restart) pkill -9 -f "sing-box run" 2>/dev/null || true ; systemctl reset-failed nexusgate.service nexusgate-singbox.service 2>/dev/null || true ; systemctl restart nexusgate.service nexusgate-singbox.service ;;
    status) systemctl status nexusgate.service nexusgate-singbox.service --no-pager ;;
    info|settings) show_info ;;
    backup|export)
      local bfile="${2:-/root/nexusgate-master-backup-$(date +%F).zip}"
      NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --export-backup "$bfile"
      ok "全集群备份已导出至: $bfile"
      ;;
    restore|import)
      local rfile="${2:-}"
      [[ -n "$rfile" ]] || die "用法: ng restore <备份文件.zip 或 .json 路径>"
      systemctl stop nexusgate.service 2>/dev/null || true
      NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --restore-backup "$rfile"
      systemctl start nexusgate.service 2>/dev/null || true
      ok "全集群配置已从 $rfile 恢复成功！"
      show_info
      ;;
    clean|cleanup) cleanup_memory_and_logs ;;
    log|logs) journalctl -u nexusgate.service -u nexusgate-singbox.service -n 100 --no-pager ;;
    bbr) bbr_menu ;;
    cert|ssl) ssl_cert_menu ;;
    firewall|fw) NG_DATA_FILE="$DATA_FILE" node "$INSTALL_DIR/server.js" --open-firewall ;;
    migrate) migrate_3xui ;;
    update) update_panel ;;
    uninstall) uninstall_panel ;;
    *) show_menu ;;
  esac
else
  while true; do
    show_menu
  done
fi
