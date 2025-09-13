#!/usr/bin/env bash
# ============================================================
#  Sing-Box-Plus 管理脚本（18 节点：直连 9 + WARP 9）
#  Version: v2.1.2
#  Repo:    https://github.com/Alvin9999/Sing-Box-Plus
#  说明：
#   - 保留原稳定版的 18 节点实现逻辑与链接格式；
#   - 修复 SS2022 psk base64 报错；
#   - “查看分享链接 / 安装部署完成”后自动退出；
#   - 卸载后自动退出；
#   - WARP 采用 wgcf 自动生成账号与 profile。
# ============================================================

set -Eeuo pipefail

SCRIPT_NAME="Sing-Box Native Manager"
SCRIPT_VERSION="v2.1.2"

# 兼容 sing-box 1.12.x 的旧 wireguard 出站
export ENABLE_DEPRECATED_WIREGUARD_OUTBOUND=${ENABLE_DEPRECATED_WIREGUARD_OUTBOUND:-true}

# ===== 颜色与 UI =====
C_RESET="\033[0m"; C_BOLD="\033[1m"; C_DIM="\033[2m"
C_RED="\033[31m";  C_GREEN="\033[32m"; C_YELLOW="\033[33m"
C_BLUE="\033[34m"; C_CYAN="\033[36m"

hr(){ printf "${C_DIM}=============================================================${C_RESET}\n"; }
hr2(){ printf "${C_DIM}──────────────────────────────────────────────────────────${C_RESET}\n"; }
banner(){
  clear
  hr
  echo -e " ${C_CYAN}🚀 Sing-Box-Plus 管理脚本 ${SCRIPT_VERSION} 🚀${C_RESET}"
  echo -e " 脚本更新地址:https://github.com/Alvin9999/Sing-Box-Plus"
  hr
  # 状态栏
  local bbr="未启用"; [[ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)" == *bbr* ]] && bbr="已启用 BBR"
  local sb="未安装"
  if command -v sing-box >/dev/null 2>&1 && systemctl list-units --type=service 2>/dev/null | grep -q '^sing-box.service'; then
    if systemctl is-active --quiet sing-box; then sb="运行中"; else sb="已安装(未运行)"; fi
  fi
  echo -e " 系统加速状态：${C_GREEN}${bbr}${C_RESET}"
  echo -e " Sing-Box 启动状态：${C_RED}${sb}${C_RESET}"
  hr
}

info(){ echo -e "[${C_CYAN}信息${C_RESET}] $*"; }
warn(){ echo -e "[${C_YELLOW}警告${C_RESET}] $*"; }
err(){  echo -e "[${C_RED}错误${C_RESET}] $*"; }

READ_OPTS=(-e -r)

# ===== 工具函数 =====
b64enc(){ base64 -w 0 2>/dev/null || base64; }
urlenc(){ python3 - <<'PY' "$1" 2>/dev/null || python - <<'PY' "$1" 2>/dev/null || busybox sh -c 'echo "$1"' ; exit 0
import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""));PY
}

# 标准 base64（包含 = 结尾也保留），用于 SS2022
rand_b64_32(){ openssl rand -base64 32 | tr -d '\n'; }
rand_hex8(){  head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
gen_uuid(){
  local u=""
  if command -v sing-box >/dev/null 2>&1; then u=$(sing-box generate uuid 2>/dev/null | head -n1 || true); fi
  [[ -z "$u" ]] && command -v uuidgen >/dev/null 2>&1 && u=$(uuidgen | tr 'A-Z' 'a-z')
  [[ -z "$u" ]] && u=$(cat /proc/sys/kernel/random/uuid)
  printf '%s' "$u" | tr -d '\r\n'
}
gen_reality(){
  sing-box generate reality-keypair 2>/dev/null || {
    err "生成 Reality 密钥失败"; return 1;
  }
}
get_ip(){
  local ip
  ip=$(dig +short -4 myip.opendns.com @resolver1.opendns.com 2>/dev/null || true)
  [[ -z "$ip" ]] && ip=$(curl -4s https://api.ipify.org 2>/dev/null || true)
  [[ -z "$ip" ]] && ip=$(curl -4s https://ip.gs 2>/dev/null || true)
  printf '%s' "${ip:-127.0.0.1}"
}

# ===== 路径与全局变量 =====
SB_DIR="/opt/sing-box"
CONF_JSON="$SB_DIR/config.json"
PORTS_ENV="$SB_DIR/ports.env"
CREDS_ENV="$SB_DIR/creds.env"
WGCF_DIR="$SB_DIR/wgcf"
SYSTEMD_SERVICE="sing-box.service"
BIN_PATH="/usr/local/bin/sing-box"

# ===== 读取与保存 ENV =====
load_ports(){ [[ -f "$PORTS_ENV" ]] && . "$PORTS_ENV"; }
load_creds(){ [[ -f "$CREDS_ENV" ]] && . "$CREDS_ENV"; }
save_ports(){
  cat > "$PORTS_ENV" <<EOF
PORT_VLESSR=${PORT_VLESSR}
PORT_VLESS_GRPCR=${PORT_VLESS_GRPCR}
PORT_TROJANR=${PORT_TROJANR}
PORT_HY2=${PORT_HY2}
PORT_VMESS_WS=${PORT_VMESS_WS}
PORT_HY2_OBFS=${PORT_HY2_OBFS}
PORT_SS2022=${PORT_SS2022}
PORT_SS=${PORT_SS}
PORT_TUIC=${PORT_TUIC}
PORT_VLESSR_W=${PORT_VLESSR_W}
PORT_VLESS_GRPCR_W=${PORT_VLESS_GRPCR_W}
PORT_TROJANR_W=${PORT_TROJANR_W}
PORT_HY2_W=${PORT_HY2_W}
PORT_VMESS_WS_W=${PORT_VMESS_WS_W}
PORT_HY2_OBFS_W=${PORT_HY2_OBFS_W}
PORT_SS2022_W=${PORT_SS2022_W}
PORT_SS_W=${PORT_SS_W}
PORT_TUIC_W=${PORT_TUIC_W}
EOF
}
save_creds(){
  cat > "$CREDS_ENV" <<EOF
UUID=${UUID}
GRPC_SERVICE=${GRPC_SERVICE}
VMESS_WS_PATH=${VMESS_WS_PATH}
REALITY_SERVER=${REALITY_SERVER}
REALITY_PRIV=${REALITY_PRIV}
REALITY_PUB=${REALITY_PUB}
REALITY_SID=${REALITY_SID}
HY2_PWD=${HY2_PWD}
HY2_PWD2=${HY2_PWD2}
HY2_OBFS_PWD=${HY2_OBFS_PWD}
SS2022_KEY=${SS2022_KEY}
SS_PWD=${SS_PWD}
TUIC_UUID=${TUIC_UUID}
TUIC_PWD=${TUIC_PWD}
# WARP from wgcf profile
WLOCAL_V4=${WLOCAL_V4}
WLOCAL_V6=${WLOCAL_V6}
WPRIV=${WPRIV}
WPEER_PUB=${WPEER_PUB}
WHOST=${WHOST}
WPORT=${WPORT}
WRSV0=${WRSV0}
WRSV1=${WRSV1}
WRSV2=${WRSV2}
EOF
}

# ===== 端口与凭据生成（不改逻辑，只是写法稳健） =====
alloc_ports(){
  # 随机分配端口（不与系统常用端口冲突）
  PORT_VLESSR=$(shuf -i 10000-19999 -n 1)
  PORT_VLESS_GRPCR=$(shuf -i 10000-19999 -n 1)
  PORT_TROJANR=$(shuf -i 10000-19999 -n 1)
  PORT_HY2=$(shuf -i 10000-19999 -n 1)
  PORT_VMESS_WS=$(shuf -i 10000-19999 -n 1)
  PORT_HY2_OBFS=$(shuf -i 20000-29999 -n 1)
  PORT_SS2022=$(shuf -i 20000-29999 -n 1)
  PORT_SS=$(shuf -i 20000-29999 -n 1)
  PORT_TUIC=$(shuf -i 20000-29999 -n 1)

  PORT_VLESSR_W=$(shuf -i 30000-39999 -n 1)
  PORT_VLESS_GRPCR_W=$(shuf -i 30000-39999 -n 1)
  PORT_TROJANR_W=$(shuf -i 30000-39999 -n 1)
  PORT_HY2_W=$(shuf -i 30000-39999 -n 1)
  PORT_VMESS_WS_W=$(shuf -i 30000-39999 -n 1)
  PORT_HY2_OBFS_W=$(shuf -i 40000-49999 -n 1)
  PORT_SS2022_W=$(shuf -i 40000-49999 -n 1)
  PORT_SS_W=$(shuf -i 40000-49999 -n 1)
  PORT_TUIC_W=$(shuf -i 40000-49999 -n 1)

  save_ports
}

ensure_creds(){
  mkdir -p "$SB_DIR" "$WGCF_DIR"
  load_creds || true

  [[ -z "${UUID:-}" ]] && UUID=$(gen_uuid)
  GRPC_SERVICE="${GRPC_SERVICE:-grpc}"
  VMESS_WS_PATH="${VMESS_WS_PATH:-/vm}"
  REALITY_SERVER="${REALITY_SERVER:-www.microsoft.com}"

  if [[ -z "${REALITY_PRIV:-}" || -z "${REALITY_PUB:-}" || -z "${REALITY_SID:-}" ]]; then
    mapfile -t RKP < <(gen_reality)
    REALITY_PRIV=$(printf '%s\n' "${RKP[@]}" | awk '/PrivateKey/{print $2}')
    REALITY_PUB=$(printf '%s\n' "${RKP[@]}"   | awk '/PublicKey/{print $2}')
    REALITY_SID=$(rand_hex8)
  fi

  [[ -z "${HY2_PWD:-}"    ]] && HY2_PWD=$(openssl rand -base64 16 | tr -d '\n')
  [[ -z "${HY2_PWD2:-}"   ]] && HY2_PWD2=$(rand_b64_32)
  [[ -z "${HY2_OBFS_PWD:-}" ]] && HY2_OBFS_PWD=$(openssl rand -base64 16 | tr -d '\n')

  # 关键修复：SS2022 必须是“标准 base64”
  [[ -z "${SS2022_KEY:-}" ]] && SS2022_KEY=$(rand_b64_32)
  [[ -z "${SS_PWD:-}"     ]] && SS_PWD=$(openssl rand -base64 24 | tr -d '\n' | tr '+/' '-_')

  TUIC_UUID="$UUID"
  TUIC_PWD="$UUID"

  save_creds
}

# ===== 安装依赖 / 安装 sing-box / 安装 wgcf =====
detect_pm(){
  if command -v apt-get >/dev/null 2>&1; then echo apt; return; fi
  if command -v dnf >/dev/null 2>&1; then echo dnf; return; fi
  if command -v yum >/dev/null 2>&1; then echo yum; return; fi
  echo unknown
}
install_deps(){
  local pm; pm=$(detect_pm)
  case "$pm" in
    apt)
      apt-get update -y
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        curl wget tar jq iproute2 ca-certificates openssl dnsutils coreutils iputils-ping
      ;;
    dnf|yum)
      $pm -y install curl wget tar jq iproute ca-certificates openssl bind-utils coreutils iputils
      ;;
    *)
      warn "未识别的包管理器，请手动安装 curl wget tar jq iproute openssl 等依赖"
      ;;
  esac
}
install_singbox(){
  mkdir -p /usr/local/bin
  if ! command -v sing-box >/dev/null 2>&1; then
    info "下载 sing-box (amd64) ..."
    local ver="1.12.7"
    local url="https://github.com/SagerNet/sing-box/releases/download/v${ver}/sing-box-${ver}-linux-amd64.tar.gz"
    curl -fsSL "$url" -o /tmp/sb.tgz
    tar -zxf /tmp/sb.tgz -C /tmp
    install -m 0755 "/tmp/sing-box-${ver}-linux-amd64/sing-box" /usr/local/bin/sing-box
    rm -rf "/tmp/sing-box-${ver}-linux-amd64" /tmp/sb.tgz
  fi
  info "检测到 sing-box：$($BIN_PATH version | head -n1)"
}
install_wgcf(){
  if ! command -v wgcf >/dev/null 2>&1; then
    local ver="2.2.20"  # 稳定版
    local url="https://github.com/ViRb3/wgcf/releases/download/v${ver}/wgcf_${ver}_linux_amd64"
    curl -fsSL "$url" -o /usr/local/bin/wgcf
    chmod +x /usr/local/bin/wgcf
  fi
}

# ===== WARP 账号与 profile（用 wgcf）=====
prepare_warp(){
  install_wgcf
  mkdir -p "$WGCF_DIR"
  if [[ ! -f "$WGCF_DIR/wgcf-account.toml" ]]; then
    info "创建 Cloudflare WARP 账号 ..."
    WGCF_DIR="$WGCF_DIR" HOME="$WGCF_DIR" wgcf register --accept-tos >/dev/null
  fi
  if [[ ! -f "$WGCF_DIR/wgcf-profile.conf" ]]; then
    WGCF_DIR="$WGCF_DIR" HOME="$WGCF_DIR" wgcf generate >/dev/null
  fi

  # 解析 profile
  WPRIV=$(awk -F'= ' '/PrivateKey/{print $2}' "$WGCF_DIR/wgcf-profile.conf" | tr -d '\r')
  WLOCAL_V4=$(awk -F'= ' '/Address = /{print $2}' "$WGCF_DIR/wgcf-profile.conf" | head -n1 | tr -d '\r"')
  WLOCAL_V6=$(awk -F'= ' '/Address = /{print $2}' "$WGCF_DIR/wgcf-profile.conf" | sed -n '2p' | tr -d '\r"')
  local ep; ep=$(awk -F'= ' '/Endpoint/{print $2}' "$WGCF_DIR/wgcf-profile.conf" | tr -d '\r"')
  WHOST=${ep%:*}; WPORT=${ep##*:}
  WPEER_PUB=$(awk -F'= ' '/PublicKey/{print $2}' "$WGCF_DIR/wgcf-profile.conf" | tr -d '\r"')
  # Reserved = x, y, z
  read -r WRSV0 WRSV1 WRSV2 < <(awk -F'= ' '/Reserved/{print $2}' "$WGCF_DIR/wgcf-profile.conf" | tr -d '\r"' | tr -d ' ' | tr -d ',')

  save_creds
}

# ===== 写入配置文件（18 个入站 + warp 出站 + 路由）=====
write_config(){
  load_ports; load_creds

  cat > "$CONF_JSON" <<JSON
{
  "log": { "level": "info" },
  "dns": {
    "servers": [
      { "address": "https://1.1.1.1/dns-query", "strategy": "prefer_ipv4" },
      { "address": "8.8.8.8", "strategy": "prefer_ipv4" }
    ]
  },
  "inbounds": [
    { "type": "vless", "tag": "vless-reality", "listen": "0.0.0.0", "listen_port": $PORT_VLESSR,
      "users": [ { "uuid": "$UUID", "flow": "xtls-rprx-vision" } ],
      "tls": { "enabled": true, "server_name": "$REALITY_SERVER",
        "reality": { "enabled": true, "handshake": { "server": "$REALITY_SERVER", "server_port": 443 },
          "private_key": "$REALITY_PRIV", "short_id": ["$REALITY_SID"] } }
    },
    { "type": "vless", "tag": "vless-grpcr", "listen": "0.0.0.0", "listen_port": $PORT_VLESS_GRPCR,
      "users": [ { "uuid": "$UUID" } ],
      "tls": { "enabled": true, "server_name": "$REALITY_SERVER",
        "reality": { "enabled": true, "handshake": { "server": "$REALITY_SERVER", "server_port": 443 },
          "private_key": "$REALITY_PRIV", "short_id": ["$REALITY_SID"] } },
      "transport": { "type": "grpc", "service_name": "$GRPC_SERVICE" }
    },
    { "type": "trojan", "tag": "trojan-reality", "listen": "0.0.0.0", "listen_port": $PORT_TROJANR,
      "users": [ { "password": "$UUID" } ],
      "tls": { "enabled": true, "server_name": "$REALITY_SERVER",
        "reality": { "enabled": true, "handshake": { "server": "$REALITY_SERVER", "server_port": 443 },
          "private_key": "$REALITY_PRIV", "short_id": ["$REALITY_SID"] } }
    },
    { "type": "hysteria2", "tag": "hy2", "listen": "0.0.0.0", "listen_port": $PORT_HY2,
      "users": [ { "password": "$HY2_PWD" } ],
      "tls": { "enabled": false }
    },
    { "type": "vmess", "tag": "vmess-ws", "listen": "0.0.0.0", "listen_port": $PORT_VMESS_WS,
      "users": [ { "uuid": "$UUID", "alterId": 0 } ],
      "transport": { "type": "ws", "path": "$VMESS_WS_PATH" }
    },
    { "type": "hysteria2", "tag": "hy2-obfs", "listen": "0.0.0.0", "listen_port": $PORT_HY2_OBFS,
      "users": [ { "password": "$HY2_PWD2" } ],
      "obfs": { "type": "salamander", "password": "$HY2_OBFS_PWD" },
      "tls": { "enabled": false }
    },
    { "type": "shadowsocks", "tag": "ss2022", "listen": "0.0.0.0", "listen_port": $PORT_SS2022,
      "method": "2022-blake3-aes-256-gcm", "password": "$SS2022_KEY"
    },
    { "type": "shadowsocks", "tag": "ss", "listen": "0.0.0.0", "listen_port": $PORT_SS,
      "method": "aes-256-gcm", "password": "$SS_PWD"
    },
    { "type": "tuic", "tag": "tuic-v5", "listen": "0.0.0.0", "listen_port": $PORT_TUIC,
      "users": [ { "uuid": "$TUIC_UUID", "password": "$TUIC_PWD" } ],
      "alpn": ["h3"], "zero_rtt_handshake": false, "tls": { "enabled": false }
    },

    { "type": "vless", "tag": "vless-reality-warp", "listen": "0.0.0.0", "listen_port": $PORT_VLESSR_W,
      "users": [ { "uuid": "$UUID", "flow": "xtls-rprx-vision" } ],
      "tls": { "enabled": true, "server_name": "$REALITY_SERVER",
        "reality": { "enabled": true, "handshake": { "server": "$REALITY_SERVER", "server_port": 443 },
          "private_key": "$REALITY_PRIV", "short_id": ["$REALITY_SID"] } }
    },
    { "type": "vless", "tag": "vless-grpcr-warp", "listen": "0.0.0.0", "listen_port": $PORT_VLESS_GRPCR_W,
      "users": [ { "uuid": "$UUID" } ],
      "tls": { "enabled": true, "server_name": "$REALITY_SERVER",
        "reality": { "enabled": true, "handshake": { "server": "$REALITY_SERVER", "server_port": 443 },
          "private_key": "$REALITY_PRIV", "short_id": ["$REALITY_SID"] } },
      "transport": { "type": "grpc", "service_name": "$GRPC_SERVICE" }
    },
    { "type": "trojan", "tag": "trojan-reality-warp", "listen": "0.0.0.0", "listen_port": $PORT_TROJANR_W,
      "users": [ { "password": "$UUID" } ],
      "tls": { "enabled": true, "server_name": "$REALITY_SERVER",
        "reality": { "enabled": true, "handshake": { "server": "$REALITY_SERVER", "server_port": 443 },
          "private_key": "$REALITY_PRIV", "short_id": ["$REALITY_SID"] } }
    },
    { "type": "hysteria2", "tag": "hy2-warp", "listen": "0.0.0.0", "listen_port": $PORT_HY2_W,
      "users": [ { "password": "$HY2_PWD" } ],
      "tls": { "enabled": false }
    },
    { "type": "vmess", "tag": "vmess-ws-warp", "listen": "0.0.0.0", "listen_port": $PORT_VMESS_WS_W,
      "users": [ { "uuid": "$UUID", "alterId": 0 } ],
      "transport": { "type": "ws", "path": "$VMESS_WS_PATH" }
    },
    { "type": "hysteria2", "tag": "hy2-obfs-warp", "listen": "0.0.0.0", "listen_port": $PORT_HY2_OBFS_W,
      "users": [ { "password": "$HY2_PWD2" } ],
      "obfs": { "type": "salamander", "password": "$HY2_OBFS_PWD" },
      "tls": { "enabled": false }
    },
    { "type": "shadowsocks", "tag": "ss2022-warp", "listen": "0.0.0.0", "listen_port": $PORT_SS2022_W,
      "method": "2022-blake3-aes-256-gcm", "password": "$SS2022_KEY"
    },
    { "type": "shadowsocks", "tag": "ss-warp", "listen": "0.0.0.0", "listen_port": $PORT_SS_W,
      "method": "aes-256-gcm", "password": "$SS_PWD"
    },
    { "type": "tuic", "tag": "tuic-v5-warp", "listen": "0.0.0.0", "listen_port": $PORT_TUIC_W,
      "users": [ { "uuid": "$TUIC_UUID", "password": "$TUIC_PWD" } ],
      "alpn": ["h3"], "zero_rtt_handshake": false, "tls": { "enabled": false }
    }
  ],
  "outbounds": [
    { "type": "direct",  "tag": "direct" },
    { "type": "block",   "tag": "block"  },
    { "type": "wireguard", "tag": "warp",
      "local_address": [ "$WLOCAL_V4", "$WLOCAL_V6" ],
      "private_key": "$WPRIV",
      "peers": [
        { "server": "$WHOST", "server_port": $WPORT,
          "public_key": "$WPEER_PUB",
          "reserved": [ $WRSV0, $WRSV1, $WRSV2 ],
          "allowed_ips": ["0.0.0.0/0", "::/0"] }
      ],
      "mtu": 1280
    }
  ],
  "route": {
    "rules": [
      { "inbound": ["vless-reality-warp","vless-grpcr-warp","trojan-reality-warp","hy2-warp","vmess-ws-warp","hy2-obfs-warp","ss2022-warp","ss-warp","tuic-v5-warp"], "outbound": "warp" }
    ],
    "final": "direct"
  }
}
JSON
}

write_systemd(){
  cat > /etc/systemd/system/$SYSTEMD_SERVICE <<EOF
[Unit]
Description=Sing-Box (Native 18 nodes)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=ENABLE_DEPRECATED_WIREGUARD_OUTBOUND=true
ExecStart=/usr/local/bin/sing-box run -c $CONF_JSON
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "$SYSTEMD_SERVICE" >/dev/null 2>&1 || true
}

open_firewall(){
  # 尽量不强依赖 ufw/firewalld，简单放行
  :
}

# ===== 链接导出（分组显示，导出后直接退出）=====
print_links(){
  load_env; load_creds; load_ports; local ip; ip=$(get_ip); local links=()

  # 直连 9
  links+=("vless://${UUID}@${ip}:${PORT_VLESSR}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#vless-reality")
  links+=("vless://${UUID}@${ip}:${PORT_VLESS_GRPCR}?encryption=none&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=grpc&serviceName=${GRPC_SERVICE}#vless-grpc-reality")
  links+=("trojan://${UUID}@${ip}:${PORT_TROJANR}?security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#trojan-reality")
  links+=("hy2://$(urlenc "${HY2_PWD}")@${ip}:${PORT_HY2}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#hysteria2")
  local VMESS_JSON
  printf -v VMESS_JSON '{"v":"2","ps":"vmess-ws","add":"%s","port":"%s","id":"%s","aid":"0","net":"ws","type":"none","host":"","path":"%s","tls":""}' \
    "$ip" "$PORT_VMESS_WS" "$UUID" "$VMESS_WS_PATH"
  links+=("vmess://$(printf '%s' "$VMESS_JSON" | b64enc)")
  links+=("hy2://$(urlenc "${HY2_PWD2}")@${ip}:${PORT_HY2_OBFS}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}&alpn=h3&obfs=salamander&obfs-password=$(urlenc "${HY2_OBFS_PWD}")#hysteria2-obfs")
  links+=("ss://$(printf "%s" "2022-blake3-aes-256-gcm:${SS2022_KEY}" | b64enc)@${ip}:${PORT_SS2022}#ss2022")
  links+=("ss://$(printf "%s" "aes-256-gcm:${SS_PWD}" | b64enc)@${ip}:${PORT_SS}#ss")
  links+=("tuic://${UUID}:$(urlenc "${UUID}")@${ip}:${PORT_TUIC}?congestion_control=bbr&alpn=h3&insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#tuic-v5")

  # WARP 9
  links+=("vless://${UUID}@${ip}:${PORT_VLESSR_W}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#vless-reality-warp")
  links+=("vless://${UUID}@${ip}:${PORT_VLESS_GRPCR_W}?encryption=none&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=grpc&serviceName=${GRPC_SERVICE}#vless-grpc-reality-warp")
  links+=("trojan://${UUID}@${ip}:${PORT_TROJANR_W}?security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#trojan-reality-warp")
  links+=("hy2://$(urlenc "${HY2_PWD}")@${ip}:${PORT_HY2_W}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#hysteria2-warp")
  local VMESS_JSON_W
  printf -v VMESS_JSON_W '{"v":"2","ps":"vmess-ws-warp","add":"%s","port":"%s","id":"%s","aid":"0","net":"ws","type":"none","host":"","path":"%s","tls":""}' \
    "$ip" "$PORT_VMESS_WS_W" "$UUID" "$VMESS_WS_PATH"
  links+=("vmess://$(printf '%s' "$VMESS_JSON_W" | b64enc)")
  links+=("hy2://$(urlenc "${HY2_PWD2}")@${ip}:${PORT_HY2_OBFS_W}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}&alpn=h3&obfs=salamander&obfs-password=$(urlenc "${HY2_OBFS_PWD}")#hysteria2-obfs-warp")
  links+=("ss://$(printf "%s" "2022-blake3-aes-256-gcm:${SS2022_KEY}" | b64enc)@${ip}:${PORT_SS2022_W}#ss2022-warp")
  links+=("ss://$(printf "%s" "aes-256-gcm:${SS_PWD}" | b64enc)@${ip}:${PORT_SS_W}#ss-warp")
  links+=("tuic://${UUID}:$(urlenc "${UUID}")@${ip}:${PORT_TUIC_W}?congestion_control=bbr&alpn=h3&insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#tuic-v5-warp")

  echo -e "${C_BLUE}${C_BOLD}分享链接（18 个）${C_RESET}"; hr2

  local direct=() warp=() l
  for l in "${links[@]}"; do
    if [[ "$l" =~ \#.*-warp$ ]]; then warp+=("$l"); else direct+=("$l"); fi
  done

  echo -e "${C_BLUE}${C_BOLD}【直连节点（9）】${C_RESET}（vless-reality / vless-grpc-reality / trojan-reality / vmess-ws / hy2 / hy2-obfs / ss2022 / ss / tuic）"
  hr2; ((${#direct[@]})) && printf '  %s\n' "${direct[@]}"; hr2; echo

  echo -e "${C_BLUE}${C_BOLD}【WARP 节点（9）】${C_RESET}（同上 9 种，带 -warp）"
  echo -e "${C_DIM}说明：带 -warp 的 9 个节点走 Cloudflare WARP 出口，流媒体解锁更友好${C_RESET}"
  echo -e "${C_DIM}提示：TUIC 默认 allowInsecure=1，v2rayN 导入即用${C_RESET}"
  hr2; ((${#warp[@]})) && printf '  %s\n' "${warp[@]}"; hr2; echo

  exit 0
}

# ===== BBR =====
enable_bbr(){
  if grep -qEi 'ubuntu|debian' /etc/os-release 2>/dev/null; then
    echo 'net.core.default_qdisc=fq' >/etc/sysctl.d/99-bbr.conf
    echo 'net.ipv4.tcp_congestion_control=bbr' >>/etc/sysctl.d/99-bbr.conf
    sysctl --system
  else
    sysctl -w net.core.default_qdisc=fq
    sysctl -w net.ipv4.tcp_congestion_control=bbr
  fi
  echo -e "${C_GREEN}BBR 已启用${C_RESET}"
}

# ===== 安装/部署 =====
load_env(){ :; } # 兼容旧调用
deploy_native(){
  install_deps
  install_singbox
  [[ ! -f "$PORTS_ENV" ]] && alloc_ports || load_ports
  ensure_creds
  prepare_warp
  write_config
  info "检查配置 ..."; ENABLE_DEPRECATED_WIREGUARD_OUTBOUND=true "$BIN_PATH" check -c "$CONF_JSON" || true
  info "写入并启用 systemd 服务 ..."; write_systemd; systemctl restart "$SYSTEMD_SERVICE" || true
  open_firewall
  echo; echo -e "${C_BOLD}${C_GREEN}★ 部署完成（18 节点）${C_RESET}"; echo
  # 打印分享链接并直接退出
  print_links
  exit 0
}

restart_service(){
  systemctl restart "$SYSTEMD_SERVICE" || true
  systemctl status "$SYSTEMD_SERVICE" --no-pager -l || true
}

rotate_ports(){ alloc_ports; write_config; systemctl restart "$SYSTEMD_SERVICE" || true; }

uninstall_all(){
  systemctl disable --now "$SYSTEMD_SERVICE" 2>/dev/null || true
  rm -f "/etc/systemd/system/$SYSTEMD_SERVICE"
  systemctl daemon-reload || true
  rm -rf "$SB_DIR" /usr/local/bin/sing-box /usr/local/bin/wgcf
  echo -e "${C_GREEN}已卸载${C_RESET}"
  exit 0
}

ensure_installed_or_hint(){
  if [[ ! -f "$CONF_JSON" ]]; then
    err "未安装。请先选择 1) 安装/部署（18 节点）"
    return 1
  fi
  return 0
}

# ===== 菜单 =====
menu(){
  banner
  echo -e "  ${C_BLUE}1)${C_RESET} 安装/部署（18 节点）"
  echo -e "  ${C_GREEN}2)${C_RESET} 查看分享链接"
  echo -e "  ${C_GREEN}3)${C_RESET} 重启服务"
  echo -e "  ${C_GREEN}4)${C_RESET} 一键更换所有端口"
  echo -e "  ${C_GREEN}5)${C_RESET} 一键开启 BBR"
  echo -e "  ${C_RED}8)${C_RESET} 卸载"
  echo -e "  ${C_RED}0)${C_RESET} 退出"
  hr
  read "${READ_OPTS[@]}" -p "选择: " op || true
  case "${op:-}" in
    1) deploy_native;;
    2) ensure_installed_or_hint && { print_links; };;
    3) ensure_installed_or_hint && restart_service;;
    4) ensure_installed_or_hint && rotate_ports;;
    5) enable_bbr;;
    8) uninstall_all;;
    0) exit 0;;
    *) :;;
  esac
}

# ===== 入口 =====
menu
