#!/usr/bin/env bash
# ============================================================
#  Sing-Box-Plus 管理脚本（18 节点：直连 9 + WARP 9）
#  Version: v2.1.3
#  Repo:    https://github.com/Alvin9999/Sing-Box-Plus
#  说明：
#   - 保留稳定版 18 节点实现逻辑与链接格式（仅做稳健性增强与美化）；
#   - 修复 SS2022 psk base64 问题；WARP Reserved 容错；
#   - “查看分享链接 / 安装部署完成 / 卸载完成”后均自动退出；
#   - WARP 使用 wgcf 自动生成账号与 profile；
#   - urlenc() 纯 Bash/JQ/Python 兜底实现（无 heredoc）。
# ============================================================

set -Eeuo pipefail

SCRIPT_NAME="Sing-Box Native Manager"
SCRIPT_VERSION="v2.1.3"

# 兼容 sing-box 1.12.x 的旧 wireguard 出站
export ENABLE_DEPRECATED_WIREGUARD_OUTBOUND=${ENABLE_DEPRECATED_WIREGUARD_OUTBOUND:-true}

# ===== UI =====
C_RESET="\033[0m"; C_BOLD="\033[1m"; C_DIM="\033[2m"
C_RED="\033[31m";  C_GREEN="\033[32m"; C_YELLOW="\033[33m"
C_BLUE="\033[34m"; C_CYAN="\033[36m"
hr(){ printf "${C_DIM}──────────────────────────────────────────────────────────${C_RESET}\n"; }
banner(){
  clear
  echo -e "${C_CYAN}${C_BOLD}${SCRIPT_NAME} ${SCRIPT_VERSION}${C_RESET}"
  hr
  # 状态栏（BBR、Sing-Box）
  local bbr="未启用"; sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -qi bbr && bbr="已启用 BBR"
  local svc="未安装"; systemctl is-active --quiet sing-box && svc="运行中"; systemctl is-enabled --quiet sing-box 2>/dev/null || svc="未安装"
  echo -e "系统加速状态：${C_GREEN}${bbr}${C_RESET}"
  echo -e "Sing-Box 启动状态：${C_RED}${svc}${C_RESET}"
  hr
  echo -e "  ${C_BLUE}1)${C_RESET} 安装/部署（18 节点）"
  echo -e "  ${C_GREEN}2)${C_RESET} 查看分享链接"
  echo -e "  ${C_GREEN}3)${C_RESET} 重启服务"
  echo -e "  ${C_GREEN}4)${C_RESET} 一键更换所有端口"
  echo -e "  ${C_GREEN}5)${C_RESET} 一键开启 BBR"
  echo -e "  ${C_RED}8)${C_RESET} 卸载"
  echo -e "  ${C_RED}0)${C_RESET} 退出"
  hr
}
info(){ echo -e "[信息] $*"; }
warn(){ echo -e "${C_YELLOW}[警告]${C_RESET} $*"; }
err(){  echo -e "${C_RED}[错误]${C_RESET} $*"; }

READ_OPTS=(-e -r)

# ===== 路径 =====
SB_DIR="/opt/sing-box"
BIN_PATH="/usr/local/bin/sing-box"
CONF_JSON="$SB_DIR/config.json"
PORTS_ENV="$SB_DIR/ports.env"
CREDS_ENV="$SB_DIR/creds.env"
WGCF_DIR="$SB_DIR/wgcf"
SYSTEMD_SERVICE="sing-box.service"

mkdir -p "$SB_DIR" "$WGCF_DIR"

# ===== 工具函数 =====
need_root(){ [ "$(id -u)" = "0" ] || { err "请用 root 运行"; exit 1; }; }
b64enc(){ base64 | tr -d '\n\r'; }
get_ip(){
  # 优先内核路由取本机出口 IP；失败再尝试 http
  ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {print $7; exit}' || \
  curl -fsSL4 https://api.ipify.org 2>/dev/null || \
  curl -fsSL4 https://ifconfig.me 2>/dev/null || echo "127.0.0.1"
}
urlenc(){
  # 优先 jq（多数发行版自带）
  if command -v jq >/dev/null 2>&1; then
    jq -sRr @uri
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import sys,urllib.parse as u;print(u.quote(sys.stdin.read().rstrip("\n"), safe=""))'
  elif command -v python >/dev/null 2>&1; then
    python -c 'import sys,urllib as u;print u.quote(sys.stdin.read().rstrip("\n"), safe="")'
  else
    # 粗略替代：仅处理常见字符
    sed -e 's/%/%25/g;s/ /%20/g;s/\//%2F/g;s/+/%2B/g;s/=/%3D/g;s/:/%3A/g'
  fi
}
rand_port(){ shuf -i 10240-65535 -n 1; }
unique_ports(){
  # 生成 18 个互不重复端口（若已有 ports.env 则复用）
  if [ -f "$PORTS_ENV" ]; then . "$PORTS_ENV"; return; fi
  declare -A used=()
  pick(){ local p; while :; do p=$(rand_port); [[ -z "${used[$p]-}" ]] && { used[$p]=1; echo "$p"; return; } done; }
  PORT_VLESSR=$(pick); PORT_VLESS_GRPCR=$(pick); PORT_TROJANR=$(pick); PORT_HY2=$(pick); PORT_VMESS_WS=$(pick); PORT_HY2_OBFS=$(pick); PORT_SS2022=$(pick); PORT_SS=$(pick); PORT_TUIC=$(pick)
  PORT_VLESSR_W=$(pick); PORT_VLESS_GRPCR_W=$(pick); PORT_TROJANR_W=$(pick); PORT_HY2_W=$(pick); PORT_VMESS_WS_W=$(pick); PORT_HY2_OBFS_W=$(pick); PORT_SS2022_W=$(pick); PORT_SS_W=$(pick); PORT_TUIC_W=$(pick)
  cat >"$PORTS_ENV"<<EOF
PORT_VLESSR=$PORT_VLESSR
PORT_VLESS_GRPCR=$PORT_VLESS_GRPCR
PORT_TROJANR=$PORT_TROJANR
PORT_HY2=$PORT_HY2
PORT_VMESS_WS=$PORT_VMESS_WS
PORT_HY2_OBFS=$PORT_HY2_OBFS
PORT_SS2022=$PORT_SS2022
PORT_SS=$PORT_SS
PORT_TUIC=$PORT_TUIC
PORT_VLESSR_W=$PORT_VLESSR_W
PORT_VLESS_GRPCR_W=$PORT_VLESS_GRPCR_W
PORT_TROJANR_W=$PORT_TROJANR_W
PORT_HY2_W=$PORT_HY2_W
PORT_VMESS_WS_W=$PORT_VMESS_WS_W
PORT_HY2_OBFS_W=$PORT_HY2_OBFS_W
PORT_SS2022_W=$PORT_SS2022_W
PORT_SS_W=$PORT_SS_W
PORT_TUIC_W=$PORT_TUIC_W
EOF
}
load_ports(){ [ -f "$PORTS_ENV" ] && . "$PORTS_ENV" || unique_ports; }

gen_uuid(){
  local u=""
  if [[ -x "$BIN_PATH" ]]; then
    u=$("$BIN_PATH" generate uuid 2>/dev/null | head -n1)
  fi
  if [[ -z "$u" ]] && command -v uuidgen >/dev/null 2>&1; then
    u=$(uuidgen | head -n1)
  fi
  if [[ -z "$u" ]] && [[ -r /proc/sys/kernel/random/uuid ]]; then
    u=$(head -n1 /proc/sys/kernel/random/uuid)
  fi
  printf '%s' "$u" | tr -d '\r\n'
}
rand_b64_32(){ openssl rand -base64 32 | tr -d '\n'; }

install_deps(){
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y curl wget tar jq openssl iproute2 coreutils ca-certificates
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl wget tar jq openssl iproute iproute-tc coreutils ca-certificates
  fi
}

install_singbox(){
  if [[ -x "$BIN_PATH" ]]; then
    info "检测到 sing-box：$("$BIN_PATH" version 2>/dev/null | head -n1)"
    return 0
  fi
  info "下载 sing-box (amd64) ..."
  local ver="1.12.7" arch="amd64"
  local url="https://github.com/SagerNet/sing-box/releases/download/v${ver}/sing-box-${ver}-linux-${arch}.tar.gz"
  local tmp; tmp=$(mktemp -d)
  curl -fsSL "$url" -o "$tmp/sb.tgz" || wget -qO "$tmp/sb.tgz" "$url"
  tar -xzf "$tmp/sb.tgz" -C "$tmp"
  install -m 0755 "$tmp/sing-box-${ver}-linux-${arch}/sing-box" "$BIN_PATH"
  rm -rf "$tmp"
  info "已安装：$("$BIN_PATH" version 2>/dev/null)"
}

# ===== 认证信息 =====
load_creds(){ [ -f "$CREDS_ENV" ] && . "$CREDS_ENV" || true; }
save_creds(){
  cat >"$CREDS_ENV"<<EOF
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
WLOCAL_V4=${WLOCAL_V4-}
WLOCAL_V6=${WLOCAL_V6-}
WPRIV=${WPRIV-}
WPEER_PUB=${WPEER_PUB-}
WHOST=${WHOST-}
WPORT=${WPORT-}
WRSV0=${WRSV0-}
WRSV1=${WRSV1-}
WRSV2=${WRSV2-}
EOF
}

ensure_creds(){
  load_creds
  [[ -z "${UUID:-}" ]] && UUID=$(gen_uuid)
  GRPC_SERVICE="${GRPC_SERVICE:-grpc}"
  VMESS_WS_PATH="${VMESS_WS_PATH:-/vm}"
  REALITY_SERVER="${REALITY_SERVER:-www.microsoft.com}"
  if [[ -z "${REALITY_PRIV:-}" || -z "${REALITY_PUB:-}" || -z "${REALITY_SID:-}" ]]; then
    # 用 sing-box 生成 reality key-pair
    mapfile -t RKP < <("$BIN_PATH" generate reality-keypair 2>/dev/null || true)
    REALITY_PRIV=$(printf "%s\n" "${RKP[@]}" | awk '/PrivateKey/{print $2}')
    REALITY_PUB=$( printf "%s\n" "${RKP[@]}" | awk '/PublicKey/{print $2}')
    [[ -z "$REALITY_SID" ]] && REALITY_SID=$(openssl rand -hex 4)
    # 兜底：若失败，用 openssl 生成随机串占位（避免空）
    [[ -z "$REALITY_PRIV" ]] && REALITY_PRIV=$(rand_b64_32 | tr -d '=' | head -c 43)
    [[ -z "$REALITY_PUB"  ]] && REALITY_PUB=$(rand_b64_32 | tr -d '=' | head -c 43)
  fi
  [[ -z "${HY2_PWD:-}"      ]] && HY2_PWD=$(openssl rand -base64 16 | tr -d '\n')
  [[ -z "${HY2_PWD2:-}"     ]] && HY2_PWD2=$(rand_b64_32)
  [[ -z "${HY2_OBFS_PWD:-}" ]] && HY2_OBFS_PWD=$(openssl rand -base64 16 | tr -d '\n')
  [[ -z "${SS2022_KEY:-}"   ]] && SS2022_KEY=$(rand_b64_32)   # 标准 base64
  [[ -z "${SS_PWD:-}"       ]] && SS_PWD=$(openssl rand -base64 24 | tr -d '=\n' | tr '+/' '-_')
  TUIC_UUID="$UUID"; TUIC_PWD="$UUID"
  save_creds
}

# ===== WARP / wgcf =====
install_wgcf(){
  command -v wgcf >/dev/null 2>&1 && return 0
  local v="2.2.20" arch="amd64" tmp; tmp=$(mktemp -d)
  local url="https://github.com/ViRb3/wgcf/releases/download/v${v}/wgcf_${v}_linux_${arch}"
  curl -fsSL "$url" -o "$tmp/wgcf" || wget -qO "$tmp/wgcf" "$url"
  install -m 0755 "$tmp/wgcf" /usr/local/bin/wgcf
  rm -rf "$tmp"
}

prepare_warp(){
  install_wgcf
  mkdir -p "$WGCF_DIR"
  if [[ ! -f "$WGCF_DIR/wgcf-account.toml" ]]; then
    WGCF_ACCOUNT_HOME="$WGCF_DIR" WGCF_CONFIG_DIR="$WGCF_DIR" wgcf register --accept-tos >/dev/null 2>&1 || true
  fi
  if [[ ! -f "$WGCF_DIR/wgcf-profile.conf" ]]; then
    WGCF_ACCOUNT_HOME="$WGCF_DIR" WGCF_CONFIG_DIR="$WGCF_DIR" wgcf generate >/dev/null 2>&1 || true
  fi
  # 解析 profile
  WPRIV=$(awk -F'= *' '/^PrivateKey/{gsub(/\r/,"");print $2}' "$WGCF_DIR/wgcf-profile.conf")
  local addr_line; addr_line=$(awk -F'= *' '/^Address/{gsub(/\r/,"");print $2;exit}' "$WGCF_DIR/wgcf-profile.conf" | tr -d '"')
  WLOCAL_V4="${addr_line%%,*}"
  WLOCAL_V6="${addr_line##*, }"
  local ep; ep=$(awk -F'= *' '/^Endpoint/{gsub(/\r/,"");print $2;exit}' "$WGCF_DIR/wgcf-profile.conf" | tr -d '"')
  WHOST=${ep%:*}; WPORT=${ep##*:}
  WPEER_PUB=$(awk -F'= *' '/^PublicKey/{gsub(/\r/,"");print $2;exit}' "$WGCF_DIR/wgcf-profile.conf" | tr -d '"')
  # Reserved 容错（可能不存在）
  if ! read -r WRSV0 WRSV1 WRSV2 < <(
    awk -FReserved\ *=\ * '/^Reserved/{
      split($2,a,","); gsub(/ /,"",a[1]); gsub(/ /,"",a[2]); gsub(/ /,"",a[3]);
      print a[1],a[2],a[3]; exit
    }' "$WGCF_DIR/wgcf-profile.conf"
  ); then
    WRSV0=0; WRSV1=0; WRSV2=0
  fi
  save_creds
}

# ===== 配置写入 =====
write_config(){
  ensure_creds; load_ports
  prepare_warp

  # 采用新格式 DNS，避免 legacy 警告
  # 直连出站 direct；WARP 出站 wireguard(tag: warp)；路由把 *-warp 入站送到 warp 出站
  cat >"$CONF_JSON"<<JSON
{
  "log": { "level": "info" },
  "dns": {
    "servers": [
      { "tag": "dns-local",  "address": "local" },
      { "tag": "dns-remote", "address": "https://1.1.1.1/dns-query" }
    ]
  },
  "inbounds": [
    {
      "type": "vless", "tag": "vless-reality", "listen": "::", "listen_port": ${PORT_VLESSR},
      "users": [ { "uuid": "${UUID}", "flow": "xtls-rprx-vision" } ],
      "tls": {
        "enabled": true, "server_name": "${REALITY_SERVER}",
        "reality": {
          "enabled": true,
          "handshake": { "server": "${REALITY_SERVER}", "server_port": 443 },
          "private_key": "${REALITY_PRIV}",
          "short_id": [ "${REALITY_SID}" ]
        }
      }
    },
    {
      "type": "vless", "tag": "vless-grpcr", "listen": "::", "listen_port": ${PORT_VLESS_GRPCR},
      "users": [ { "uuid": "${UUID}" } ],
      "transport": { "type": "grpc", "service_name": "${GRPC_SERVICE}" },
      "tls": {
        "enabled": true, "server_name": "${REALITY_SERVER}",
        "reality": {
          "enabled": true,
          "handshake": { "server": "${REALITY_SERVER}", "server_port": 443 },
          "private_key": "${REALITY_PRIV}",
          "short_id": [ "${REALITY_SID}" ]
        }
      }
    },
    {
      "type": "trojan", "tag": "trojan-reality", "listen": "::", "listen_port": ${PORT_TROJANR},
      "users": [ { "password": "${UUID}" } ],
      "tls": {
        "enabled": true, "server_name": "${REALITY_SERVER}",
        "reality": {
          "enabled": true,
          "handshake": { "server": "${REALITY_SERVER}", "server_port": 443 },
          "private_key": "${REALITY_PRIV}",
          "short_id": [ "${REALITY_SID}" ]
        }
      }
    },
    {
      "type": "hysteria2", "tag": "hy2", "listen": "::", "listen_port": ${PORT_HY2},
      "users": [ { "name": "u", "password": "${HY2_PWD}" } ]
    },
    {
      "type": "vmess", "tag": "vmess-ws", "listen": "::", "listen_port": ${PORT_VMESS_WS},
      "users": [ { "uuid": "${UUID}" } ],
      "transport": { "type": "ws", "path": "${VMESS_WS_PATH}" }
    },
    {
      "type": "hysteria2", "tag": "hy2-obfs", "listen": "::", "listen_port": ${PORT_HY2_OBFS},
      "users": [ { "name": "u2", "password": "${HY2_PWD2}" } ],
      "obfs": { "type": "salamander", "password": "${HY2_OBFS_PWD}" }
    },
    {
      "type": "shadowsocks", "tag": "ss2022", "listen": "::", "listen_port": ${PORT_SS2022},
      "method": "2022-blake3-aes-256-gcm", "password": "${SS2022_KEY}"
    },
    {
      "type": "shadowsocks", "tag": "ss", "listen": "::", "listen_port": ${PORT_SS},
      "method": "aes-256-gcm", "password": "${SS_PWD}"
    },
    {
      "type": "tuic", "tag": "tuic-v5", "listen": "::", "listen_port": ${PORT_TUIC},
      "users": [ { "uuid": "${TUIC_UUID}", "password": "${TUIC_PWD}" } ],
      "congestion_control": "bbr", "alpn": ["h3"]
    },

    // ======== 下面是 WARP 套壳的 9 个入站 ========
    {
      "type": "vless", "tag": "vless-reality-warp", "listen": "::", "listen_port": ${PORT_VLESSR_W},
      "users": [ { "uuid": "${UUID}", "flow": "xtls-rprx-vision" } ],
      "tls": {
        "enabled": true, "server_name": "${REALITY_SERVER}",
        "reality": {
          "enabled": true,
          "handshake": { "server": "${REALITY_SERVER}", "server_port": 443 },
          "private_key": "${REALITY_PRIV}",
          "short_id": [ "${REALITY_SID}" ]
        }
      }
    },
    {
      "type": "vless", "tag": "vless-grpcr-warp", "listen": "::", "listen_port": ${PORT_VLESS_GRPCR_W},
      "users": [ { "uuid": "${UUID}" } ],
      "transport": { "type": "grpc", "service_name": "${GRPC_SERVICE}" },
      "tls": {
        "enabled": true, "server_name": "${REALITY_SERVER}",
        "reality": {
          "enabled": true,
          "handshake": { "server": "${REALITY_SERVER}", "server_port": 443 },
          "private_key": "${REALITY_PRIV}",
          "short_id": [ "${REALITY_SID}" ]
        }
      }
    },
    {
      "type": "trojan", "tag": "trojan-reality-warp", "listen": "::", "listen_port": ${PORT_TROJANR_W},
      "users": [ { "password": "${UUID}" } ],
      "tls": {
        "enabled": true, "server_name": "${REALITY_SERVER}",
        "reality": {
          "enabled": true,
          "handshake": { "server": "${REALITY_SERVER}", "server_port": 443 },
          "private_key": "${REALITY_PRIV}",
          "short_id": [ "${REALITY_SID}" ]
        }
      }
    },
    {
      "type": "hysteria2", "tag": "hy2-warp", "listen": "::", "listen_port": ${PORT_HY2_W},
      "users": [ { "name": "u", "password": "${HY2_PWD}" } ]
    },
    {
      "type": "vmess", "tag": "vmess-ws-warp", "listen": "::", "listen_port": ${PORT_VMESS_WS_W},
      "users": [ { "uuid": "${UUID}" } ],
      "transport": { "type": "ws", "path": "${VMESS_WS_PATH}" }
    },
    {
      "type": "hysteria2", "tag": "hy2-obfs-warp", "listen": "::", "listen_port": ${PORT_HY2_OBFS_W},
      "users": [ { "name": "u2", "password": "${HY2_PWD2}" } ],
      "obfs": { "type": "salamander", "password": "${HY2_OBFS_PWD}" }
    },
    {
      "type": "shadowsocks", "tag": "ss2022-warp", "listen": "::", "listen_port": ${PORT_SS2022_W},
      "method": "2022-blake3-aes-256-gcm", "password": "${SS2022_KEY}"
    },
    {
      "type": "shadowsocks", "tag": "ss-warp", "listen": "::", "listen_port": ${PORT_SS_W},
      "method": "aes-256-gcm", "password": "${SS_PWD}"
    },
    {
      "type": "tuic", "tag": "tuic-v5-warp", "listen": "::", "listen_port": ${PORT_TUIC_W},
      "users": [ { "uuid": "${TUIC_UUID}", "password": "${TUIC_PWD}" } ],
      "congestion_control": "bbr", "alpn": ["h3"]
    }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" },
    { "type": "block",  "tag": "block" },
    {
      "type": "wireguard", "tag": "warp",
      "local_address": [ "${WLOCAL_V4}", "${WLOCAL_V6}" ],
      "private_key": "${WPRIV}",
      "system_interface": false,
      "peers": [
        {
          "server": "${WHOST}", "server_port": ${WPORT},
          "public_key": "${WPEER_PUB}",
          "reserved": [ ${WRSV0}, ${WRSV1}, ${WRSV2} ],
          "allowed_ips": [ "0.0.0.0/0", "::/0" ]
        }
      ],
      "mtu": 1280
    }
  ],
  "route": {
    "default_domain_resolver": "dns-remote",
    "rules": [
      {
        "inbound": [
          "vless-reality-warp","vless-grpcr-warp","trojan-reality-warp",
          "hy2-warp","vmess-ws-warp","hy2-obfs-warp","ss2022-warp","ss-warp","tuic-v5-warp"
        ],
        "outbound": "warp"
      }
    ],
    "final": "direct"
  }
}
JSON
}

# ===== systemd =====
write_systemd(){
  cat >/etc/systemd/system/${SYSTEMD_SERVICE}<<EOF
[Unit]
Description=Sing-Box (Native 18 nodes)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=ENABLE_DEPRECATED_WIREGUARD_OUTBOUND=${ENABLE_DEPRECATED_WIREGUARD_OUTBOUND}
ExecStart=${BIN_PATH} run -c ${CONF_JSON}
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable ${SYSTEMD_SERVICE} >/dev/null 2>&1 || true
  systemctl restart ${SYSTEMD_SERVICE} || true
}

open_firewall(){ :; }  # 按需放行（此处留空）

# ===== 输出链接（分组美化） =====
print_links(){
  load_creds; load_ports
  local ip; ip=$(get_ip)

  local direct=() warp=()

  # 直连 9
  direct+=("vless://${UUID}@${ip}:${PORT_VLESSR}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#vless-reality")
  direct+=("vless://${UUID}@${ip}:${PORT_VLESS_GRPCR}?encryption=none&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=grpc&serviceName=${GRPC_SERVICE}#vless-grpc-reality")
  direct+=("trojan://${UUID}@${ip}:${PORT_TROJANR}?security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#trojan-reality")
  direct+=("hy2://$(printf '%s' "${HY2_PWD}" | urlenc)@${ip}:${PORT_HY2}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#hysteria2")
  local VMESS_JSON; VMESS_JSON=$(cat <<JSON
{"v":"2","ps":"vmess-ws","add":"${ip}","port":"${PORT_VMESS_WS}","id":"${UUID}","aid":"0","net":"ws","type":"none","host":"","path":"${VMESS_WS_PATH}","tls":""}
JSON
  )
  direct+=("vmess://$(printf "%s" "$VMESS_JSON" | b64enc)")
  direct+=("hy2://$(printf '%s' "${HY2_PWD2}" | urlenc)@${ip}:${PORT_HY2_OBFS}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}&alpn=h3&obfs=salamander&obfs-password=$(printf '%s' "${HY2_OBFS_PWD}" | urlenc)#hysteria2-obfs")
  direct+=("ss://$(printf "%s" "2022-blake3-aes-256-gcm:${SS2022_KEY}" | b64enc)@${ip}:${PORT_SS2022}#ss2022")
  direct+=("ss://$(printf "%s" "aes-256-gcm:${SS_PWD}" | b64enc)@${ip}:${PORT_SS}#ss")
  direct+=("tuic://${UUID}:$(printf '%s' "${UUID}" | urlenc)@${ip}:${PORT_TUIC}?congestion_control=bbr&alpn=h3&insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#tuic-v5")

  # WARP 9
  warp+=("vless://${UUID}@${ip}:${PORT_VLESSR_W}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#vless-reality-warp")
  warp+=("vless://${UUID}@${ip}:${PORT_VLESS_GRPCR_W}?encryption=none&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=grpc&serviceName=${GRPC_SERVICE}#vless-grpc-reality-warp")
  warp+=("trojan://${UUID}@${ip}:${PORT_TROJANR_W}?security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#trojan-reality-warp")
  warp+=("hy2://$(printf '%s' "${HY2_PWD}" | urlenc)@${ip}:${PORT_HY2_W}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#hysteria2-warp")
  local VMESS_JSON_W; VMESS_JSON_W=$(cat <<JSON
{"v":"2","ps":"vmess-ws-warp","add":"${ip}","port":"${PORT_VMESS_WS_W}","id":"${UUID}","aid":"0","net":"ws","type":"none","host":"","path":"${VMESS_WS_PATH}","tls":""}
JSON
  )
  warp+=("vmess://$(printf "%s" "$VMESS_JSON_W" | b64enc)")
  warp+=("hy2://$(printf '%s' "${HY2_PWD2}" | urlenc)@${ip}:${PORT_HY2_OBFS_W}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}&alpn=h3&obfs=salamander&obfs-password=$(printf '%s' "${HY2_OBFS_PWD}" | urlenc)#hysteria2-obfs-warp")
  warp+=("ss://$(printf "%s" "2022-blake3-aes-256-gcm:${SS2022_KEY}" | b64enc)@${ip}:${PORT_SS2022_W}#ss2022-warp")
  warp+=("ss://$(printf "%s" "aes-256-gcm:${SS_PWD}" | b64enc)@${ip}:${PORT_SS_W}#ss-warp")
  warp+=("tuic://${UUID}:$(printf '%s' "${UUID}" | urlenc)@${ip}:${PORT_TUIC_W}?congestion_control=bbr&alpn=h3&insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#tuic-v5-warp")

  echo -e "${C_BLUE}${C_BOLD}分享链接（18 个）${C_RESET}"; hr
  echo -e "${C_BLUE}${C_BOLD}【直连节点（9）】${C_RESET}（vless-reality / vless-grpc-reality / trojan-reality / vmess-ws / hy2 / hy2-obfs / ss2022 / ss / tuic）"
  printf "${C_DIM}──────────────────────────────────────────────────────────${C_RESET}\n"
  for l in "${direct[@]}"; do echo "  $l"; done
  printf "${C_DIM}──────────────────────────────────────────────────────────${C_RESET}\n\n"

  echo -e "${C_BLUE}${C_BOLD}【WARP 节点（9）】${C_RESET}（同上 9 种，带 -warp）"
  echo -e "${C_DIM}说明：带 -warp 的 9 个节点走 Cloudflare WARP 出口，流媒体更友好${C_RESET}"
  echo -e "${C_DIM}提示：TUIC 默认 allowInsecure=1，v2rayN 导入即用${C_RESET}"
  printf "${C_DIM}──────────────────────────────────────────────────────────${C_RESET}\n"
  for l in "${warp[@]}"; do echo "  $l"; done
  printf "${C_DIM}──────────────────────────────────────────────────────────${C_RESET}\n"
}

# ===== 操作 =====
enable_bbr(){
  if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -qi bbr; then
    info "BBR 已启用"; return
  fi
  echo "net.core.default_qdisc=fq" >/etc/sysctl.d/99-bbr.conf
  echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.d/99-bbr.conf
  sysctl --system >/dev/null 2>&1 || true
  info "BBR 已开启"
}

restart_service(){
  systemctl restart ${SYSTEMD_SERVICE} || true
  systemctl is-active --quiet ${SYSTEMD_SERVICE} && info "已重启" || err "重启失败"
}

rotate_ports(){
  rm -f "$PORTS_ENV"
  unique_ports
  write_config
  write_systemd
  info "端口已更换并重启服务"
}

uninstall_all(){
  systemctl disable ${SYSTEMD_SERVICE} >/dev/null 2>&1 || true
  systemctl stop ${SYSTEMD_SERVICE} >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/${SYSTEMD_SERVICE}
  systemctl daemon-reload || true
  rm -rf "$SB_DIR"
  info "已卸载并清理"
  exit 0
}

ensure_installed_or_hint(){
  if [[ ! -x "$BIN_PATH" ]] || [[ ! -f "$CONF_JSON" ]]; then
    warn "尚未安装，请先选择 1 进行安装/部署。"
    return 1
  fi
  return 0
}

deploy_native(){
  install_deps
  install_singbox
  info "检查配置 ..."
  ensure_creds; load_ports
  write_config
  "$BIN_PATH" check -c "$CONF_JSON"
  info "写入并启用 systemd 服务 ..."
  write_systemd
  open_firewall
  echo; echo -e "${C_BOLD}${C_GREEN}★ 部署完成（18 节点）${C_RESET}"; echo
  print_links
  exit 0
}

menu(){
  banner
  read "${READ_OPTS[@]}" -p "选择: " op || true
  case "${op:-}" in
    1) deploy_native;;
    2) ensure_installed_or_hint && { print_links; exit 0; };;
    3) ensure_installed_or_hint && restart_service;;
    4) ensure_installed_or_hint && rotate_ports;;
    5) enable_bbr;;
    8) uninstall_all;;
    0) exit 0;;
    *) :;;
  esac
}

need_root
menu
