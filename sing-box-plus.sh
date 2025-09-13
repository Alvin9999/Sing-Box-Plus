#!/usr/bin/env bash
# =======================================================
# 🚀 Sing-Box-Plus 管理脚本（直连 9 + WARP 9）
# Version: v2.1.3
# 仅优化 UI/交互 + 依赖检测修复；功能与之前成功版本一致
# =======================================================
set -euo pipefail

# ---------- 颜色 ----------
C_RESET="\033[0m"; C_BOLD="\033[1m"; C_DIM="\033[2m"
C_RED="\033[31m";  C_GREEN="\033[32m"; C_YELLOW="\033[33m"
C_BLUE="\033[34m"; C_CYAN="\033[36m" # 浅蓝
hr(){ printf "${C_DIM}=============================================================${C_RESET}\n"; }
hr2(){ printf "${C_DIM}─────────────────────────────────────────────────────────────${C_RESET}\n"; }

SCRIPT_NAME="Sing-Box-Plus 管理脚本"
SCRIPT_VERSION="v2.1.3"

# ---------- 路径 ----------
SB_DIR="/opt/sing-box"
BIN_PATH="/usr/local/bin/sing-box"
SYSTEMD_SERVICE="sing-box.service"
CONF_JSON="$SB_DIR/config.json"
PORTS_ENV="$SB_DIR/ports.env"
CREDS_ENV="$SB_DIR/creds.env"
WARP_ENV="$SB_DIR/warp.env"
WGCF_DIR="$SB_DIR/wgcf"
mkdir -p "$SB_DIR" "$WGCF_DIR"

# ---------- 输出 ----------
info(){ echo -e "${C_CYAN}[信息]${C_RESET} $*"; }
warn(){ echo -e "${C_YELLOW}[警告]${C_RESET} $*"; }
err(){  echo -e "${C_RED}[错误]${C_RESET} $*"; }
need_root(){ [[ $EUID -eq 0 ]] || { err "请以 root 运行：bash $0"; exit 1; }; }

# ---------- Banner 与状态 ----------
bbr_status(){
  if sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | grep -qi bbr; then
    echo -e "系统加速状态：${C_GREEN}已启用 BBR${C_RESET}"
  else
    echo -e "系统加速状态：${C_RED}未启用 BBR${C_RESET}"
  fi
}
sb_status(){
  if [[ ! -x "$BIN_PATH" || ! -f "$CONF_JSON" ]]; then
    echo -e "Sing-Box 启动状态：${C_RED}未安装${C_RESET}"; return
  fi
  if systemctl is-active "$SYSTEMD_SERVICE" >/dev/null 2>&1; then
    echo -e "Sing-Box 启动状态：${C_GREEN}运行中${C_RESET}"
  else
    echo -e "Sing-Box 启动状态：${C_RED}未运行${C_RESET}"
  fi
}
banner(){
  clear
  hr
  echo -e " ${C_CYAN}🚀 ${SCRIPT_NAME} ${SCRIPT_VERSION} 🚀${C_RESET}"
  echo -e " ${C_CYAN}脚本更新地址:https://github.com/Alvin9999/Sing-Box-Plus${C_RESET}"
  hr
  bbr_status
  sb_status
  hr
}

# ---------- 依赖 ----------
_pkg_install(){
  local pkg="$1" alt="$2"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y "$pkg" >/dev/null 2>&1 || apt-get install -y "$alt" >/dev/null 2>&1 || return 1
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y "$pkg" >/dev/null 2>&1 || dnf install -y "$alt" >/dev/null 2>&1 || return 1
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "$pkg" >/dev/null 2>&1 || yum install -y "$alt" >/dev/null 2>&1 || return 1
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache "$pkg" >/dev/null 2>&1 || apk add --no-cache "$alt" >/dev/null 2>&1 || return 1
  else
    return 1
  fi
}
need_tool(){
  local bin="$1" pkg="$2" alt="${3:-}"
  command -v "$bin" >/dev/null 2>&1 && return 0
  _pkg_install "$pkg" "$alt" || true
  command -v "$bin" >/dev/null 2>&1 || { err "依赖 $pkg 安装失败（需要可执行：$bin）"; exit 1; }
}
ensure_bins(){
  need_tool curl curl
  need_tool jq jq
  need_tool tar tar
  need_tool sed sed
  need_tool awk gawk awk
  # ss/ip（检测端口用）：不同系包名不同
  if ! command -v ss >/dev/null 2>&1; then
    _pkg_install iproute2 iproute || true
  fi
  # base64 一般自带；openssl 可选（用于 rand_hex）
  command -v openssl >/dev/null 2>&1 || _pkg_install openssl openssl || true
  # wgcf
  if ! command -v wgcf >/dev/null 2>&1; then
    info "安装 wgcf ..."
    ver="2.2.21"
    url="https://github.com/ViRb3/wgcf/releases/download/v${ver}/wgcf_${ver}_linux_amd64"
    curl -fsSL "$url" -o /usr/local/bin/wgcf
    chmod +x /usr/local/bin/wgcf
  fi
}

# ---------- 随机 & 端口 ----------
gen_uuid(){
  local u=""
  if [[ -x "$BIN_PATH" ]]; then
    u=$("$BIN_PATH" generate uuid 2>/dev/null | head -n1 || true)
  fi
  if [[ -z "$u" ]] && command -v uuidgen >/dev/null 2>&1; then
    u=$(uuidgen | head -n1)
  fi
  if [[ -z "$u" ]]; then
    u=$(cat /proc/sys/kernel/random/uuid | head -n1)
  fi
  printf '%s' "$u" | tr -d '\r\n'
}
rand(){ awk -v min=11000 -v max=49999 'BEGIN{srand();print int(min+rand()*(max-min+1))}'; }
port_free(){
  local p="$1"
  if command -v ss >/dev/null 2>&1; then
    ! ss -ltnup 2>/dev/null | grep -q ":${p}\b"
  elif command -v netstat >/dev/null 2>&1; then
    ! netstat -tunlp 2>/dev/null | grep -q ":${p}\b"
  else
    # 没有检测工具就直接认为可用（极少见环境）
    true
  fi
}
gen_port(){ local p; for _ in {1..999}; do p=$(rand); port_free "$p" && { echo "$p"; return; }; done; echo 0; }
rand_b64(){ head -c 16 /dev/urandom | base64 | tr -d '\r\n='; }
rand_hex(){
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 8
  elif command -v hexdump >/dev/null 2>&1; then
    hexdump -vn8 -e '8/1 "%02x"' /dev/urandom
  else
    od -An -N8 -tx1 /dev/urandom | tr -d ' \n'
  fi
}

# ---------- 安装 sing-box ----------
install_singbox(){
  if [[ -x "$BIN_PATH" ]]; then
    info "检测到 sing-box：$("$BIN_PATH" version | head -n1)"; return
  fi
  info "下载 sing-box (amd64) ..."
  SB_VER="1.12.7"
  TARBALL="sing-box-${SB_VER}-linux-amd64.tar.gz"
  URL="https://github.com/SagerNet/sing-box/releases/download/v${SB_VER}/${TARBALL}"
  curl -fsSL "$URL" -o "/tmp/${TARBALL}"
  tar -xf "/tmp/${TARBALL}" -C /tmp
  install -m 0755 "/tmp/sing-box-${SB_VER}-linux-amd64/sing-box" "$BIN_PATH"
  rm -rf "/tmp/${TARBALL}" "/tmp/sing-box-${SB_VER}-linux-amd64"
  info "已安装：$("$BIN_PATH" version | head -n1)"
}

# ---------- 端口/凭据 ----------
write_ports(){
  info "生成端口 ..."
  cat >"$PORTS_ENV" <<EOF
# 直连
PORT_VLESSR=$(gen_port)
PORT_VLESS_GRPCR=$(gen_port)
PORT_TROJANR=$(gen_port)
PORT_VMESS_WS=$(gen_port)
PORT_HY2=$(gen_port)
PORT_HY2_OBFS=$(gen_port)
PORT_SS2022=$(gen_port)
PORT_SS=$(gen_port)
PORT_TUIC=$(gen_port)
# WARP
PORT_VLESSR_W=$(gen_port)
PORT_VLESS_GRPCR_W=$(gen_port)
PORT_TROJANR_W=$(gen_port)
PORT_VMESS_WS_W=$(gen_port)
PORT_HY2_W=$(gen_port)
PORT_HY2_OBFS_W=$(gen_port)
PORT_SS2022_W=$(gen_port)
PORT_SS_W=$(gen_port)
PORT_TUIC_W=$(gen_port)
EOF
}
write_creds(){
  info "生成凭据 ..."
  local uuid sni sid
  uuid=$(gen_uuid)
  sni="www.microsoft.com"
  sid="$(rand_hex)"
  mapfile -t KP < <("$BIN_PATH" generate reality-keypair)
  local REALITY_PRIVATE_KEY REALITY_PUBLIC_KEY
  REALITY_PRIVATE_KEY=$(echo "${KP[0]}" | awk -F': ' '{print $2}')
  REALITY_PUBLIC_KEY=$(echo "${KP[1]}" | awk -F': ' '{print $2}')
  cat >"$CREDS_ENV" <<EOF
UUID=$uuid
SS_PWD=$(rand_b64)
SS2022_KEY=$(rand_b64)
HY2_PWD=$(rand_b64)
HY2_OBFS_PWD=$(rand_b64)
REALITY_PRIVATE_KEY=$REALITY_PRIVATE_KEY
REALITY_PUBLIC_KEY=$REALITY_PUBLIC_KEY
REALITY_SERVER=$sni
REALITY_SID=$sid
VMESS_WS_PATH=/vm
GRPC_SERVICE=grpc
EOF
}

# ---------- WARP（wgcf） ----------
ensure_warp(){
  info "初始化 WARP 账户 ..."
  local acct="$WGCF_DIR/wgcf-account.toml" prof="$WGCF_DIR/wgcf-profile.conf"
  if [[ ! -f "$acct" ]]; then (cd "$WGCF_DIR"; WGCF_TRACE=1 wgcf register --accept-tos >/dev/null); fi
  (cd "$WGCF_DIR"; wgcf generate >/dev/null)
  # 解析
  local priv pub endpoint v4 v6 r1 r2 r3 host port ip
  priv=$(grep -m1 '^PrivateKey' "$prof" | awk '{print $3}')
  pub=$(grep -m1 '^PublicKey'  "$prof" | awk '{print $3}')
  endpoint=$(grep -m1 '^Endpoint' "$prof" | awk '{print $3}')
  v4=$(grep -m1 '^Address = ' "$prof" | awk -F'[ ="]+' '{print $6}')
  v6=$(grep -m2 '^Address = ' "$prof" | awk -F'[ ="]+' 'NR==2{print $6}')
  if grep -q '^Reserved' "$prof"; then
    r1=$(sed -n 's/.*Reserved = \[\s*\([0-9]\+\),.*/\1/p' "$prof" | head -n1)
    r2=$(sed -n 's/.*Reserved = \[[0-9]\+,\s*\([0-9]\+\),.*/\1/p' "$prof" | head -n1)
    r3=$(sed -n 's/.*Reserved = \[[0-9]\+,\s*[0-9]\+,\s*\([0-9]\+\).*/\1/p' "$prof" | head -n1)
  else r1=0;r2=0;r3=0; fi
  host=$(echo "$endpoint" | awk -F: '{print $1}')
  port=$(echo "$endpoint" | awk -F: '{print $2}')
  ip=$(curl -fsSL --max-time 5 'https://1.1.1.1/dns-query?name=engage.cloudflareclient.com&type=A' -H 'accept: application/dns-json' \
      | jq -r '.Answer[0].data' 2>/dev/null || true)
  [[ -z "$ip" ]] && ip="162.159.192.1"
  cat >"$WARP_ENV" <<EOF
WARP_PRIVATE_KEY=$priv
WARP_PEER_PUBLIC_KEY=$pub
WARP_ENDPOINT_HOST=$ip
WARP_ENDPOINT_PORT=${port:-2408}
WARP_ADDRESS_V4=${v4:-172.16.0.2/32}
WARP_ADDRESS_V6=${v6:-2606:4700:110:0000:0000:0000:0000:0002/128}
WARP_RESERVED_1=$r1
WARP_RESERVED_2=$r2
WARP_RESERVED_3=$r3
EOF
}

# ---------- 写配置 ----------
write_config(){
  info "写入配置 ..."
  . "$PORTS_ENV"; . "$CREDS_ENV"; . "$WARP_ENV"
  cat >"$CONF_JSON" <<JSON
{
  "log": { "level": "info" },
  "dns": {
    "servers": [
      { "tag": "dns-remote", "address": "https://1.1.1.1/dns-query", "detour": "direct" },
      { "address": "tls://dns.google", "detour": "direct" }
    ],
    "strategy": "prefer_ipv4"
  },
  "inbounds": [
    { "type":"vless", "tag":"vless-reality", "listen":"::", "listen_port": $PORT_VLESSR,
      "users":[{"uuid":"$UUID","flow":"xtls-rprx-vision"}],
      "tls":{"enabled":true,"server_name":"$REALITY_SERVER","reality":{"enabled":true,"handshake":{"server":"$REALITY_SERVER","server_port":443},"private_key":"$REALITY_PRIVATE_KEY","short_id":["$REALITY_SID"]}}},
    { "type":"vless", "tag":"vless-grpcr", "listen":"::", "listen_port": $PORT_VLESS_GRPCR,
      "users":[{"uuid":"$UUID"}],
      "transport":{"type":"grpc","service_name":"$GRPC_SERVICE"},
      "tls":{"enabled":true,"server_name":"$REALITY_SERVER","reality":{"enabled":true,"handshake":{"server":"$REALITY_SERVER","server_port":443},"private_key":"$REALITY_PRIVATE_KEY","short_id":["$REALITY_SID"]}}},
    { "type":"trojan", "tag":"trojan-reality", "listen":"::", "listen_port": $PORT_TROJANR,
      "users":[{"password":"$UUID"}],
      "tls":{"enabled":true,"server_name":"$REALITY_SERVER","reality":{"enabled":true,"handshake":{"server":"$REALITY_SERVER","server_port":443},"private_key":"$REALITY_PRIVATE_KEY","short_id":["$REALITY_SID"]}}},
    { "type":"vmess", "tag":"vmess-ws", "listen":"::", "listen_port": $PORT_VMESS_WS,
      "users":[{"uuid":"$UUID"}],
      "transport":{"type":"ws","path":"$VMESS_WS_PATH"} },
    { "type":"hysteria2", "tag":"hy2", "listen":"::", "listen_port": $PORT_HY2,
      "users":[{"password":"$HY2_PWD"}],
      "tls":{"enabled":true,"server_name":"$REALITY_SERVER","insecure":true}},
    { "type":"hysteria2", "tag":"hy2-obfs", "listen":"::", "listen_port": $PORT_HY2_OBFS,
      "users":[{"password":"$HY2_PWD"}],
      "obfs":{"type":"salamander","password":"$HY2_OBFS_PWD"},
      "tls":{"enabled":true,"server_name":"$REALITY_SERVER","insecure":true,"alpn":["h3"]}},
    { "type":"shadowsocks", "tag":"ss2022", "listen":"::", "listen_port": $PORT_SS2022,
      "method":"2022-blake3-aes-256-gcm", "password":"$SS2022_KEY" },
    { "type":"shadowsocks", "tag":"ss", "listen":"::", "listen_port": $PORT_SS,
      "method":"aes-256-gcm", "password":"$SS_PWD" },
    { "type":"tuic", "tag":"tuic-v5", "listen":"::", "listen_port": $PORT_TUIC,
      "users":[{"uuid":"$UUID","password":"$UUID"}],
      "congestion_control":"bbr", "tls":{"enabled":true,"server_name":"$REALITY_SERVER","insecure":true,"alpn":["h3"]}},

    { "type":"vless", "tag":"vless-reality-warp", "listen":"::", "listen_port": $PORT_VLESSR_W,
      "users":[{"uuid":"$UUID","flow":"xtls-rprx-vision"}],
      "tls":{"enabled":true,"server_name":"$REALITY_SERVER","reality":{"enabled":true,"handshake":{"server":"$REALITY_SERVER","server_port":443},"private_key":"$REALITY_PRIVATE_KEY","short_id":["$REALITY_SID"]}}},
    { "type":"vless", "tag":"vless-grpcr-warp", "listen":"::", "listen_port": $PORT_VLESS_GRPCR_W,
      "users":[{"uuid":"$UUID"}],
      "transport":{"type":"grpc","service_name":"$GRPC_SERVICE"},
      "tls":{"enabled":true,"server_name":"$REALITY_SERVER","reality":{"enabled":true,"handshake":{"server":"$REALITY_SERVER","server_port":443},"private_key":"$REALITY_PRIVATE_KEY","short_id":["$REALITY_SID"]}}},
    { "type":"trojan", "tag":"trojan-reality-warp", "listen":"::", "listen_port": $PORT_TROJANR_W,
      "users":[{"password":"$UUID"}],
      "tls":{"enabled":true,"server_name":"$REALITY_SERVER","reality":{"enabled":true,"handshake":{"server":"$REALITY_SERVER","server_port":443},"private_key":"$REALITY_PRIVATE_KEY","short_id":["$REALITY_SID"]}}},
    { "type":"hysteria2", "tag":"hy2-warp", "listen":"::", "listen_port": $PORT_HY2_W,
      "users":[{"password":"$HY2_PWD"}],
      "tls":{"enabled":true,"server_name":"$REALITY_SERVER","insecure":true}},
    { "type":"vmess", "tag":"vmess-ws-warp", "listen":"::", "listen_port": $PORT_VMESS_WS_W,
      "users":[{"uuid":"$UUID"}], "transport":{"type":"ws","path":"$VMESS_WS_PATH"} },
    { "type":"hysteria2", "tag":"hy2-obfs-warp", "listen":"::", "listen_port": $PORT_HY2_OBFS_W,
      "users":[{"password":"$HY2_PWD"}],
      "obfs":{"type":"salamander","password":"$HY2_OBFS_PWD"},
      "tls":{"enabled":true,"server_name":"$REALITY_SERVER","insecure":true,"alpn":["h3"]}},
    { "type":"shadowsocks", "tag":"ss2022-warp", "listen":"::", "listen_port": $PORT_SS2022_W,
      "method":"2022-blake3-aes-256-gcm", "password":"$SS2022_KEY" },
    { "type":"shadowsocks", "tag":"ss-warp", "listen":"::", "listen_port": $PORT_SS_W,
      "method":"aes-256-gcm", "password":"$SS_PWD" },
    { "type":"tuic", "tag":"tuic-v5-warp", "listen":"::", "listen_port": $PORT_TUIC_W,
      "users":[{"uuid":"$UUID","password":"$UUID"}],
      "congestion_control":"bbr", "tls":{"enabled":true,"server_name":"$REALITY_SERVER","insecure":true,"alpn":["h3"]}}
  ],
  "outbounds":[
    { "type":"direct","tag":"direct" },
    { "type":"block","tag":"block" },
    { "type":"wireguard","tag":"warp",
      "local_address":[ "$WARP_ADDRESS_V4", "$WARP_ADDRESS_V6" ],
      "system_interface": false,
      "private_key":"$WARP_PRIVATE_KEY",
      "peers":[ { "server":"$WARP_ENDPOINT_HOST", "server_port": $WARP_ENDPOINT_PORT,
        "public_key":"$WARP_PEER_PUBLIC_KEY",
        "reserved":[ $WARP_RESERVED_1, $WARP_RESERVED_2, $WARP_RESERVED_3 ],
        "allowed_ips":[ "0.0.0.0/0", "::/0" ] } ],
      "mtu":1280
    }
  ],
  "route":{
    "default_domain_resolver":"dns-remote",
    "rules":[
      { "inbound":[
        "vless-reality-warp","vless-grpcr-warp","trojan-reality-warp",
        "hy2-warp","vmess-ws-warp","hy2-obfs-warp","ss2022-warp","ss-warp","tuic-v5-warp"
      ], "outbound":"warp" }
    ],
    "final":"direct"
  }
}
JSON
}

# ---------- systemd ----------
write_systemd(){
  cat >/etc/systemd/system/${SYSTEMD_SERVICE} <<EOF
[Unit]
Description=Sing-Box (Native 18 nodes)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=ENABLE_DEPRECATED_WIREGUARD_OUTBOUND=true
ExecStart=${BIN_PATH} run -c ${CONF_JSON}
Restart=always
RestartSec=3
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable ${SYSTEMD_SERVICE} >/dev/null 2>&1 || true
  systemctl restart ${SYSTEMD_SERVICE}
}

# ---------- 分享链接 ----------
b64(){ base64 -w0 2>/dev/null || base64 | tr -d '\n'; }
urlenc(){ jq -sRr @uri 2>/dev/null; }
get_pub_ip(){ curl -fsS4 https://ip.gs || curl -fsS4 https://ifconfig.me || hostname -I 2>/dev/null | awk '{print $1}'; }

print_links(){
  . "$PORTS_ENV"; . "$CREDS_ENV"; . "$WARP_ENV"
  local ip; ip=$(get_pub_ip)
  hr; echo -e "${C_BOLD}分享链接（18 个）${C_RESET}"; hr

  echo -e "${C_BLUE}${C_BOLD}【直连节点（9）】${C_RESET}（vless-reality / vless-grpc-reality / trojan-reality / vmess-ws / hy2 / hy2-obfs / ss2022 / ss / tuic）"
  hr2
  echo "  vless://$UUID@$ip:$PORT_VLESSR?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$REALITY_SERVER&fp=chrome&pbk=$REALITY_PUBLIC_KEY&sid=$REALITY_SID&type=tcp#vless-reality"
  echo "  vless://$UUID@$ip:$PORT_VLESS_GRPCR?encryption=none&security=reality&sni=$REALITY_SERVER&fp=chrome&pbk=$REALITY_PUBLIC_KEY&sid=$REALITY_SID&type=grpc&serviceName=$GRPC_SERVICE#vless-grpc-reality"
  echo "  trojan://$UUID@$ip:$PORT_TROJANR?security=reality&sni=$REALITY_SERVER&fp=chrome&pbk=$REALITY_PUBLIC_KEY&sid=$REALITY_SID&type=tcp#trojan-reality"
  echo "  vmess://$(printf '{"v":"2","ps":"vmess-ws","add":"%s","port":"%s","id":"%s","aid":"0","net":"ws","type":"none","host":"","path":"%s","tls":""}' "$ip" "$PORT_VMESS_WS" "$UUID" "$VMESS_WS_PATH" | b64)"
  echo "  hy2://$(printf '%s' "$HY2_PWD" | urlenc)@$ip:$PORT_HY2?insecure=1&allowInsecure=1&sni=$REALITY_SERVER#hysteria2"
  echo "  hy2://$(printf '%s' "$HY2_PWD" | urlenc)@$ip:$PORT_HY2_OBFS?insecure=1&allowInsecure=1&sni=$REALITY_SERVER&alpn=h3&obfs=salamander&obfs-password=$(printf '%s' "$HY2_OBFS_PWD" | urlenc)#hysteria2-obfs"
  echo "  ss://$(printf '2022-blake3-aes-256-gcm:%s' "$SS2022_KEY" | b64)@$ip:$PORT_SS2022#ss2022"
  echo "  ss://$(printf 'aes-256-gcm:%s' "$SS_PWD" | b64)@$ip:$PORT_SS#ss"
  echo "  tuic://$UUID:$(printf '%s' "$UUID" | urlenc)@$ip:$PORT_TUIC?congestion_control=bbr&alpn=h3&insecure=1&allowInsecure=1&sni=$REALITY_SERVER#tuic-v5"

  hr2; echo
  echo -e "${C_BLUE}${C_BOLD}【WARP 节点（9）】${C_RESET}（同上 9 种，带 -warp）"
  echo -e "${C_DIM}说明：带 -warp 的 9 个节点走 Cloudflare WARP 出口，流媒体解锁更友好${C_RESET}"
  echo -e "${C_DIM}提示：TUIC 默认 allowInsecure=1，v2rayN 导入即用${C_RESET}"
  hr2
  echo "  vless://$UUID@$ip:$PORT_VLESSR_W?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$REALITY_SERVER&fp=chrome&pbk=$REALITY_PUBLIC_KEY&sid=$REALITY_SID&type=tcp#vless-reality-warp"
  echo "  vless://$UUID@$ip:$PORT_VLESS_GRPCR_W?encryption=none&security=reality&sni=$REALITY_SERVER&fp=chrome&pbk=$REALITY_PUBLIC_KEY&sid=$REALITY_SID&type=grpc&serviceName=$GRPC_SERVICE#vless-grpc-reality-warp"
  echo "  trojan://$UUID@$ip:$PORT_TROJANR_W?security=reality&sni=$REALITY_SERVER&fp=chrome&pbk=$REALITY_PUBLIC_KEY&sid=$REALITY_SID&type=tcp#trojan-reality-warp"
  echo "  vmess://$(printf '{"v":"2","ps":"vmess-ws-warp","add":"%s","port":"%s","id":"%s","aid":"0","net":"ws","type":"none","host":"","path":"%s","tls":""}' "$ip" "$PORT_VMESS_WS_W" "$UUID" "$VMESS_WS_PATH" | b64)"
  echo "  hy2://$(printf '%s' "$HY2_PWD" | urlenc)@$ip:$PORT_HY2_W?insecure=1&allowInsecure=1&sni=$REALITY_SERVER#hysteria2-warp"
  echo "  hy2://$(printf '%s' "$HY2_PWD" | urlenc)@$ip:$PORT_HY2_OBFS_W?insecure=1&allowInsecure=1&sni=$REALITY_SERVER&alpn=h3&obfs=salamander&obfs-password=$(printf '%s' "$HY2_OBFS_PWD" | urlenc)#hysteria2-obfs-warp"
  echo "  ss://$(printf '2022-blake3-aes-256-gcm:%s' "$SS2022_KEY" | b64)@$ip:$PORT_SS2022_W#ss2022-warp"
  echo "  ss://$(printf 'aes-256-gcm:%s' "$SS_PWD" | b64)@$ip:$PORT_SS_W#ss-warp"
  echo "  tuic://$UUID:$(printf '%s' "$UUID" | urlenc)@$ip:$PORT_TUIC_W?congestion_control=bbr&alpn=h3&insecure=1&allowInsecure=1&sni=$REALITY_SERVER#tuic-v5-warp"

  hr
  echo -e "${C_DIM}导出完毕：脚本将自动退出（再次运行：./sing-box-plus.sh）${C_RESET}"
}

# ---------- 部署 ----------
deploy_native(){
  ensure_bins
  install_singbox
  write_ports
  write_creds
  ensure_warp
  write_config
  # 校验（忽略 deprecated 警告）
  ENABLE_DEPRECATED_WIREGUARD_OUTBOUND=true "$BIN_PATH" check -c "$CONF_JSON"
  write_systemd
  echo
  echo -e "${C_GREEN}${C_BOLD}★ 部署完成（18 节点）${C_RESET}"
  print_links
  exit 0
}

# ---------- 动作 ----------
show_links_only(){
  if [[ ! -f "$PORTS_ENV" || ! -f "$CREDS_ENV" ]]; then
    err "未安装，请先执行 1）安装/部署"; exit 1
  fi
  print_links; exit 0
}
restart_service(){
  systemctl restart "$SYSTEMD_SERVICE" || true
  systemctl status "$SYSTEMD_SERVICE" --no-pager | sed -n '1,12p'
  exit 0
}
rotate_ports(){
  write_ports
  write_config
  systemctl restart "$SYSTEMD_SERVICE"
  echo -e "${C_GREEN}端口已全部更换并重启服务。${C_RESET}"
  exit 0
}
enable_bbr(){
  modprobe tcp_bbr 2>/dev/null || true
  echo "net.core.default_qdisc=fq" >/etc/sysctl.d/99-bbr.conf
  echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.d/99-bbr.conf
  sysctl -p /etc/sysctl.d/99-bbr.conf >/dev/null 2>&1 || true
  echo -e "${C_GREEN}BBR 已启用${C_RESET}"
  exit 0
}
uninstall_all(){
  read -r -p "确认卸载并删除 ${SB_DIR} ? (y/N): " yn || true
  if [[ "${yn,,}" == y ]]; then
    systemctl disable --now "$SYSTEMD_SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SYSTEMD_SERVICE}"
    systemctl daemon-reload
    rm -rf "$SB_DIR" "$BIN_PATH"
    echo -e "${C_GREEN}已卸载并清理${C_RESET}"
  else
    echo "已取消卸载"
  fi
  exit 0
}

# ---------- 菜单 ----------
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
  read -r -p "选择: " op || true
  case "${op:-}" in
    1) deploy_native ;;
    2) show_links_only ;;
    3) restart_service ;;
    4) rotate_ports ;;
    5) enable_bbr ;;
    8) uninstall_all ;;
    0) exit 0 ;;
    *) exit 0 ;;
  esac
}

# ---------- 入口 ----------
need_root
menu
