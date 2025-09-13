#!/usr/bin/env bash
# =================================================================
# Sing-Box-Plus 管理脚本  v2.1.0
# Author: ported & refined for native sing-box + WARP (no docker)
# Repo : https://github.com/Alvin9999/Sing-Box-Plus
# OS   : Debian / Ubuntu / CentOS / RHEL / Rocky / Alma (systemd)
# =================================================================

set -euo pipefail

# ------------------------- 颜色 & 符号 ---------------------------
C_RESET="\033[0m"; C_BOLD="\033[1m"; C_DIM="\033[2m"
C_RED="\033[31m"; C_GREEN="\033[32m"; C_YELLOW="\033[33m"
C_BLUE="\033[34m"; C_CYAN="\033[36m"

hr(){ printf "${C_DIM}=============================================================${C_RESET}\n"; }

SCRIPT_NAME="Sing-Box-Plus 管理脚本"
SCRIPT_VERSION="v2.1.0"

# ------------------------- 路径 & 常量 ---------------------------
SB_DIR="/opt/sing-box"
BIN_PATH="/usr/local/bin/sing-box"
SYSTEMD_SERVICE="sing-box.service"
CONF_JSON="$SB_DIR/config.json"
PORTS_ENV="$SB_DIR/ports.env"
CREDS_ENV="$SB_DIR/creds.env"
WARP_ENV="$SB_DIR/warp.env"
WGCF_DIR="$SB_DIR/wgcf"

READ_OPTS=(-e -r)

mkdir -p "$SB_DIR" "$WGCF_DIR"

# ------------------------- 小工具函数 ---------------------------
need_cmd(){ command -v "$1" >/dev/null 2>&1 || (echo "[信息] 安装 $1 ..." && apt-get update -y >/dev/null 2>&1 || true && apt-get install -y "$1"); }
is_root(){ [ "$(id -u)" -eq 0 ]; }
fail(){ echo -e "${C_RED}[错误]${C_RESET} $*"; exit 1; }
info(){ echo -e "${C_CYAN}[信息]${C_RESET} $*"; }

fix_tty(){ stty sane 2>/dev/null || true; }
trap fix_tty EXIT

# 生成 UUID（单行，无换行）
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

# 随机端口（避开已占用，默认 11000-49999）
rand(){ awk -v min=11000 -v max=49999 'BEGIN{srand();print int(min+rand()*(max-min+1))}'; }
port_free(){ ! ss -ltnup 2>/dev/null | grep -q ":$1\b"; }
gen_port(){
  local p; for _ in {1..1000}; do p=$(rand); port_free "$p" && { echo "$p"; return; }; done
  echo 0
}

# 生成随机密钥/密码（base64 安全）
rand_b64(){ head -c 16 /dev/urandom | base64 | tr -d '\r\n='; }
rand_hex(){ head -c 16 /dev/urandom | xxd -p | tr -d '\r\n'; }

# ------------------------- UI：Banner & 状态 --------------------
banner(){
  clear
  echo -e "${C_CYAN}${C_BOLD}${SCRIPT_NAME}${C_RESET}  ${C_DIM}${SCRIPT_VERSION}${C_RESET}"
  echo -e "脚本更新地址: ${C_BLUE}https://github.com/Alvin9999/Sing-Box-Plus${C_RESET}"
  hr
}

status_overview(){
  local bbr_text sb_text
  if sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | grep -qi bbr; then
    bbr_text="${C_GREEN}已启用 BBR${C_RESET}"
  else
    bbr_text="${C_RED}未启用（bbr）${C_RESET}"
  fi
  if systemctl list-unit-files 2>/dev/null | grep -q "^${SYSTEMD_SERVICE}"; then
    if systemctl is-active "${SYSTEMD_SERVICE}" >/dev/null 2>&1; then
      sb_text="${C_GREEN}运行中${C_RESET}"
    else
      sb_text="${C_RED}未运行${C_RESET}"
    fi
  else
    sb_text="${C_RED}未安装${C_RESET}"
  fi
  echo -e "系统加速状态：${bbr_text}"
  echo -e "Sing-Box 启动状态：${sb_text}"
  hr
}

# ------------------------- 安装依赖 & 程序 ----------------------
ensure_bins(){
  need_cmd curl; need_cmd jq; need_cmd tar; need_cmd sed; need_cmd awk; need_cmd iproute2 || true
  if ! command -v wgcf >/dev/null 2>&1; then
    info "安装 wgcf ..."
    local ver url
    ver="2.2.21"
    url="https://github.com/ViRb3/wgcf/releases/download/v${ver}/wgcf_${ver}_linux_amd64"
    curl -fsSL "$url" -o /usr/local/bin/wgcf
    chmod +x /usr/local/bin/wgcf
  fi
}

install_singbox(){
  if [[ -x "$BIN_PATH" ]]; then
    info "检测到 sing-box：$("$BIN_PATH" version | head -n1)"
    return
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

# ------------------------- 生成端口 & 凭据 ---------------------
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
  local uuidTrojan uuidVless vmessId ssPass ss2022Key hy2Pwd hy2ObfsPwd tuicPass
  local sni="www.microsoft.com" sid="$(rand_hex)"
  uuidVless=$(gen_uuid)
  uuidTrojan="$uuidVless"
  vmessId="$uuidVless"
  ssPass=$(rand_b64)
  ss2022Key=$(rand_b64)
  hy2Pwd=$(rand_b64)
  hy2ObfsPwd=$(rand_b64)
  tuicPass="$uuidVless"

  # Reality KeyPair
  mapfile -t KP < <("$BIN_PATH" generate reality-keypair)
  local REALITY_PRIVATE_KEY REALITY_PUBLIC_KEY
  REALITY_PRIVATE_KEY=$(echo "${KP[0]}" | awk -F': ' '{print $2}')
  REALITY_PUBLIC_KEY=$(echo "${KP[1]}"  | awk -F': ' '{print $2}')

  cat >"$CREDS_ENV" <<EOF
UUID_VLESS=$uuidVless
UUID_TROJAN=$uuidTrojan
UUID_VMESS=$vmessId
SS_PASS=$ssPass
SS2022_KEY=$ss2022Key
HY2_PWD=$hy2Pwd
HY2_OBFS_PWD=$hy2ObfsPwd
TUIC_UUID=$uuidVless
TUIC_PASS=$uuidVless
REALITY_PRIVATE_KEY=$REALITY_PRIVATE_KEY
REALITY_PUBLIC_KEY=$REALITY_PUBLIC_KEY
REALITY_SNI=$sni
REALITY_SID=$sid
EOF
}

# ------------------------- WARP（wgcf） ------------------------
ensure_warp(){
  info "初始化 WARP 账户 ..."
  local acct="$WGCF_DIR/wgcf-account.toml" prof="$WGCF_DIR/wgcf-profile.conf"
  if [[ ! -f "$acct" ]]; then
    (cd "$WGCF_DIR"; WGCF_TRACE=1 wgcf register --accept-tos >/dev/null)
  fi
  (cd "$WGCF_DIR"; wgcf generate >/dev/null)

  # 解析 wgcf-profile
  local priv pub endpoint v4 v6 r1 r2 r3 eph
  priv=$(grep -m1 '^PrivateKey' "$prof" | awk '{print $3}')
  pub=$(grep -m1 '^PublicKey' "$prof"  | awk '{print $3}')
  endpoint=$(grep -m1 '^Endpoint' "$prof" | awk '{print $3}')
  v4=$(grep -m1 '^Address = ' "$prof" | awk -F'[ ="]+' '{print $6}')
  v6=$(grep -m1 '^Address = ' "$prof" | awk -F'[ ="]+' 'NR==2{print $6}')
  # reserved
  if grep -q '^Reserved' "$prof"; then
    r1=$(grep -m1 '^Reserved' "$prof" | sed 's/.*=\s*\[\s*\([0-9]\+\),\s*\([0-9]\+\),\s*\([0-9]\+\)\s*\].*/\1/'); 
    r2=$(grep -m1 '^Reserved' "$prof" | sed 's/.*=\s*\[\s*\([0-9]\+\),\s*\([0-9]\+\),\s*\([0-9]\+\)\s*\].*/\2/'); 
    r3=$(grep -m1 '^Reserved' "$prof" | sed 's/.*=\s*\[\s*\([0-9]\+\),\s*\([0-9]\+\),\s*\([0-9]\+\)\s*\].*/\3/')
  else r1=0;r2=0;r3=0; fi

  # 端点：预解析成 IP，避免本地 DNS 异常
  local host port ip
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

# ------------------------- 写入 config.json --------------------
write_config(){
  info "写入配置 ..."
  . "$PORTS_ENV"
  . "$CREDS_ENV"
  . "$WARP_ENV"

  local SNI="$REALITY_SNI" PBK="$REALITY_PUBLIC_KEY" SID="$REALITY_SID"

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
    { "type":"vless", "tag":"vless-reality", "listen": "::", "listen_port": $PORT_VLESSR,
      "users":[{"uuid":"$UUID_VLESS","flow":"xtls-rprx-vision"}],
      "tls":{"enabled":true,"server_name":"$SNI","reality":{"enabled":true,"handshake":{"server":"$SNI","server_port":443},"private_key":"$REALITY_PRIVATE_KEY","short_id":["$SID"]}}},
    { "type":"vless", "tag":"vless-grpcr", "listen":"::", "listen_port": $PORT_VLESS_GRPCR,
      "users":[{"uuid":"$UUID_VLESS"}],
      "transport":{"type":"grpc","service_name":"grpc"},
      "tls":{"enabled":true,"server_name":"$SNI","reality":{"enabled":true,"handshake":{"server":"$SNI","server_port":443},"private_key":"$REALITY_PRIVATE_KEY","short_id":["$SID"]}}},
    { "type":"trojan", "tag":"trojan-reality", "listen":"::", "listen_port": $PORT_TROJANR,
      "users":[{"password":"$UUID_TROJAN"}],
      "tls":{"enabled":true,"server_name":"$SNI","reality":{"enabled":true,"handshake":{"server":"$SNI","server_port":443},"private_key":"$REALITY_PRIVATE_KEY","short_id":["$SID"]}}},
    { "type":"vmess", "tag":"vmess-ws", "listen":"::", "listen_port": $PORT_VMESS_WS,
      "users":[{"uuid":"$UUID_VMESS"}],
      "transport":{"type":"ws","path":"/vm"} },
    { "type":"hysteria2", "tag":"hy2", "listen":"::", "listen_port": $PORT_HY2,
      "password":"$HY2_PWD", "tls":{"enabled":true,"server_name":"$SNI","insecure":true}},
    { "type":"hysteria2", "tag":"hy2-obfs", "listen":"::", "listen_port": $PORT_HY2_OBFS,
      "password":"$HY2_PWD", "obfs":{"type":"salamander","password":"$HY2_OBFS_PWD"},
      "tls":{"enabled":true,"server_name":"$SNI","insecure":true,"alpn":["h3"]}},
    { "type":"shadowsocks", "tag":"ss2022", "listen":"::", "listen_port": $PORT_SS2022,
      "method":"2022-blake3-aes-256-gcm", "password":"$SS2022_KEY" },
    { "type":"shadowsocks", "tag":"ss", "listen":"::", "listen_port": $PORT_SS,
      "method":"aes-256-gcm", "password":"$SS_PASS" },
    { "type":"tuic", "tag":"tuic-v5", "listen":"::", "listen_port": $PORT_TUIC,
      "users":[{"uuid":"$TUIC_UUID","password":"$TUIC_PASS"}],
      "congestion_control":"bbr",
      "tls":{"enabled":true,"server_name":"$SNI","insecure":true,"alpn":["h3"]}},

    { "type":"vless", "tag":"vless-reality-warp", "listen": "::", "listen_port": $PORT_VLESSR_W,
      "users":[{"uuid":"$UUID_VLESS","flow":"xtls-rprx-vision"}],
      "tls":{"enabled":true,"server_name":"$SNI","reality":{"enabled":true,"handshake":{"server":"$SNI","server_port":443},"private_key":"$REALITY_PRIVATE_KEY","short_id":["$SID"]}}},
    { "type":"vless", "tag":"vless-grpcr-warp", "listen":"::", "listen_port": $PORT_VLESS_GRPCR_W,
      "users":[{"uuid":"$UUID_VLESS"}],
      "transport":{"type":"grpc","service_name":"grpc"},
      "tls":{"enabled":true,"server_name":"$SNI","reality":{"enabled":true,"handshake":{"server":"$SNI","server_port":443},"private_key":"$REALITY_PRIVATE_KEY","short_id":["$SID"]}}},
    { "type":"trojan", "tag":"trojan-reality-warp", "listen":"::", "listen_port": $PORT_TROJANR_W,
      "users":[{"password":"$UUID_TROJAN"}],
      "tls":{"enabled":true,"server_name":"$SNI","reality":{"enabled":true,"handshake":{"server":"$SNI","server_port":443},"private_key":"$REALITY_PRIVATE_KEY","short_id":["$SID"]}}},
    { "type":"hysteria2", "tag":"hy2-warp", "listen":"::", "listen_port": $PORT_HY2_W,
      "password":"$HY2_PWD", "tls":{"enabled":true,"server_name":"$SNI","insecure":true}},
    { "type":"vmess", "tag":"vmess-ws-warp", "listen":"::", "listen_port": $PORT_VMESS_WS_W,
      "users":[{"uuid":"$UUID_VMESS"}], "transport":{"type":"ws","path":"/vm"} },
    { "type":"hysteria2", "tag":"hy2-obfs-warp", "listen":"::", "listen_port": $PORT_HY2_OBFS_W,
      "password":"$HY2_PWD", "obfs":{"type":"salamander","password":"$HY2_OBFS_PWD"},
      "tls":{"enabled":true,"server_name":"$SNI","insecure":true,"alpn":["h3"]}},
    { "type":"shadowsocks", "tag":"ss2022-warp", "listen":"::", "listen_port": $PORT_SS2022_W,
      "method":"2022-blake3-aes-256-gcm", "password":"$SS2022_KEY" },
    { "type":"shadowsocks", "tag":"ss-warp", "listen":"::", "listen_port": $PORT_SS_W,
      "method":"aes-256-gcm", "password":"$SS_PASS" },
    { "type":"tuic", "tag":"tuic-v5-warp", "listen":"::", "listen_port": $PORT_TUIC_W,
      "users":[{"uuid":"$TUIC_UUID","password":"$TUIC_PASS"}],
      "congestion_control":"bbr",
      "tls":{"enabled":true,"server_name":"$SNI","insecure":true,"alpn":["h3"]}}
  ],
  "outbounds":[
    { "type":"direct", "tag":"direct" },
    { "type":"block",  "tag":"block" },
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
        ],
        "outbound":"warp"
      }
    ],
    "final":"direct"
  }
}
JSON
}

# ------------------------- systemd 服务 ------------------------
write_systemd(){
  cat >/etc/systemd/system/${SYSTEMD_SERVICE} <<EOF
[Unit]
Description=Sing-Box (Native 18 nodes)
After=network-online.target

[Service]
Type=simple
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

# ------------------------- 分享链接 ----------------------------
b64(){ printf "%s" "$1" | base64 -w0; }

print_links(){
  . "$PORTS_ENV"; . "$CREDS_ENV"; . "$WARP_ENV"
  local host ip; host=$(curl -fsSL ifconfig.me || curl -fsSL ip.sb || hostname -I | awk '{print $1}')
  ip="${host}"

  hr; echo -e "${C_BOLD}分享链接（18 个）${C_RESET}"; hr

  echo -e "${C_GREEN}【直连节点（9）】${C_RESET}"
  echo "  vless://$UUID_VLESS@$ip:$PORT_VLESSR?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$REALITY_SNI&fp=chrome&pbk=$REALITY_PUBLIC_KEY&sid=$REALITY_SID&type=tcp#vless-reality"
  echo "  vless://$UUID_VLESS@$ip:$PORT_VLESS_GRPCR?encryption=none&security=reality&sni=$REALITY_SNI&fp=chrome&pbk=$REALITY_PUBLIC_KEY&sid=$REALITY_SID&type=grpc&serviceName=grpc#vless-grpc-reality"
  echo "  trojan://$UUID_TROJAN@$ip:$PORT_TROJANR?security=reality&sni=$REALITY_SNI&fp=chrome&pbk=$REALITY_PUBLIC_KEY&sid=$REALITY_SID&type=tcp#trojan-reality"
  echo "  vmess://$(b64 "{\"v\":\"2\",\"ps\":\"vmess-ws\",\"add\":\"$ip\",\"port\":\"$PORT_VMESS_WS\",\"id\":\"$UUID_VMESS\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"\",\"path\":\"/vm\",\"tls\":\"\"}")"
  echo "  hy2://$(printf %s "$HY2_PWD" | jq -sRr @uri)@$ip:$PORT_HY2?insecure=1&allowInsecure=1&sni=$REALITY_SNI#hysteria2"
  echo "  hy2://$(printf %s "$HY2_PWD" | jq -sRr @uri)@$ip:$PORT_HY2_OBFS?insecure=1&allowInsecure=1&sni=$REALITY_SNI&alpn=h3&obfs=salamander&obfs-password=$(printf %s "$HY2_OBFS_PWD" | jq -sRr @uri)#hysteria2-obfs"
  echo "  ss://$(b64 "2022-blake3-aes-256-gcm:$SS2022_KEY")@$ip:$PORT_SS2022#ss2022"
  echo "  ss://$(b64 "aes-256-gcm:$SS_PASS")@$ip:$PORT_SS#ss"
  echo "  tuic://$TUIC_UUID:$TUIC_PASS@$ip:$PORT_TUIC?congestion_control=bbr&alpn=h3&insecure=1&allowInsecure=1&sni=$REALITY_SNI#tuic-v5"

  hr
  echo -e "${C_YELLOW}提示：以上 9 个为直连出口；下方 9 个为 WARP 出口（Cloudflare AS13335），更适合流媒体解锁。${C_RESET}"
  hr

  echo -e "${C_GREEN}【WARP 节点（9）】${C_RESET}"
  echo "  vless://$UUID_VLESS@$ip:$PORT_VLESSR_W?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$REALITY_SNI&fp=chrome&pbk=$REALITY_PUBLIC_KEY&sid=$REALITY_SID&type=tcp#vless-reality-warp"
  echo "  vless://$UUID_VLESS@$ip:$PORT_VLESS_GRPCR_W?encryption=none&security=reality&sni=$REALITY_SNI&fp=chrome&pbk=$REALITY_PUBLIC_KEY&sid=$REALITY_SID&type=grpc&serviceName=grpc#vless-grpc-reality-warp"
  echo "  trojan://$UUID_TROJAN@$ip:$PORT_TROJANR_W?security=reality&sni=$REALITY_SNI&fp=chrome&pbk=$REALITY_PUBLIC_KEY&sid=$REALITY_SID&type=tcp#trojan-reality-warp"
  echo "  vmess://$(b64 "{\"v\":\"2\",\"ps\":\"vmess-ws-warp\",\"add\":\"$ip\",\"port\":\"$PORT_VMESS_WS_W\",\"id\":\"$UUID_VMESS\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"\",\"path\":\"/vm\",\"tls\":\"\"}")"
  echo "  hy2://$(printf %s "$HY2_PWD" | jq -sRr @uri)@$ip:$PORT_HY2_W?insecure=1&allowInsecure=1&sni=$REALITY_SNI#hysteria2-warp"
  echo "  hy2://$(printf %s "$HY2_PWD" | jq -sRr @uri)@$ip:$PORT_HY2_OBFS_W?insecure=1&allowInsecure=1&sni=$REALITY_SNI&alpn=h3&obfs=salamander&obfs-password=$(printf %s "$HY2_OBFS_PWD" | jq -sRr @uri)#hysteria2-obfs-warp"
  echo "  ss://$(b64 "2022-blake3-aes-256-gcm:$SS2022_KEY")@$ip:$PORT_SS2022_W#ss2022-warp"
  echo "  ss://$(b64 "aes-256-gcm:$SS_PASS")@$ip:$PORT_SS_W#ss-warp"
  echo "  tuic://$TUIC_UUID:$TUIC_PASS@$ip:$PORT_TUIC_W?congestion_control=bbr&alpn=h3&insecure=1&allowInsecure=1&sni=$REALITY_SNI#tuic-v5-warp"

  hr
  echo -e "${C_DIM}导出完毕：脚本将自动退出（再次运行：./sing-box-plus.sh）${C_RESET}"
}

# ------------------------- 功能动作 ----------------------------
deploy_native(){
  ensure_bins
  install_singbox
  write_ports
  write_creds
  ensure_warp
  write_config
  write_systemd
  echo
  echo -e "${C_BOLD}${C_GREEN}★ 部署完成（18 节点）${C_RESET}"
  print_links
  exit 0
}

restart_service(){
  systemctl restart ${SYSTEMD_SERVICE} || true
  systemctl status ${SYSTEMD_SERVICE} --no-pager
}

rotate_ports(){
  write_ports
  write_config
  systemctl restart ${SYSTEMD_SERVICE}
  echo -e "${C_GREEN}端口已全部更换并重启服务。${C_RESET}"
}

enable_bbr(){
  if sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | grep -qi bbr; then
    echo -e "${C_GREEN}已启用 BBR。${C_RESET}"
    return
  fi
  echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
  echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
  sysctl -p
  echo -e "${C_GREEN}BBR 已启用。${C_RESET}"
}

uninstall_all(){
  systemctl disable --now ${SYSTEMD_SERVICE} 2>/dev/null || true
  rm -f /etc/systemd/system/${SYSTEMD_SERVICE}
  systemctl daemon-reload
  rm -rf "$SB_DIR"
  rm -f "$BIN_PATH"
  echo -e "${C_YELLOW}已卸载 sing-box 与相关文件。${C_RESET}"
}

# ------------------------- 菜单 -------------------------------
menu(){
  banner
  status_overview
  echo -e "  ${C_GREEN}1)${C_RESET} 安装/部署（18 节点）"
  echo -e "  ${C_GREEN}2)${C_RESET} 查看分享链接"
  echo -e "  ${C_GREEN}3)${C_RESET} 重启服务"
  echo -e "  ${C_GREEN}4)${C_RESET} 一键更换所有端口"
  echo -e "  ${C_GREEN}5)${C_RESET} 一键开启 BBR"
  echo -e "  ${C_GREEN}8)${C_RESET} 卸载"
  echo -e "  ${C_GREEN}0)${C_RESET} 退出"
  hr
  read -r -p "选择: " op
  case "${op:-}" in
    1) deploy_native ;;
    2) 
       if [[ -f "$PORTS_ENV" && -f "$CREDS_ENV" ]]; then
         print_links; exit 0
       else
         echo -e "${C_RED}未安装，请先执行 1）安装/部署。${C_RESET}"
       fi
       ;;
    3) restart_service ;;
    4) rotate_ports ;;
    5) enable_bbr ;;
    8) uninstall_all ;;
    0) exit 0 ;;
    *) ;;
  esac
}

# ------------------------- 入口 -------------------------------
is_root || fail "请以 root 运行。"
menu
