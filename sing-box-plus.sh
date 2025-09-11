#!/usr/bin/env bash
# -------------------------------------------------------
# Sing-Box Docker Manager (Reality + HY2 + VMess WS + extras)
# Author: Alvin9999
# OS: Debian / Ubuntu
# Version:
SCRIPT_NAME="Sing-Box Docker Manager"
SCRIPT_VERSION="v1.4.6"
# -------------------------------------------------------
set -euo pipefail

########################  颜色  ########################
C_RESET="\033[0m"; C_BOLD="\033[1m"; C_DIM="\033[2m"
C_RED="\033[31m";  C_GREEN="\033[32m"; C_YELLOW="\033[33m"
C_BLUE="\033[34m"; C_CYAN="\033[36m"
# 防手误别名（即使写成 CRESET 也不报错）
: "${CRESET:=$C_RESET}"

hr(){ printf "${C_DIM}──────────────────────────────────────────────────────────${C_RESET}\n"; }
banner(){ clear; echo -e "${C_CYAN}${C_BOLD}$SCRIPT_NAME ${SCRIPT_VERSION}${C_RESET}"; hr; }

########################  输入修复（退格可用）  ########################
READ_OPTS=(-e -r)
fix_tty(){
  if [[ -t 0 && -t 1 ]]; then
    stty sane 2>/dev/null || true
    local kbs; kbs=$(tput kbs 2>/dev/null || echo '^?')
    case "$kbs" in
      $'\177'|'^?') stty erase '^?' 2>/dev/null || true ;;
      $'\b'|'^H')  stty erase '^H' 2>/dev/null || true ;;
      *)           stty erase '^?' 2>/dev/null || true ;;
    esac
  fi
}

########################  选项与默认  ########################
SB_DIR=${SB_DIR:-/opt/sing-box}
IMAGE=${IMAGE:-ghcr.io/sagernet/sing-box:latest}
CONTAINER_NAME=${CONTAINER_NAME:-sing-box}

# 协议（按你的方案：无 h2r）
ENABLE_VLESS_REALITY=${ENABLE_VLESS_REALITY:-true}
ENABLE_VLESS_GRPCR=${ENABLE_VLESS_GRPCR:-true}
ENABLE_TROJAN_REALITY=${ENABLE_TROJAN_REALITY:-true}
ENABLE_HYSTERIA2=${ENABLE_HYSTERIA2:-true}
ENABLE_VMESS_WS=${ENABLE_VMESS_WS:-true}
ENABLE_HY2_OBFS=${ENABLE_HY2_OBFS:-true}
ENABLE_SS2022=${ENABLE_SS2022:-true}
ENABLE_SS=${ENABLE_SS:-true}
ENABLE_TUIC=${ENABLE_TUIC:-true}

# Reality 目标 & 细节
REALITY_SERVER=${REALITY_SERVER:-www.microsoft.com}
REALITY_SERVER_PORT=${REALITY_SERVER_PORT:-443}
GRPC_SERVICE=${GRPC_SERVICE:-grpc}
VMESS_WS_PATH=${VMESS_WS_PATH:-/vm}

# 外部脚本更新源
PLUS_RAW_URL="https://raw.githubusercontent.com/Alvin9999/Sing-Box-Plus/main/sing-box-plus.sh"
PLUS_LOCAL="${SB_DIR}/tools/sing-box-plus.sh"

SYSTEMD_SERVICE="sing-box-docker.service"

########################  工具函数  ########################
info(){ echo -e "${C_GREEN}[信息]${C_RESET} $*"; }
warn(){ echo -e "${C_YELLOW}[警告]${C_RESET} $*"; }
err(){  echo -e "${C_RED}[错误]${C_RESET} $*"; }
need_root(){ [[ $EUID -eq 0 ]] || { err "请以 root 运行：bash $0"; exit 1; }; }
require_cmd(){ command -v "$1" >/dev/null 2>&1 || { err "缺少命令 $1"; exit 1; }; }

urlenc(){ local s="$1" o= c; for((i=0;i<${#s};i++)){ c="${s:i:1}"; case "$c" in [a-zA-Z0-9.~_-])o+="$c";;*)printf -v h '%%%02X' "'$c"; o+="$h";; esac; }; printf '%s' "$o"; }
detect_os(){ . /etc/os-release; case "${ID,,}" in debian|ubuntu) :;; *) err "仅支持 Debian/Ubuntu"; exit 1;; esac; }
ensure_dirs(){ mkdir -p "$SB_DIR" "$SB_DIR/data" "$SB_DIR/tools" "$SB_DIR/cert"; chmod 700 "$SB_DIR"; }
dcomp(){ if docker compose version >/dev/null 2>&1; then docker compose "$@"; else docker-compose "$@"; fi; }
get_ip(){ curl -fsS4 https://ip.gs || curl -fsS4 https://ifconfig.me || echo "YOUR_SERVER_IP"; }

install_docker(){
  if ! command -v docker >/dev/null 2>&1; then info "安装 Docker ..."; curl -fsSL https://get.docker.com | bash; else info "已安装 Docker"; fi
  systemctl enable --now docker >/dev/null 2>&1 || true
  if ! dcomp version >/dev/null 2>&1; then info "安装 Docker Compose 插件 ..."; apt-get update -y && apt-get install -y docker-compose-plugin >/dev/null 2>&1 || true; fi
  for dep in openssl jq curl; do command -v "$dep" >/dev/null 2>&1 || { apt-get update -y && apt-get install -y "$dep" >/dev/null 2>&1 || true; }; done
}

rand_hex8(){ head -c 8 /dev/urandom | xxd -p; }
rand_b64_32(){ openssl rand -base64 32 | tr -d '\n'; }
gen_uuid(){ docker run --rm "$IMAGE" generate uuid; }
gen_reality(){ docker run --rm "$IMAGE" generate reality-keypair; }

mk_cert(){
  local crt="$SB_DIR/cert/fullchain.pem" key="$SB_DIR/cert/key.pem"
  if [[ ! -s "$crt" || ! -s "$key" ]]; then
    info "生成自签证书 ..."
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 3650 -nodes \
      -keyout "$key" -out "$crt" -subj "/CN=$REALITY_SERVER" \
      -addext "subjectAltName=DNS:$REALITY_SERVER" >/dev/null 2>&1
  fi
}

########################  端口（五位随机且不重复）  ########################
PORTS=()
gen_port(){ while :; do p=$(( ( RANDOM % 55536 ) + 10000 )); [[ $p -le 65535 ]] || continue; [[ ! " ${PORTS[*]} " =~ " $p " ]] && { PORTS+=("$p"); echo "$p"; return; }; done; }
rand_ports_reset(){ PORTS=(); }

########################  保存/加载  ########################
save_env(){ cat > "${SB_DIR}/env.conf" <<EOF
IMAGE=$IMAGE
CONTAINER_NAME=$CONTAINER_NAME
ENABLE_VLESS_REALITY=$ENABLE_VLESS_REALITY
ENABLE_VLESS_GRPCR=$ENABLE_VLESS_GRPCR
ENABLE_TROJAN_REALITY=$ENABLE_TROJAN_REALITY
ENABLE_HYSTERIA2=$ENABLE_HYSTERIA2
ENABLE_VMESS_WS=$ENABLE_VMESS_WS
ENABLE_HY2_OBFS=$ENABLE_HY2_OBFS
ENABLE_SS2022=$ENABLE_SS2022
ENABLE_SS=$ENABLE_SS
ENABLE_TUIC=$ENABLE_TUIC
REALITY_SERVER=$REALITY_SERVER
REALITY_SERVER_PORT=$REALITY_SERVER_PORT
GRPC_SERVICE=$GRPC_SERVICE
VMESS_WS_PATH=$VMESS_WS_PATH
EOF
}
load_env(){ [[ -f "${SB_DIR}/env.conf" ]] && . "${SB_DIR}/env.conf" || true; }

save_creds(){ cat > "${SB_DIR}/creds.env" <<EOF
UUID=$UUID
HY2_PWD=$HY2_PWD
REALITY_PRIV=$REALITY_PRIV
REALITY_PUB=$REALITY_PUB
REALITY_SID=$REALITY_SID
HY2_PWD2=$HY2_PWD2
HY2_OBFS_PWD=$HY2_OBFS_PWD
SS2022_KEY=$SS2022_KEY
SS_PWD=$SS_PWD
TUIC_UUID=$TUIC_UUID
TUIC_PWD=$TUIC_PWD
EOF
}
load_creds(){ [[ -f "${SB_DIR}/creds.env" ]] && . "${SB_DIR}/creds.env" || return 1; }

save_ports(){ cat > "${SB_DIR}/ports.env" <<EOF
PORT_VLESSR=$PORT_VLESSR
PORT_VLESS_GRPCR=$PORT_VLESS_GRPCR
PORT_TROJANR=$PORT_TROJANR
PORT_HY2=$PORT_HY2
PORT_VMESS_WS=$PORT_VMESS_WS
PORT_HY2_OBFS=$PORT_HY2_OBFS
PORT_SS2022=$PORT_SS2022
PORT_SS=$PORT_SS
PORT_TUIC=$PORT_TUIC
EOF
}
load_ports(){ [[ -f "${SB_DIR}/ports.env" ]] && . "${SB_DIR}/ports.env" || return 1; }

########################  BBR（原版）  ########################
enable_bbr(){
  info "开启 BBR 加速（原版 bbr）..."
  modprobe tcp_bbr 2>/dev/null || true
  cat > /etc/sysctl.d/99-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  sysctl -p /etc/sysctl.d/99-bbr.conf >/dev/null || true
  local cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "?")
  local qd=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "?")
  echo; echo -e "${C_BOLD}${C_GREEN}★ 执行结果：已应用原版 BBR${C_RESET}"
  echo "  当前拥塞算法: $cc"; echo "  默认队列:     $qd"; echo
  read "${READ_OPTS[@]}" -p "按回车返回菜单..." _
}

########################  防火墙  ########################
_open_ufw(){ local proto port; for it in "$@"; do proto="${it#*/}"; port="${it%/*}"; ufw allow "${port}/${proto}" >/dev/null 2>&1 || true; done; ufw reload >/dev/null 2>&1 || true; }
_open_iptables(){
  DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent >/dev/null 2>&1 || true
  local proto port
  for it in "$@"; do proto="${it#*/}"; port="${it%/*}"
    [[ "$proto" == "tcp" ]] && iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$port" -j ACCEPT
    [[ "$proto" == "udp" ]] && iptables -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport "$port" -j ACCEPT
  done
  command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
}
open_firewall(){
  local rules=()
  [[ "$ENABLE_VLESS_REALITY" == true ]]  && rules+=("${PORT_VLESSR}/tcp")
  [[ "$ENABLE_VLESS_GRPCR" == true ]]    && rules+=("${PORT_VLESS_GRPCR}/tcp")
  [[ "$ENABLE_TROJAN_REALITY" == true ]] && rules+=("${PORT_TROJANR}/tcp")
  [[ "$ENABLE_HYSTERIA2" == true ]]      && rules+=("${PORT_HY2}/udp")
  [[ "$ENABLE_VMESS_WS" == true ]]       && rules+=("${PORT_VMESS_WS}/tcp")
  [[ "$ENABLE_HY2_OBFS" == true ]]       && rules+=("${PORT_HY2_OBFS}/udp")
  [[ "$ENABLE_SS2022" == true ]]         && { rules+=("${PORT_SS2022}/tcp"); rules+=("${PORT_SS2022}/udp"); }
  [[ "$ENABLE_SS" == true ]]             && { rules+=("${PORT_SS}/tcp"); rules+=("${PORT_SS}/udp"); }
  [[ "$ENABLE_TUIC" == true ]]           && rules+=("${PORT_TUIC}/udp")
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q -E "Status: active|状态： 活跃"; then info "检测到 UFW，放行端口..."; _open_ufw "${rules[@]}"; else info "使用 iptables 放行端口..."; _open_iptables "${rules[@]}"; fi
}

########################  Compose & Systemd  ########################
write_compose(){
cat > "$SB_DIR/docker-compose.yml" <<EOF
services:
  sing-box:
    image: $IMAGE
    container_name: $CONTAINER_NAME
    restart: always
    network_mode: host
    volumes:
      - $SB_DIR/config.json:/etc/sing-box/config.json:ro
      - $SB_DIR/data:/var/lib/sing-box
      - $SB_DIR/cert:/etc/sing-box/cert:ro
    command: >
      -D /var/lib/sing-box
      -C /etc/sing-box
      run
EOF
}
write_systemd(){
cat > "/etc/systemd/system/${SYSTEMD_SERVICE}" <<EOF
[Unit]
Description=Sing-Box (Docker Compose)
After=network-online.target docker.service
Wants=network-online.target docker.service

[Service]
Type=oneshot
WorkingDirectory=$SB_DIR
ExecStart=/usr/bin/env bash -c '/usr/bin/docker compose up -d || /usr/bin/docker-compose up -d'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true
}

########################  凭据/端口/配置  ########################
PORT_VLESSR=""; PORT_VLESS_GRPCR=""; PORT_TROJANR=""; PORT_HY2=""; PORT_VMESS_WS=""
PORT_HY2_OBFS=""; PORT_SS2022=""; PORT_SS=""; PORT_TUIC=""

ensure_creds(){
  [[ -z "${UUID:-}" ]] && UUID=$(gen_uuid)

  [[ -z "${HY2_PWD:-}" ]] && HY2_PWD=$(rand_b64_32)
  if [[ -z "${REALITY_PRIV:-}" || -z "${REALITY_PUB:-}" || -z "${REALITY_SID:-}" ]]; then
    readarray -t RKP < <(gen_reality)
    REALITY_PRIV=$(printf "%s\n" "${RKP[@]}" | awk '/PrivateKey/{print $2}')
    REALITY_PUB=$(printf "%s\n" "${RKP[@]}" | awk '/PublicKey/{print $2}')
    REALITY_SID=$(rand_hex8)
  fi

  [[ -z "${HY2_PWD2:-}" ]]      && HY2_PWD2=$(rand_b64_32)
  [[ -z "${HY2_OBFS_PWD:-}" ]]  && HY2_OBFS_PWD=$(openssl rand -base64 16 | tr -d '\n')
  [[ -z "${SS2022_KEY:-}" ]]    && SS2022_KEY=$(rand_b64_32)
  [[ -z "${SS_PWD:-}" ]]        && SS_PWD=$(openssl rand -base64 24 | tr -d '=\n' | tr '+/' '-_')

  # TUIC：用户ID和密码都用 UUID
  TUIC_UUID="$UUID"
  TUIC_PWD="$UUID"

  save_creds
}

write_config(){
  ensure_dirs; load_env || true; load_creds || true; load_ports || true
  docker pull "$IMAGE" >/dev/null
  ensure_creds
  rand_ports_reset
  for v in PORT_VLESSR PORT_VLESS_GRPCR PORT_TROJANR PORT_HY2 PORT_VMESS_WS PORT_HY2_OBFS PORT_SS2022 PORT_SS PORT_TUIC; do
    [[ -n "${!v:-}" ]] && PORTS+=("${!v}")
  done
  [[ -z "${PORT_VLESSR:-}"      ]] && PORT_VLESSR=$(gen_port)
  [[ -z "${PORT_VLESS_GRPCR:-}" ]] && PORT_VLESS_GRPCR=$(gen_port)
  [[ -z "${PORT_TROJANR:-}"     ]] && PORT_TROJANR=$(gen_port)
  [[ -z "${PORT_HY2:-}"         ]] && PORT_HY2=$(gen_port)
  [[ -z "${PORT_VMESS_WS:-}"    ]] && PORT_VMESS_WS=$(gen_port)
  [[ -z "${PORT_HY2_OBFS:-}"    ]] && PORT_HY2_OBFS=$(gen_port)
  [[ -z "${PORT_SS2022:-}"      ]] && PORT_SS2022=$(gen_port)
  [[ -z "${PORT_SS:-}"          ]] && PORT_SS=$(gen_port)
  [[ -z "${PORT_TUIC:-}"        ]] && PORT_TUIC=$(gen_port)
  save_ports

  mk_cert
  local CRT="/etc/sing-box/cert/fullchain.pem" KEY="/etc/sing-box/cert/key.pem"

  cat > "$SB_DIR/config.json" <<EOF
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality",
      "listen": "0.0.0.0",
      "listen_port": $PORT_VLESSR,
      "users": [ { "uuid": "$UUID", "flow": "xtls-rprx-vision" } ],
      "tls": { "enabled": true, "server_name": "$REALITY_SERVER",
        "reality": { "enabled": true,
          "handshake": { "server": "$REALITY_SERVER", "server_port": $REALITY_SERVER_PORT },
          "private_key": "$REALITY_PRIV", "short_id": ["$REALITY_SID"] } }
    },
    {
      "type": "vless",
      "tag": "vless-grpcr",
      "listen": "0.0.0.0",
      "listen_port": $PORT_VLESS_GRPCR,
      "users": [ { "uuid": "$UUID" } ],
      "tls": { "enabled": true, "server_name": "$REALITY_SERVER",
        "reality": { "enabled": true,
          "handshake": { "server": "$REALITY_SERVER", "server_port": $REALITY_SERVER_PORT },
          "private_key": "$REALITY_PRIV", "short_id": ["$REALITY_SID"] } },
      "transport": { "type": "grpc", "service_name": "$GRPC_SERVICE" }
    },
    {
      "type": "trojan",
      "tag": "trojan-reality",
      "listen": "0.0.0.0",
      "listen_port": $PORT_TROJANR,
      "users": [ { "password": "$UUID" } ],
      "tls": { "enabled": true, "server_name": "$REALITY_SERVER",
        "reality": { "enabled": true,
          "handshake": { "server": "$REALITY_SERVER", "server_port": $REALITY_SERVER_PORT },
          "private_key": "$REALITY_PRIV", "short_id": ["$REALITY_SID"] } }
    },
    {
      "type": "hysteria2",
      "tag": "hy2",
      "listen": "0.0.0.0",
      "listen_port": $PORT_HY2,
      "users": [ { "name": "hy2", "password": "$HY2_PWD" } ],
      "tls": { "enabled": true, "certificate_path": "$CRT", "key_path": "$KEY" }
    },
    {
      "type": "vmess",
      "tag": "vmess-ws",
      "listen": "0.0.0.0",
      "listen_port": $PORT_VMESS_WS,
      "users": [ { "uuid": "$UUID" } ],
      "transport": { "type": "ws", "path": "$VMESS_WS_PATH" }
    },
    {
      "type": "hysteria2",
      "tag": "hy2-obfs",
      "listen": "0.0.0.0",
      "listen_port": $PORT_HY2_OBFS,
      "users": [ { "name": "hy2", "password": "$HY2_PWD2" } ],
      "obfs": { "type": "salamander", "password": "$HY2_OBFS_PWD" },
      "tls": { "enabled": true, "certificate_path": "$CRT", "key_path": "$KEY", "alpn": ["h3"] }
    },
    {
      "type": "shadowsocks",
      "tag": "ss2022",
      "listen": "0.0.0.0",
      "listen_port": $PORT_SS2022,
      "method": "2022-blake3-aes-256-gcm",
      "password": "$SS2022_KEY"
    },
    {
      "type": "shadowsocks",
      "tag": "ss",
      "listen": "0.0.0.0",
      "listen_port": $PORT_SS,
      "method": "aes-256-gcm",
      "password": "$SS_PWD"
    },
    {
      "type": "tuic",
      "tag": "tuic-v5",
      "listen": "0.0.0.0",
      "listen_port": $PORT_TUIC,
      "users": [ { "uuid": "$UUID", "password": "$UUID" } ],
      "congestion_control": "bbr",
      "tls": { "enabled": true, "certificate_path": "$CRT", "key_path": "$KEY", "alpn": ["h3"] }
    }
  ],
  "outbounds": [ { "type": "direct" }, { "type": "block" } ]
}
EOF

  # 清理历史残留
  jq '.inbounds = [ .inbounds[] | select(.tag!="vless-h2r" and .tag!="stls-ss" and .type!="shadowtls") ]' \
    "$SB_DIR/config.json" > "$SB_DIR/config.json.tmp" && mv "$SB_DIR/config.json.tmp" "$SB_DIR/config.json"

  write_compose
  write_systemd
  save_env
}

########################  分享链接（v2rayN 可导入）  ########################
print_links(){
  load_env; load_creds; load_ports
  local ip; ip=$(get_ip)
  local links=()

  links+=("vless://${UUID}@${ip}:${PORT_VLESSR}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#vless-reality")
  links+=("vless://${UUID}@${ip}:${PORT_VLESS_GRPCR}?encryption=none&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=grpc&serviceName=${GRPC_SERVICE}#vless-grpc-reality")
  links+=("trojan://${UUID}@${ip}:${PORT_TROJANR}?security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#trojan-reality")

  # HY2 & HY2-Obfs（补混淆密码，并兼容 allowInsecure/insecure 两种写法）
  links+=("hy2://$(urlenc "${HY2_PWD}")@${ip}:${PORT_HY2}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#hysteria2")
  links+=("hy2://$(urlenc "${HY2_PWD2}")@${ip}:${PORT_HY2_OBFS}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}&alpn=h3&obfs=salamander&obfs-password=$(urlenc "${HY2_OBFS_PWD}")&obfsParam=$(urlenc "${HY2_OBFS_PWD}")#hysteria2-obfs")

  # VMess WS
  local VMESS_JSON; VMESS_JSON=$(cat <<JSON
{"v":"2","ps":"vmess-ws","add":"${ip}","port":"${PORT_VMESS_WS}","id":"${UUID}","aid":"0","net":"ws","type":"none","host":"","path":"${VMESS_WS_PATH}","tls":""}
JSON
)
  links+=("vmess://$(printf "%s" "$VMESS_JSON" | base64 -w 0 2>/dev/null || printf "%s" "$VMESS_JSON" | base64 | tr -d '\n')")

  # TUIC：兼容 allowInsecure / insecure；密码=UUID
  links+=("tuic://${UUID}:$(urlenc "${UUID}")@${ip}:${PORT_TUIC}?congestion_control=bbr&alpn=h3&insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#tuic-v5")

  echo -e "${C_BLUE}${C_BOLD}分享链接（可直接导入 v2rayN）${C_RESET}"
  hr; for l in "${links[@]}"; do echo "  $l"; done; hr
}

########################  账号参数（英/中文双语 + 对齐）  ########################
print_manual_params(){
  load_env; load_creds; load_ports
  local ip; ip=$(get_ip)
  echo -e "${C_BLUE}${C_BOLD}账号参数（手动填写用）${C_RESET}"
  hr
  _tbl(){ column -t -s $'\t' | sed 's/^/  /'; }

  echo "📌 节点1（VLESS Reality / TCP）"
  { echo -e "Address (地址)\t$ip"
    echo -e "Port (端口)\t$PORT_VLESSR"
    echo -e "UUID (用户ID)\t$UUID"
    echo -e "flow (流控)\txtls-rprx-vision"
    echo -e "encryption (加密)\tnone"
    echo -e "network (传输)\ttcp"
    echo -e "headerType (伪装型)\tnone"
    echo -e "TLS (传输层安全)\treality"
    echo -e "SNI (serverName)\t$REALITY_SERVER"
    echo -e "Fingerprint (指纹)\tchrome"
    echo -e "Public key (公钥)\t$REALITY_PUB"
    echo -e "ShortId\t$REALITY_SID"; } | _tbl
  hr

  echo "📌 节点2（VLESS Reality / gRPC）"
  { echo -e "Address (地址)\t$ip"
    echo -e "Port (端口)\t$PORT_VLESS_GRPCR"
    echo -e "UUID (用户ID)\t$UUID"
    echo -e "encryption (加密)\tnone"
    echo -e "network (传输)\tgrpc"
    echo -e "ServiceName (服务名)\t$GRPC_SERVICE"
    echo -e "TLS (传输层安全)\treality"
    echo -e "SNI (serverName)\t$REALITY_SERVER"
    echo -e "Fingerprint (指纹)\tchrome"
    echo -e "Public key (公钥)\t$REALITY_PUB"
    echo -e "ShortId\t$REALITY_SID"; } | _tbl
  hr

  echo "📌 节点3（Trojan Reality / TCP）"
  { echo -e "Address (地址)\t$ip"
    echo -e "Port (端口)\t$PORT_TROJANR"
    echo -e "Password (密码)\t$UUID"
    echo -e "network (传输)\ttcp"
    echo -e "headerType (伪装型)\tnone"
    echo -e "TLS (传输层安全)\treality"
    echo -e "SNI (serverName)\t$REALITY_SERVER"
    echo -e "Fingerprint (指纹)\tchrome"
    echo -e "Public key (公钥)\t$REALITY_PUB"
    echo -e "ShortId\t$REALITY_SID"; } | _tbl
  hr

  echo "📌 节点4（Hysteria2 / UDP）"
  { echo -e "Address (地址)\t$ip"
    echo -e "Port (端口)\t$PORT_HY2"
    echo -e "Password (密码)\t$HY2_PWD"
    echo -e "TLS (传输层安全)\ttls"
    echo -e "SNI (serverName)\t$REALITY_SERVER"
    echo -e "Alpn\th3(可选)"
    echo -e "AllowInsecure\ttrue"; } | _tbl
  hr

  echo "📌 节点5（VMess WS / TCP）"
  { echo -e "Address (地址)\t$ip"
    echo -e "Port (端口)\t$PORT_VMESS_WS"
    echo -e "UUID (用户ID)\t$UUID"
    echo -e "AlterID\t0"
    echo -e "network (传输)\tws"
    echo -e "Path (路径)\t$VMESS_WS_PATH"
    echo -e "TLS\tnone"; } | _tbl
  hr

  echo "📌 节点6（Hysteria2-Obfs / UDP）"
  { echo -e "Address (地址)\t$ip"
    echo -e "Port (端口)\t$PORT_HY2_OBFS"
    echo -e "Password (密码)\t$HY2_PWD2"
    echo -e "TLS (传输层安全)\ttls"
    echo -e "SNI (serverName)\t$REALITY_SERVER"
    echo -e "ALPN\th3"
    echo -e "Obfs (混淆)\tsalamander"
    echo -e "Obfs password (混淆密钥)\t$HY2_OBFS_PWD"
    echo -e "AllowInsecure\ttrue"; } | _tbl
  hr

  echo "📌 节点7（Shadowsocks 2022 / TCP+UDP）"
  { echo -e "Address (地址)\t$ip"
    echo -e "Port (端口)\t$PORT_SS2022"
    echo -e "Method (加密方式)\t2022-blake3-aes-256-gcm"
    echo -e "Password (密钥，Base64)\t$SS2022_KEY"; } | _tbl
  hr

  echo "📌 节点8（Shadowsocks aes-256-gcm / TCP+UDP）"
  { echo -e "Address (地址)\t$ip"
    echo -e "Port (端口)\t$PORT_SS"
    echo -e "Method (加密方式)\taes-256-gcm"
    echo -e "Password (密码)\t$SS_PWD"; } | _tbl
  hr

  echo "📌 节点9（TUIC v5 / UDP）"
  { echo -e "Address (地址)\t$ip"
    echo -e "Port (端口)\t$PORT_TUIC"
    echo -e "UUID (用户ID)\t$UUID"
    echo -e "Password (密码)\t$UUID"
    echo -e "Congestion (拥塞控制)\tbbr"
    echo -e "ALPN\th3"
    echo -e "SNI (serverName)\t$REALITY_SERVER"
    echo -e "AllowInsecure\ttrue"; } | _tbl
  hr
}

########################  状态块  ########################
show_status_block(){
  load_env; load_ports || true
  local ip; ip=$(get_ip)
  echo -e "${C_BLUE}${C_BOLD}运行状态${C_RESET}"
  hr
  { echo -e "名称\t镜像\t状态"
    docker ps --filter "name=${CONTAINER_NAME}" --format "{{.Names}}\t{{.Image}}\t{{.Status}}"; } \
  | column -t -s $'\t'
  hr
  echo -e "${C_DIM}配置目录:${C_RESET} $SB_DIR"
  echo -e "${C_DIM}服务器 IP:${C_RESET} $ip"
  echo
  echo -e "${C_BLUE}${C_BOLD}已启用协议与端口${C_RESET}"
  hr
  [[ "$ENABLE_VLESS_REALITY" == true ]]  && echo "  - VLESS Reality (TCP):           ${PORT_VLESSR:-?}"
  [[ "$ENABLE_VLESS_GRPCR" == true ]]    && echo "  - VLESS gRPC Reality (TCP):      ${PORT_VLESS_GRPCR:-?}  服务名: $GRPC_SERVICE"
  [[ "$ENABLE_TROJAN_REALITY" == true ]] && echo "  - Trojan Reality (TCP):          ${PORT_TROJANR:-?}"
  [[ "$ENABLE_HYSTERIA2" == true ]]      && echo "  - Hysteria2 (UDP):               ${PORT_HY2:-?}"
  [[ "$ENABLE_VMESS_WS" == true ]]       && echo "  - VMess WS (TCP):                ${PORT_VMESS_WS:-?}  路径: $VMESS_WS_PATH"
  [[ "$ENABLE_HY2_OBFS" == true ]]       && echo "  - Hysteria2-Obfs (UDP):          ${PORT_HY2_OBFS:-?}"
  [[ "$ENABLE_SS2022" == true ]]         && echo "  - Shadowsocks 2022 (TCP/UDP):    ${PORT_SS2022:-?}"
  [[ "$ENABLE_SS" == true ]]             && echo "  - Shadowsocks aes-256-gcm (TCP/UDP): ${PORT_SS:-?}"
  [[ "$ENABLE_TUIC" == true ]]           && echo "  - TUIC v5 (UDP):                 ${PORT_TUIC:-?}"
  hr
}

########################  中文系统状态条  ########################
OK="${C_GREEN}✔${C_RESET}"; NO="${C_RED}✘${C_RESET}"; WAIT="${C_YELLOW}…${C_RESET}"
status_bar(){
  local docker_stat bbr_stat sbox_stat raw
  if command -v docker >/dev/null 2>&1; then
    if systemctl is-active --quiet docker 2>/dev/null || pgrep -x dockerd >/dev/null; then docker_stat="${OK} 运行中"; else docker_stat="${NO} 未运行"; fi
  else docker_stat="${NO} 未安装"; fi

  local cc qd; cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "未知")
  qd=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "未知")
  if [[ "$cc" == "bbr" ]]; then bbr_stat="${OK} 已启用（bbr）"; else bbr_stat="${NO} 未启用（当前：${cc}，队列：${qd}）"; fi

  if command -v docker >/dev/null 2>&1; then raw=$(docker inspect -f '{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo "none"); else raw="none"; fi
  case "$raw" in
    running)   sbox_stat="${OK} 运行中";;
    exited)    sbox_stat="${NO} 已停止";;
    created)   sbox_stat="${NO} 未启动";;
    restarting)sbox_stat="${WAIT} 重启中";;
    paused)    sbox_stat="${NO} 已暂停";;
    none|*)    sbox_stat="${NO} 未部署";;
  esac

  echo -e "${C_DIM}系统状态：${C_RESET} Docker：${docker_stat}    BBR：${bbr_stat}    Sing-Box：${sbox_stat}"
}

########################  核心操作  ########################
deploy_stack(){
  install_docker; ensure_dirs; write_config
  docker run --rm -v "$SB_DIR/config.json:/config.json:ro" -v "$SB_DIR/cert:/etc/sing-box/cert:ro" "$IMAGE" check -c /config.json
  info "启动/更新容器 ..."; (cd "$SB_DIR" && dcomp up -d); systemctl start "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true
  open_firewall
  echo; echo -e "${C_BOLD}${C_GREEN}★ 执行结果：部署完成${C_RESET}"; echo
  show_status_block; print_manual_params; print_links
  echo; read "${READ_OPTS[@]}" -p "按回车返回菜单，输入 q 退出: " x; [[ "${x:-}" == q ]] && exit 0
}
restart_stack(){ load_env; (cd "$SB_DIR" && dcomp restart); echo; echo -e "${C_BOLD}${C_GREEN}★ 执行结果：容器已重启${C_RESET}"; show_status_block; echo; read "${READ_OPTS[@]}" -p "按回车返回菜单..." _; }
update_image(){
  load_env; install_docker; require_cmd docker
  local before after; before=$(docker image inspect "$IMAGE" -f '{{index .RepoDigests 0}}' 2>/dev/null || echo "none")
  docker pull "$IMAGE" >/dev/null || true; (cd "$SB_DIR" && dcomp up -d)
  after=$(docker image inspect "$IMAGE" -f '{{index .RepoDigests 0}}' 2>/dev/null || echo "none")
  echo; if [[ "$before" == "$after" ]]; then echo -e "${C_BOLD}${C_GREEN}★ 执行结果：当前已是最新版（$IMAGE）${C_RESET}"; else echo -e "${C_BOLD}${C_GREEN}★ 执行结果：已更新至最新镜像（$IMAGE）${C_RESET}"; fi
  show_status_block; echo; read "${READ_OPTS[@]}" -p "按回车返回菜单..." _; }
update_plus_script(){
  ensure_dirs; local tmp; tmp="$(mktemp)"
  if ! curl -fsSL "$PLUS_RAW_URL" -o "$tmp"; then echo -e "${C_BOLD}${C_RED}★ 执行结果：获取远程脚本失败${C_RESET}"; rm -f "$tmp"
  else
    if [[ -f "$PLUS_LOCAL" ]] && cmp -s "$PLUS_LOCAL" "$tmp"; then echo -e "${C_BOLD}${C_GREEN}★ 执行结果：脚本已是最新版（$PLUS_LOCAL）${C_RESET}"
    else install -m 0755 "$tmp" "$PLUS_LOCAL"; echo -e "${C_BOLD}${C_GREEN}★ 执行结果：脚本已更新（$PLUS_LOCAL）${C_RESET}"; fi
    rm -f "$tmp"
  fi
  echo; read "${READ_OPTS[@]}" -p "按回车返回菜单..." _; }
rotate_ports(){
  load_env; load_creds || { err "未找到凭据，请先部署"; read "${READ_OPTS[@]}" -p "按回车返回菜单..." _; return 1; }
  echo; info "随机更换所有端口 ..."
  PORTS=()
  PORT_VLESSR=$(gen_port); PORT_VLESS_GRPCR=$(gen_port); PORT_TROJANR=$(gen_port); PORT_HY2=$(gen_port); PORT_VMESS_WS=$(gen_port)
  PORT_HY2_OBFS=$(gen_port); PORT_SS2022=$(gen_port); PORT_SS=$(gen_port); PORT_TUIC=$(gen_port)
  save_ports; write_config
  docker run --rm -v "$SB_DIR/config.json:/config.json:ro" -v "$SB_DIR/cert:/etc/sing-box/cert:ro" "$IMAGE" check -c /config.json
  (cd "$SB_DIR" && dcomp up -d); open_firewall
  echo -e "${C_BOLD}${C_GREEN}★ 执行结果：端口已全部更换（五位随机且互不重复）${C_RESET}"
  show_status_block; print_manual_params; print_links
  echo; read "${READ_OPTS[@]}" -p "按回车返回菜单，输入 q 退出: " x; [[ "${x:-}" == q ]] && exit 0
}
uninstall_all(){
  read "${READ_OPTS[@]}" -p "确认卸载并删除 ${SB_DIR} ? (y/N): " yn
  [[ "${yn,,}" == y ]] || { echo "已取消"; read "${READ_OPTS[@]}" -p "按回车返回菜单..." _; return; }
  (cd "$SB_DIR" && dcomp down) || true
  systemctl disable "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/${SYSTEMD_SERVICE}"; systemctl daemon-reload || true
  rm -rf "$SB_DIR"
  echo; echo -e "${C_BOLD}${C_GREEN}★ 执行结果：已卸载完成${C_RESET}"; echo; read "${READ_OPTS[@]}" -p "按回车返回菜单..." _
}

########################  菜单  ########################
menu(){
  fix_tty; banner
  echo -e "${C_BOLD}${C_BLUE}================  管 理 菜 单  ================${C_RESET}"
  echo -e "  ${C_GREEN}1)${C_RESET} 安装 Sing-Box"
  echo -e "  ${C_GREEN}2)${C_RESET} 查看状态 & 分享链接"
  echo -e "  ${C_GREEN}3)${C_RESET} 重启容器"
  echo -e "  ${C_GREEN}4)${C_RESET} 更新 Sing-Box Docker 镜像"
  echo -e "  ${C_GREEN}5)${C_RESET} 更新脚本"
  echo -e "  ${C_GREEN}6)${C_RESET} 一键更换所有端口（五位随机且互不重复）"
  echo -e "  ${C_GREEN}7)${C_RESET} 一键开启 BBR 加速"
  echo -e "  ${C_GREEN}8)${C_RESET} 卸载"
  echo -e "  ${C_GREEN}0)${C_RESET} 退出"
  echo -e "${C_BOLD}${C_BLUE}===============================================${C_RESET}"
  status_bar
  read "${READ_OPTS[@]}" -p "选择操作（回车退出）: " op
  [[ -z "${op:-}" ]] && exit 0
  case "$op" in
    1) deploy_stack;;
    2) show_status_block; print_manual_params; print_links; echo; read "${READ_OPTS[@]}" -p "按回车返回菜单，输入 q 退出: " x; [[ "${x:-}" == q ]] && exit 0;;
    3) restart_stack;;
    4) update_image;;
    5) update_plus_script;;
    6) rotate_ports;;
    7) enable_bbr;;
    8) uninstall_all;;
    0) exit 0;;
    *) echo "无效选项"; sleep 1;;
  esac
}

########################  主入口  ########################
need_root; detect_os; ensure_dirs; install_docker
while true; do menu; done
