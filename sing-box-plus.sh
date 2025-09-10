#!/usr/bin/env bash
# -------------------------------------------------------
# Sing-Box Docker Manager (Multi-Protocol, No-Cert)
# Author: Alvin9999
# OS: Debian / Ubuntu
# Version:
SCRIPT_NAME="Sing-Box Docker Manager"
SCRIPT_VERSION="v1.1.0"
# -------------------------------------------------------
set -euo pipefail

########################  彩色样式  ########################
C_RESET="\033[0m"; C_BOLD="\033[1m"; C_DIM="\033[2m"
C_RED="\033[31m";  C_GREEN="\033[32m"; C_YELLOW="\033[33m"
C_BLUE="\033[34m"; C_CYAN="\033[36m"
hr(){ printf "${C_DIM}──────────────────────────────────────────────────────────${C_RESET}\n"; }
banner(){
  clear
  echo -e "${C_CYAN}${C_BOLD}$SCRIPT_NAME ${SCRIPT_VERSION}${C_RESET}"
  hr
  if [[ -f /etc/os-release ]]; then . /etc/os-release; echo -e "${C_DIM}OS:${C_RESET} $PRETTY_NAME"; fi
  echo -e "${C_DIM}Time:${C_RESET} $(date '+%F %T')"
  hr
}

########################  默认项（首装就全开）  ########################
SB_DIR=${SB_DIR:-/opt/sing-box}
IMAGE=${IMAGE:-ghcr.io/sagernet/sing-box:latest}
CONTAINER_NAME=${CONTAINER_NAME:-sing-box}

# 全部协议默认开启（一次性全部生成）
ENABLE_VLESS_REALITY=${ENABLE_VLESS_REALITY:-true}
ENABLE_VLESS_H2R=${ENABLE_VLESS_H2R:-true}
ENABLE_VLESS_GRPCR=${ENABLE_VLESS_GRPCR:-true}
ENABLE_TROJAN_REALITY=${ENABLE_TROJAN_REALITY:-true}
ENABLE_HYSTERIA2=${ENABLE_HYSTERIA2:-true}
ENABLE_TUIC=${ENABLE_TUIC:-true}
ENABLE_SS2022=${ENABLE_SS2022:-true}
ENABLE_SHADOWTLS_SS=${ENABLE_SHADOWTLS_SS:-true}
ENABLE_VMESS_WS=${ENABLE_VMESS_WS:-true}  # 明文WS，仍默认开（首装“全开”符合你的要求）

# Reality 握手目标
REALITY_SERVER=${REALITY_SERVER:-www.microsoft.com}
REALITY_SERVER_PORT=${REALITY_SERVER_PORT:-443}

# 传输细节
GRPC_SERVICE=${GRPC_SERVICE:-grpc}
H2_PATH=${H2_PATH:-/h2}
VMESS_WS_PATH=${VMESS_WS_PATH:-/vm}

# 外部一键脚本（更新用）
PLUS_RAW_URL="https://raw.githubusercontent.com/Alvin9999/Sing-Box-Plus/main/sing-box-plus.sh"
PLUS_LOCAL="${SB_DIR}/tools/sing-box-plus.sh"

SYSTEMD_SERVICE="sing-box-docker.service"

########################  工具函数  ########################
info(){ echo -e "${C_GREEN}[INFO]${C_RESET} $*"; }
warn(){ echo -e "${C_YELLOW}[WARN]${C_RESET} $*"; }
err(){  echo -e "${C_RED}[ERR ]${C_RESET} $*"; }
need_root(){ [[ $EUID -eq 0 ]] || { err "请以 root 运行：sudo bash $0"; exit 1; }; }
require_cmd(){ command -v "$1" >/dev/null 2>&1 || { err "缺少命令 $1"; exit 1; }; }

detect_os(){
  . /etc/os-release
  case "${ID,,}" in
    debian|ubuntu) info "系统: $PRETTY_NAME";;
    *) err "仅支持 Debian/Ubuntu"; exit 1;;
  esac
}

ensure_dirs(){ mkdir -p "$SB_DIR" "$SB_DIR/data" "$SB_DIR/tools"; chmod 700 "$SB_DIR"; }
dcomp(){ if docker compose version >/dev/null 2>&1; then docker compose "$@"; else docker-compose "$@"; fi; }
get_ip(){ curl -fsS4 https://ip.gs || curl -fsS4 https://ifconfig.me || echo "YOUR_SERVER_IP"; }

install_docker(){
  if ! command -v docker >/dev/null 2>&1; then
    info "安装 Docker ..."
    curl -fsSL https://get.docker.com | bash
  else
    info "已安装 Docker"
  fi
  systemctl enable --now docker >/dev/null 2>&1 || true
  if ! dcomp version >/dev/null 2>&1; then
    info "安装 Docker Compose 插件 ..."
    apt-get update -y && apt-get install -y docker-compose-plugin || true
  fi
}

rand_hex8(){ head -c 8 /dev/urandom | xxd -p; }
rand_b64_32(){
  if command -v openssl >/dev/null 2>&1; then openssl rand -base64 32 | tr -d '\n'
  else dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64 | tr -d '\n'; fi
}
gen_uuid(){ docker run --rm "$IMAGE" generate uuid; }
gen_reality(){ docker run --rm "$IMAGE" generate reality-keypair; }

# 五位随机端口（10000-65535）不重复
PORTS=()
gen_port(){
  while :; do
    p=$(( ( RANDOM % 55536 ) + 10000 ))
    [[ $p -gt 65535 ]] && continue
    if [[ ! " ${PORTS[*]} " =~ " $p " ]]; then PORTS+=("$p"); echo "$p"; return; fi
  done
}

save_env(){
  cat > "${SB_DIR}/env.conf" <<EOF
IMAGE=$IMAGE
CONTAINER_NAME=$CONTAINER_NAME
ENABLE_VLESS_REALITY=$ENABLE_VLESS_REALITY
ENABLE_VLESS_H2R=$ENABLE_VLESS_H2R
ENABLE_VLESS_GRPCR=$ENABLE_VLESS_GRPCR
ENABLE_TROJAN_REALITY=$ENABLE_TROJAN_REALITY
ENABLE_HYSTERIA2=$ENABLE_HYSTERIA2
ENABLE_TUIC=$ENABLE_TUIC
ENABLE_SS2022=$ENABLE_SS2022
ENABLE_SHADOWTLS_SS=$ENABLE_SHADOWTLS_SS
ENABLE_VMESS_WS=$ENABLE_VMESS_WS
REALITY_SERVER=$REALITY_SERVER
REALITY_SERVER_PORT=$REALITY_SERVER_PORT
GRPC_SERVICE=$GRPC_SERVICE
H2_PATH=$H2_PATH
VMESS_WS_PATH=$VMESS_WS_PATH
EOF
}
load_env(){ [[ -f "${SB_DIR}/env.conf" ]] && . "${SB_DIR}/env.conf" || true; }

save_creds(){
  cat > "${SB_DIR}/creds.env" <<EOF
UUID=$UUID
UUID_TUIC=$UUID_TUIC
HY2_AUTH=$HY2_AUTH
TUIC_PWD=$TUIC_PWD
SS2022_PWD=$SS2022_PWD
REALITY_PRIV=$REALITY_PRIV
REALITY_PUB=$REALITY_PUB
REALITY_SID=$REALITY_SID
EOF
}
load_creds(){ [[ -f "${SB_DIR}/creds.env" ]] && . "${SB_DIR}/creds.env" || return 1; }

save_ports(){
  cat > "${SB_DIR}/ports.env" <<EOF
$( [[ "$ENABLE_VLESS_REALITY" == true ]]   && echo "PORT_VLESSR=$PORT_VLESSR" )
$( [[ "$ENABLE_VLESS_H2R" == true ]]       && echo "PORT_VLESS_H2R=$PORT_VLESS_H2R" )
$( [[ "$ENABLE_VLESS_GRPCR" == true ]]     && echo "PORT_VLESS_GRPCR=$PORT_VLESS_GRPCR" )
$( [[ "$ENABLE_TROJAN_REALITY" == true ]]  && echo "PORT_TROJANR=$PORT_TROJANR" )
$( [[ "$ENABLE_HYSTERIA2" == true ]]       && echo "PORT_HY2=$PORT_HY2" )
$( [[ "$ENABLE_TUIC" == true ]]            && echo "PORT_TUIC=$PORT_TUIC" )
$( [[ "$ENABLE_SS2022" == true ]]          && echo "PORT_SS2022=$PORT_SS2022" )
$( [[ "$ENABLE_SHADOWTLS_SS" == true ]]    && echo "PORT_STLS=$PORT_STLS
PORT_STLS_SS=$PORT_STLS_SS" )
$( [[ "$ENABLE_VMESS_WS" == true ]]        && echo "PORT_VMESS_WS=$PORT_VMESS_WS" )
EOF
}
load_ports(){ [[ -f "${SB_DIR}/ports.env" ]] && . "${SB_DIR}/ports.env" || return 1; }

b64url(){ printf "%s" "$1" | base64 -w 0 2>/dev/null || printf "%s" "$1" | base64; }
b64url_strip(){ b64url "$1" | tr -d '\n' | tr '+/' '-_' | tr -d '='; }

########################  BBR 加速  ########################
enable_bbr(){
  info "开启 BBR（优先 bbr2）..."
  modprobe tcp_bbr 2>/dev/null || true
  local avail cc="bbr"
  avail=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "")
  if echo "$avail" | grep -qw bbr2; then cc="bbr2"; fi
  cat > /etc/sysctl.d/99-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=$cc
EOF
  sysctl -p /etc/sysctl.d/99-bbr.conf >/dev/null || true
  info "BBR 设置完成（如为新装内核，重启后更稳）。"
}

########################  防火墙放行  ########################
_open_ufw(){
  local p proto; for p in "$@"; do
    proto="${p#*/}"; port="${p%/*}"
    ufw allow "${port}/${proto}" >/dev/null 2>&1 || true
  done
  ufw reload >/dev/null 2>&1 || true
}
_open_iptables(){
  apt-get update -y >/dev/null 2>&1 || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent >/dev/null 2>&1 || true
  local port proto
  for it in "$@"; do
    proto="${it#*/}"; port="${it%/*}"
    [[ "$proto" == "tcp" ]] && iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$port" -j ACCEPT
    [[ "$proto" == "udp" ]] && iptables -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport "$port" -j ACCEPT
  done
  netfilter-persistent save >/dev/null 2>&1 || true
}
open_firewall(){
  # 组装需要放行的端口/协议
  local rules=()
  [[ "$ENABLE_VLESS_REALITY" == true ]]  && rules+=("${PORT_VLESSR}/tcp")
  [[ "$ENABLE_VLESS_H2R" == true ]]      && rules+=("${PORT_VLESS_H2R}/tcp")
  [[ "$ENABLE_VLESS_GRPCR" == true ]]    && rules+=("${PORT_VLESS_GRPCR}/tcp")
  [[ "$ENABLE_TROJAN_REALITY" == true ]] && rules+=("${PORT_TROJANR}/tcp")
  [[ "$ENABLE_HYSTERIA2" == true ]]      && rules+=("${PORT_HY2}/udp")
  [[ "$ENABLE_TUIC" == true ]]           && rules+=("${PORT_TUIC}/udp")
  [[ "$ENABLE_SS2022" == true ]]         && rules+=("${PORT_SS2022}/tcp")
  if [[ "$ENABLE_SHADOWTLS_SS" == true ]]; then
    rules+=("${PORT_STLS}/tcp" "${PORT_STLS_SS}/tcp")
  fi
  [[ "$ENABLE_VMESS_WS" == true ]]       && rules+=("${PORT_VMESS_WS}/tcp")

  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q -E "Status: active|状态： 活跃"; then
    info "检测到 UFW，放行端口..."
    _open_ufw "${rules[@]}"
  else
    info "使用 iptables 放行端口..."
    _open_iptables "${rules[@]}"
  fi
}

########################  配置写入  ########################
write_compose(){
cat > "$SB_DIR/docker-compose.yml" <<EOF
version: "3.8"
services:
  sing-box:
    image: $IMAGE
    container_name: $CONTAINER_NAME
    restart: always
    network_mode: host
    volumes:
      - $SB_DIR/config.json:/etc/sing-box/config.json:ro
      - $SB_DIR/data:/var/lib/sing-box
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

write_config(){
  ensure_dirs; load_env || true; load_creds || true; load_ports || true
  docker pull "$IMAGE" >/dev/null

  # 凭据
  if [[ -z "${UUID:-}" ]]; then
    info "生成凭据 ..."
    UUID=$(gen_uuid); UUID_TUIC=$(gen_uuid)
    HY2_AUTH=$(rand_b64_32); TUIC_PWD=$(rand_b64_32); SS2022_PWD=$(rand_b64_32)
    readarray -t RKP < <(gen_reality)
    REALITY_PRIV=$(printf "%s\n" "${RKP[@]}" | awk '/PrivateKey/{print $2}')
    REALITY_PUB=$(printf "%s\n" "${RKP[@]}" | awk '/PublicKey/{print $2}')
    REALITY_SID=$(rand_hex8)
    save_creds
  fi

  # 端口（五位且唯一）
  PORTS=()
  for v in PORT_VLESSR PORT_VLESS_H2R PORT_VLESS_GRPCR PORT_TROJANR PORT_HY2 PORT_TUIC PORT_SS2022 PORT_STLS PORT_STLS_SS PORT_VMESS_WS; do
    [[ -n "${!v:-}" ]] && PORTS+=("${!v}")
  done
  [[ -z "${PORT_VLESSR:-}"      ]] && PORT_VLESSR=$(gen_port)
  [[ -z "${PORT_VLESS_H2R:-}"   ]] && PORT_VLESS_H2R=$(gen_port)
  [[ -z "${PORT_VLESS_GRPCR:-}" ]] && PORT_VLESS_GRPCR=$(gen_port)
  [[ -z "${PORT_TROJANR:-}"     ]] && PORT_TROJANR=$(gen_port)
  [[ -z "${PORT_HY2:-}"         ]] && PORT_HY2=$(gen_port)
  [[ -z "${PORT_TUIC:-}"        ]] && PORT_TUIC=$(gen_port)
  [[ -z "${PORT_SS2022:-}"      ]] && PORT_SS2022=$(gen_port)
  [[ -z "${PORT_STLS:-}"        ]] && PORT_STLS=$(gen_port)
  [[ -z "${PORT_STLS_SS:-}"     ]] && PORT_STLS_SS=$(gen_port)
  [[ -z "${PORT_VMESS_WS:-}"    ]] && PORT_VMESS_WS=$(gen_port)
  save_ports

  # 配置文件（全部 inbound 的 listen 改为 0.0.0.0，避免仅绑 IPv6）
  SERVER_IP=$(get_ip)
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
      "tag": "vless-h2r",
      "listen": "0.0.0.0",
      "listen_port": $PORT_VLESS_H2R,
      "users": [ { "uuid": "$UUID" } ],
      "tls": { "enabled": true, "server_name": "$REALITY_SERVER",
        "reality": { "enabled": true,
          "handshake": { "server": "$REALITY_SERVER", "server_port": $REALITY_SERVER_PORT },
          "private_key": "$REALITY_PRIV", "short_id": ["$REALITY_SID"] } },
      "transport": { "type": "http", "path": "$H2_PATH" }
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
      "users": [ { "name": "hy2", "auth": "$HY2_AUTH" } ]
    },
    {
      "type": "tuic",
      "tag": "tuic",
      "listen": "0.0.0.0",
      "listen_port": $PORT_TUIC,
      "users": [ { "uuid": "$UUID_TUIC", "password": "$TUIC_PWD" } ],
      "congestion_control": "bbr",
      "udp_relay_mode": "native",
      "zero_rtt_handshake": true
    },
    {
      "type": "shadowsocks",
      "tag": "ss2022",
      "listen": "0.0.0.0",
      "listen_port": $PORT_SS2022,
      "method": "2022-blake3-aes-256-gcm",
      "password": "$SS2022_PWD"
    },
    {
      "type": "shadowtls",
      "tag": "shadowtls",
      "listen": "0.0.0.0",
      "listen_port": $PORT_STLS,
      "version": 3,
      "handshake": { "server": "$REALITY_SERVER", "server_port": $REALITY_SERVER_PORT },
      "detour": "stls-ss"
    },
    {
      "type": "shadowsocks",
      "tag": "stls-ss",
      "listen": "0.0.0.0",
      "listen_port": $PORT_STLS_SS,
      "method": "2022-blake3-aes-256-gcm",
      "password": "$SS2022_PWD"
    },
    {
      "type": "vmess",
      "tag": "vmess-ws",
      "listen": "0.0.0.0",
      "listen_port": $PORT_VMESS_WS,
      "users": [ { "uuid": "$UUID" } ],
      "transport": { "type": "ws", "path": "$VMESS_WS_PATH" }
    }
  ],
  "outbounds": [ { "type": "direct" }, { "type": "block" } ]
}
EOF

  write_compose
  write_systemd
  save_env
}

########################  分享链接输出  ########################
print_links(){
  load_env; load_creds; load_ports
  local ip; ip=$(get_ip)
  local NAME_BASE="sbdk"; local links=()

  links+=("vless://${UUID}@${ip}:${PORT_VLESSR}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#${NAME_BASE}-vlessr")
  links+=("vless://${UUID}@${ip}:${PORT_VLESS_H2R}?encryption=none&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=http&path=${H2_PATH}#${NAME_BASE}-h2r")
  links+=("vless://${UUID}@${ip}:${PORT_VLESS_GRPCR}?encryption=none&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=grpc&serviceName=${GRPC_SERVICE}#${NAME_BASE}-grpcr")
  links+=("trojan://${UUID}@${ip}:${PORT_TROJANR}?security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#${NAME_BASE}-trojanr")
  links+=("hy2://${HY2_AUTH}@${ip}:${PORT_HY2}?insecure=1&sni=${REALITY_SERVER}#${NAME_BASE}-hy2")
  links+=("tuic://${UUID_TUIC}:${TUIC_PWD}@${ip}:${PORT_TUIC}?congestion_control=bbr&udp_relay_mode=native&alpn=h3#${NAME_BASE}-tuic")
  links+=("ss://2022-blake3-aes-256-gcm:$(b64url_strip "${SS2022_PWD}")@${ip}:${PORT_SS2022}#${NAME_BASE}-ss2022")
  links+=("shadowtls://${ip}:${PORT_STLS}?server=${REALITY_SERVER}:${REALITY_SERVER_PORT}  ← 先连此，再连本机 SS(${PORT_STLS_SS})")
  local VMESS_JSON
  VMESS_JSON=$(cat <<JSON
{"v":"2","ps":"${NAME_BASE}-vmessws","add":"${ip}","port":"${PORT_VMESS_WS}","id":"${UUID}","aid":"0","net":"ws","type":"none","host":"","path":"${VMESS_WS_PATH}","tls":""}
JSON
)
  links+=("vmess://$(b64url "$VMESS_JSON" | tr -d '\n')")

  echo -e "${C_BLUE}${C_BOLD}分享链接（可导入 v2rayN）${C_RESET}"
  hr; for l in "${links[@]}"; do echo "  $l"; done; hr
}

########################  端口巡检  ########################
verify_ports(){
  info "检查端口监听情况 ..."
  sleep 1
  local miss=0; local line
  declare -A want=()
  want["$PORT_VLESSR/tcp"]="VLESS Reality"
  want["$PORT_VLESS_H2R/tcp"]="VLESS H2 Reality"
  want["$PORT_VLESS_GRPCR/tcp"]="VLESS gRPC Reality"
  want["$PORT_TROJANR/tcp"]="Trojan Reality"
  want["$PORT_HY2/udp"]="Hysteria2"
  want["$PORT_TUIC/udp"]="TUIC v5"
  want["$PORT_SS2022/tcp"]="SS 2022"
  want["$PORT_STLS/tcp"]="ShadowTLS"
  want["$PORT_STLS_SS/tcp"]="ShadowTLS-SS"
  want["$PORT_VMESS_WS/tcp"]="VMess WS"

  for k in "${!want[@]}"; do
    local p="${k%/*}"; local proto="${k#*/}"
    if ss -lntu | grep -q ":${p} "; then
      printf "  %-22s %s\n" "${want[$k]}" "✅ 监听 ${p}/${proto}"
    else
      printf "  %-22s %s\n" "${want[$k]}" "❌ 未监听 ${p}/${proto}"
      miss=$((miss+1))
    fi
  done
  [[ $miss -eq 0 ]] && info "所有端口已监听。" || warn "有端口未监听：请检查 docker 日志、防火墙/安全组、或端口占用。"
}

########################  核心操作  ########################
deploy_stack(){
  install_docker
  write_config
  info "启动/更新容器 ..."
  (cd "$SB_DIR" && dcomp up -d)
  systemctl start "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true
  open_firewall
  info "部署完成！"
  show_status
  verify_ports
}

show_status(){
  load_env; load_ports || true
  local ip; ip=$(get_ip)
  echo -e "${C_BLUE}${C_BOLD}运行状态${C_RESET}"
  hr
  docker ps --filter "name=${CONTAINER_NAME}" --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"
  hr
  echo -e "${C_DIM}配置目录:${C_RESET} $SB_DIR"
  echo -e "${C_DIM}服务器IP:${C_RESET} $ip"
  echo
  echo -e "${C_BLUE}${C_BOLD}已启用协议与端口${C_RESET}"
  hr
  echo "  - VLESS Reality (TCP):      $PORT_VLESSR"
  echo "  - VLESS H2 Reality (TCP):   $PORT_VLESS_H2R   路径: $H2_PATH"
  echo "  - VLESS gRPC Reality (TCP): $PORT_VLESS_GRPCR service: $GRPC_SERVICE"
  echo "  - Trojan Reality (TCP):     $PORT_TROJANR"
  echo "  - Hysteria2 (UDP):          $PORT_HY2"
  echo "  - TUIC v5 (UDP):            $PORT_TUIC"
  echo "  - Shadowsocks 2022 (TCP):   $PORT_SS2022"
  echo "  - ShadowTLS (TCP):          $PORT_STLS  -> 本机SS: $PORT_STLS_SS"
  echo "  - VMess WS 明文 (TCP):      $PORT_VMESS_WS   路径: $VMESS_WS_PATH"
  hr
  print_links
}

restart_stack(){ load_env; info "重启容器 ..."; (cd "$SB_DIR" && dcomp restart); info "完成"; }

update_image(){
  load_env; install_docker; require_cmd docker
  info "检查 sing-box 镜像更新 ..."
  local before after
  before=$(docker image inspect "$IMAGE" -f '{{index .RepoDigests 0}}' 2>/dev/null || echo "none")
  docker pull "$IMAGE" >/dev/null || true
  (cd "$SB_DIR" && dcomp up -d)
  after=$(docker image inspect "$IMAGE" -f '{{index .RepoDigests 0}}' 2>/dev/null || echo "none")
  if [[ "$before" == "$after" ]]; then
    info "当前已是最新版（$IMAGE）"
  else
    info "已更新到最新镜像（$IMAGE）"
  fi
  show_status
}

update_plus_script(){
  ensure_dirs
  info "检查外部脚本 $PLUS_LOCAL 的更新 ..."
  local tmp; tmp="$(mktemp)"
  if ! curl -fsSL "$PLUS_RAW_URL" -o "$tmp"; then
    err "获取远程脚本失败"; rm -f "$tmp"; return 1
  fi
  if [[ -f "$PLUS_LOCAL" ]] && cmp -s "$PLUS_LOCAL" "$tmp"; then
    info "已是最新版：$PLUS_LOCAL"
  else
    install -m 0755 "$tmp" "$PLUS_LOCAL"
    info "已更新：$PLUS_LOCAL"
  fi
  rm -f "$tmp"
}

rotate_ports(){
  load_env; load_creds || { err "未找到凭据，请先部署"; return 1; }
  info "随机更换所有端口 ..."
  PORTS=()
  PORT_VLESSR=$(gen_port); PORT_VLESS_H2R=$(gen_port); PORT_VLESS_GRPCR=$(gen_port)
  PORT_TROJANR=$(gen_port); PORT_HY2=$(gen_port); PORT_TUIC=$(gen_port)
  PORT_SS2022=$(gen_port); PORT_STLS=$(gen_port); PORT_STLS_SS=$(gen_port)
  PORT_VMESS_WS=$(gen_port)
  save_ports
  write_config
  (cd "$SB_DIR" && dcomp up -d)
  open_firewall
  info "端口已全部更换完成（五位随机且互不重复）"
  show_status
  verify_ports
}

uninstall_all(){
  read -r -p "确认卸载并删除 ${SB_DIR} ? (y/N): " yn
  [[ "${yn,,}" == y ]] || { echo "已取消"; return; }
  (cd "$SB_DIR" && dcomp down) || true
  systemctl disable "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/${SYSTEMD_SERVICE}"
  systemctl daemon-reload || true
  rm -rf "$SB_DIR"
  info "已卸载"
}

########################  菜单  ########################
menu(){
  banner
  echo -e "${C_BOLD}${C_BLUE}================  管 理 菜 单  ================${C_RESET}"
  echo -e "  ${C_GREEN}1)${C_RESET} 安装/更新 Sing-Box（生成配置并启动）"
  echo -e "  ${C_GREEN}2)${C_RESET} 查看状态 & 分享链接"
  echo -e "  ${C_GREEN}3)${C_RESET} 重启容器"
  echo -e "  ${C_GREEN}4)${C_RESET} 更新 Sing-Box Docker 镜像"
  echo -e "  ${C_GREEN}5)${C_RESET} 更新外部脚本 sing-box-plus.sh"
  echo -e "  ${C_GREEN}6)${C_RESET} 一键更换所有端口（五位随机且互不重复）"
  echo -e "  ${C_GREEN}7)${C_RESET} 一键开启 BBR 加速（优先 bbr2）"
  echo -e "  ${C_GREEN}8)${C_RESET} 卸载（停止并删除配置）"
  echo -e "  ${C_GREEN}0)${C_RESET} 退出"
  echo -e "${C_BOLD}${C_BLUE}===============================================${C_RESET}"
  read -r -p "选择操作: " op
  case "$op" in
    1) deploy_stack; read -r -p "回车返回菜单..." _;;
    2) show_status;  read -r -p "回车返回菜单..." _;;
    3) restart_stack;read -r -p "回车返回菜单..." _;;
    4) update_image; read -r -p "回车返回菜单..." _;;
    5) update_plus_script; read -r -p "回车返回菜单..." _;;
    6) rotate_ports; read -r -p "回车返回菜单..." _;;
    7) enable_bbr;   read -r -p "回车返回菜单..." _;;
    8) uninstall_all;read -r -p "回车返回菜单..." _;;
    0) exit 0;;
    *) echo "无效选项"; sleep 1;;
  esac
}

########################  主入口  ########################
need_root
detect_os
ensure_dirs
# 启动时自动安装 Docker，然后进入菜单（第1项就是安装/更新 Sing-Box）
install_docker
while true; do menu; done
