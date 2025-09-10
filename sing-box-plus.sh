#!/usr/bin/env bash
# -------------------------------------------------------
# Sing-Box Docker Manager (Reality + HY2 w/ self-signed TLS)
# Author: Alvin9999
# OS: Debian / Ubuntu
# Version:
SCRIPT_NAME="Sing-Box Docker Manager"
SCRIPT_VERSION="v1.3.6"
# -------------------------------------------------------
set -euo pipefail

########################  彩色样式  ########################
C_RESET="\033[0m"; C_BOLD="\033[1m"; C_DIM="\033[2m"
C_RED="\033[31m";  C_GREEN="\033[32m"; C_YELLOW="\033[33m"
C_BLUE="\033[34m"; C_CYAN="\033[36m"
hr(){ printf "${C_DIM}──────────────────────────────────────────────────────────${C_RESET}\n"; }

banner(){
  clear
  # 只显示标题 & 版本，不显示 OS/Time
  echo -e "${C_CYAN}${C_BOLD}$SCRIPT_NAME ${SCRIPT_VERSION}${C_RESET}"
  hr
}

########################  输入修复（退格可用）  ########################
READ_OPTS=(-e -r)  # -e 启用 readline，退格/左右键可用；-r 原样读取
fix_tty(){
  if [[ -t 0 && -t 1 ]]; then
    stty sane 2>/dev/null || true
    local kbs; kbs=$(tput kbs 2>/dev/null || echo '^?')
    case "$kbs" in
      $'\177'|'^?') stty erase '^?' 2>/dev/null || true ;;
      $'\b'|'^H')   stty erase '^H' 2>/dev/null || true ;;
      *)            stty erase '^?' 2>/dev/null || true ;;
    esac
  fi
}

########################  开关与默认项  ########################
SB_DIR=${SB_DIR:-/opt/sing-box}
IMAGE=${IMAGE:-ghcr.io/sagernet/sing-box:latest}
CONTAINER_NAME=${CONTAINER_NAME:-sing-box}

# 保留：VLESS Reality / VLESS gRPC Reality / Trojan Reality / HY2 / VMess WS
# 移除：H2R / TUIC / SS2022 / ShadowTLS
ENABLE_VLESS_REALITY=${ENABLE_VLESS_REALITY:-true}
ENABLE_VLESS_GRPCR=${ENABLE_VLESS_GRPCR:-true}
ENABLE_TROJAN_REALITY=${ENABLE_TROJAN_REALITY:-true}
ENABLE_HYSTERIA2=${ENABLE_HYSTERIA2:-true}
ENABLE_VMESS_WS=${ENABLE_VMESS_WS:-true}

# Reality 握手目标
REALITY_SERVER=${REALITY_SERVER:-www.microsoft.com}
REALITY_SERVER_PORT=${REALITY_SERVER_PORT:-443}

# 传输细节
GRPC_SERVICE=${GRPC_SERVICE:-grpc}
VMESS_WS_PATH=${VMESS_WS_PATH:-/vm}

# 外部一键脚本（更新用）
PLUS_RAW_URL="https://raw.githubusercontent.com/Alvin9999/Sing-Box-Plus/main/sing-box-plus.sh"
PLUS_LOCAL="${SB_DIR}/tools/sing-box-plus.sh"

SYSTEMD_SERVICE="sing-box-docker.service"

########################  工具函数  ########################
info(){ echo -e "${C_GREEN}[INFO]${C_RESET} $*"; }
warn(){ echo -e "${C_YELLOW}[WARN]${C_RESET} $*"; }
err(){  echo -e "${C_RED}[ERR ]${C_RESET} $*"; }
need_root(){ [[ $EUID -eq 0 ]] || { err "请以 root 运行：bash $0"; exit 1; }; }
require_cmd(){ command -v "$1" >/dev/null 2>&1 || { err "缺少命令 $1"; exit 1; }; }

# URL 编码（用于分享链接里的密码）
urlenc(){ # usage: urlenc "raw string"
  local s="$1" o= c
  for ((i=0;i<${#s};i++)); do
    c="${s:i:1}"
    case "$c" in [a-zA-Z0-9.~_-]) o+="$c";; *)
      printf -v hex '%%%02X' "'$c"; o+="$hex";;
    esac
  done
  printf '%s' "$o"
}

detect_os(){
  . /etc/os-release
  case "${ID,,}" in
    debian|ubuntu) : ;;  # 不打印 OS
    *) err "仅支持 Debian/Ubuntu"; exit 1;;
  esac
}

ensure_dirs(){ mkdir -p "$SB_DIR" "$SB_DIR/data" "$SB_DIR/tools" "$SB_DIR/cert"; chmod 700 "$SB_DIR"; }
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
    apt-get update -y && apt-get install -y docker-compose-plugin >/dev/null 2>&1 || true
  fi
  for dep in openssl jq; do
    command -v "$dep" >/dev/null 2>&1 || { apt-get update -y && apt-get install -y "$dep" >/dev/null 2>&1 || true; }
  done
}

rand_hex8(){ head -c 8 /dev/urandom | xxd -p; }
rand_b64_32(){ openssl rand -base64 32 | tr -d '\n'; }
gen_uuid(){ docker run --rm "$IMAGE" generate uuid; }
gen_reality(){ docker run --rm "$IMAGE" generate reality-keypair; }

mk_cert(){
  local crt="$SB_DIR/cert/fullchain.pem" key="$SB_DIR/cert/key.pem"
  if [[ ! -s "$crt" || ! -s "$key" ]]; then
    info "生成自签证书 ..."
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -days 3650 -nodes -keyout "$key" -out "$crt" \
      -subj "/CN=$REALITY_SERVER" \
      -addext "subjectAltName=DNS:$REALITY_SERVER" >/dev/null 2>&1
  fi
}

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
ENABLE_VLESS_GRPCR=$ENABLE_VLESS_GRPCR
ENABLE_TROJAN_REALITY=$ENABLE_TROJAN_REALITY
ENABLE_HYSTERIA2=$ENABLE_HYSTERIA2
ENABLE_VMESS_WS=$ENABLE_VMESS_WS
REALITY_SERVER=$REALITY_SERVER
REALITY_SERVER_PORT=$REALITY_SERVER_PORT
GRPC_SERVICE=$GRPC_SERVICE
VMESS_WS_PATH=$VMESS_WS_PATH
EOF
}
load_env(){ [[ -f "${SB_DIR}/env.conf" ]] && . "${SB_DIR}/env.conf" || true; }

save_creds(){
  cat > "${SB_DIR}/creds.env" <<EOF
UUID=$UUID
HY2_PWD=$HY2_PWD
REALITY_PRIV=$REALITY_PRIV
REALITY_PUB=$REALITY_PUB
REALITY_SID=$REALITY_SID
EOF
}
load_creds(){ [[ -f "${SB_DIR}/creds.env" ]] && . "${SB_DIR}/creds.env" || return 1; }

save_ports(){
  cat > "${SB_DIR}/ports.env" <<EOF
PORT_VLESSR=$PORT_VLESSR
PORT_VLESS_GRPCR=$PORT_VLESS_GRPCR
PORT_TROJANR=$PORT_TROJANR
PORT_HY2=$PORT_HY2
PORT_VMESS_WS=$PORT_VMESS_WS
EOF
}
load_ports(){ [[ -f "${SB_DIR}/ports.env" ]] && . "${SB_DIR}/ports.env" || return 1; }

b64url(){ printf "%s" "$1" | base64 -w 0 2>/dev/null || printf "%s" "$1" | base64; }

########################  BBR 加速（原版 bbr）  ########################
enable_bbr(){
  info "开启 BBR 加速（原版 bbr）..."
  modprobe tcp_bbr 2>/dev/null || true
  cat > /etc/sysctl.d/99-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  sysctl -p /etc/sysctl.d/99-bbr.conf >/dev/null || true
  local cc qd
  cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
  qd=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "unknown")
  echo
  echo -e "${C_BOLD}${C_GREEN}★ 执行结果：已应用原版 BBR${C_RESET}"
  echo    "  当前拥塞算法: $cc"
  echo    "  默认队列:     $qd"
  echo
  read "${READ_OPTS[@]}" -p "按回车返回菜单..." _
}

########################  防火墙放行  ########################
_open_ufw(){
  local proto port
  for it in "$@"; do proto="${it#*/}"; port="${it%/*}"; ufw allow "${port}/${proto}" >/dev/null 2>&1 || true; done
  ufw reload >/dev/null 2>&1 || true
}
_open_iptables(){
  DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent >/dev/null 2>&1 || true
  local proto port
  for it in "$@"; do
    proto="${it#*/}"; port="${it%/*}"
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

# 凭据 & 端口
rand_ports_reset(){ PORTS=(); }
ensure_creds(){
  [[ -z "${UUID:-}"       ]] && UUID=$(gen_uuid)
  [[ -z "${HY2_PWD:-}"    ]] && HY2_PWD=$(rand_b64_32)
  if [[ -z "${REALITY_PRIV:-}" || -z "${REALITY_PUB:-}" || -z "${REALITY_SID:-}" ]]; then
    readarray -t RKP < <(gen_reality)
    REALITY_PRIV=$(printf "%s\n" "${RKP[@]}" | awk '/PrivateKey/{print $2}')
    REALITY_PUB=$(printf "%s\n" "${RKP[@]}" | awk '/PublicKey/{print $2}')
    REALITY_SID=$(rand_hex8)
  fi
  save_creds
}

PORT_VLESSR=""; PORT_VLESS_GRPCR=""; PORT_TROJANR=""; PORT_HY2=""; PORT_VMESS_WS=""

write_config(){
  ensure_dirs; load_env || true; load_creds || true; load_ports || true
  docker pull "$IMAGE" >/dev/null
  ensure_creds
  rand_ports_reset
  for v in PORT_VLESSR PORT_VLESS_GRPCR PORT_TROJANR PORT_HY2 PORT_VMESS_WS; do
    [[ -n "${!v:-}" ]] && PORTS+=("${!v}")
  done
  [[ -z "${PORT_VLESSR:-}"      ]] && PORT_VLESSR=$(gen_port)
  [[ -z "${PORT_VLESS_GRPCR:-}" ]] && PORT_VLESS_GRPCR=$(gen_port)
  [[ -z "${PORT_TROJANR:-}"     ]] && PORT_TROJANR=$(gen_port)
  [[ -z "${PORT_HY2:-}"         ]] && PORT_HY2=$(gen_port)
  [[ -z "${PORT_VMESS_WS:-}"    ]] && PORT_VMESS_WS=$(gen_port)
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
    }
  ],
  "outbounds": [ { "type": "direct" }, { "type": "block" } ]
}
EOF

  # 清理历史残留
  jq '.inbounds = [
        .inbounds[] |
        select(.tag!="vless-h2r" and .tag!="tuic" and .tag!="ss2022" and .type!="shadowtls" and .tag!="stls-ss")
     ]' "$SB_DIR/config.json" > "$SB_DIR/config.json.tmp" && mv "$SB_DIR/config.json.tmp" "$SB_DIR/config.json"

  write_compose
  write_systemd
  save_env
}

########################  账号参数（手填用）打印  ########################
print_manual_params(){
  load_env; load_creds; load_ports
  local ip; ip=$(get_ip)
  echo -e "${C_BLUE}${C_BOLD}账号参数（手动填写用）${C_RESET}"
  hr
  # VLESS Reality
  cat <<EOT
[ VLESS Reality (TCP) ]
  地址(Address):      $ip
  端口(Port):         $PORT_VLESSR
  UUID(ID):           $UUID
  加密(Encryption):   none
  流控(Flow):         xtls-rprx-vision
  SNI/Host:           $REALITY_SERVER
  PublicKey(pbk):     $REALITY_PUB
  ShortID(sid):       $REALITY_SID
  传输(Transport):    tcp
EOT
  echo
  # VLESS gRPC Reality
  cat <<EOT
[ VLESS gRPC Reality ]
  地址(Address):      $ip
  端口(Port):         $PORT_VLESS_GRPCR
  UUID(ID):           $UUID
  SNI/Host:           $REALITY_SERVER
  PublicKey(pbk):     $REALITY_PUB
  ShortID(sid):       $REALITY_SID
  传输(Transport):    grpc
  ServiceName:        $GRPC_SERVICE
EOT
  echo
  # Trojan Reality
  cat <<EOT
[ Trojan Reality (TCP) ]
  地址(Address):      $ip
  端口(Port):         $PORT_TROJANR
  密码(Password):     $UUID
  SNI/Host:           $REALITY_SERVER
  PublicKey(pbk):     $REALITY_PUB
  ShortID(sid):       $REALITY_SID
  传输(Transport):    tcp
EOT
  echo
  # HY2
  cat <<EOT
[ Hysteria2 (UDP) ]
  地址(Address):      $ip
  端口(Port):         $PORT_HY2
  密码(Password):     $HY2_PWD
  SNI/Host:           $REALITY_SERVER
  证书校验:           关闭 (insecure=1)
EOT
  echo
  # VMess WS
  cat <<EOT
[ VMess WS 明文 ]
  地址(Address):      $ip
  端口(Port):         $PORT_VMESS_WS
  UUID(ID):           $UUID
  AlterID:            0
  传输(Transport):    ws
  路径(Path):         $VMESS_WS_PATH
  TLS:                none
EOT
  hr
}

########################  分享链接输出（带回显控制）  ########################
print_links(){
  load_env; load_creds; load_ports
  local ip; ip=$(get_ip)
  local NAME_BASE="sbdk"; local links=()

  links+=("vless://${UUID}@${ip}:${PORT_VLESSR}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#${NAME_BASE}-vlessr")
  links+=("vless://${UUID}@${ip}:${PORT_VLESS_GRPCR}?encryption=none&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=grpc&serviceName=${GRPC_SERVICE}#${NAME_BASE}-grpcr")
  links+=("trojan://${UUID}@${ip}:${PORT_TROJANR}?security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#${NAME_BASE}-trojanr")
  links+=("hy2://$(urlenc "${HY2_PWD}")@${ip}:${PORT_HY2}?insecure=1&sni=${REALITY_SERVER}#${NAME_BASE}-hy2")

  local VMESS_JSON
  VMESS_JSON=$(cat <<JSON
{"v":"2","ps":"${NAME_BASE}-vmessws","add":"${ip}","port":"${PORT_VMESS_WS}","id":"${UUID}","aid":"0","net":"ws","type":"none","host":"","path":"${VMESS_WS_PATH}","tls":""}
JSON
)
  links+=("vmess://$(printf "%s" "$VMESS_JSON" | base64 -w 0 2>/dev/null || printf "%s" "$VMESS_JSON" | base64 | tr -d '\n')")

  echo -e "${C_BLUE}${C_BOLD}分享链接（可导入 v2rayN）${C_RESET}"
  hr; for l in "${links[@]}"; do echo "  $l"; done; hr
}

########################  核心操作  ########################
deploy_stack(){
  install_docker
  ensure_dirs
  write_config
  docker run --rm \
    -v "$SB_DIR/config.json:/config.json:ro" \
    -v "$SB_DIR/cert:/etc/sing-box/cert:ro" \
    "$IMAGE" check -c /config.json
  info "启动/更新容器 ..."
  (cd "$SB_DIR" && dcomp up -d)
  systemctl start "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true
  open_firewall

  # 显眼回显 + 参数区 + 链接；用户选择返回菜单或退出
  echo
  echo -e "${C_BOLD}${C_GREEN}★ 执行结果：部署完成${C_RESET}"
  echo
  show_status_block
  print_manual_params
  print_links
  echo
  read "${READ_OPTS[@]}" -p "按回车返回菜单，输入 q 退出: " opt; [[ "${opt:-}" == q ]] && exit 0
}

show_status_block(){
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
  echo "  - VLESS Reality (TCP):      ${PORT_VLESSR:-?}"
  echo "  - VLESS gRPC Reality (TCP): ${PORT_VLESS_GRPCR:-?}  service: $GRPC_SERVICE"
  echo "  - Trojan Reality (TCP):     ${PORT_TROJANR:-?}"
  echo "  - Hysteria2 (UDP):          ${PORT_HY2:-?}"
  echo "  - VMess WS 明文 (TCP):      ${PORT_VMESS_WS:-?}  路径: $VMESS_WS_PATH"
  hr
}

restart_stack(){
  load_env
  (cd "$SB_DIR" && dcomp restart)
  echo
  echo -e "${C_BOLD}${C_GREEN}★ 执行结果：容器已重启${C_RESET}"
  show_status_block
  echo
  read "${READ_OPTS[@]}" -p "按回车返回菜单..." _
}

update_image(){
  load_env; install_docker; require_cmd docker
  local before after
  before=$(docker image inspect "$IMAGE" -f '{{index .RepoDigests 0}}' 2>/dev/null || echo "none")
  docker pull "$IMAGE" >/dev/null || true
  (cd "$SB_DIR" && dcomp up -d)
  after=$(docker image inspect "$IMAGE" -f '{{index .RepoDigests 0}}' 2>/dev/null || echo "none")
  echo
  if [[ "$before" == "$after" ]]; then
    echo -e "${C_BOLD}${C_GREEN}★ 执行结果：当前已是最新版（$IMAGE）${C_RESET}"
  else
    echo -e "${C_BOLD}${C_GREEN}★ 执行结果：已更新至最新镜像（$IMAGE）${C_RESET}"
  fi
  show_status_block
  echo
  read "${READ_OPTS[@]}" -p "按回车返回菜单..." _
}

update_plus_script(){
  ensure_dirs
  local tmp; tmp="$(mktemp)"
  if ! curl -fsSL "$PLUS_RAW_URL" -o "$tmp"; then
    echo -e "${C_BOLD}${C_RED}★ 执行结果：获取远程脚本失败${C_RESET}"
    rm -f "$tmp"
  else
    if [[ -f "$PLUS_LOCAL" ]] && cmp -s "$PLUS_LOCAL" "$tmp"; then
      echo -e "${C_BOLD}${C_GREEN}★ 执行结果：脚本已是最新版（$PLUS_LOCAL）${C_RESET}"
    else
      install -m 0755 "$tmp" "$PLUS_LOCAL"
      echo -e "${C_BOLD}${C_GREEN}★ 执行结果：脚本已更新（$PLUS_LOCAL）${C_RESET}"
    fi
    rm -f "$tmp"
  fi
  echo
  read "${READ_OPTS[@]}" -p "按回车返回菜单..." _
}

rotate_ports(){
  load_env; load_creds || { err "未找到凭据，请先部署"; read "${READ_OPTS[@]}" -p "按回车返回菜单..." _; return 1; }
  echo
  info "随机更换所有端口 ..."
  PORTS=()
  PORT_VLESSR=$(gen_port); PORT_VLESS_GRPCR=$(gen_port)
  PORT_TROJANR=$(gen_port); PORT_HY2=$(gen_port); PORT_VMESS_WS=$(gen_port)
  save_ports
  write_config
  docker run --rm -v "$SB_DIR/config.json:/config.json:ro" -v "$SB_DIR/cert:/etc/sing-box/cert:ro" "$IMAGE" check -c /config.json
  (cd "$SB_DIR" && dcomp up -d)
  open_firewall
  echo -e "${C_BOLD}${C_GREEN}★ 执行结果：端口已全部更换（五位随机且互不重复）${C_RESET}"
  show_status_block
  print_manual_params
  print_links
  echo
  read "${READ_OPTS[@]}" -p "按回车返回菜单，输入 q 退出: " opt; [[ "${opt:-}" == q ]] && exit 0
}

uninstall_all(){
  read "${READ_OPTS[@]}" -p "确认卸载并删除 ${SB_DIR} ? (y/N): " yn
  [[ "${yn,,}" == y ]] || { echo "已取消"; read "${READ_OPTS[@]}" -p "按回车返回菜单..." _; return; }
  (cd "$SB_DIR" && dcomp down) || true
  systemctl disable "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/${SYSTEMD_SERVICE}"
  systemctl daemon-reload || true
  rm -rf "$SB_DIR"
  echo
  echo -e "${C_BOLD}${C_GREEN}★ 执行结果：已卸载完成${C_RESET}"
  echo
  read "${READ_OPTS[@]}" -p "按回车返回菜单..." _
}

########################  菜单（文案调整 & 回车退出）  ########################
menu(){
  fix_tty
  banner
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
  read "${READ_OPTS[@]}" -p "选择操作（回车退出）: " op
  [[ -z "${op:-}" ]] && exit 0
  case "$op" in
    1) deploy_stack;;
    2) show_status_block; print_manual_params; print_links; echo; read "${READ_OPTS[@]}" -p "按回车返回菜单，输入 q 退出: " opt; [[ "${opt:-}" == q ]] && exit 0;;
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
need_root
detect_os
ensure_dirs
install_docker
while true; do menu; done
