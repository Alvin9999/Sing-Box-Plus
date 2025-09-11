#!/usr/bin/env bash
# -------------------------------------------------------
# Sing-Box Docker Manager (Reality + HY2/Obfs + TUIC v5 + VMess WS + SS AES-256-GCM)
# Author: Alvin9999
# OS: Debian / Ubuntu / CentOS / RHEL / Rocky / Alma
# Version:
SCRIPT_NAME="Sing-Box Docker Manager"
SCRIPT_VERSION="v1.6.3"
# -------------------------------------------------------
set -euo pipefail

########################  颜色 & UI  ########################
C_RESET="\033[0m"; C_BOLD="\033[1m"; C_DIM="\033[2m"
C_RED="\033[31m"; C_GREEN="\033[32m"; C_YELLOW="\033[33m"
C_BLUE="\033[34m"; C_CYAN="\033[36m"

hr(){ printf "${C_DIM}──────────────────────────────────────────────────────────${C_RESET}\n"; }
title(){ clear; echo -e "${C_CYAN}${C_BOLD}$SCRIPT_NAME ${SCRIPT_VERSION}${C_RESET}"; hr; }
sec(){ echo; echo -e "${C_BLUE}${C_BOLD}$*${C_RESET}"; hr; }
ok(){  echo -e "${C_GREEN}✓${C_RESET} $*"; }
warn(){ echo -e "${C_YELLOW}[警告]${C_RESET} $*"; }
err(){ echo -e "${C_RED}[错误]${C_RESET} $*"; }
info(){ echo -e "${C_GREEN}[信息]${C_RESET} $*"; }

# 读入时让退格可用
READ_OPTS=(-e -r)
fix_tty(){
  if [[ -t 0 && -t 1 ]]; then
    stty sane 2>/dev/null || true
    local kbs; kbs=$(tput kbs 2>/dev/null || echo '^?')
    case "$kbs" in $'\177'|'^?') stty erase '^?' 2>/dev/null || true ;;
                      $'\b'|'^H') stty erase '^H' 2>/dev/null || true ;;
                      *)          stty erase '^?' 2>/dev/null || true ;;
    esac
  fi
}

########################  进度条工具  ########################
mklog(){ mktemp -p /tmp sbplus.$(date +%s).XXXX.log; }

bar_draw(){ # $1:百分比 $2:标题 $3:状态msg
  local p=$1; ((p<0))&&p=0; ((p>100))&&p=100
  local w=34 filled=$(( p*w/100 ))
  local fill=$(printf "%${filled}s" | tr ' ' '█')
  local rest=$(printf "%$((w-filled))s" | tr ' ' '░')
  printf "\r%s [%-s%s] %3d%%  %s" "$2" "$fill" "$rest" "$p" "$3"
}

run_with_progress(){ # "描述" 预计秒数 -- 命令...
  local desc="$1"; local est=${2:-20}; shift 2
  local logf; logf=$(mklog)
  info "开始：$desc"
  ( "$@" >>"$logf" 2>&1 ) &
  local pid=$! start=$(date +%s) p=0 frame=0
  local frames=( "⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏" )
  while kill -0 "$pid" 2>/dev/null; do
    local elapsed=$(( $(date +%s) - start ))
    p=$(( elapsed*90/est )); ((p>90))&&p=90
    bar_draw "$p" "${C_CYAN}${frames[frame]}${C_RESET} ${desc}" "处理中..."
    frame=$(( (frame+1)%${#frames[@]} )); sleep 0.2
  done
  if wait "$pid"; then
    bar_draw 100 "${C_GREEN}✔${C_RESET} ${desc}" "完成"; echo
  else
    bar_draw "$p" "${C_RED}✘${C_RESET} ${desc}" "失败"; echo
    err "$desc 失败，日志末尾："; tail -n 50 "$logf" || true
    return 1
  fi
}

########################  路径 & 默认  ########################
SB_DIR=${SB_DIR:-/opt/sing-box}
DATA_DIR="$SB_DIR/data"
TOOLS_DIR="$SB_DIR/tools"
CERT_DIR="$SB_DIR/cert"
CFG="$SB_DIR/config.json"
COMPOSE="$SB_DIR/docker-compose.yml"
IMAGE=${IMAGE:-ghcr.io/sagernet/sing-box:latest}
CONTAINER_NAME=${CONTAINER_NAME:-sing-box}

REALITY_SNI=${REALITY_SNI:-www.microsoft.com}
GRPC_SERVICE=${GRPC_SERVICE:-grpc}
WS_PATH=${WS_PATH:-/vm}

OKICON="${C_GREEN}✔${C_RESET}"; NOICON="${C_RED}✘${C_RESET}"; WAITICON="${C_YELLOW}…${C_RESET}"

########################  工具函数  ########################
need_root(){ [[ $EUID -eq 0 ]] || { err "请用 root 运行"; exit 1; }; }

status_bar(){
  local docker_stat bbr_stat sbox_stat raw cc qd
  if command -v docker >/dev/null 2>&1; then
    if systemctl is-active --quiet docker 2>/dev/null || pgrep -x dockerd >/dev/null; then
      docker_stat="${OKICON} 运行中"; else docker_stat="${NOICON} 未运行"; fi
  else docker_stat="${NOICON} 未安装"; fi
  cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "未知")
  qd=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "未知")
  if [[ "$cc" == "bbr" ]]; then bbr_stat="${OKICON} 已启用（bbr）"; else bbr_stat="${NOICON} 未启用（当前：${cc}，队列：${qd}）"; fi
  if command -v docker >/dev/null 2>&1; then raw=$(docker inspect -f '{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo "none"); else raw="none"; fi
  case "$raw" in
    running) sbox_stat="${OKICON} 运行中";;
    exited)  sbox_stat="${NOICON} 已停止";;
    created) sbox_stat="${NOICON} 未启动";;
    restarting) sbox_stat="${WAITICON} 重启中";;
    paused)  sbox_stat="${NOICON} 已暂停";;
    none|*)  sbox_stat="${NOICON} 未部署";;
  esac
  echo -e "${C_DIM}系统状态：${C_RESET} Docker：${docker_stat}    BBR：${bbr_stat}    Sing-Box：${sbox_stat}"
}

# 端口生成：五位数且互不重复
_rand5(){ awk 'BEGIN{srand();print int(10000+rand()*55536)}'; }
gen_ports(){
  declare -A used=(); local p
  gen_one(){ while :; do p=$(_rand5); [[ -z "${used[$p]:-}" ]] && { used[$p]=1; echo "$p"; return; }; done; }
  P_VLESSR=$(gen_one)
  P_GRPCR=$(gen_one)
  P_TROJANR=$(gen_one)
  P_HY2=$(gen_one)
  P_TUIC=$(gen_one)
  P_VMESS=$(gen_one)
  P_SS=$(gen_one)
}

rand_uuid(){ cat /proc/sys/kernel/random/uuid; }
rand_sid(){ tr -dc a-f0-9 </dev/urandom | head -c 8; echo; }
b64(){ printf "%s" "$1" | openssl base64 -A; }

urlenc(){
  # 主要用于 SNI，无特殊字符时原样返回
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY' "$1"; import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1])); PY "$1"
  else
    printf "%s" "$1"
  fi
}

ensure_dirs(){
  mkdir -p "$SB_DIR" "$DATA_DIR" "$TOOLS_DIR" "$CERT_DIR"
  chmod 700 "$SB_DIR"
}

install_docker(){
  if command -v docker >/dev/null 2>&1; then ok "已安装 Docker"; return 0; fi
  run_with_progress "安装 Docker" 50 -- bash -c '
    set -e
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker >/dev/null 2>&1 || true
  '
  ok "Docker 就绪"
}

pull_image(){
  run_with_progress "拉取 Sing-Box 镜像" 40 -- docker pull "$IMAGE"
}

gen_cert(){
  # 自签证书：供 TUIC 使用；HY2/Reality 不依赖它
  run_with_progress "生成自签证书" 6 -- bash -c '
    mkdir -p "'"$CERT_DIR"'"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -days 3650 -nodes \
      -keyout "'"$CERT_DIR"'/key.pem" \
      -out   "'"$CERT_DIR"'/fullchain.pem" \
      -subj "/CN='"$REALITY_SNI"'" \
      -addext "subjectAltName=DNS:'"$REALITY_SNI"'" >/dev/null 2>&1
  '
}

reality_keypair(){ # echo priv|pub
  local out; out=$(docker run --rm "$IMAGE" generate reality-keypair | tr -d '\r')
  local priv=$(echo "$out" | awk -F': ' '/PrivateKey/{print $2}')
  local pub=$(echo  "$out" | awk -F': ' '/PublicKey/{print $2}')
  echo "$priv|$pub"
}

make_compose(){
  cat >"$COMPOSE" <<YML
services:
  sing-box:
    image: $IMAGE
    container_name: $CONTAINER_NAME
    restart: always
    network_mode: host
    volumes:
      - $CFG:/etc/sing-box/config.json:ro
      - $CERT_DIR:/etc/sing-box/cert:ro
    command: ["sing-box","run","-c","/etc/sing-box/config.json"]
YML
}

########################  配置生成  ########################
generate_config(){
  local IP SNI="$REALITY_SNI"
  IP=$(curl -4s https://ipinfo.io/ip || curl -4s https://api.ip.sb/ip || echo "0.0.0.0")

  gen_ports

  # 凭据
  local UUID VUUID TRPASS HY2PWD HY2OBFS TUICUUID SSPASS SID
  UUID=$(rand_uuid)
  VUUID="$UUID"
  TRPASS="$UUID"
  HY2PWD=$(openssl rand -base64 16)
  HY2OBFS=$(openssl rand -hex 8)
  TUICUUID=$(rand_uuid)
  SSPASS=$(openssl rand -base64 24)
  SID=$(rand_sid)

  # Reality 密钥
  IFS='|' read -r REAL_PRIV REAL_PUB <<<"$(reality_keypair)"

  # JSON（包含：VLESS Reality TCP、VLESS gRPC Reality、Trojan Reality、HY2+obfs、TUIC v5、VMess WS、SS AES-256-GCM）
  cat >"$CFG" <<JSON
{
  "log": { "level": "info" },
  "dns": {
    "servers": [{ "tag": "cf", "address": "1.1.1.1" }],
    "strategy": "prefer_ipv4"
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality",
      "listen": "::",
      "listen_port": $P_VLESSR,
      "users": [ { "uuid": "$VUUID", "flow": "xtls-rprx-vision" } ],
      "tls": {
        "enabled": true,
        "server_name": "$SNI",
        "reality": {
          "enabled": true,
          "handshake": { "server": "$SNI", "server_port": 443 },
          "private_key": "$REAL_PRIV",
          "short_id": [ "$SID" ]
        }
      },
      "transport": { "type": "tcp" }
    },
    {
      "type": "vless",
      "tag": "vless-grpcr",
      "listen": "::",
      "listen_port": $P_GRPCR,
      "users": [ { "uuid": "$UUID" } ],
      "tls": {
        "enabled": true,
        "server_name": "$SNI",
        "reality": {
          "enabled": true,
          "handshake": { "server": "$SNI", "server_port": 443 },
          "private_key": "$REAL_PRIV",
          "short_id": [ "$SID" ]
        }
      },
      "transport": { "type": "grpc", "service_name": "$GRPC_SERVICE" }
    },
    {
      "type": "trojan",
      "tag": "trojan-reality",
      "listen": "::",
      "listen_port": $P_TROJANR,
      "users": [ { "password": "$TRPASS" } ],
      "tls": {
        "enabled": true,
        "server_name": "$SNI",
        "reality": {
          "enabled": true,
          "handshake": { "server": "$SNI", "server_port": 443 },
          "private_key": "$REAL_PRIV",
          "short_id": [ "$SID" ]
        }
      },
      "transport": { "type": "tcp" }
    },
    {
      "type": "hysteria2",
      "tag": "hy2",
      "listen": "::",
      "listen_port": $P_HY2,
      "users": [ { "password": "$HY2PWD" } ],
      "obfs": "salamander",
      "obfs_password": "$HY2OBFS",
      "tls": { "enabled": true, "server_name": "$SNI", "insecure": true }
    },
    {
      "type": "tuic",
      "tag": "tuic",
      "listen": "::",
      "listen_port": $P_TUIC,
      "users": [ { "uuid": "$TUICUUID", "password": "$TUICUUID" } ],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "certificate_path": "/etc/sing-box/cert/fullchain.pem",
        "key_path": "/etc/sing-box/cert/key.pem"
      }
    },
    {
      "type": "vmess",
      "tag": "vmess-ws",
      "listen": "::",
      "listen_port": $P_VMESS,
      "users": [ { "uuid": "$UUID" } ],
      "transport": { "type": "ws", "path": "$WS_PATH" }
    },
    {
      "type": "shadowsocks",
      "tag": "ss-aes256gcm",
      "listen": "::",
      "listen_port": $P_SS,
      "method": "aes-256-gcm",
      "password": "$SSPASS",
      "udp": true
    }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" },
    { "type": "dns",    "tag": "dns" },
    { "type": "block",  "tag": "block" }
  ],
  "route": {
    "auto_detect_interface": true,
    "rules": [ { "protocol": [ "dns" ], "outbound": "dns" } ]
  }
}
JSON

  make_compose

  # 保存“展示用”信息
  cat >"$SB_DIR/last.env" <<ENV
IP=$IP
SNI=$SNI
P_VLESSR=$P_VLESSR
P_GRPCR=$P_GRPCR
P_TROJANR=$P_TROJANR
P_HY2=$P_HY2
P_TUIC=$P_TUIC
P_VMESS=$P_VMESS
P_SS=$P_SS
UUID=$UUID
VUUID=$VUUID
TRPASS=$TRPASS
HY2PWD=$HY2PWD
HY2OBFS=$HY2OBFS
TUICUUID=$TUICUUID
SSPASS=$SSPASS
REAL_PUB=$REAL_PUB
SID=$SID
GRPC_SERVICE=$GRPC_SERVICE
WS_PATH=$WS_PATH
ENV
}

########################  分享链接 & 账号参数  ########################
print_params(){
  . "$SB_DIR/last.env"
  sec "账号参数（便于手动填写）"
  local pad="%-20s %s\n"
  echo "📌 节点1（VLESS Reality / TCP）"
  printf "$pad" "  Address (地址)" "$IP"
  printf "$pad" "  Port (端口)" "$P_VLESSR"
  printf "$pad" "  UUID (用户ID)" "$VUUID"
  printf "$pad" "  flow (流控)" "xtls-rprx-vision"
  printf "$pad" "  encryption (加密)" "none"
  printf "$pad" "  network (传输)" "tcp"
  printf "$pad" "  headerType (伪装型)" "none"
  printf "$pad" "  TLS (传输层安全)" "reality"
  printf "$pad" "  SNI (serverName)" "$SNI"
  printf "$pad" "  Fingerprint (指纹)" "chrome"
  printf "$pad" "  Public key (公钥)" "$REAL_PUB"
  printf "$pad" "  ShortId" "$SID"
  hr

  echo "📌 节点2（VLESS Reality / gRPC）"
  printf "$pad" "  Address (地址)" "$IP"
  printf "$pad" "  Port (端口)" "$P_GRPCR"
  printf "$pad" "  UUID (用户ID)" "$UUID"
  printf "$pad" "  network (传输)" "grpc"
  printf "$pad" "  ServiceName" "$GRPC_SERVICE"
  printf "$pad" "  TLS (传输层安全)" "reality"
  printf "$pad" "  SNI (serverName)" "$SNI"
  printf "$pad" "  Fingerprint (指纹)" "chrome"
  printf "$pad" "  Public key (公钥)" "$REAL_PUB"
  printf "$pad" "  ShortId" "$SID"
  hr

  echo "📌 节点3（Trojan Reality / TCP）"
  printf "$pad" "  Address (地址)" "$IP"
  printf "$pad" "  Port (端口)" "$P_TROJANR"
  printf "$pad" "  Password (密码)" "$TRPASS"
  printf "$pad" "  TLS (传输层安全)" "reality"
  printf "$pad" "  SNI (serverName)" "$SNI"
  printf "$pad" "  Fingerprint (指纹)" "chrome"
  printf "$pad" "  Public key (公钥)" "$REAL_PUB"
  printf "$pad" "  ShortId" "$SID"
  hr

  echo "📌 节点4（Hysteria2 / UDP + 混淆）"
  printf "$pad" "  Address (地址)" "$IP"
  printf "$pad" "  Port (端口)" "$P_HY2"
  printf "$pad" "  Password (密码)" "$HY2PWD"
  printf "$pad" "  Obfs (混淆)" "salamander"
  printf "$pad" "  Obfs-Password" "$HY2OBFS"
  printf "$pad" "  TLS" "tls（跳过证书：true）"
  printf "$pad" "  SNI (serverName)" "$SNI"
  hr

  echo "📌 节点5（TUIC v5 / UDP）"
  printf "$pad" "  Address (地址)" "$IP"
  printf "$pad" "  Port (端口)" "$P_TUIC"
  printf "$pad" "  UUID" "$TUICUUID"
  printf "$pad" "  Password" "$TUICUUID"
  printf "$pad" "  congestion_control" "bbr"
  printf "$pad" "  ALPN" "h3"
  printf "$pad" "  TLS证书" "自签（已内置）"
  printf "$pad" "  客户端建议" "allowInsecure=true"
  hr

  echo "📌 节点6（VMess / WS）"
  printf "$pad" "  Address (地址)" "$IP"
  printf "$pad" "  Port (端口)" "$P_VMESS"
  printf "$pad" "  UUID (用户ID)" "$UUID"
  printf "$pad" "  Network" "ws"
  printf "$pad" "  Path" "$WS_PATH"
  hr

  echo "📌 节点7（Shadowsocks / AES-256-GCM / TCP+UDP）"
  printf "$pad" "  Address (地址)" "$IP"
  printf "$pad" "  Port (端口)" "$P_SS"
  printf "$pad" "  Method" "aes-256-gcm"
  printf "$pad" "  Password (密码)" "$SSPASS"
  hr
}

share_links(){
  . "$SB_DIR/last.env"
  sec "分享链接（可导入 v2rayN 等）"
  # vless reality tcp
  echo "  vless://$VUUID@$IP:$P_VLESSR?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$(urlenc "$SNI")&fp=chrome&pbk=$REAL_PUB&sid=$SID&type=tcp#vless-reality"
  # vless grpc reality
  echo "  vless://$UUID@$IP:$P_GRPCR?encryption=none&security=reality&sni=$(urlenc "$SNI")&fp=chrome&pbk=$REAL_PUB&sid=$SID&type=grpc&serviceName=$GRPC_SERVICE#vless-grpc-reality"
  # trojan reality
  echo "  trojan://$TRPASS@$IP:$P_TROJANR?security=reality&sni=$(urlenc "$SNI")&fp=chrome&pbk=$REAL_PUB&sid=$SID&type=tcp#trojan-reality"
  # hy2（密码 base64）
  local HY2_B64; HY2_B64=$(b64 "$HY2PWD")
  echo "  hy2://$HY2_B64@$IP:$P_HY2?insecure=1&sni=$(urlenc "$SNI")&obfs=salamander&obfs-password=$(urlenc "$HY2OBFS")#hysteria2"
  # tuic v5
  echo "  tuic://$TUICUUID:$TUICUUID@$IP:$P_TUIC?congestion_control=bbr&alpn=h3&sni=$(urlenc "$SNI")&allow_insecure=1#tuic-v5"
  # vmess ws
  local VMESS_JSON VMESS_B64
  VMESS_JSON=$(cat <<VJ
{"v":"2","ps":"vmess-ws","add":"$IP","port":"$P_VMESS","id":"$UUID","aid":"0","net":"ws","type":"none","host":"","path":"$WS_PATH","tls":""}
VJ
)
  VMESS_B64=$(echo -n "$VMESS_JSON" | openssl base64 -A)
  echo "  vmess://$VMESS_B64"
  # ss aes-256-gcm
  local SS_HDR SS_TAG
  SS_HDR=$(b64 "aes-256-gcm:$SSPASS")
  SS_TAG="#ss-aes256gcm"
  echo "  ss://$SS_HDR@$IP:$P_SS$SS_TAG"
}

########################  核心动作  ########################
deploy(){
  ensure_dirs
  install_docker
  pull_image
  gen_cert
  run_with_progress "生成配置文件" 5 -- bash -c 'true'  # 视觉进度
  generate_config
  run_with_progress "启动容器" 12 -- docker compose -f "$COMPOSE" up -d
  ok "部署完成！配置目录：$SB_DIR"
}

show_status_and_links_then_exit(){
  if ! docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
    warn "容器未部署"; return 1
  fi
  . "$SB_DIR/last.env"
  sec "已启用协议与端口"
  echo "  - VLESS Reality (TCP):      $P_VLESSR"
  echo "  - VLESS gRPC Reality (TCP): $P_GRPCR  service: $GRPC_SERVICE"
  echo "  - Trojan Reality (TCP):     $P_TROJANR"
  echo "  - Hysteria2 (UDP):          $P_HY2   obfs: salamander"
  echo "  - TUIC v5 (UDP):            $P_TUIC"
  echo "  - VMess WS (TCP):           $P_VMESS   path: $WS_PATH"
  echo "  - Shadowsocks AES-256-GCM (TCP/UDP): $P_SS"
  print_params
  share_links
}

restart_container(){ run_with_progress "重启容器" 6 -- docker restart "$CONTAINER_NAME"; ok "已重启"; }

update_image(){ pull_image; ok "镜像已检查（如有新版本已拉取）。"; }

self_update(){
  local URL="https://raw.githubusercontent.com/Alvin9999/Sing-Box-Plus/main/sing-box-plus.sh"
  local TMP; TMP=$(mktemp)
  run_with_progress "下载最新脚本" 6 -- curl -fsSL -o "$TMP" "$URL"
  if cmp -s "$TMP" "$0"; then ok "已是最新版"; else
    install -m 0755 "$TMP" "$0"; ok "脚本已更新，重新运行生效。"
  fi
}

enable_bbr(){
  run_with_progress "启用 BBR" 4 -- bash -c '
    set -e
    sysctl -w net.core.default_qdisc=fq >/dev/null
    sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null
    grep -q "net.core.default_qdisc" /etc/sysctl.conf || echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    grep -q "net.ipv4.tcp_congestion_control" /etc/sysctl.conf || echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
  '
  ok "BBR（原版）已启用。"
}

reassign_ports(){
  if ! docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; then warn "容器未部署"; return 1; fi
  info "将生成新的随机端口并重建配置..."
  generate_config
  run_with_progress "应用新端口并重启" 8 -- docker compose -f "$COMPOSE" up -d
  ok "端口已更新。"
  show_status_and_links_then_exit
  exit 0
}

uninstall_all(){
  if docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; then docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true; fi
  rm -rf "$SB_DIR"
  ok "已卸载并删除配置目录 $SB_DIR"
}

########################  菜单  ########################
menu(){
  title
  echo -e "${C_BOLD}================  管 理 菜 单  ================${C_RESET}"
  echo "  1) 安装 Sing-Box"
  echo "  2) 查看状态 & 分享链接"
  echo "  3) 重启容器"
  echo "  4) 更新 Sing-Box Docker 镜像"
  echo "  5) 更新脚本"
  echo "  6) 一键更换所有端口（五位随机且互不重复）"
  echo "  7) 一键开启 BBR 加速"
  echo "  8) 卸载"
  echo "  0) 退出"
  echo -e "==============================================="
  status_bar
  echo
  read "${READ_OPTS[@]}" -p "选择操作（回车退出）： " opt || true
  [[ -z "${opt:-}" ]] && exit 0
  case "$opt" in
    1) deploy ;;
    2) show_status_and_links_then_exit; exit 0 ;;
    3) restart_container ;;
    4) update_image ;;
    5) self_update ;;
    6) reassign_ports ;;
    7) enable_bbr ;;
    8) uninstall_all ;;
    0) exit 0 ;;
    *) warn "无效选项" ;;
  esac
  echo; read -p "回车返回菜单..." _ || true
  menu
}

########################  入口  ########################
need_root
fix_tty
menu
