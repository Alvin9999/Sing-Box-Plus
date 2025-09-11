#!/usr/bin/env bash
# -------------------------------------------------------
# Sing-Box Docker Manager (Reality + HY2/Obfs + TUIC v5 + VMess WS)
# Author: Alvin9999
# OS: Debian / Ubuntu / CentOS / RHEL / Rocky / Alma
# Version:
SCRIPT_NAME="Sing-Box Docker Manager"
SCRIPT_VERSION="v1.6.6"
# -------------------------------------------------------
set -euo pipefail

########################  颜色  ########################
: "${C_RESET:=\033[0m}" ; : "${C_BOLD:=\033[1m}" ; : "${C_DIM:=\033[2m}"
: "${C_RED:=\033[31m}"  ; : "${C_GREEN:=\033[32m}" ; : "${C_YELLOW:=\033[33m}"
: "${C_BLUE:=\033[34m}" ; : "${C_CYAN:=\033[36m}"

READ_OPTS=(-e -r)
hr(){ printf "${C_DIM}===============================================${C_RESET}\n"; }
ok(){  echo -e "${C_GREEN}[信息]${C_RESET} $*"; }
warn(){echo -e "${C_YELLOW}[警告]${C_RESET} $*"; }
err(){ echo -e "${C_RED}[错误]${C_RESET} $*"; }

########################  变量与默认  ########################
SB_DIR=${SB_DIR:-/opt/sing-box}
DATA_DIR="$SB_DIR/data"
TOOLS_DIR="$SB_DIR/tools"
CERT_DIR="$SB_DIR/cert"
IMAGE=${IMAGE:-ghcr.io/sagernet/sing-box:latest}
CONTAINER_NAME=${CONTAINER_NAME:-sing-box}
REALITY_SNI=${REALITY_SNI:-www.microsoft.com}
GRPC_SERVICE=${GRPC_SERVICE:-grpc}
VMESS_WS_PATH=${VMESS_WS_PATH:-/vm}
HY2_OBFS=${HY2_OBFS:-true}      # 是否开启 salamander 混淆
HY2_ALPN=${HY2_ALPN:-h3}
TUIC_ALPN=${TUIC_ALPN:-h3}

IPV4_ADDR="$(curl -fsSL -4 ip.sb 2>/dev/null || hostname -I | awk '{print $1}')"

mkdir -p "$DATA_DIR" "$TOOLS_DIR" "$CERT_DIR"
chmod 700 "$SB_DIR"

########################  小工具  ########################
rand_port(){
  # 10000-65535
  shuf -i 10000-65535 -n 1
}
ensure_unique_ports(){
  # 传入一组变量名，保证互不重复
  local -a names=("$@")
  local used="" v
  for n in "${names[@]}"; do
    while :; do
      v="${!n}"
      [[ -n "$v" ]] || v=$(rand_port)
      if [[ ! "$used" =~ (^|,)"$v"(,|$) ]]; then
        eval "$n=$v"
        used="${used:+$used,}$v"
        break
      fi
      v=
    done
  done
}

uuid(){ cat /proc/sys/kernel/random/uuid; }
rand_sid(){ hexdump -vn8 -e '8/1 "%02x"' /dev/urandom; }
rand_str(){ tr -dc 'A-Za-z0-9' </dev/urandom | head -c ${1:-24}; }

# URL 编码（纯 bash）
urlenc() {
  local s="$1" out="" c i
  local LC_ALL_BACKUP=${LC_ALL-}; local LC_CTYPE_BACKUP=${LC_CTYPE-}
  export LC_ALL=C LC_CTYPE=C
  for ((i=0; i<${#s}; i++)); do
    c="${s:i:1}"
    case "$c" in
      [a-zA-Z0-9.~_-]) out+="$c" ;;
      *) printf -v out '%s%%%02X' "$out" "'$c" ;;
    esac
  done
  [[ -n "${LC_ALL_BACKUP-}"  ]] && export LC_ALL="$LC_ALL_BACKUP"  || unset LC_ALL
  [[ -n "${LC_CTYPE_BACKUP-}" ]] && export LC_CTYPE="$LC_CTYPE_BACKUP" || unset LC_CTYPE
  printf '%s' "$out"
}
b64(){ printf '%s' "$1" | base64 -w0; }

########################  UI  ########################
title() {
  clear
  echo -e "${C_CYAN}${C_BOLD}Sing-Box 管理脚本  ${SCRIPT_VERSION}${C_RESET}  ${C_DIM}✎${C_RESET}"
  echo -e "脚本更新地址：${C_GREEN}https://github.com/Alvin9999/Sing-Box-Plus${C_RESET}"
  hr
}
status_bar() {
  local OK="${C_GREEN}✔${C_RESET}" NO="${C_RED}✘${C_RESET}" WAIT="${C_YELLOW}…${C_RESET}"
  local docker_stat=" ${NO} 未安装" bbr_stat=" ${NO} 未启用" sbox_stat=" ${NO} 未部署"
  if command -v docker >/dev/null 2>&1; then
    if systemctl is-active --quiet docker 2>/dev/null || pgrep -x dockerd >/dev/null; then
      docker_stat=" ${OK} 运行中"
    else docker_stat=" ${NO} 未运行"; fi
  fi
  local cc qd; cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)
  qd=$(sysctl -n net.core.default_qdisc 2>/dev/null || true)
  if [[ "${cc:-}" == "bbr" ]]; then bbr_stat=" ${OK} 已启用（bbr）"
  else bbr_stat=" ${NO} 未启用${C_DIM}（当前: ${cc:-未知} / 队列: ${qd:-未知}）${C_RESET}"; fi
  local raw="none"
  if command -v docker >/dev/null 2>&1; then
    raw="$(docker inspect -f '{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo none)"
  fi
  case "$raw" in
    running) sbox_stat=" ${OK} 运行中" ;;
    exited)  sbox_stat=" ${NO} 已停止" ;;
    created) sbox_stat=" ${NO} 未启动" ;;
    restarting) sbox_stat=" ${WAIT} 重启中" ;;
    paused)  sbox_stat=" ${NO} 已暂停" ;;
    none|*)  sbox_stat=" ${NO} 未部署" ;;
  esac
  echo
  echo -e "系统加速状态： ${bbr_stat}"
  echo -e "Sing-Box 当前状态： ${sbox_stat}"
  hr
}
show_result(){
  echo
  echo -e "${C_BOLD}${C_GREEN}【完成】${C_RESET} $1"
  [[ -n "${2-}" ]] && echo -e "${C_DIM}$2${C_RESET}"
  hr
}

########################  系统/依赖  ########################
need_root(){ [[ $EUID -eq 0 ]] || { err "请用 root 运行"; exit 1; }; }
detect_pm(){
  if command -v apt-get >/dev/null 2>&1; then echo apt
  elif command -v dnf >/dev/null 2>&1; then echo dnf
  elif command -v yum >/dev/null 2>&1; then echo yum
  else echo unknown; fi
}
pkg_install(){
  local pm; pm=$(detect_pm)
  case "$pm" in
    apt) apt-get update -y >/dev/null; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null ;;
    dnf) dnf install -y -q "$@" >/dev/null ;;
    yum) yum install -y -q "$@" >/dev/null ;;
    *) err "无法识别的包管理器"; exit 1 ;;
  esac
}
install_docker(){
  if ! command -v docker >/dev/null 2>&1; then
    ok "安装 Docker ..."
    curl -fsSL https://get.docker.com | sh >/dev/null
    systemctl enable --now docker >/dev/null 2>&1 || true
  else
    ok "已安装 Docker"
  fi
  command -v jq >/dev/null 2>&1 || pkg_install jq
  command -v openssl >/dev/null 2>&1 || pkg_install openssl
  command -v ss >/dev/null 2>&1 || pkg_install iproute2
  command -v curl >/dev/null 2>&1 || pkg_install curl
}

########################  凭据与端口  ########################
randomize_ports(){
  PORT_VLESS_R=${PORT_VLESS_R:-}
  PORT_VLESS_GRPCR=${PORT_VLESS_GRPCR:-}
  PORT_TROJAN_R=${PORT_TROJAN_R:-}
  PORT_HY2=${PORT_HY2:-}
  PORT_TUIC=${PORT_TUIC:-}
  PORT_VMESS_WS=${PORT_VMESS_WS:-}
  ensure_unique_ports PORT_VLESS_R PORT_VLESS_GRPCR PORT_TROJAN_R PORT_HY2 PORT_TUIC PORT_VMESS_WS
  cat > "$SB_DIR/ports.env" <<EOF
PORT_VLESS_R=$PORT_VLESS_R
PORT_VLESS_GRPCR=$PORT_VLESS_GRPCR
PORT_TROJAN_R=$PORT_TROJAN_R
PORT_HY2=$PORT_HY2
PORT_TUIC=$PORT_TUIC
PORT_VMESS_WS=$PORT_VMESS_WS
EOF
}
load_ports(){ [ -f "$SB_DIR/ports.env" ] && source "$SB_DIR/ports.env" || randomize_ports; }

gen_reality_keys(){
  if [ ! -f "$SB_DIR/reality.json" ]; then
    docker run --rm "$IMAGE" generate reality-keypair > "$SB_DIR/reality.json"
  fi
  REAL_PRIV=$(jq -r '.PrivateKey' "$SB_DIR/reality.json")
  REAL_PUB=$(jq -r '.PublicKey' "$SB_DIR/reality.json")
  SHORT_ID=${SHORT_ID:-$(rand_sid)}
}

gen_cert(){
  if [ ! -f "$CERT_DIR/fullchain.pem" ] || [ ! -f "$CERT_DIR/key.pem" ]; then
    ok "生成自签证书 ..."
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -days 3650 -nodes \
      -keyout "$CERT_DIR/key.pem" \
      -out   "$CERT_DIR/fullchain.pem" \
      -subj "/CN=$REALITY_SNI" \
      -addext "subjectAltName=DNS:$REALITY_SNI" >/dev/null 2>&1
    chmod 600 "$CERT_DIR/key.pem"
  fi
}

########################  生成配置  ########################
write_config(){
  load_ports
  gen_reality_keys
  gen_cert

  UUID=${UUID:-$(uuid)}
  HY2_PASS=${HY2_PASS:-$(rand_str 20)}
  TUIC_ID=${TUIC_ID:-$(uuid)}  # tuic: uuid == password
  TUIC_PASS="$TUIC_ID"
  OBFS_PASS=${OBFS_PASS:-$(rand_str 16)}

  cat > "$SB_DIR/config.json" <<JSON
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality",
      "listen": "::",
      "listen_port": $PORT_VLESS_R,
      "users": [{ "uuid": "$UUID", "flow": "xtls-rprx-vision" }],
      "tls": {
        "enabled": true,
        "server_name": "$REALITY_SNI",
        "reality": {
          "enabled": true,
          "handshake": { "server": "$REALITY_SNI", "server_port": 443 },
          "private_key": "$REAL_PRIV",
          "short_id": [ "$SHORT_ID" ]
        }
      }
    },
    {
      "type": "vless",
      "tag": "vless-grpc-reality",
      "listen": "::",
      "listen_port": $PORT_VLESS_GRPCR,
      "users": [{ "uuid": "$UUID" }],
      "transport": { "type": "grpc", "service_name": "$GRPC_SERVICE" },
      "tls": {
        "enabled": true,
        "server_name": "$REALITY_SNI",
        "reality": {
          "enabled": true,
          "handshake": { "server": "$REALITY_SNI", "server_port": 443 },
          "private_key": "$REAL_PRIV",
          "short_id": [ "$SHORT_ID" ]
        }
      }
    },
    {
      "type": "trojan",
      "tag": "trojan-reality",
      "listen": "::",
      "listen_port": $PORT_TROJAN_R,
      "users": [{ "password": "$UUID" }],
      "tls": {
        "enabled": true,
        "server_name": "$REALITY_SNI",
        "reality": {
          "enabled": true,
          "handshake": { "server": "$REALITY_SNI", "server_port": 443 },
          "private_key": "$REAL_PRIV",
          "short_id": [ "$SHORT_ID" ]
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "hy2",
      "listen": "::",
      "listen_port": $PORT_HY2,
      "users": [{ "password": "$HY2_PASS" }],
      "tls": {
        "enabled": true,
        "server_name": "$REALITY_SNI",
        "certificate_path": "/etc/sing-box/cert/fullchain.pem",
        "key_path": "/etc/sing-box/cert/key.pem"
      }$( [[ "$HY2_OBFS" == "true" ]] && printf ',\n      "obfs": { "type": "salamander", "password": "%s" }' "$OBFS_PASS" )
    },
    {
      "type": "tuic",
      "tag": "tuic",
      "listen": "::",
      "listen_port": $PORT_TUIC,
      "users": [{ "uuid": "$TUIC_ID", "password": "$TUIC_PASS" }],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "alpn": [ "$TUIC_ALPN" ],
        "certificate_path": "/etc/sing-box/cert/fullchain.pem",
        "key_path": "/etc/sing-box/cert/key.pem"
      }
    },
    {
      "type": "vmess",
      "tag": "vmess-ws",
      "listen": "::",
      "listen_port": $PORT_VMESS_WS,
      "users": [{ "uuid": "$UUID" }],
      "transport": { "type": "ws", "path": "$VMESS_WS_PATH" }
    }
  ]
}
JSON

  # 保存账号元信息供展示
  cat > "$SB_DIR/account.env" <<EOF
IPV4=$IPV4_ADDR
UUID=$UUID
REAL_PUB=$REAL_PUB
SHORT_ID=$SHORT_ID
HY2_PASS=$HY2_PASS
OBFS_PASS=$OBFS_PASS
TUIC_ID=$TUIC_ID
TUIC_PASS=$TUIC_PASS
EOF
}

########################  Docker 启动/更新  ########################
docker_run(){
  load_ports
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  docker run -d --name "$CONTAINER_NAME" --restart=always \
    -v "$SB_DIR/config.json":/etc/sing-box/config.json:ro \
    -v "$CERT_DIR":/etc/sing-box/cert:ro \
    -p "$PORT_VLESS_R:$PORT_VLESS_R/tcp" \
    -p "$PORT_VLESS_GRPCR:$PORT_VLESS_GRPCR/tcp" \
    -p "$PORT_TROJAN_R:$PORT_TROJAN_R/tcp" \
    -p "$PORT_HY2:$PORT_HY2/udp" \
    -p "$PORT_TUIC:$PORT_TUIC/udp" \
    -p "$PORT_VMESS_WS:$PORT_VMESS_WS/tcp" \
    "$IMAGE" -c /etc/sing-box/config.json >/dev/null
}

########################  显示与链接  ########################
pad(){ printf "%-18s" "$1"; }

show_params(){
  source "$SB_DIR/ports.env"
  source "$SB_DIR/account.env"

  echo -e "${C_BOLD}已启用协议与端口${C_RESET}"
  hr
  echo "  - VLESS Reality (TCP):      $PORT_VLESS_R"
  echo "  - VLESS gRPC Reality (TCP): $PORT_VLESS_GRPCR  service: $GRPC_SERVICE"
  echo "  - Trojan Reality (TCP):     $PORT_TROJAN_R"
  echo "  - Hysteria2 (UDP):          $PORT_HY2"
  echo "  - TUIC v5 (UDP):            $PORT_TUIC"
  echo "  - VMess WS (TCP):           $PORT_VMESS_WS   路径: $VMESS_WS_PATH"
  hr

  echo -e "${C_BOLD}账号参数（手动填写用）${C_RESET}"
  hr

  # 节点1：VLESS Reality / TCP
  echo "📌 节点1（VLESS Reality / TCP）"
  pad "  Address (地址)";       echo " $IPV4"
  pad "  Port (端口)";          echo " $PORT_VLESS_R"
  pad "  UUID (用户ID)";        echo " $UUID"
  pad "  flow (流控)";          echo " xtls-rprx-vision"
  pad "  encryption (加密)";    echo " none"
  pad "  network (传输)";       echo " tcp"
  pad "  headerType (伪装型)";  echo " none"
  pad "  TLS (传输层安全)";     echo " reality"
  pad "  SNI (serverName)";     echo " $REALITY_SNI"
  pad "  Fingerprint (指纹)";   echo " chrome"
  pad "  Public key (公钥)";    echo " $REAL_PUB"
  pad "  ShortId";              echo " $SHORT_ID"
  hr

  # 节点2：VLESS Reality / gRPC
  echo "📌 节点2（VLESS Reality / gRPC）"
  pad "  Address (地址)";       echo " $IPV4"
  pad "  Port (端口)";          echo " $PORT_VLESS_GRPCR"
  pad "  UUID (用户ID)";        echo " $UUID"
  pad "  encryption (加密)";    echo " none"
  pad "  network (传输)";       echo " grpc"
  pad "  ServiceName";          echo " $GRPC_SERVICE"
  pad "  TLS (传输层安全)";     echo " reality"
  pad "  SNI (serverName)";     echo " $REALITY_SNI"
  pad "  Fingerprint (指纹)";   echo " chrome"
  pad "  Public key (公钥)";    echo " $REAL_PUB"
  pad "  ShortId";              echo " $SHORT_ID"
  hr

  # 节点3：Trojan Reality / TCP
  echo "📌 节点3（Trojan Reality / TCP）"
  pad "  Address (地址)";       echo " $IPV4"
  pad "  Port (端口)";          echo " $PORT_TROJAN_R"
  pad "  Password (密码)";      echo " $UUID"
  pad "  TLS (传输层安全)";     echo " reality"
  pad "  SNI (serverName)";     echo " $REALITY_SNI"
  pad "  Fingerprint (指纹)";   echo " chrome"
  pad "  Public key (公钥)";    echo " $REAL_PUB"
  pad "  ShortId";              echo " $SHORT_ID"
  hr

  # 节点4：Hysteria2
  echo "📌 节点4（Hysteria2）"
  pad "  Address (地址)";       echo " $IPV4"
  pad "  Port (端口)";          echo " $PORT_HY2"
  pad "  Password (密码)";      echo " $HY2_PASS"
  pad "  TLS";                  echo " tls"
  pad "  SNI (serverName)";     echo " $REALITY_SNI"
  pad "  Alpn";                 echo " $HY2_ALPN"
  if [[ "$HY2_OBFS" == "true" ]]; then
    pad "  Obfs";               echo " salamander"
    pad "  Obfs-Password";      echo " $OBFS_PASS"
  fi
  pad "  AllowInsecure";        echo " true"
  hr

  # 节点5：TUIC v5
  echo "📌 节点5（Tuic-v5）"
  pad "  Address (地址)";       echo " $IPV4"
  pad "  Port (端口)";          echo " $PORT_TUIC"
  pad "  UUID (用户ID)";        echo " $TUIC_ID"
  pad "  Password (密码)";      echo " $TUIC_PASS"
  pad "  congestion_control";   echo " bbr"
  pad "  Alpn";                 echo " $TUIC_ALPN"
  pad "  SNI (serverName)";     echo " $REALITY_SNI"
  pad "  AllowInsecure";        echo " true"
  hr

  # 节点6：VMess WS
  echo "📌 节点6（VMess / WS）"
  pad "  Address (地址)";       echo " $IPV4"
  pad "  Port (端口)";          echo " $PORT_VMESS_WS"
  pad "  UUID (用户ID)";        echo " $UUID"
  pad "  network (传输)";       echo " ws"
  pad "  path (路径)";          echo " $VMESS_WS_PATH"
  pad "  TLS";                  echo " none"
  hr
}

share_links(){
  source "$SB_DIR/ports.env"
  source "$SB_DIR/account.env"
  local sni_enc; sni_enc=$(urlenc "$REALITY_SNI")
  local pbk_enc; pbk_enc=$(urlenc "$REAL_PUB")
  local sid_enc; sid_enc=$(urlenc "$SHORT_ID")

  echo -e "${C_BOLD}分享链接（可导入 v2rayN）${C_RESET}"
  hr

  echo "  vless://$UUID@$IPV4:$PORT_VLESS_R?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$sni_enc&fp=chrome&pbk=$pbk_enc&sid=$sid_enc&type=tcp#vless-reality"
  echo "  vless://$UUID@$IPV4:$PORT_VLESS_GRPCR?encryption=none&security=reality&sni=$sni_enc&fp=chrome&pbk=$pbk_enc&sid=$sid_enc&type=grpc&serviceName=$(urlenc "$GRPC_SERVICE")#vless-grpc-reality"
  echo "  trojan://$UUID@$IPV4:$PORT_TROJAN_R?security=reality&sni=$sni_enc&fp=chrome&pbk=$pbk_enc&sid=$sid_enc&type=tcp#trojan-reality"

  local hy2_q="insecure=1&sni=$sni_enc"
  if [[ "$HY2_OBFS" == "true" ]]; then
    hy2_q="$hy2_q&obfs=salamander&obfs-password=$(urlenc "$OBFS_PASS")"
  fi
  echo "  hy2://$(urlenc "$HY2_PASS")@$IPV4:$PORT_HY2?$hy2_q#hysteria2"

  echo "  tuic://$TUIC_ID:$TUIC_PASS@$IPV4:$PORT_TUIC?congestion_control=bbr&alpn=$(urlenc "$TUIC_ALPN")&sni=$sni_enc&allow_insecure=1#tuic-v5"

  local vm_json="{\"v\":\"2\",\"ps\":\"vmess-ws\",\"add\":\"$IPV4\",\"port\":\"$PORT_VMESS_WS\",\"id\":\"$UUID\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"\",\"path\":\"$VMESS_WS_PATH\",\"tls\":\"\"}"
  echo "  vmess://$(printf '%s' "$vm_json" | base64 -w0)"
}

########################  功能动作  ########################
deploy(){
  install_docker
  write_config
  docker_run
  show_result "部署完成！"
  show_status_and_links_then_exit
  exit 0
}
restart_container(){
  docker restart "$CONTAINER_NAME" >/dev/null 2>&1 || err "容器未安装"
}
update_image(){
  install_docker
  local old new
  old=$(docker inspect --format='{{.Image}}' "$CONTAINER_NAME" 2>/dev/null || echo "")
  docker pull "$IMAGE" >/dev/null
  new=$(docker image inspect "$IMAGE" --format='{{.Id}}' 2>/dev/null || echo "")
  if [[ -n "$old" && -n "$new" && "$old" != "$new" ]]; then
    docker_run
    ok "已更新为最新镜像并重启。"
  else
    ok "已是最新镜像。"
  fi
}
self_update(){
  local url="https://raw.githubusercontent.com/Alvin9999/Sing-Box-Plus/main/sing-box-plus.sh"
  curl -fsSL -o "$TOOLS_DIR/sing-box-plus.new" "$url"
  if ! cmp -s "$0" "$TOOLS_DIR/sing-box-plus.new"; then
    mv "$TOOLS_DIR/sing-box-plus.new" "$0"
    chmod +x "$0"
    ok "脚本已更新。请重新运行。"
  else
    rm -f "$TOOLS_DIR/sing-box-plus.new"
    ok "脚本已是最新版。"
  fi
}
reassign_ports(){
  randomize_ports
  write_config
  docker_run
}
enable_bbr(){
  sysctl -w net.core.default_qdisc=fq >/dev/null
  sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null
  cat >/etc/sysctl.d/99-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  sysctl --system >/dev/null
}
uninstall_all(){
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  rm -rf "$SB_DIR"
}

show_status_and_links_then_exit(){
  echo
  echo -e "${C_BOLD}配置目录: ${C_RESET}$SB_DIR"
  echo -e "${C_BOLD}服务器IP: ${C_RESET}$IPV4_ADDR"
  echo
  show_params
  share_links
}

########################  主菜单  ########################
menu() {
  while true; do
    title
    echo -e "${C_BOLD}================  管 理 菜 单  ================${C_RESET}"
    echo -e "  ${C_GREEN}1)${C_RESET} 安装 Sing-Box"
    echo -e "  ${C_GREEN}2)${C_RESET} 查看状态 & 分享链接"
    echo -e "  ${C_GREEN}3)${C_RESET} 重启容器"
    echo -e "  ${C_GREEN}4)${C_RESET} 更新 Sing-Box Docker 镜像"
    echo -e "  ${C_GREEN}5)${C_RESET} 更新脚本"
    echo -e "  ${C_GREEN}6)${C_RESET} 一键更换所有端口（五位随机且互不重复）"
    echo -e "  ${C_GREEN}7)${C_RESET} 一键开启 BBR 加速"
    echo -e "  ${C_GREEN}8)${C_RESET} 卸载"
    echo -e "  ${C_GREEN}0)${C_RESET} 退出"
    hr
    status_bar
    echo
    read "${READ_OPTS[@]}" -p "请输入选项 [0-8]： " opt || true
    [[ -z "${opt:-}" ]] && exit 0
    case "$opt" in
      1) deploy ; exit 0 ;;
      2) show_status_and_links_then_exit ; exit 0 ;;
      3) restart_container ; show_result "容器重启完成" ; read -p "按回车返回菜单..." _ || true ;;
      4) update_image ; show_result "镜像更新检查完成" ; read -p "按回车返回菜单..." _ || true ;;
      5) self_update ; read -p "按回车返回菜单..." _ || true ;;
      6) reassign_ports ; show_result "端口已全部更换" "请到“查看状态 & 分享链接”获取最新链接。" ; read -p "按回车返回菜单..." _ || true ;;
      7) enable_bbr ; show_result "BBR 启用流程已执行" ; read -p "按回车返回菜单..." _ || true ;;
      8) uninstall_all ; show_result "卸载完成" ; read -p "按回车返回菜单..." _ || true ;;
      0) exit 0 ;;
      *) echo -e "${C_YELLOW}无效选项${C_RESET}" ; sleep 1 ;;
    esac
  done
}

########################  入口  ########################
need_root
menu
