#!/usr/bin/env bash
# sing-box-docker.sh
# 一键部署 sing-box (Docker) - 多协议无证书版 + 端口随机不重复（五位数）
# Author: you + chatgpt
set -euo pipefail

############################
# 可配置开关（默认值）
############################
ENABLE_VLESS_REALITY=${ENABLE_VLESS_REALITY:-true}
ENABLE_VLESS_H2R=${ENABLE_VLESS_H2R:-true}
ENABLE_VLESS_GRPCR=${ENABLE_VLESS_GRPCR:-false}
ENABLE_TROJAN_REALITY=${ENABLE_TROJAN_REALITY:-false}
ENABLE_HYSTERIA2=${ENABLE_HYSTERIA2:-true}
ENABLE_TUIC=${ENABLE_TUIC:-true}
ENABLE_SS2022=${ENABLE_SS2022:-true}
ENABLE_SHADOWTLS_SS=${ENABLE_SHADOWTLS_SS:-false}
ENABLE_VMESS_WS=${ENABLE_VMESS_WS:-false}

# 基本设置
SB_DIR=${SB_DIR:-/opt/sing-box}
IMAGE=${IMAGE:-ghcr.io/sagernet/sing-box:latest}
CONTAINER_NAME=${CONTAINER_NAME:-sing-box}

# Reality 公共握手目标
REALITY_SERVER=${REALITY_SERVER:-www.microsoft.com}
REALITY_SERVER_PORT=${REALITY_SERVER_PORT:-443}

# gRPC/H2/WS 细节
GRPC_SERVICE=${GRPC_SERVICE:-grpc}
H2_PATH=${H2_PATH:-/h2}
VMESS_WS_PATH=${VMESS_WS_PATH:-/vm}

############################
# 参数解析 (--KEY=VALUE)
############################
for arg in "$@"; do
  case $arg in
    --SB_DIR=*) SB_DIR="${arg#*=}";;
    --IMAGE=*) IMAGE="${arg#*=}";;
    --CONTAINER_NAME=*) CONTAINER_NAME="${arg#*=}";;
    --REALITY_SERVER=*) REALITY_SERVER="${arg#*=}";;
    --REALITY_SERVER_PORT=*) REALITY_SERVER_PORT="${arg#*=}";;
    --GRPC_SERVICE=*) GRPC_SERVICE="${arg#*=}";;
    --H2_PATH=*) H2_PATH="${arg#*=}";;
    --VMESS_WS_PATH=*) VMESS_WS_PATH="${arg#*=}";;
    --ENABLE_*=*)
      key="${arg%%=*}"; val="${arg#*=}"
      export "${key/--/}"="$val"
      ;;
    --help|-h)
      cat <<EOF
用法: sudo bash $0 [可选参数] [--ENABLE_xxx=true|false]
常用可选参数：
  --SB_DIR=/opt/sing-box
  --IMAGE=ghcr.io/sagernet/sing-box:latest
  --CONTAINER_NAME=sing-box
  --REALITY_SERVER=www.microsoft.com
  --REALITY_SERVER_PORT=443
  --GRPC_SERVICE=grpc        # gRPC service_name
  --H2_PATH=/h2              # H2 路径
  --VMESS_WS_PATH=/vm        # WS 路径
开关（无需证书协议）：
  --ENABLE_VLESS_REALITY=true|false   (默认 true)
  --ENABLE_VLESS_H2R=true|false       (默认 true)
  --ENABLE_VLESS_GRPCR=true|false     (默认 false)
  --ENABLE_TROJAN_REALITY=true|false  (默认 false)
  --ENABLE_HYSTERIA2=true|false       (默认 true)
  --ENABLE_TUIC=true|false            (默认 true)
  --ENABLE_SS2022=true|false          (默认 true)
  --ENABLE_SHADOWTLS_SS=true|false    (默认 false)
  --ENABLE_VMESS_WS=true|false        (默认 false, 明文)
EOF
      exit 0;;
  esac
done

############################
# 工具函数
############################
info(){ echo -e "\033[1;32m[INFO]\033[0m $*"; }
warn(){ echo -e "\033[1;33m[WARN]\033[0m $*"; }
err(){  echo -e "\033[1;31m[ERR ]\033[0m $*"; }

need_root(){
  if [[ $EUID -ne 0 ]]; then err "请以 root 运行：sudo bash $0"; exit 1; fi
}

detect_os(){
  if [[ -f /etc/os-release ]]; then . /etc/os-release; OS=$ID; else OS=$(uname -s); fi
  info "检测到系统：$OS"
}

install_docker(){
  if ! command -v docker >/dev/null 2>&1; then
    info "安装 Docker ..."
    curl -fsSL https://get.docker.com | bash
  else
    info "已安装 Docker"
  fi
  systemctl enable --now docker >/dev/null 2>&1 || true
  if ! docker compose version >/dev/null 2>&1; then
    info "安装 Docker Compose 插件 ..."
    if command -v apt >/dev/null 2>&1; then
      apt-get update -y && apt-get install -y docker-compose-plugin
    fi
  fi
}

ensure_dirs(){
  mkdir -p "$SB_DIR" "$SB_DIR/data"
  chmod 700 "$SB_DIR"
}

gen_uuid(){ docker run --rm "$IMAGE" generate uuid; }
gen_reality(){ docker run --rm "$IMAGE" generate reality-keypair; }
rand_hex8(){ head -c 8 /dev/urandom | xxd -p; }
rand_b64_32(){
  if command -v openssl >/dev/null 2>&1; then openssl rand -base64 32 | tr -d '\n'
  else dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64 | tr -d '\n'; fi
}
get_ip(){
  curl -fsS4 https://ip.gs || curl -fsS4 https://ifconfig.me || echo "YOUR_SERVER_IP"
}

# 随机五位端口且不重复（10000-65535）
PORTS=()
gen_port(){
  while :; do
    p=$(( ( RANDOM % 55536 ) + 10000 ))   # 10000..65535
    [[ $p -gt 65535 ]] && continue
    if [[ ! " ${PORTS[*]} " =~ " $p " ]]; then
      PORTS+=("$p"); echo "$p"; return
    fi
  done
}

############################
# 主流程
############################
need_root
detect_os
install_docker
ensure_dirs

info "拉取镜像：$IMAGE"
docker pull "$IMAGE"

info "生成密钥与 UUID ..."
UUID=$(gen_uuid)
UUID_TUIC=$(gen_uuid)                # tuic 用独立 uuid
HY2_AUTH=$(rand_b64_32)              # hysteria2 auth
TUIC_PWD=$(rand_b64_32)              # tuic 密码
SS2022_PWD=$(rand_b64_32)            # ss2022 key

REALITY_OUT=$(gen_reality)
REALITY_PRIV=$(echo "$REALITY_OUT" | awk '/PrivateKey/{print $2}')
REALITY_PUB=$(echo  "$REALITY_OUT" | awk '/PublicKey/{print $2}')
REALITY_SID=$(rand_hex8)

SERVER_IP=$(get_ip)

# 端口分配（随机不重复）
if [[ "$ENABLE_VLESS_REALITY" == true ]]; then PORT_VLESSR=$(gen_port); fi
if [[ "$ENABLE_VLESS_H2R" == true ]]; then PORT_VLESS_H2R=$(gen_port); fi
if [[ "$ENABLE_VLESS_GRPCR" == true ]]; then PORT_VLESS_GRPCR=$(gen_port); fi
if [[ "$ENABLE_TROJAN_REALITY" == true ]]; then PORT_TROJANR=$(gen_port); fi
if [[ "$ENABLE_HYSTERIA2" == true ]]; then PORT_HY2=$(gen_port); fi
if [[ "$ENABLE_TUIC" == true ]]; then PORT_TUIC=$(gen_port); fi
if [[ "$ENABLE_SS2022" == true ]]; then PORT_SS2022=$(gen_port); fi
if [[ "$ENABLE_SHADOWTLS_SS" == true ]]; then PORT_STLS=$(gen_port); PORT_STLS_SS=$(gen_port); fi
if [[ "$ENABLE_VMESS_WS" == true ]]; then PORT_VMESS_WS=$(gen_port); fi

info "写入配置：$SB_DIR/config.json"
cat > "$SB_DIR/config.json" <<EOF
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
$( # ---- VLESS Reality (TCP)
if [[ "$ENABLE_VLESS_REALITY" == true ]]; then
cat <<JSON
    {
      "type": "vless",
      "tag": "vless-reality",
      "listen": "::",
      "listen_port": $PORT_VLESSR,
      "users": [ { "uuid": "$UUID", "flow": "xtls-rprx-vision" } ],
      "tls": {
        "enabled": true,
        "server_name": "$REALITY_SERVER",
        "reality": {
          "enabled": true,
          "handshake": { "server": "$REALITY_SERVER", "server_port": $REALITY_SERVER_PORT },
          "private_key": "$REALITY_PRIV",
          "short_id": ["$REALITY_SID"]
        }
      }
    },
JSON
fi

# ---- VLESS H2 Reality
if [[ "$ENABLE_VLESS_H2R" == true ]]; then
cat <<JSON
    {
      "type": "vless",
      "tag": "vless-h2r",
      "listen": "::",
      "listen_port": $PORT_VLESS_H2R,
      "users": [ { "uuid": "$UUID" } ],
      "tls": {
        "enabled": true,
        "server_name": "$REALITY_SERVER",
        "reality": {
          "enabled": true,
          "handshake": { "server": "$REALITY_SERVER", "server_port": $REALITY_SERVER_PORT },
          "private_key": "$REALITY_PRIV",
          "short_id": ["$REALITY_SID"]
        }
      },
      "transport": { "type": "http", "path": "$H2_PATH" }
    },
JSON
fi

# ---- VLESS gRPC Reality
if [[ "$ENABLE_VLESS_GRPCR" == true ]]; then
cat <<JSON
    {
      "type": "vless",
      "tag": "vless-grpcr",
      "listen": "::",
      "listen_port": $PORT_VLESS_GRPCR,
      "users": [ { "uuid": "$UUID" } ],
      "tls": {
        "enabled": true,
        "server_name": "$REALITY_SERVER",
        "reality": {
          "enabled": true,
          "handshake": { "server": "$REALITY_SERVER", "server_port": $REALITY_SERVER_PORT },
          "private_key": "$REALITY_PRIV",
          "short_id": ["$REALITY_SID"]
        }
      },
      "transport": { "type": "grpc", "service_name": "$GRPC_SERVICE" }
    },
JSON
fi

# ---- Trojan Reality
if [[ "$ENABLE_TROJAN_REALITY" == true ]]; then
cat <<JSON
    {
      "type": "trojan",
      "tag": "trojan-reality",
      "listen": "::",
      "listen_port": $PORT_TROJANR,
      "users": [ { "password": "$UUID" } ],
      "tls": {
        "enabled": true,
        "server_name": "$REALITY_SERVER",
        "reality": {
          "enabled": true,
          "handshake": { "server": "$REALITY_SERVER", "server_port": $REALITY_SERVER_PORT },
          "private_key": "$REALITY_PRIV",
          "short_id": ["$REALITY_SID"]
        }
      }
    },
JSON
fi

# ---- Hysteria2 (UDP)
if [[ "$ENABLE_HYSTERIA2" == true ]]; then
cat <<JSON
    {
      "type": "hysteria2",
      "tag": "hy2",
      "listen": "::",
      "listen_port": $PORT_HY2,
      "users": [ { "name": "hy2", "auth": "$HY2_AUTH" } ]
    },
JSON
fi

# ---- TUIC v5 (UDP)
if [[ "$ENABLE_TUIC" == true ]]; then
cat <<JSON
    {
      "type": "tuic",
      "tag": "tuic",
      "listen": "::",
      "listen_port": $PORT_TUIC,
      "users": [ { "uuid": "$UUID_TUIC", "password": "$TUIC_PWD" } ],
      "congestion_control": "bbr",
      "udp_relay_mode": "native",
      "zero_rtt_handshake": true
    },
JSON
fi

# ---- SS 2022 (TCP)
if [[ "$ENABLE_SS2022" == true ]]; then
cat <<JSON
    {
      "type": "shadowsocks",
      "tag": "ss2022",
      "listen": "::",
      "listen_port": $PORT_SS2022,
      "method": "2022-blake3-aes-256-gcm",
      "password": "$SS2022_PWD"
    },
JSON
fi

# ---- ShadowTLS + SS (前置 STLS 转发到本地 SS)
if [[ "$ENABLE_SHADOWTLS_SS" == true ]]; then
cat <<JSON
    {
      "type": "shadowtls",
      "tag": "shadowtls",
      "listen": "::",
      "listen_port": $PORT_STLS,
      "version": 3,
      "handshake": { "server": "$REALITY_SERVER", "server_port": $REALITY_SERVER_PORT },
      "detour": "stls-ss"
    },
    {
      "type": "shadowsocks",
      "tag": "stls-ss",
      "listen": "::",
      "listen_port": $PORT_STLS_SS,
      "method": "2022-blake3-aes-256-gcm",
      "password": "$SS2022_PWD"
    },
JSON
fi

# ---- VMess WS 明文（仅测试/内网）
if [[ "$ENABLE_VMESS_WS" == true ]]; then
cat <<JSON
    {
      "type": "vmess",
      "tag": "vmess-ws",
      "listen": "::",
      "listen_port": $PORT_VMESS_WS,
      "users": [ { "uuid": "$UUID" } ],
      "transport": { "type": "ws", "path": "$VMESS_WS_PATH" }
    },
JSON
fi
)
    { "type": "direct", "tag": "direct" },
    { "type": "block",  "tag": "block" }
  ]
}
EOF

info "写入 docker-compose：$SB_DIR/docker-compose.yml"
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

info "启动容器 ..."
cd "$SB_DIR"
docker compose up -d

############################
# 构造分享链接 (v2rayN / 通用)
############################
NAME_BASE="sbdk"
b64url(){ echo -n "$1" | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '='; }

links=()

if [[ "${ENABLE_VLESS_REALITY}" == true ]]; then
  VLESSR_URI="vless://${UUID}@${SERVER_IP}:${PORT_VLESSR}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#${NAME_BASE}-vlessr"
  links+=("$VLESSR_URI")
fi

if [[ "${ENABLE_VLESS_H2R}" == true ]]; then
  VLESS_H2_URI="vless://${UUID}@${SERVER_IP}:${PORT_VLESS_H2R}?encryption=none&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=http&path=$(python3 - <<PY
import urllib.parse; print(urllib.parse.quote('${H2_PATH}'))
PY
)#${NAME_BASE}-h2r"
  links+=("$VLESS_H2_URI")
fi

if [[ "${ENABLE_VLESS_GRPCR}" == true ]]; then
  VLESS_GRPC_URI="vless://${UUID}@${SERVER_IP}:${PORT_VLESS_GRPCR}?encryption=none&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=grpc&serviceName=${GRPC_SERVICE}#${NAME_BASE}-grpcr"
  links+=("$VLESS_GRPC_URI")
fi

if [[ "${ENABLE_TROJAN_REALITY}" == true ]]; then
  TROJANR_URI="trojan://${UUID}@${SERVER_IP}:${PORT_TROJANR}?security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#${NAME_BASE}-trojanr"
  links+=("$TROJANR_URI")
fi

if [[ "${ENABLE_HYSTERIA2}" == true ]]; then
  # v2rayN 支持 hy2://auth@host:port?insecure=1&sni=xxx
  HY2_URI="hy2://${HY2_AUTH}@${SERVER_IP}:${PORT_HY2}?insecure=1&sni=${REALITY_SERVER}#${NAME_BASE}-hy2"
  links+=("$HY2_URI")
fi

if [[ "${ENABLE_TUIC}" == true ]]; then
  TUIC_URI="tuic://${UUID_TUIC}:${TUIC_PWD}@${SERVER_IP}:${PORT_TUIC}?congestion_control=bbr&udp_relay_mode=native&alpn=h3#${NAME_BASE}-tuic"
  links+=("$TUIC_URI")
fi

if [[ "${ENABLE_SS2022}" == true ]]; then
  SS_METHOD="2022-blake3-aes-256-gcm"
  SS_URI="ss://${SS_METHOD}:$(b64url "${SS2022_PWD}")@${SERVER_IP}:${PORT_SS2022}#${NAME_BASE}-ss2022"
  links+=("$SS_URI")
fi

if [[ "${ENABLE_SHADOWTLS_SS}" == true ]]; then
  STLS_HINT="shadowtls://${SERVER_IP}:${PORT_STLS}?server=${REALITY_SERVER}:${REALITY_SERVER_PORT}  ← 先连此，再连本机 SS(${PORT_STLS_SS})；请用支持 ShadowTLS 的客户端"
  links+=("$STLS_HINT")
fi

if [[ "${ENABLE_VMESS_WS}" == true ]]; then
  VMESS_JSON=$(cat <<JSON
{"v":"2","ps":"${NAME_BASE}-vmessws","add":"${SERVER_IP}","port":"${PORT_VMESS_WS}","id":"${UUID}","aid":"0","net":"ws","type":"none","host":"","path":"${VMESS_WS_PATH}","tls":""}
JSON
)
  VMESS_URI="vmess://$(echo -n "$VMESS_JSON" | base64 -w 0 2>/dev/null || echo -n "$VMESS_JSON" | base64 | tr -d '\n')"
  links+=("$VMESS_URI")
fi

cat <<EOF

================= 部署完成 =================
配置目录: $SB_DIR
容器名称: $CONTAINER_NAME
镜像版本: $IMAGE
服务器IP: $SERVER_IP

已启用的协议与端口（随机五位数，互不重复）:
$( [[ "${ENABLE_VLESS_REALITY}" == true ]]   && echo "  - VLESS Reality (TCP):        $PORT_VLESSR" )
$( [[ "${ENABLE_VLESS_H2R}" == true ]]       && echo "  - VLESS H2 Reality (TCP):     $PORT_VLESS_H2R   路径: $H2_PATH" )
$( [[ "${ENABLE_VLESS_GRPCR}" == true ]]     && echo "  - VLESS gRPC Reality (TCP):   $PORT_VLESS_GRPCR service: $GRPC_SERVICE" )
$( [[ "${ENABLE_TROJAN_REALITY}" == true ]]  && echo "  - Trojan Reality (TCP):       $PORT_TROJANR" )
$( [[ "${ENABLE_HYSTERIA2}" == true ]]       && echo "  - Hysteria2 (UDP):            $PORT_HY2" )
$( [[ "${ENABLE_TUIC}" == true ]]            && echo "  - TUIC v5 (UDP):              $PORT_TUIC" )
$( [[ "${ENABLE_SS2022}" == true ]]          && echo "  - Shadowsocks 2022 (TCP):     $PORT_SS2022" )
$( [[ "${ENABLE_SHADOWTLS_SS}" == true ]]    && echo "  - ShadowTLS (TCP):            $PORT_STLS  -> 本机SS: $PORT_STLS_SS" )
$( [[ "${ENABLE_VMESS_WS}" == true ]]        && echo "  - VMess WS 明文 (TCP):        $PORT_VMESS_WS   路径: $VMESS_WS_PATH" )

分享链接（v2rayN/通用可导入）:
$( for l in "${links[@]}"; do echo "  $l"; done )

常用命令：
  查看日志：   docker logs -f ${CONTAINER_NAME}
  重启服务：   docker compose restart
  修改配置：   vim ${SB_DIR}/config.json && docker compose restart
  卸载清理：   cd ${SB_DIR} && docker compose down && rm -rf ${SB_DIR}

注意：
  * Reality 系列无需证书，但需设置握手目标（当前：${REALITY_SERVER}:${REALITY_SERVER_PORT}），可改为其他常见大站。
  * Hysteria2/TUIC 使用 UDP 端口，需确保防火墙/安全组放行。
  * VMess-WS 明文仅适合内网/测试；生产建议使用 Reality/H2R/gRPC-R 等更隐蔽方案。
===========================================
EOF
