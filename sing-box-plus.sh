#!/usr/bin/env bash
# ============================================================
#  Sing-Box-Plus 管理脚本（18 节点：直连 9 + WARP 9）
#  Version: v2.1.6
#  Repo:    https://github.com/Alvin9999/Sing-Box-Plus
#  说明：
#   - 保留原稳定版的 18 节点实现逻辑与链接格式；
#   - SS2022 密钥为标准 Base64，避免 psk 报错；
#   - “查看分享链接 / 安装部署完成”后自动退出；
#   - 卸载后自动退出；
#   - WARP 使用 wgcf 生成账号与 profile，Reserved 缺失容错为 0,0,0。
# ============================================================

set -Eeuo pipefail

SCRIPT_NAME="Sing-Box Native Manager"
SCRIPT_VERSION="v2.1.6"

# 兼容 sing-box 1.12.x 的旧 wireguard 出站
export ENABLE_DEPRECATED_WIREGUARD_OUTBOUND=${ENABLE_DEPRECATED_WIREGUARD_OUTBOUND:-true}

# ===== 颜色 / UI =====
C_RESET="\033[0m"; C_BOLD="\033[1m"; C_DIM="\033[2m"
C_RED="\033[31m";  C_GREEN="\033[32m"; C_YELLOW="\033[33m"
C_BLUE="\033[34m"; C_CYAN="\033[36m"
hr(){ printf "${C_DIM}=============================================================${C_RESET}\n"; }

bbr_status(){
  local on="未开启"
  if [[ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "")" =~ bbr ]]; then on="已启用 BBR"; fi
  [[ "$on" == "已启用 BBR" ]] && echo -e "${C_GREEN}${on}${C_RESET}" || echo -e "${C_RED}${on}${C_RESET}"
}
sb_status(){
  if systemctl is-active --quiet "$SYSTEMD_SERVICE"; then
    echo -e "${C_GREEN}运行中${C_RESET}"
  else
    if systemctl is-enabled --quiet "$SYSTEMD_SERVICE" 2>/dev/null; then
      echo -e "${C_YELLOW}未运行${C_RESET}"
    else
      echo -e "${C_RED}未安装${C_RESET}"
    fi
  fi
}
banner(){
  clear
  echo -e "${C_CYAN}${C_BOLD} 🚀 Sing-Box-Plus 管理脚本 ${SCRIPT_VERSION} 🚀${C_RESET}"
  echo -e "${C_CYAN} 脚本更新地址:https://github.com/Alvin9999/Sing-Box-Plus${C_RESET}"
  hr
  echo -e "系统加速状态：$(bbr_status)"
  echo -e "Sing-Box 启动状态：$(sb_status)"
  hr
}

READ_OPTS=(-e -r)

# ===== 路径 / 变量 =====
SB_DIR="/opt/sing-box"
CONF_JSON="$SB_DIR/config.json"
CERT_DIR="$SB_DIR/cert"
WGCF_DIR="$SB_DIR/wgcf"
ENV_FILE="$SB_DIR/env.conf"
CREDS_ENV="$SB_DIR/creds.env"
PORTS_ENV="$SB_DIR/ports.env"
WARP_ENV="$SB_DIR/warp.env"
SYSTEMD_SERVICE="sing-box.service"
BIN_PATH="/usr/local/bin/sing-box"

# 默认开启 WARP（保留 9 + 9）
ENABLE_WARP="${ENABLE_WARP:-true}"
ENABLE_VLESS_REALITY=true
ENABLE_VLESS_GRPCR=true
ENABLE_TROJAN_REALITY=true
ENABLE_HYSTERIA2=true
ENABLE_VMESS_WS=true
ENABLE_HY2_OBFS=true
ENABLE_SS2022=true
ENABLE_SS=true
ENABLE_TUIC=true
REALITY_SERVER="${REALITY_SERVER:-www.microsoft.com}"
REALITY_SERVER_PORT="${REALITY_SERVER_PORT:-443}"
GRPC_SERVICE="${GRPC_SERVICE:-grpc}"
VMESS_WS_PATH="${VMESS_WS_PATH:-/vm}"

# ===== 通用函数 =====
info(){ echo -e "[信息] $*"; }
warn(){ echo -e "${C_YELLOW}[警告]${C_RESET} $*"; }
err(){ echo -e "${C_RED}[错误]${C_RESET} $*" >&2; }
need_root(){ [[ $EUID -ne 0 ]] && { err "请以 root 运行"; exit 1; }; }
b64enc(){ base64 -w0; }
urlenc(){ jq -Rr @uri; }
is_uuid(){ [[ "$1" =~ ^[0-9a-fA-F-]{36}$ ]]; }
gen_uuid(){
  local u=""
  if [[ -x "$BIN_PATH" ]]; then u=$("$BIN_PATH" generate uuid 2>/dev/null | head -n1 || true); fi
  if [[ -z "$u" ]] && command -v uuidgen >/dev/null 2>&1; then u=$(uuidgen | head -n1 || true); fi
  if [[ -z "$u" ]]; then u=$(cat /proc/sys/kernel/random/uuid | head -n1 || true); fi
  printf '%s' "$u" | tr -d '\r\n'
}
rand_hex8(){ tr -dc '0-9a-f' </dev/urandom | head -c8; }
rand_b64_32(){ openssl rand -base64 32 | tr -d '\n'; }           # 标准 base64
rand_pwd_urlsafe(){ openssl rand -base64 24 | tr -d '=\n' | tr '+/' '-_'; }
get_ip(){
  ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/{print $7;exit}' && return 0
  curl -fsSL4 https://ipinfo.io/ip || curl -fsSL https://api.ipify.org || echo "127.0.0.1"
}
safe_source_env(){ local f="$1"; [[ -f "$f" ]] || return 1; set +u; . "$f"; set -u; }

arch_map(){
  case "$(uname -m)" in
    x86_64|amd64) echo amd64;;
    aarch64|arm64) echo arm64;;
    armv7l|armv7) echo armv7;;
    i386|i686|386) echo 386;;
    *) echo amd64;;
  esac
}

# ===== 端口（18 个互不重复） =====
PORTS=(); gen_port(){ while :; do p=$(( ( RANDOM % 55536 ) + 10000 )); [[ $p -le 65535 ]] || continue; [[ ! " ${PORTS[*]} " =~ " $p " ]] && { PORTS+=("$p"); echo "$p"; return; }; done; }; rand_ports_reset(){ PORTS=(); }
PORT_VLESSR=""; PORT_VLESS_GRPCR=""; PORT_TROJANR=""; PORT_HY2=""; PORT_VMESS_WS=""
PORT_HY2_OBFS=""; PORT_SS2022=""; PORT_SS=""; PORT_TUIC=""
PORT_VLESSR_W=""; PORT_VLESS_GRPCR_W=""; PORT_TROJANR_W=""; PORT_HY2_W=""; PORT_VMESS_WS_W=""
PORT_HY2_OBFS_W=""; PORT_SS2022_W=""; PORT_SS_W=""; PORT_TUIC_W=""

save_ports(){ cat > "$PORTS_ENV" <<EOF
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
load_ports(){ safe_source_env "$PORTS_ENV" || return 1; }
save_all_ports(){
  rand_ports_reset
  for v in PORT_VLESSR PORT_VLESS_GRPCR PORT_TROJANR PORT_HY2 PORT_VMESS_WS PORT_HY2_OBFS PORT_SS2022 PORT_SS PORT_TUIC \
           PORT_VLESSR_W PORT_VLESS_GRPCR_W PORT_TROJANR_W PORT_HY2_W PORT_VMESS_WS_W PORT_HY2_OBFS_W PORT_SS2022_W PORT_SS_W PORT_TUIC_W; do
    [[ -n "${!v:-}" ]] && PORTS+=("${!v}")
  done
  [[ -z "${PORT_VLESSR:-}" ]] && PORT_VLESSR=$(gen_port)
  [[ -z "${PORT_VLESS_GRPCR:-}" ]] && PORT_VLESS_GRPCR=$(gen_port)
  [[ -z "${PORT_TROJANR:-}" ]] && PORT_TROJANR=$(gen_port)
  [[ -z "${PORT_HY2:-}" ]] && PORT_HY2=$(gen_port)
  [[ -z "${PORT_VMESS_WS:-}" ]] && PORT_VMESS_WS=$(gen_port)
  [[ -z "${PORT_HY2_OBFS:-}" ]] && PORT_HY2_OBFS=$(gen_port)
  [[ -z "${PORT_SS2022:-}" ]] && PORT_SS2022=$(gen_port)
  [[ -z "${PORT_SS:-}" ]] && PORT_SS=$(gen_port)
  [[ -z "${PORT_TUIC:-}" ]] && PORT_TUIC=$(gen_port)
  [[ -z "${PORT_VLESSR_W:-}" ]] && PORT_VLESSR_W=$(gen_port)
  [[ -z "${PORT_VLESS_GRPCR_W:-}" ]] && PORT_VLESS_GRPCR_W=$(gen_port)
  [[ -z "${PORT_TROJANR_W:-}" ]] && PORT_TROJANR_W=$(gen_port)
  [[ -z "${PORT_HY2_W:-}" ]] && PORT_HY2_W=$(gen_port)
  [[ -z "${PORT_VMESS_WS_W:-}" ]] && PORT_VMESS_WS_W=$(gen_port)
  [[ -z "${PORT_HY2_OBFS_W:-}" ]] && PORT_HY2_OBFS_W=$(gen_port) || true
  [[ -z "${PORT_SS2022_W:-}" ]] && PORT_SS2022_W=$(gen_port)
  [[ -z "${PORT_SS_W:-}" ]] && PORT_SS_W=$(gen_port)
  [[ -z "${PORT_TUIC_W:-}" ]] && PORT_TUIC_W=$(gen_port)
  save_ports
}

# ===== env / creds / warp =====
save_env(){ cat > "$ENV_FILE" <<EOF
BIN_PATH=$BIN_PATH
ENABLE_VLESS_REALITY=$ENABLE_VLESS_REALITY
ENABLE_VLESS_GRPCR=$ENABLE_VLESS_GRPCR
ENABLE_TROJAN_REALITY=$ENABLE_TROJAN_REALITY
ENABLE_HYSTERIA2=$ENABLE_HYSTERIA2
ENABLE_VMESS_WS=$ENABLE_VMESS_WS
ENABLE_HY2_OBFS=$ENABLE_HY2_OBFS
ENABLE_SS2022=$ENABLE_SS2022
ENABLE_SS=$ENABLE_SS
ENABLE_TUIC=$ENABLE_TUIC
ENABLE_WARP=$ENABLE_WARP
REALITY_SERVER=$REALITY_SERVER
REALITY_SERVER_PORT=$REALITY_SERVER_PORT
GRPC_SERVICE=$GRPC_SERVICE
VMESS_WS_PATH=$VMESS_WS_PATH
EOF
}
load_env(){ safe_source_env "$ENV_FILE" || true; }

save_creds(){ cat > "$CREDS_ENV" <<EOF
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
load_creds(){ safe_source_env "$CREDS_ENV" || return 1; }

save_warp(){ cat > "$WARP_ENV" <<EOF
WARP_PRIVATE_KEY=$WARP_PRIVATE_KEY
WARP_PEER_PUBLIC_KEY=$WARP_PEER_PUBLIC_KEY
WARP_ENDPOINT_HOST=$WARP_ENDPOINT_HOST
WARP_ENDPOINT_PORT=$WARP_ENDPOINT_PORT
WARP_ADDRESS_V4=$WARP_ADDRESS_V4
WARP_ADDRESS_V6=$WARP_ADDRESS_V6
WARP_RESERVED_1=$WARP_RESERVED_1
WARP_RESERVED_2=$WARP_RESERVED_2
WARP_RESERVED_3=$WARP_RESERVED_3
EOF
}
load_warp(){ safe_source_env "$WARP_ENV" || return 1; }

gen_reality(){ "$BIN_PATH" generate reality-keypair; }
mk_cert(){
  local crt="$CERT_DIR/fullchain.pem" key="$CERT_DIR/key.pem"
  if [[ ! -s "$crt" || ! -s "$key" ]]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 3650 -nodes \
      -keyout "$key" -out "$crt" -subj "/CN=$REALITY_SERVER" \
      -addext "subjectAltName=DNS:$REALITY_SERVER" >/dev/null 2>&1
  fi
}
ensure_creds(){
  [[ -z "${UUID:-}" ]] && UUID=$(gen_uuid)
  is_uuid "$UUID" || UUID=$(gen_uuid)
  [[ -z "${HY2_PWD:-}" ]] && HY2_PWD=$(rand_b64_32)
  if [[ -z "${REALITY_PRIV:-}" || -z "${REALITY_PUB:-}" || -z "${REALITY_SID:-}" ]]; then
    readarray -t RKP < <(gen_reality)
    REALITY_PRIV=$(printf "%s\n" "${RKP[@]}" | awk "/PrivateKey/{print \$2}")
    REALITY_PUB=$(printf "%s\n" "${RKP[@]}" | awk "/PublicKey/{print \$2}")
    REALITY_SID=$(rand_hex8)
  fi
  [[ -z "${HY2_PWD2:-}" ]] && HY2_PWD2=$(rand_b64_32)
  [[ -z "${HY2_OBFS_PWD:-}" ]] && HY2_OBFS_PWD=$(openssl rand -base64 16 | tr -d "\n")
  [[ -z "${SS2022_KEY:-}" ]] && SS2022_KEY=$(rand_b64_32)        # 标准 base64
  [[ -z "${SS_PWD:-}" ]] && SS_PWD=$(rand_pwd_urlsafe)
  TUIC_UUID="$UUID"; TUIC_PWD="$UUID"
  save_creds
}

# ===== WARP（wgcf） =====
WGCF_BIN=/usr/local/bin/wgcf
install_wgcf(){
  [[ -x "$WGCF_BIN" ]] && return 0
  local GOA url tmp; case "$(arch_map)" in amd64) GOA=amd64;; arm64) GOA=arm64;; armv7) GOA=armv7;; 386) GOA=386;; *) GOA=amd64;; esac
  url=$(curl -fsSL https://api.github.com/repos/ViRb3/wgcf/releases/latest \
        | jq -r ".assets[] | select(.name|test(\"linux_${GOA}$\")) | .browser_download_url" | head -n1)
  [[ -n "$url" ]] || { warn "获取 wgcf 失败"; return 1; }
  tmp=$(mktemp -d); curl -fsSL "$url" -o "$tmp/wgcf"; install -m0755 "$tmp/wgcf" "$WGCF_BIN"; rm -rf "$tmp"
}
ensure_warp_profile(){
  [[ "$ENABLE_WARP" == "true" ]] || return 0
  if load_warp 2>/dev/null; then return 0; fi
  install_wgcf || { warn "wgcf 安装失败，已自动禁用 WARP 节点"; ENABLE_WARP=false; save_env; return 0; }
  local wd="$WGCF_DIR"; mkdir -p "$wd"
  if [[ ! -f "$wd/wgcf-account.toml" ]]; then "$WGCF_BIN" register --accept-tos --config "$wd/wgcf-account.toml" >/dev/null; fi
  "$WGCF_BIN" generate --config "$wd/wgcf-account.toml" --profile "$wd/wgcf-profile.conf" >/dev/null

  local prof="$wd/wgcf-profile.conf"
  local addr_line ep rs
  WARP_PRIVATE_KEY=$(awk -F'= *' '/^PrivateKey/{gsub(/\r/,"");print $2}' "$prof" | tr -d '"')
  addr_line=$(awk -F'= *' '/^Address/{gsub(/\r/,"");print $2;exit}' "$prof" | tr -d '"')
  WARP_ADDRESS_V4="${addr_line%%,*}"
  WARP_ADDRESS_V6="${addr_line##*, }"
  ep=$(awk -F'= *' '/^Endpoint/{gsub(/\r/,"");print $2;exit}' "$prof" | tr -d '"')
  WARP_ENDPOINT_HOST=${ep%:*}; WARP_ENDPOINT_PORT=${ep##*:}
  WARP_PEER_PUBLIC_KEY=$(awk -F'= *' '/^PublicKey/{gsub(/\r/,"");print $2;exit}' "$prof" | tr -d '"')
  rs=$(awk -F'= *' '/^Reserved/{gsub(/\r/,"");print $2;exit}' "$prof" | tr -d '" ')
  if [[ -n "$rs" ]]; then
    WARP_RESERVED_1=${rs%%,*}; rs=${rs#*,}
    WARP_RESERVED_2=${rs%%,*}; WARP_RESERVED_3=${rs##*,}
  else
    WARP_RESERVED_1=0; WARP_RESERVED_2=0; WARP_RESERVED_3=0
  fi
  save_warp
}

# ===== 安装依赖 / sing-box / systemd / 防火墙 =====
install_deps(){
  apt-get update -y
  apt-get install -y --no-install-recommends ca-certificates curl wget tar jq coreutils iproute2 openssl
}
install_singbox(){
  if [[ -x "$BIN_PATH" ]]; then
    info "检测到 sing-box：$("$BIN_PATH" version 2>/dev/null | head -n1)"
    return 0
  fi
  info "下载 sing-box (amd64) ..."
  local SB_VER URL tmpdir
  SB_VER="v1.12.7"
  URL="https://github.com/SagerNet/sing-box/releases/download/${SB_VER}/sing-box-${SB_VER#v}-linux-amd64.tar.gz"
  tmpdir=$(mktemp -d); trap 'rm -rf "$tmpdir"' EXIT
  curl -fL --retry 3 -o "$tmpdir/sb.tgz" "$URL"
  tar -xzf "$tmpdir/sb.tgz" -C "$tmpdir"
  install -m 0755 "$tmpdir"/sing-box-*/sing-box "$BIN_PATH"
  "$BIN_PATH" version || true
}
write_systemd(){
  cat > /etc/systemd/system/${SYSTEMD_SERVICE} <<EOF
[Unit]
Description=Sing-Box (Native 18 nodes)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=${BIN_PATH} run -c ${CONF_JSON}
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576
Environment=ENABLE_DEPRECATED_WIREGUARD_OUTBOUND=${ENABLE_DEPRECATED_WIREGUARD_OUTBOUND}

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable ${SYSTEMD_SERVICE} >/dev/null 2>&1 || true
}
open_firewall(){
  local rules=()
  rules+=("${PORT_VLESSR}/tcp" "${PORT_VLESS_GRPCR}/tcp" "${PORT_TROJANR}/tcp" "${PORT_VMESS_WS}/tcp")
  rules+=("${PORT_HY2}/udp" "${PORT_HY2_OBFS}/udp" "${PORT_TUIC}/udp")
  rules+=("${PORT_SS2022}/tcp" "${PORT_SS2022}/udp" "${PORT_SS}/tcp" "${PORT_SS}/udp")
  rules+=("${PORT_VLESSR_W}/tcp" "${PORT_VLESS_GRPCR_W}/tcp" "${PORT_TROJANR_W}/tcp" "${PORT_VMESS_WS_W}/tcp")
  rules+=("${PORT_HY2_W}/udp" "${PORT_HY2_OBFS_W}/udp" "${PORT_TUIC_W}/udp")
  rules+=("${PORT_SS2022_W}/tcp" "${PORT_SS2022_W}/udp" "${PORT_SS_W}/tcp" "${PORT_SS_W}/udp")
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q -E "active|活跃"; then
    for r in "${rules[@]}"; do ufw allow "$r" >/dev/null 2>&1 || true; done; ufw reload >/dev/null 2>&1 || true
  elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    systemctl enable --now firewalld >/dev/null 2>&1 || true
    for r in "${rules[@]}"; do firewall-cmd --permanent --add-port="$r" >/dev/null 2>&1 || true; done; firewall-cmd --reload >/dev/null 2>&1 || true
  else
    local p proto
    for r in "${rules[@]}"; do p="${r%/*}"; proto="${r#*/}";
      if [[ "$proto" == tcp ]]; then iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$p" -j ACCEPT; fi
      if [[ "$proto" == udp ]]; then iptables -C INPUT -p udp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport "$p" -j ACCEPT; fi
    done
    command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
  fi
}

# ===== 配置写入（按你提供的稳定版本） =====
write_config(){
  ensure_dirs; load_env || true; load_creds || true; load_ports || true
  ensure_creds; save_all_ports; mk_cert
  [[ "$ENABLE_WARP" == "true" ]] && ensure_warp_profile || true

  local CRT="$CERT_DIR/fullchain.pem" KEY="$CERT_DIR/key.pem"
  jq -n \
  --arg RS "$REALITY_SERVER" --argjson RSP "${REALITY_SERVER_PORT:-443}" --arg UID "$UUID" \
  --arg RPR "$REALITY_PRIV" --arg RPB "$REALITY_PUB" --arg SID "$REALITY_SID" \
  --arg HY2 "$HY2_PWD" --arg HY22 "$HY2_PWD2" --arg HY2O "$HY2_OBFS_PWD" \
  --arg GRPC "$GRPC_SERVICE" --arg VMWS "$VMESS_WS_PATH" --arg CRT "$CRT" --arg KEY "$KEY" \
  --arg SS2022 "$SS2022_KEY" --arg SSPWD "$SS_PWD" --arg TUICUUID "$TUIC_UUID" --arg TUICPWD "$TUIC_PWD" \
  --argjson P1 "$PORT_VLESSR" --argjson P2 "$PORT_VLESS_GRPCR" --argjson P3 "$PORT_TROJANR" \
  --argjson P4 "$PORT_HY2" --argjson P5 "$PORT_VMESS_WS" --argjson P6 "$PORT_HY2_OBFS" \
  --argjson P7 "$PORT_SS2022" --argjson P8 "$PORT_SS" --argjson P9 "$PORT_TUIC" \
  --argjson PW1 "$PORT_VLESSR_W" --argjson PW2 "$PORT_VLESS_GRPCR_W" --argjson PW3 "$PORT_TROJANR_W" \
  --argjson PW4 "$PORT_HY2_W" --argjson PW5 "$PORT_VMESS_WS_W" --argjson PW6 "$PORT_HY2_OBFS_W" \
  --argjson PW7 "$PORT_SS2022_W" --argjson PW8 "$PORT_SS_W" --argjson PW9 "$PORT_TUIC_W" \
  --arg ENABLE_WARP "$ENABLE_WARP" \
  --arg WPRIV "${WARP_PRIVATE_KEY:-}" --arg WPPUB "${WARP_PEER_PUBLIC_KEY:-}" \
  --arg WHOST "${WARP_ENDPOINT_HOST:-}" --argjson WPORT "${WARP_ENDPOINT_PORT:-0}" \
  --arg W4 "${WARP_ADDRESS_V4:-}" --arg W6 "${WARP_ADDRESS_V6:-}" \
  --argjson WR1 "${WARP_RESERVED_1:-0}" --argjson WR2 "${WARP_RESERVED_2:-0}" --argjson WR3 "${WARP_RESERVED_3:-0}" \
  '
  def inbound_vless($port): {type:"vless", listen:"0.0.0.0", listen_port:$port, users:[{uuid:$UID}], tls:{enabled:true, server_name:$RS, reality:{enabled:true, handshake:{server:$RS, server_port:$RSP}, private_key:$RPR, short_id:[$SID]}}};
  def inbound_vless_flow($port): {type:"vless", listen:"0.0.0.0", listen_port:$port, users:[{uuid:$UID, flow:"xtls-rprx-vision"}], tls:{enabled:true, server_name:$RS, reality:{enabled:true, handshake:{server:$RS, server_port:$RSP}, private_key:$RPR, short_id:[$SID]}}};
  def inbound_trojan($port): {type:"trojan", listen:"0.0.0.0", listen_port:$port, users:[{password:$UID}], tls:{enabled:true, server_name:$RS, reality:{enabled:true, handshake:{server:$RS, server_port:$RSP}, private_key:$RPR, short_id:[$SID]}}};
  def inbound_hy2($port): {type:"hysteria2", listen:"0.0.0.0", listen_port:$port, users:[{name:"hy2", password:$HY2}], tls:{enabled:true, certificate_path:$CRT, key_path:$KEY}};
  def inbound_vmess_ws($port): {type:"vmess", listen:"0.0.0.0", listen_port:$port, users:[{uuid:$UID}], transport:{type:"ws", path:$VMWS}};
  def inbound_hy2_obfs($port): {type:"hysteria2", listen:"0.0.0.0", listen_port:$port, users:[{name:"hy2", password:$HY22}], obfs:{type:"salamander", password:$HY2O}, tls:{enabled:true, certificate_path:$CRT, key_path:$KEY, alpn:["h3"]}};
  def inbound_ss2022($port): {type:"shadowsocks", listen:"0.0.0.0", listen_port:$port, method:"2022-blake3-aes-256-gcm", password:$SS2022};
  def inbound_ss($port): {type:"shadowsocks", listen:"0.0.0.0", listen_port:$port, method:"aes-256-gcm", password:$SSPWD};
  def inbound_tuic($port): {type:"tuic", listen:"0.0.0.0", listen_port:$port, users:[{uuid:$TUICUUID, password:$TUICPWD}], congestion_control:"bbr", tls:{enabled:true, certificate_path:$CRT, key_path:$KEY, alpn:["h3"]}};

  def warp_outbound:
    {type:"wireguard", tag:"warp",
      local_address: ( [ $W4, $W6 ] | map(select(. != "")) ),
      system_interface: false,
      private_key:$WPRIV,
      peers: [ {
        server:$WHOST, server_port:$WPORT, public_key:$WPPUB,
        reserved: [ $WR1, $WR2, $WR3 ],
        allowed_ips: ["0.0.0.0/0","::/0"]
      } ],
      mtu:1280
    };

  {
    log:{level:"info", timestamp:true},
    dns:{ servers:[ {tag:"dns-remote", address:"https://1.1.1.1/dns-query", detour:"direct"}, {address:"tls://dns.google", detour:"direct"} ], strategy:"prefer_ipv4" },
    inbounds:[
      (inbound_vless_flow($P1) + {tag:"vless-reality"}),
      (inbound_vless($P2) + {tag:"vless-grpcr", transport:{type:"grpc", service_name:$GRPC}}),
      (inbound_trojan($P3) + {tag:"trojan-reality"}),
      (inbound_hy2($P4) + {tag:"hy2"}),
      (inbound_vmess_ws($P5) + {tag:"vmess-ws"}),
      (inbound_hy2_obfs($P6) + {tag:"hy2-obfs"}),
      (inbound_ss2022($P7) + {tag:"ss2022"}),
      (inbound_ss($P8) + {tag:"ss"}),
      (inbound_tuic($P9) + {tag:"tuic-v5"}),

      (inbound_vless_flow($PW1) + {tag:"vless-reality-warp"}),
      (inbound_vless($PW2) + {tag:"vless-grpcr-warp", transport:{type:"grpc", service_name:$GRPC}}),
      (inbound_trojan($PW3) + {tag:"trojan-reality-warp"}),
      (inbound_hy2($PW4) + {tag:"hy2-warp"}),
      (inbound_vmess_ws($PW5) + {tag:"vmess-ws-warp"}),
      (inbound_hy2_obfs($PW6) + {tag:"hy2-obfs-warp"}),
      (inbound_ss2022($PW7) + {tag:"ss2022-warp"}),
      (inbound_ss($PW8) + {tag:"ss-warp"}),
      (inbound_tuic($PW9) + {tag:"tuic-v5-warp"})
    ],
    outbounds: (
      if $ENABLE_WARP=="true" and ($WPRIV|length)>0 and ($WHOST|length)>0 then
        [{type:"direct", tag:"direct"}, {type:"block", tag:"block"}, warp_outbound]
      else
        [{type:"direct", tag:"direct"}, {type:"block", tag:"block"}]
      end
    ),
    route: (
      if $ENABLE_WARP=="true" and ($WPRIV|length)>0 and ($WHOST|length)>0 then
        { default_domain_resolver:"dns-remote", rules:[
            { inbound: ["vless-reality-warp","vless-grpcr-warp","trojan-reality-warp","hy2-warp","vmess-ws-warp","hy2-obfs-warp","ss2022-warp","ss-warp","tuic-v5-warp"], outbound:"warp" }
          ],
          final:"direct"
        }
      else
        { final:"direct" }
      end
    )
  }' > "$CONF_JSON"
  save_env
}

# ===== 分享链接（分组美化，打印后 exit 0） =====
print_links(){
  load_env; load_creds; load_ports
  local ip; ip=$(get_ip)
  local links=()

  # 直连 9
  links+=("vless://${UUID}@${ip}:${PORT_VLESSR}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#vless-reality")
  links+=("vless://${UUID}@${ip}:${PORT_VLESS_GRPCR}?encryption=none&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=grpc&serviceName=${GRPC_SERVICE}#vless-grpc-reality")
  links+=("trojan://${UUID}@${ip}:${PORT_TROJANR}?security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#trojan-reality")
  links+=("hy2://$(urlenc "${HY2_PWD}")@${ip}:${PORT_HY2}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#hysteria2")
  VMESS_JSON=$(cat <<JSON
{"v":"2","ps":"vmess-ws","add":"${ip}","port":"${PORT_VMESS_WS}","id":"${UUID}","aid":"0","net":"ws","type":"none","host":"","path":"${VMESS_WS_PATH}","tls":""}
JSON
); links+=("vmess://$(printf "%s" "$VMESS_JSON" | b64enc)")
  links+=("hy2://$(urlenc "${HY2_PWD2}")@${ip}:${PORT_HY2_OBFS}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}&alpn=h3&obfs=salamander&obfs-password=$(urlenc "${HY2_OBFS_PWD}")#hysteria2-obfs")
  links+=("ss://$(printf "%s" "2022-blake3-aes-256-gcm:${SS2022_KEY}" | b64enc)@${ip}:${PORT_SS2022}#ss2022")
  links+=("ss://$(printf "%s" "aes-256-gcm:${SS_PWD}" | b64enc)@${ip}:${PORT_SS}#ss")
  links+=("tuic://${UUID}:$(urlenc "${UUID}")@${ip}:${PORT_TUIC}?congestion_control=bbr&alpn=h3&insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#tuic-v5")

  # WARP 9
  links+=("vless://${UUID}@${ip}:${PORT_VLESSR_W}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#vless-reality-warp")
  links+=("vless://${UUID}@${ip}:${PORT_VLESS_GRPCR_W}?encryption=none&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=grpc&serviceName=${GRPC_SERVICE}#vless-grpc-reality-warp")
  links+=("trojan://${UUID}@${ip}:${PORT_TROJANR_W}?security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#trojan-reality-warp")
  links+=("hy2://$(urlenc "${HY2_PWD}")@${ip}:${PORT_HY2_W}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#hysteria2-warp")
  VMESS_JSON_W=$(cat <<JSON
{"v":"2","ps":"vmess-ws-warp","add":"${ip}","port":"${PORT_VMESS_WS_W}","id":"${UUID}","aid":"0","net":"ws","type":"none","host":"","path":"${VMESS_WS_PATH}","tls":""}
JSON
); links+=("vmess://$(printf "%s" "$VMESS_JSON_W" | b64enc)")
  links+=("hy2://$(urlenc "${HY2_PWD2}")@${ip}:${PORT_HY2_OBFS_W}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}&alpn=h3&obfs=salamander&obfs-password=$(urlenc "${HY2_OBFS_PWD}")#hysteria2-obfs-warp")
  links+=("ss://$(printf "%s" "2022-blake3-aes-256-gcm:${SS2022_KEY}" | b64enc)@${ip}:${PORT_SS2022_W}#ss2022-warp")
  links+=("ss://$(printf "%s" "aes-256-gcm:${SS_PWD}" | b64enc)@${ip}:${PORT_SS_W}#ss-warp")
  links+=("tuic://${UUID}:$(urlenc "${UUID}")@${ip}:${PORT_TUIC_W}?congestion_control=bbr&alpn=h3&insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#tuic-v5-warp")

  # 分组展示
  local direct=() warp=()
  for l in "${links[@]}"; do
    if [[ "$l" == *"-warp"* ]]; then warp+=("$l"); else direct+=("$l"); fi
  done

  echo -e "${C_BLUE}${C_BOLD}【直连节点（9）】${C_RESET}（vless-reality / vless-grpc-reality / trojan-reality / vmess-ws / hy2 / hy2-obfs / ss2022 / ss / tuic）"
  hr; for l in "${direct[@]}"; do echo "  $l"; done; hr; echo
  echo -e "${C_BLUE}${C_BOLD}【WARP 节点（9）】${C_RESET}（同上 9 种，带 -warp）"
  echo -e "${C_DIM}说明：带 -warp 的 9 个节点走 Cloudflare WARP 出口，流媒体解锁更友好${C_RESET}"
  echo -e "${C_DIM}提示：TUIC 默认 allowInsecure=1，v2rayN 导入即用${C_RESET}"
  hr; for l in "${warp[@]}"; do echo "  $l"; done; hr
}

# ===== 操作 =====
restart_service(){ systemctl restart "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true; }
rotate_ports(){
  ensure_dirs; load_env || true; load_creds || true; load_ports || true
  save_all_ports; write_config
  ENABLE_DEPRECATED_WIREGUARD_OUTBOUND=true "$BIN_PATH" check -c "$CONF_JSON" || true
  restart_service
  info "所有端口已重新生成并生效"
}
enable_bbr(){
  echo "net.core.default_qdisc=fq" >/etc/sysctl.d/99-bbr.conf
  echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.d/99-bbr.conf
  sysctl --system >/dev/null 2>&1 || true
  echo -e "${C_GREEN}BBR 已尝试开启（如内核支持）${C_RESET}"
}
uninstall_all(){
  systemctl stop "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true
  systemctl disable "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/${SYSTEMD_SERVICE}"
  systemctl daemon-reload
  rm -rf "$SB_DIR"
  echo -e "${C_RED}已卸载并清理完毕${C_RESET}"
  exit 0
}
ensure_installed_or_hint(){
  if [[ ! -x "$BIN_PATH" || ! -f "$CONF_JSON" ]]; then
    err "未安装，请先选择 1 安装/部署（18 节点）"
    return 1
  fi
  return 0
}

deploy_native(){
  install_deps
  install_singbox
  write_config
  info "检查配置 ..."; ENABLE_DEPRECATED_WIREGUARD_OUTBOUND=true "$BIN_PATH" check -c "$CONF_JSON" || true
  info "写入并启用 systemd 服务 ..."; write_systemd; restart_service
  open_firewall
  echo; echo -e "${C_BOLD}${C_GREEN}★ 部署完成（18 节点）${C_RESET}"; echo
  print_links
  exit 0
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
    1) deploy_native;;                                           # 安装后直接 exit 0
    2) ensure_installed_or_hint && { print_links; exit 0; } || exit 0;;
    3) ensure_installed_or_hint && { restart_service; echo -e "${C_GREEN}已重启${C_RESET}"; read -p "回车返回..." _ || true; } || true;;
    4) ensure_installed_or_hint && { rotate_ports; read -p "回车返回..." _ || true; } || true;;
    5) enable_bbr; read -p "回车返回..." _ || true;;
    8) uninstall_all;;                                          # 卸载后直接 exit 0
    0) exit 0;;
    *) :;;
  esac
  menu
}

# ===== 入口 =====
need_root
menu
