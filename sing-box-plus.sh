#!/usr/bin/env bash
# =======================================================
# Sing-Box Native Manager (18 节点：直出 9 + WARP 9)
#  - 去 Docker，原生 systemd 管理
#  - jq 安全生成 config.json（杜绝 \n/控制字符导致解析失败）
#  - safe_source_env 防护（跳过损坏的 *.env）
#  - 修复 gen_uuid()（确保只返回单一 UUID）
#  - 自动安装 wgcf，生成 WARP WireGuard 出站
#  - 端口为 10000–65535 的 5 位随机数，18 个端口互不重复
#  - 菜单：部署/查看链接/重启/一键换端口/启用BBR/卸载
# =======================================================
set -euo pipefail

SCRIPT_NAME="Sing-Box Native Manager"
SCRIPT_VERSION="v1.5.0-native-warp"

# ================ 颜色 & UI ================
C_RESET="\033[0m"; C_BOLD="\033[1m"; C_DIM="\033[2m"
C_RED="\033[31m";  C_GREEN="\033[32m"; C_YELLOW="\033[33m"
C_BLUE="\033[34m"; C_CYAN="\033[36m"
CRESET="$C_RESET"   # ← 兼容别名，避免未定义
hr(){ printf "${C_DIM}──────────────────────────────────────────────────────────${C_RESET}\n"; }
banner(){ clear; echo -e "${C_CYAN}${C_BOLD}$SCRIPT_NAME ${SCRIPT_VERSION}${C_RESET}"; hr; }
READ_OPTS=(-e -r)

# ================ 路径 & 开关 ================
SB_DIR=${SB_DIR:-/opt/sing-box}; DATA_DIR="$SB_DIR/data"; CERT_DIR="$SB_DIR/cert"; CONF_JSON="$SB_DIR/config.json"
BIN_PATH=${BIN_PATH:-/usr/local/bin/sing-box}; SYSTEMD_SERVICE=${SYSTEMD_SERVICE:-sing-box.service}

# 直出 9 个
ENABLE_VLESS_REALITY=${ENABLE_VLESS_REALITY:-true}
ENABLE_VLESS_GRPCR=${ENABLE_VLESS_GRPCR:-true}
ENABLE_TROJAN_REALITY=${ENABLE_TROJAN_REALITY:-true}
ENABLE_HYSTERIA2=${ENABLE_HYSTERIA2:-true}
ENABLE_VMESS_WS=${ENABLE_VMESS_WS:-true}
ENABLE_HY2_OBFS=${ENABLE_HY2_OBFS:-true}
ENABLE_SS2022=${ENABLE_SS2022:-true}
ENABLE_SS=${ENABLE_SS:-true}
ENABLE_TUIC=${ENABLE_TUIC:-true}

# 再复制 9 个走 WARP
ENABLE_WARP=${ENABLE_WARP:-true}

# 细节
REALITY_SERVER=${REALITY_SERVER:-www.microsoft.com}
REALITY_SERVER_PORT=${REALITY_SERVER_PORT:-443}
GRPC_SERVICE=${GRPC_SERVICE:-grpc}
VMESS_WS_PATH=${VMESS_WS_PATH:-/vm}

# ================ 工具函数 ================
info(){ echo -e "${C_GREEN}[信息]${C_RESET} $*"; }
warn(){ echo -e "${C_YELLOW}[警告]${C_RESET} $*"; }
err(){  echo -e "${C_RED}[错误]${C_RESET} $*"; }
need_root(){ [[ $EUID -eq 0 ]] || { err "请以 root 运行：bash $0"; exit 1; }; }
ensure_dirs(){ mkdir -p "$SB_DIR" "$DATA_DIR" "$CERT_DIR"; chmod 700 "$SB_DIR"; }
safe_source_env(){ local f="$1"; [[ -f "$f" ]] || return 1; sed -i 's/\r$//' "$f" 2>/dev/null || true
  if ! awk -F= 'BEGIN{ok=1} /^[[:space:]]*$/||/^[[:space:]]*#/{next} /^[A-Za-z_][A-Za-z0-9_]*=.*/{next} {ok=0} END{exit ok?0:1}' "$f"; then
    echo "[警告] 跳过损坏的环境文件：$f"; return 1; fi; . "$f"; }
urlenc(){ local s="$1" o= c; for((i=0;i<${#s};i++)){ c="${s:i:1}"; case "$c" in [a-zA-Z0-9.~_-])o+="$c";;*)printf -v h '%%%02X' "'$c"; o+="$h";; esac; }; printf '%s' "$o"; }
get_ip(){ curl -fsS4 https://ip.gs || curl -fsS4 https://ifconfig.me || echo "YOUR_SERVER_IP"; }
is_uuid(){ [[ ${1:-} =~ ^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$ ]]; }

# ================ 平台 / 包管理 ================
OS_FAMILY=""; PKG=""
pkg_detect(){ . /etc/os-release
  case "${ID,,}" in
    debian|ubuntu|linuxmint) OS_FAMILY=debian; PKG=apt;;
    rhel|centos|rocky|almalinux|ol|fedora) OS_FAMILY=rhel; PKG=$(command -v dnf >/dev/null 2>&1 && echo dnf || echo yum);;
    *) err "不支持的系统: $ID"; exit 1;;
  esac
}
pkg_update(){ case "$PKG" in
  apt) DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true;;
  dnf) dnf makecache -y >/dev/null 2>&1 || true;;
  yum) yum makecache -y >/dev/null 2>&1 || true;;
esac; }
pkg_install(){ local pkgs=("$@"); case "$PKG" in
  apt) apt-get install -y "${pkgs[@]}" >/dev/null 2>&1 || true;;
  dnf) dnf install -y "${pkgs[@]}" >/dev/null 2>&1 || true;;
  yum) yum install -y "${pkgs[@]}" >/dev/null 2>&1 || true;;
esac; }

# ================ 安装 sing-box ================
arch_map(){ case "$(uname -m)" in x86_64|amd64) echo amd64;; aarch64|arm64) echo arm64;; armv7l|armv7) echo armv7;; i386|i686) echo 386;; s390x) echo s390x;; *) err "不支持架构 $(uname -m)"; exit 1;; esac; }
install_prereqs(){ pkg_update
  if [[ "$OS_FAMILY" == "debian" ]]; then pkg_install jq curl openssl iproute2 ca-certificates tar xz-utils coreutils
    command -v ufw >/dev/null 2>&1 || pkg_install ufw
    command -v setcap >/dev/null 2>&1 || pkg_install libcap2-bin
  else pkg_install jq curl openssl iproute ca-certificates tar xz coreutils
    command -v firewall-cmd >/dev/null 2>&1 || pkg_install firewalld
    command -v setcap >/dev/null 2>&1 || pkg_install libcap
  fi
}
fetch_latest_url(){ local GOARCH="$1"
  curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest \
  | jq -r ".assets[] | select(.name|test(\"linux-${GOARCH}\\\\.(tar\\\\.(xz|gz))$\")) | .browser_download_url" | head -n1; }
install_singbox(){ install_prereqs
  if [[ -x "$BIN_PATH" ]]; then info "检测到 sing-box：$("$BIN_PATH" version 2>/dev/null || echo 已安装)"; return 0; fi
  local GOARCH url tmp tarfile bin; GOARCH=$(arch_map); url=$(fetch_latest_url "$GOARCH")
  [[ -n "$url" ]] || { err "获取 sing-box 下载地址失败"; exit 1; }
  info "下载 sing-box (${GOARCH}) ..."; tmp="$(mktemp -d)"; tarfile="$tmp/sb.tar"
  curl -fsSL "$url" -o "$tarfile"; mkdir -p "$tmp/x"
  if file "$tarfile" | grep -qi xz; then tar -xJf "$tarfile" -C "$tmp/x"; else tar -xzf "$tarfile" -C "$tmp/x"; fi
  bin="$(find "$tmp/x" -type f -name sing-box -perm -u+x | head -n1 || true)"; [[ -n "$bin" ]] || { err "未找到 sing-box 可执行文件"; exit 1; }
  install -m0755 "$bin" "$BIN_PATH"; setcap 'cap_net_bind_service=+ep' "$BIN_PATH" 2>/dev/null || true
  info "已安装：$("$BIN_PATH" version 2>/dev/null || echo sing-box)"; rm -rf "$tmp"
}

# ================ 端口（18 个互不重复） ================
PORTS=(); gen_port(){ while :; do p=$(( ( RANDOM % 55536 ) + 10000 )); [[ $p -le 65535 ]] || continue; [[ ! " ${PORTS[*]} " =~ " $p " ]] && { PORTS+=("$p"); echo "$p"; return; }; done; }; rand_ports_reset(){ PORTS=(); }

# 直出 9
PORT_VLESSR=""; PORT_VLESS_GRPCR=""; PORT_TROJANR=""; PORT_HY2=""; PORT_VMESS_WS=""
PORT_HY2_OBFS=""; PORT_SS2022=""; PORT_SS=""; PORT_TUIC=""
# WARP 9
PORT_VLESSR_W=""; PORT_VLESS_GRPCR_W=""; PORT_TROJANR_W=""; PORT_HY2_W=""; PORT_VMESS_WS_W=""
PORT_HY2_OBFS_W=""; PORT_SS2022_W=""; PORT_SS_W=""; PORT_TUIC_W=""

save_ports(){
cat > "$SB_DIR/ports.env" <<EOF
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
load_ports(){ safe_source_env "$SB_DIR/ports.env" || return 1; }
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
  # warp 9
  [[ -z "${PORT_VLESSR_W:-}" ]] && PORT_VLESSR_W=$(gen_port)
  [[ -z "${PORT_VLESS_GRPCR_W:-}" ]] && PORT_VLESS_GRPCR_W=$(gen_port)
  [[ -z "${PORT_TROJANR_W:-}" ]] && PORT_TROJANR_W=$(gen_port)
  [[ -z "${PORT_HY2_W:-}" ]] && PORT_HY2_W=$(gen_port)
  [[ -z "${PORT_VMESS_WS_W:-}" ]] && PORT_VMESS_WS_W=$(gen_port)
  [[ -z "${PORT_HY2_OBFS_W:-}" ]] && PORT_HY2_OBFS_W=$(gen_port)
  [[ -z "${PORT_SS2022_W:-}" ]] && PORT_SS2022_W=$(gen_port)
  [[ -z "${PORT_SS_W:-}" ]] && PORT_SS_W=$(gen_port)
  [[ -z "${PORT_TUIC_W:-}" ]] && PORT_TUIC_W=$(gen_port)
  save_ports
}

# ================ env / creds / warp ================
save_env(){ cat > "$SB_DIR/env.conf" <<EOF
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
load_env(){ safe_source_env "$SB_DIR/env.conf" || true; }

save_creds(){ cat > "$SB_DIR/creds.env" <<EOF
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
load_creds(){ safe_source_env "$SB_DIR/creds.env" || return 1; }

# warp.env
save_warp(){ cat > "$SB_DIR/warp.env" <<EOF
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
load_warp(){ safe_source_env "$SB_DIR/warp.env" || return 1; }

# ================ 凭据 & 证书生成 ================
rand_hex8(){ head -c 8 /dev/urandom | xxd -p; }
rand_b64_32(){ openssl rand -base64 32 | tr -d "\n"; }
gen_uuid(){
  local u=""
  if [[ -x "$BIN_PATH" ]]; then u=$("$BIN_PATH" generate uuid 2>/dev/null | head -n1); fi
  if [[ -z "$u" ]] && command -v uuidgen >/dev/null 2>&1; then u=$(uuidgen | head -n1); fi
  if [[ -z "$u" ]]; then u=$(cat /proc/sys/kernel/random/uuid | head -n1); fi
  printf "%s" "$u" | tr -d "\r\n"
}
gen_reality(){ "$BIN_PATH" generate reality-keypair; }
mk_cert(){ local crt="$CERT_DIR/fullchain.pem" key="$CERT_DIR/key.pem"
  if [[ ! -s "$crt" || ! -s "$key" ]]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 3650 -nodes \
      -keyout "$key" -out "$crt" -subj "/CN=$REALITY_SERVER" \
      -addext "subjectAltName=DNS:$REALITY_SERVER" >/dev/null 2>&1
  fi
}
ensure_creds(){
  [[ -z "${UUID:-}" ]] && UUID=$(gen_uuid)
  if ! is_uuid "$UUID"; then UUID=$(gen_uuid); fi
  [[ -z "${HY2_PWD:-}" ]] && HY2_PWD=$(rand_b64_32)
  if [[ -z "${REALITY_PRIV:-}" || -z "${REALITY_PUB:-}" || -z "${REALITY_SID:-}" ]]; then
    readarray -t RKP < <(gen_reality)
    REALITY_PRIV=$(printf "%s\n" "${RKP[@]}" | awk "/PrivateKey/{print \$2}")
    REALITY_PUB=$(printf "%s\n" "${RKP[@]}" | awk "/PublicKey/{print \$2}")
    REALITY_SID=$(rand_hex8)
  fi
  [[ -z "${HY2_PWD2:-}" ]] && HY2_PWD2=$(rand_b64_32)
  [[ -z "${HY2_OBFS_PWD:-}" ]] && HY2_OBFS_PWD=$(openssl rand -base64 16 | tr -d "\n")
  [[ -z "${SS2022_KEY:-}" ]] && SS2022_KEY=$(rand_b64_32)
  [[ -z "${SS_PWD:-}" ]] && SS_PWD=$(openssl rand -base64 24 | tr -d "=\n" | tr "+/" "-_")
  TUIC_UUID="$UUID"; TUIC_PWD="$UUID"
  save_creds
}

# ================ WARP（wgcf） ================
WGCF_BIN=/usr/local/bin/wgcf
install_wgcf(){
  [[ -x "$WGCF_BIN" ]] && return 0
  local GOA url tmp
  case "$(arch_map)" in
    amd64) GOA=amd64;;
    arm64) GOA=arm64;;
    armv7) GOA=armv7;;
    386)   GOA=386;;
    *)     GOA=amd64;;
  esac
  url=$(curl -fsSL https://api.github.com/repos/ViRb3/wgcf/releases/latest \
        | jq -r ".assets[] | select(.name|test(\"linux_${GOA}$\")) | .browser_download_url" | head -n1)
  [[ -n "$url" ]] || { warn "获取 wgcf 失败"; return 1; }
  tmp=$(mktemp -d); curl -fsSL "$url" -o "$tmp/wgcf"; install -m0755 "$tmp/wgcf" "$WGCF_BIN"; rm -rf "$tmp"
}
ensure_warp_profile(){
  [[ "$ENABLE_WARP" == "true" ]] || return 0
  if load_warp 2>/dev/null; then return 0; fi
  install_wgcf || { warn "wgcf 安装失败，已自动禁用 WARP 节点"; ENABLE_WARP=false; save_env; return 0; }
  local wd="$SB_DIR/wgcf"; mkdir -p "$wd"
  if [[ ! -f "$wd/wgcf-account.toml" ]]; then "$WGCF_BIN" register --accept-tos --config "$wd/wgcf-account.toml" >/dev/null; fi
  "$WGCF_BIN" generate --config "$wd/wgcf-account.toml" --profile "$wd/wgcf-profile.conf" >/dev/null
  local prof="$wd/wgcf-profile.conf"
  WARP_PRIVATE_KEY=$(awk -F'= ' '/PrivateKey/{print $2}' "$prof")
  WARP_PEER_PUBLIC_KEY=$(awk -F'= ' '/PublicKey/{print $2}' "$prof")
  local ep; ep=$(awk -F'= ' '/Endpoint/{print $2}' "$prof")
  WARP_ENDPOINT_HOST=${ep%:*}; WARP_ENDPOINT_PORT=${ep##*:}
  local ad; ad=$(awk -F'= ' '/Address/{print $2}' "$prof" | tr -d " ")
  WARP_ADDRESS_V4=${ad%%,*}; WARP_ADDRESS_V6=${ad##*,}
  local rs; rs=$(awk -F'= ' '/Reserved/{print $2}' "$prof" | tr -d " ")
  WARP_RESERVED_1=${rs%%,*}; rs=${rs#*,}; WARP_RESERVED_2=${rs%%,*}; WARP_RESERVED_3=${rs##*,}
  save_warp
}

# ================ systemd ================
write_systemd(){ cat > "/etc/systemd/system/${SYSTEMD_SERVICE}" <<EOF
[Unit]
Description=Sing-Box (Native 18 nodes)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=${BIN_PATH} -D ${DATA_DIR} -C ${SB_DIR} run
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload; systemctl enable "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true; }

# ================ 写 config.json（18 入站 + WARP 出站 + 路由） ================
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
  def inbound_vless(port): {type:"vless", listen:"0.0.0.0", listen_port:port, users:[{uuid:$UID}], tls:{enabled:true, server_name:$RS, reality:{enabled:true, handshake:{server:$RS, server_port:$RSP}, private_key:$RPR, short_id:[$SID]}}};
  def inbound_vless_flow(port): {type:"vless", listen:"0.0.0.0", listen_port:port, users:[{uuid:$UID, flow:"xtls-rprx-vision"}], tls:{enabled:true, server_name:$RS, reality:{enabled:true, handshake:{server:$RS, server_port:$RSP}, private_key:$RPR, short_id:[$SID]}}};
  def inbound_trojan(port): {type:"trojan", listen:"0.0.0.0", listen_port:port, users:[{password:$UID}], tls:{enabled:true, server_name:$RS, reality:{enabled:true, handshake:{server:$RS, server_port:$RSP}, private_key:$RPR, short_id:[$SID]}}};
  def inbound_hy2(port): {type:"hysteria2", listen:"0.0.0.0", listen_port:port, users:[{name:"hy2", password:$HY2}], tls:{enabled:true, certificate_path:$CRT, key_path:$KEY}};
  def inbound_vmess_ws(port): {type:"vmess", listen:"0.0.0.0", listen_port:port, users:[{uuid:$UID}], transport:{type:"ws", path:$VMWS}};
  def inbound_hy2_obfs(port): {type:"hysteria2", listen:"0.0.0.0", listen_port:port, users:[{name:"hy2", password:$HY22}], obfs:{type:"salamander", password:$HY2O}, tls:{enabled:true, certificate_path:$CRT, key_path:$KEY, alpn:["h3"]}};
  def inbound_ss2022(port): {type:"shadowsocks", listen:"0.0.0.0", listen_port:port, method:"2022-blake3-aes-256-gcm", password:$SS2022};
  def inbound_ss(port): {type:"shadowsocks", listen:"0.0.0.0", listen_port:port, method:"aes-256-gcm", password:$SSPWD};
  def inbound_tuic(port): {type:"tuic", listen:"0.0.0.0", listen_port:port, users:[{uuid:$TUICUUID, password:$TUICPWD}], congestion_control:"bbr", tls:{enabled:true, certificate_path:$CRT, key_path:$KEY, alpn:["h3"]}};

  {
    log:{level:"info", timestamp:true},
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
      if $ENABLE_WARP=="true" and ($WPRIV|length)>0 then
        [
          {type:"direct", tag:"direct"},
          {type:"block", tag:"block"},
          {type:"wireguard", tag:"warp",
            server:$WHOST, server_port:$WPORT,
            local_address: [ $W4, $W6 ],
            private_key:$WPRIV, peer_public_key:$WPPUB,
            reserved: [ $WR1, $WR2, $WR3 ],
            mtu:1280, persistent_keepalive:25
          }
        ]
      else
        [{type:"direct", tag:"direct"}, {type:"block", tag:"block"}]
      end
    ),
    route: (
      if $ENABLE_WARP=="true" and ($WPRIV|length)>0 then
        { rules:[
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

# ================ 防火墙 ================
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
    for r in "${rules[@]}"; do p="${r%/*}"; proto="${r#*/}";
      if [[ "$proto" == tcp ]]; then iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$p" -j ACCEPT; fi
      if [[ "$proto" == udp ]]; then iptables -C INPUT -p udp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport "$p" -j ACCEPT; fi
    done
    command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
  fi
}

# ================ 分享链接（18 条） ================
print_links(){
  load_env; load_creds; load_ports; local ip; ip=$(get_ip); local links=()
  # 直出 9
  links+=("vless://${UUID}@${ip}:${PORT_VLESSR}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#vless-reality")
  links+=("vless://${UUID}@${ip}:${PORT_VLESS_GRPCR}?encryption=none&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=grpc&serviceName=${GRPC_SERVICE}#vless-grpc-reality")
  links+=("trojan://${UUID}@${ip}:${PORT_TROJANR}?security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#trojan-reality")
  links+=("hy2://$(urlenc "${HY2_PWD}")@${ip}:${PORT_HY2}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#hysteria2")
  links+=("vmess://$(printf "%s" "{\"v\":\"2\",\"ps\":\"vmess-ws\",\"add\":\"${ip}\",\"port\":\"${PORT_VMESS_WS}\",\"id\":\"${UUID}\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"\",\"path\":\"${VMESS_WS_PATH}\",\"tls\":\"\"}" | base64 -w 0 2>/dev/null || base64 | tr -d "\n")")
  links+=("hy2://$(urlenc "${HY2_PWD2}")@${ip}:${PORT_HY2_OBFS}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}&alpn=h3&obfs=salamander&obfs-password=$(urlenc "${HY2_OBFS_PWD}")#hysteria2-obfs")
  links+=("ss://$(printf "%s" "2022-blake3-aes-256-gcm:${SS2022_KEY}" | base64 -w 0 2>/dev/null || base64 | tr -d "\n")@${ip}:${PORT_SS2022}#ss2022")
  links+=("ss://$(printf "%s" "aes-256-gcm:${SS_PWD}" | base64 -w 0 2>/dev/null || base64 | tr -d "\n")@${ip}:${PORT_SS}#ss")
  links+=("tuic://${UUID}:$(urlenc "${UUID}")@${ip}:${PORT_TUIC}?congestion_control=bbr&alpn=h3&insecure=1&sni=${REALITY_SERVER}#tuic-v5")

  # WARP 9
  links+=("vless://${UUID}@${ip}:${PORT_VLESSR_W}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#vless-reality-warp")
  links+=("vless://${UUID}@${ip}:${PORT_VLESS_GRPCR_W}?encryption=none&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=grpc&serviceName=${GRPC_SERVICE}#vless-grpc-reality-warp")
  links+=("trojan://${UUID}@${ip}:${PORT_TROJANR_W}?security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#trojan-reality-warp")
  links+=("hy2://$(urlenc "${HY2_PWD}")@${ip}:${PORT_HY2_W}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#hysteria2-warp")
  links+=("vmess://$(printf "%s" "{\"v\":\"2\",\"ps\":\"vmess-ws-warp\",\"add\":\"${ip}\",\"port\":\"${PORT_VMESS_WS_W}\",\"id\":\"${UUID}\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"\",\"path\":\"${VMESS_WS_PATH}\",\"tls\":\"\"}" | base64 -w 0 2>/dev/null || base64 | tr -d "\n")")
  links+=("hy2://$(urlenc "${HY2_PWD2}")@${ip}:${PORT_HY2_OBFS_W}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}&alpn=h3&obfs=salamander&obfs-password=$(urlenc "${HY2_OBFS_PWD}")#hysteria2-obfs-warp")
  links+=("ss://$(printf "%s" "2022-blake3-aes-256-gcm:${SS2022_KEY}" | base64 -w 0 2>/dev/null || base64 | tr -d "\n")@${ip}:${PORT_SS2022_W}#ss2022-warp")
  links+=("ss://$(printf "%s" "aes-256-gcm:${SS_PWD}" | base64 -w 0 2>/dev/null || base64 | tr -d "\n")@${ip}:${PORT_SS_W}#ss-warp")
  links+=("tuic://${UUID}:$(urlenc "${UUID}")@${ip}:${PORT_TUIC_W}?congestion_control=bbr&alpn=h3&insecure=1&sni=${REALITY_SERVER}#tuic-v5-warp")

  echo -e "${C_BLUE}${C_BOLD}分享链接（18 个）${C_RESET}"; hr; for l in "${links[@]}"; do echo "  $l"; done; hr
}

# ================ 运维功能 ================
restart_service(){ systemctl restart "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true; echo -e "${C_GREEN}已重启${C_RESET}"; }
rotate_ports(){
  load_env; load_creds || { err "未找到凭据"; return 1; }
  PORTS=()
  PORT_VLESSR=$(gen_port); PORT_VLESS_GRPCR=$(gen_port); PORT_TROJANR=$(gen_port); PORT_HY2=$(gen_port); PORT_VMESS_WS=$(gen_port)
  PORT_HY2_OBFS=$(gen_port); PORT_SS2022=$(gen_port); PORT_SS=$(gen_port); PORT_TUIC=$(gen_port)
  PORT_VLESSR_W=$(gen_port); PORT_VLESS_GRPCR_W=$(gen_port); PORT_TROJANR_W=$(gen_port); PORT_HY2_W=$(gen_port); PORT_VMESS_WS_W=$(gen_port)
  PORT_HY2_OBFS_W=$(gen_port); PORT_SS2022_W=$(gen_port); PORT_SS_W=$(gen_port); PORT_TUIC_W=$(gen_port)
  save_ports; write_config; "$BIN_PATH" check -c "$CONF_JSON"; systemctl restart "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true; open_firewall
  echo -e "${C_GREEN}端口已全部更换${C_RESET}"
}
enable_bbr(){
  modprobe tcp_bbr 2>/dev/null || true
  cat > /etc/sysctl.d/99-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  sysctl -p /etc/sysctl.d/99-bbr.conf >/dev/null 2>&1 || true
  echo -e "${C_GREEN}BBR 已启用${C_RESET}"
}
uninstall_all(){
  read "${READ_OPTS[@]}" -p "确认卸载并删除 ${SB_DIR} ? (y/N): " yn || true
  [[ "${yn,,}" == y ]] || { echo "已取消"; return; }
  systemctl disable "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true
  systemctl stop "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/${SYSTEMD_SERVICE}"; systemctl daemon-reload || true
  rm -rf "$SB_DIR" "$BIN_PATH"
  echo -e "${C_GREEN}已卸载${C_RESET}"
}

# ================ 部署流程 & 菜单 ================
deploy_native(){
  install_singbox
  write_config
  info "检查配置 ..."; "$BIN_PATH" check -c "$CONF_JSON"
  info "写入并启用 systemd 服务 ..."; write_systemd; systemctl restart "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true
  open_firewall
  echo; echo -e "${C_BOLD}${C_GREEN}★ 部署完成（18 节点）${C_RESET}"; echo
  print_links
  echo; read "${READ_OPTS[@]}" -p "按回车返回菜单..." _ || true
}
menu(){
  banner
  echo -e "  ${C_GREEN}1)${C_RESET} 安装/部署（18 节点）"
  echo -e "  ${C_GREEN}2)${CRESET} 查看分享链接"
  echo -e "  ${C_GREEN}3)${CRESET} 重启服务"
  echo -e "  ${C_GREEN}4)${CRESET} 一键更换所有端口"
  echo -e "  ${C_GREEN}5)${CRESET} 一键开启 BBR"
  echo -e "  ${C_GREEN}8)${CRESET} 卸载"
  echo -e "  ${C_GREEN}0)${CRESET} 退出"
  hr
  read "${READ_OPTS[@]}" -p "选择: " op || true
  case "${op:-}" in
    1) deploy_native;;
    2) print_links; read -p "回车返回..." _ || true;;
    3) restart_service;;
    4) rotate_ports;;
    5) enable_bbr;;
    8) uninstall_all;;
    0) exit 0;;
    *) :;;
  esac
}

# ================ 入口 ================
need_root; pkg_detect; ensure_dirs
save_env
load_creds || true; ensure_creds
load_ports || true; save_all_ports
while true; do menu; done
