#!/usr/bin/env bash
# ============================================================
#  Sing-Box-Plus 管理脚本（18 节点：直连 9 + WARP 9）
#  Version: v2.1.6
#  Repo:    https://github.com/Alvin9999/Sing-Box-Plus
#  说明：
#   - 保留稳定版的 18 节点实现逻辑与链接格式；
#   - 分享链接分两组输出（直连 9 / WARP 9），打印完即退出；
#   - 卸载完成后直接退出；
#   - SS2022 密钥标准 Base64，避免 “psk: illegal base64 …”；
#   - WARP Reserved 缺失时容错为 0,0,0；
#   - gen_uuid() 采用稳妥实现；状态栏/配色与菜单文案优化。
# ============================================================

set -Eeuo pipefail

# ===== 提前设默认，避免 set -u 早期引用未定义变量导致脚本直接退出 =====
SYSTEMD_SERVICE=${SYSTEMD_SERVICE:-sing-box.service}
BIN_PATH=${BIN_PATH:-/usr/local/bin/sing-box}
SB_DIR=${SB_DIR:-/opt/sing-box}
CONF_JSON=${CONF_JSON:-$SB_DIR/config.json}
DATA_DIR=${DATA_DIR:-$SB_DIR/data}
CERT_DIR=${CERT_DIR:-$SB_DIR/cert}
WGCF_DIR=${WGCF_DIR:-$SB_DIR/wgcf}

# 功能开关（保持稳定默认）
ENABLE_WARP=${ENABLE_WARP:-true}
ENABLE_VLESS_REALITY=${ENABLE_VLESS_REALITY:-true}
ENABLE_VLESS_GRPCR=${ENABLE_VLESS_GRPCR:-true}
ENABLE_TROJAN_REALITY=${ENABLE_TROJAN_REALITY:-true}
ENABLE_HYSTERIA2=${ENABLE_HYSTERIA2:-true}
ENABLE_VMESS_WS=${ENABLE_VMESS_WS:-true}
ENABLE_HY2_OBFS=${ENABLE_HY2_OBFS:-true}
ENABLE_SS2022=${ENABLE_SS2022:-true}
ENABLE_SS=${ENABLE_SS:-true}
ENABLE_TUIC=${ENABLE_TUIC:-true}

# 常量
SCRIPT_NAME="Sing-Box-Plus 管理脚本"
SCRIPT_VERSION="v2.1.6"
REALITY_SERVER=${REALITY_SERVER:-www.microsoft.com}
REALITY_SERVER_PORT=${REALITY_SERVER_PORT:-443}
GRPC_SERVICE=${GRPC_SERVICE:-grpc}
VMESS_WS_PATH=${VMESS_WS_PATH:-/vm}

# 兼容 sing-box 1.12.x 的旧 wireguard 出站
export ENABLE_DEPRECATED_WIREGUARD_OUTBOUND=${ENABLE_DEPRECATED_WIREGUARD_OUTBOUND:-true}

# ===== 颜色 =====
C_RESET="\033[0m"; C_BOLD="\033[1m"; C_DIM="\033[2m"
C_RED="\033[31m";  C_GREEN="\033[32m"; C_YELLOW="\033[33m"
C_BLUE="\033[34m"; C_CYAN="\033[36m"; C_MAGENTA="\033[35m"
hr(){ printf "${C_DIM}=============================================================${C_RESET}\n"; }

# ===== 基础工具 =====
info(){ echo -e "[${C_CYAN}信息${C_RESET}] $*"; }
warn(){ echo -e "[${C_YELLOW}警告${C_RESET}] $*"; }
die(){  echo -e "[${C_RED}错误${C_RESET}] $*" >&2; exit 1; }

# --- 架构映射：uname -m -> 发行资产名 ---
arch_map() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l|armv7) echo "armv7" ;;
    armv6l)       echo "armv7" ;;   # 上游无 armv6，回退 armv7
    i386|i686)    echo "386"  ;;
    *)            echo "amd64" ;;
  esac
}

# --- 依赖安装：兼容 apt / yum / dnf / apk / pacman / zypper ---
ensure_deps() {
  local pkgs=("$@") miss=()
  for p in "${pkgs[@]}"; do command -v "$p" >/dev/null 2>&1 || miss+=("$p"); done
  ((${#miss[@]}==0)) && return 0

  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y "${miss[@]}" || apt-get install -y --no-install-recommends "${miss[@]}"
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y "${miss[@]}"
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "${miss[@]}"
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache "${miss[@]}"
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm "${miss[@]}"
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install "${miss[@]}"
  else
    err "无法自动安装依赖：${miss[*]}，请手动安装后重试"
    return 1
  fi
}

b64enc(){ base64 -w 0 2>/dev/null || base64; }
urlenc(){ # 纯 bash urlencode（不依赖 python）
  local s="$1" out="" c
  for ((i=0; i<${#s}; i++)); do
    c=${s:i:1}
    case "$c" in
      [a-zA-Z0-9._~-]) out+="$c" ;;
      ' ') out+="%20" ;;
      *) printf -v out "%s%%%02X" "$out" "'$c" ;;
    esac
  done
  printf "%s" "$out"
}

safe_source_env(){ # 安全 source，忽略不存在文件
  local f="$1"; [[ -f "$f" ]] || return 1
  set +u; # 避免未定义变量报错
  # shellcheck disable=SC1090
  source "$f"
  set -u
}

get_ip(){ # 多源获取公网IP
  local ip
  ip=$(curl -fsSL ipv4.icanhazip.com || true)
  [[ -z "$ip" ]] && ip=$(curl -fsSL ifconfig.me || true)
  [[ -z "$ip" ]] && ip=$(curl -fsSL ip.sb || true)
  echo "${ip:-127.0.0.1}"
}

is_uuid(){ [[ "$1" =~ ^[0-9a-fA-F-]{36}$ ]]; }

ensure_dirs(){ mkdir -p "$SB_DIR" "$DATA_DIR" "$CERT_DIR" "$WGCF_DIR"; }

# ===== 端口（18 个互不重复） =====
PORTS=()
gen_port(){ while :; do p=$(( ( RANDOM % 55536 ) + 10000 )); [[ $p -le 65535 ]] || continue; [[ ! " ${PORTS[*]} " =~ " $p " ]] && { PORTS+=("$p"); echo "$p"; return; }; done; }
rand_ports_reset(){ PORTS=(); }

PORT_VLESSR=""; PORT_VLESS_GRPCR=""; PORT_TROJANR=""; PORT_HY2=""; PORT_VMESS_WS=""
PORT_HY2_OBFS=""; PORT_SS2022=""; PORT_SS=""; PORT_TUIC=""
PORT_VLESSR_W=""; PORT_VLESS_GRPCR_W=""; PORT_TROJANR_W=""; PORT_HY2_W=""; PORT_VMESS_WS_W=""
PORT_HY2_OBFS_W=""; PORT_SS2022_W=""; PORT_SS_W=""; PORT_TUIC_W=""

save_ports(){ cat > "$SB_DIR/ports.env" <<EOF
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

rand_hex8(){ head -c 8 /dev/urandom | xxd -p; }
rand_b64_32(){ openssl rand -base64 32 | tr -d "\n"; }

gen_uuid(){
  local u=""
  if [[ -x "$BIN_PATH" ]]; then u=$("$BIN_PATH" generate uuid 2>/dev/null | head -n1); fi
  if [[ -z "$u" ]] && command -v uuidgen >/dev/null 2>&1; then u=$(uuidgen | head -n1); fi
  if [[ -z "$u" ]]; then u=$(cat /proc/sys/kernel/random/uuid | head -n1); fi
  printf '%s' "$u" | tr -d '\r\n'
}
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
    REALITY_PRIV=$(printf "%s\n" "${RKP[@]}" | awk '/PrivateKey/{print $2}')
    REALITY_PUB=$(printf "%s\n" "${RKP[@]}" | awk '/PublicKey/{print $2}')
    REALITY_SID=$(rand_hex8)
  fi
  [[ -z "${HY2_PWD2:-}" ]] && HY2_PWD2=$(rand_b64_32)
  [[ -z "${HY2_OBFS_PWD:-}" ]] && HY2_OBFS_PWD=$(openssl rand -base64 16 | tr -d "\n")
  [[ -z "${SS2022_KEY:-}" ]] && SS2022_KEY=$(rand_b64_32)
  [[ -z "${SS_PWD:-}" ]] && SS_PWD=$(openssl rand -base64 24 | tr -d "=\n" | tr "+/" "-_")
  TUIC_UUID="$UUID"; TUIC_PWD="$UUID"
  save_creds
}

# ===== WARP（wgcf） =====
WGCF_BIN=/usr/local/bin/wgcf
install_wgcf(){
  [[ -x "$WGCF_BIN" ]] && return 0
  local GOA url tmp
  case "$(arch_map)" in
    amd64) GOA=amd64;; arm64) GOA=arm64;; armv7) GOA=armv7;; 386) GOA=386;; *) GOA=amd64;;
  esac
  url=$(curl -fsSL https://api.github.com/repos/ViRb3/wgcf/releases/latest \
        | jq -r ".assets[] | select(.name|test(\"linux_${GOA}$\")) | .browser_download_url" | head -n1)
  [[ -n "$url" ]] || { warn "获取 wgcf 下载地址失败"; return 1; }
  tmp=$(mktemp -d)
  curl -fsSL "$url" -o "$tmp/wgcf"
  install -m0755 "$tmp/wgcf" "$WGCF_BIN"
  rm -rf "$tmp"
}
ensure_warp_profile(){
  [[ "$ENABLE_WARP" == "true" ]] || return 0
  if load_warp 2>/dev/null; then return 0; fi
  install_wgcf || { warn "wgcf 安装失败，自动禁用 WARP 节点"; ENABLE_WARP=false; save_env; return 0; }
  local wd="$WGCF_DIR"; mkdir -p "$wd"
  if [[ ! -f "$wd/wgcf-account.toml" ]]; then "$WGCF_BIN" register --accept-tos --config "$wd/wgcf-account.toml" >/dev/null; fi
  "$WGCF_BIN" generate --config "$wd/wgcf-account.toml" --profile "$wd/wgcf-profile.conf" >/dev/null
  local prof="$wd/wgcf-profile.conf"

  WARP_PRIVATE_KEY=$(awk -F'= *' '/^PrivateKey/{gsub(/\r/,"");print $2}' "$prof")
  WARP_PEER_PUBLIC_KEY=$(awk -F'= *' '/^PublicKey/{gsub(/\r/,"");print $2}' "$prof")
  local ep; ep=$(awk -F'= *' '/^Endpoint/{gsub(/\r/,"");print $2;exit}' "$prof" | tr -d '"')
  local host port
  if [[ "$ep" =~ ^\[(.+)\]:(.+)$ ]]; then host="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"; else host="${ep%:*}"; port="${ep##*:}"; fi
  # 预解析域名 → IP（DoH）
  if [[ "$host" =~ [A-Za-z] ]]; then
    local ip4; ip4=$(curl -fsSL -H 'accept: application/dns-json' "https://1.1.1.1/dns-query?name=${host}&type=A" \
              | jq -r '.Answer[]? | select(.type==1) | .data' | head -n1 2>/dev/null || true)
    [[ -n "$ip4" ]] && host="$ip4"
  fi
  WARP_ENDPOINT_HOST="$host"
  WARP_ENDPOINT_PORT="$port"
  local ad; ad=$(awk -F'= *' '/^Address/{gsub(/\r/,"");print $2;exit}' "$prof" | tr -d '"')
  WARP_ADDRESS_V4="${ad%%,*}"
  WARP_ADDRESS_V6="${ad##*, }"
  local rs; rs=$(awk -F'= *' '/^Reserved/{gsub(/\r/,"");print $2;exit}' "$prof" | tr -d '" ')
  if [[ -n "$rs" && "$rs" == *","* ]]; then
    WARP_RESERVED_1="${rs%%,*}"; rs="${rs#*,}"; WARP_RESERVED_2="${rs%%,*}"; WARP_RESERVED_3="${rs##*,}"
  else
    WARP_RESERVED_1=0; WARP_RESERVED_2=0; WARP_RESERVED_3=0
  fi
  save_warp
}

# ===== 依赖与安装 =====
install_deps(){
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y ca-certificates curl wget jq tar iproute2 openssl coreutils uuid-runtime >/dev/null 2>&1 || true
}

# --- 安装 sing-box（通用且带回退，不再 404） ---
install_singbox() {
  umask 022
  : "${BIN_PATH:=/usr/local/bin/sing-box}"

  # 已安装直接跳过
  if command -v "$BIN_PATH" >/dev/null 2>&1; then
    info "检测到 sing-box：$("$BIN_PATH" version | head -n1)"
    return 0
  fi

  # 基础依赖
  ensure_deps curl jq tar || return 1
  # 某些资产会发 zip；装个 unzip（若没有）
  command -v unzip >/dev/null 2>&1 || ensure_deps unzip

  local repo="SagerNet/sing-box"
  local tag="${SINGBOX_TAG:-latest}"   # 可通过环境变量固定版本，比如 v1.12.7
  local api url tmp arch asset_regex found= ""

  arch="$(arch_map)"

  info "下载 sing-box (${arch}) ..."

  # 1) 解析版本 tag
  if [[ "$tag" == "latest" ]]; then
    tag="$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null | jq -r '.tag_name' || true)"
    # API 限流或失败时，用 302 跳转拿到真实 tag
    if [[ -z "$tag" || "$tag" == "null" ]]; then
      tag="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/${repo}/releases/latest" \
             | sed 's#^.*/tag/##' || true)"
    fi
  fi
  [[ -n "$tag" && "$tag" != "null" ]] || { err "获取 sing-box 版本失败"; return 1; }

  # 2) 在该 tag 里找匹配资产（优先 amd64，找不到再 amd64v3；其它架构直接单一匹配）
  api="https://api.github.com/repos/${repo}/releases/tags/${tag}"

  if [[ "$arch" == "amd64" ]]; then
    # 优先非 v3，防止老 CPU 无法运行；若没找到再尝试 v3
    for pattern in "linux-amd64" "linux-amd64v3"; do
      url="$(curl -fsSL "$api" 2>/dev/null \
            | jq -r --arg pat "$pattern" \
              '.assets[] | select(.name | test($pat + "(\\.tar\\.gz|\\.zip)$"))) | .browser_download_url' \
            | head -n1)"
      if [[ -n "$url" && "$url" != "null" ]]; then found=1; break; fi
    done
  else
    url="$(curl -fsSL "$api" 2>/dev/null \
          | jq -r --arg pat "linux-${arch}" \
            '.assets[] | select(.name | test($pat + "(\\.tar\\.gz|\\.zip)$"))) | .browser_download_url' \
          | head -n1)"
    [[ -n "$url" && "$url" != "null" ]] && found=1 || true
  fi

  # 3) API 失败或未找到 → 回退到 HTML 抓取（尽量稳）
  if [[ -z "$found" ]]; then
    # 构造正则：amd64 试两个；其它一次
    if [[ "$arch" == "amd64" ]]; then
      for pattern in "linux-amd64" "linux-amd64v3"; do
        url="$(curl -fsSL "https://github.com/${repo}/releases/expanded_assets/${tag}" 2>/dev/null \
              | grep -Eo "/${repo}/releases/download/${tag}/sing-box-[^\"']*-${pattern}\.(tar\.gz|zip)" \
              | head -n1 | sed "s#^#https://github.com#")"
        [[ -n "$url" ]] && { found=1; break; }
      done
    else
      url="$(curl -fsSL "https://github.com/${repo}/releases/expanded_assets/${tag}" 2>/dev/null \
            | grep -Eo "/${repo}/releases/download/${tag}/sing-box-[^\"']*-linux-${arch}\.(tar\.gz|zip)" \
            | head -n1 | sed "s#^#https://github.com#")"
      [[ -n "$url" ]] && found=1 || true
    fi
  fi

  [[ -n "$found" ]] || { err "下载 sing-box 失败（未找到 ${arch} 匹配资产）"; return 1; }

  # 4) 下载并解包安装
  tmp="$(mktemp -d)"
  if ! curl -fL "$url" -o "$tmp/pkg"; then
    rm -rf "$tmp"; err "下载 sing-box 失败"; return 1
  fi

  if file "$tmp/pkg" | grep -qi zip; then
    unzip -q "$tmp/pkg" -d "$tmp"
  else
    tar -xzf "$tmp/pkg" -f "$tmp/pkg" -C "$tmp"
  fi

  # 发行包通常是 ./sing-box 或 ./sing-box*/sing-box
  local bin
  bin="$(find "$tmp" -type f -name 'sing-box' | head -n1)"
  [[ -n "$bin" ]] || { rm -rf "$tmp"; err "安装包中未找到 sing-box 可执行文件"; return 1; }

  install -m0755 "$bin" "$BIN_PATH"
  rm -rf "$tmp"

  # 打印版本
  info "已安装：$("$BIN_PATH" version | head -n1)"
}
# ===== systemd =====
write_systemd(){ cat > "/etc/systemd/system/${SYSTEMD_SERVICE}" <<EOF
[Unit]
Description=Sing-Box (Native 18 nodes)
After=network-online.target
Requires=network-online.target

[Service]
Type=simple
Environment=ENABLE_DEPRECATED_WIREGUARD_OUTBOUND=true
ExecStart=${BIN_PATH} run -c ${CONF_JSON} -D ${DATA_DIR}
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true
}

# ===== 写 config.json（使用你提供的稳定配置逻辑） =====
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

# ===== 防火墙 =====
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

# ===== 分享链接（分组输出 + 提示） =====
print_links_grouped(){
  load_env; load_creds; load_ports
  local ip; ip=$(get_ip)
  local links_direct=() links_warp=()
  # 直连9
  links_direct+=("vless://${UUID}@${ip}:${PORT_VLESSR}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#vless-reality")
  links_direct+=("vless://${UUID}@${ip}:${PORT_VLESS_GRPCR}?encryption=none&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=grpc&serviceName=${GRPC_SERVICE}#vless-grpc-reality")
  links_direct+=("trojan://${UUID}@${ip}:${PORT_TROJANR}?security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#trojan-reality")
  links_direct+=("hy2://$(urlenc "${HY2_PWD}")@${ip}:${PORT_HY2}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#hysteria2")
  local VMESS_JSON; VMESS_JSON=$(cat <<JSON
{"v":"2","ps":"vmess-ws","add":"${ip}","port":"${PORT_VMESS_WS}","id":"${UUID}","aid":"0","net":"ws","type":"none","host":"","path":"${VMESS_WS_PATH}","tls":""}
JSON
  )
  links_direct+=("vmess://$(printf "%s" "$VMESS_JSON" | b64enc)")
  links_direct+=("hy2://$(urlenc "${HY2_PWD2}")@${ip}:${PORT_HY2_OBFS}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}&alpn=h3&obfs=salamander&obfs-password=$(urlenc "${HY2_OBFS_PWD}")#hysteria2-obfs")
  links_direct+=("ss://$(printf "%s" "2022-blake3-aes-256-gcm:${SS2022_KEY}" | b64enc)@${ip}:${PORT_SS2022}#ss2022")
  links_direct+=("ss://$(printf "%s" "aes-256-gcm:${SS_PWD}" | b64enc)@${ip}:${PORT_SS}#ss")
  links_direct+=("tuic://${UUID}:$(urlenc "${UUID}")@${ip}:${PORT_TUIC}?congestion_control=bbr&alpn=h3&insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#tuic-v5")

  # WARP 9
  links_warp+=("vless://${UUID}@${ip}:${PORT_VLESSR_W}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#vless-reality-warp")
  links_warp+=("vless://${UUID}@${ip}:${PORT_VLESS_GRPCR_W}?encryption=none&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=grpc&serviceName=${GRPC_SERVICE}#vless-grpc-reality-warp")
  links_warp+=("trojan://${UUID}@${ip}:${PORT_TROJANR_W}?security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#trojan-reality-warp")
  links_warp+=("hy2://$(urlenc "${HY2_PWD}")@${ip}:${PORT_HY2_W}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#hysteria2-warp")
  local VMESS_JSON_W; VMESS_JSON_W=$(cat <<JSON
{"v":"2","ps":"vmess-ws-warp","add":"${ip}","port":"${PORT_VMESS_WS_W}","id":"${UUID}","aid":"0","net":"ws","type":"none","host":"","path":"${VMESS_WS_PATH}","tls":""}
JSON
  )
  links_warp+=("vmess://$(printf "%s" "$VMESS_JSON_W" | b64enc)")
  links_warp+=("hy2://$(urlenc "${HY2_PWD2}")@${ip}:${PORT_HY2_OBFS_W}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}&alpn=h3&obfs=salamander&obfs-password=$(urlenc "${HY2_OBFS_PWD}")#hysteria2-obfs-warp")
  links_warp+=("ss://$(printf "%s" "2022-blake3-aes-256-gcm:${SS2022_KEY}" | b64enc)@${ip}:${PORT_SS2022_W}#ss2022-warp")
  links_warp+=("ss://$(printf "%s" "aes-256-gcm:${SS_PWD}" | b64enc)@${ip}:${PORT_SS_W}#ss-warp")
  links_warp+=("tuic://${UUID}:$(urlenc "${UUID}")@${ip}:${PORT_TUIC_W}?congestion_control=bbr&alpn=h3&insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#tuic-v5-warp")

  echo -e "${C_BLUE}${C_BOLD}分享链接（18 个）${C_RESET}"
  hr
  echo -e "${C_CYAN}${C_BOLD}【直连节点（9）】${C_RESET}（vless-reality / vless-grpc-reality / trojan-reality / vmess-ws / hy2 / hy2-obfs / ss2022 / ss / tuic）"
  for l in "${links_direct[@]}"; do echo "  $l"; done
  hr
  echo -e "${C_CYAN}${C_BOLD}【WARP 节点（9）】${C_RESET}（同上 9 种，带 -warp）"
  echo -e "${C_DIM}说明：带 -warp 的 9 个节点走 Cloudflare WARP 出口，流媒体解锁更友好${C_RESET}"
  echo -e "${C_DIM}提示：TUIC 默认 allowInsecure=1，v2rayN 导入即用${C_RESET}"
  for l in "${links_warp[@]}"; do echo "  $l"; done
  hr
}

# ===== BBR =====
enable_bbr(){
  if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
    info "BBR 已启用"
  else
    echo "net.core.default_qdisc=fq" >/etc/sysctl.d/99-bbr.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.d/99-bbr.conf
    sysctl --system >/dev/null 2>&1 || true
    info "已尝试开启 BBR（如内核不支持需自行升级）"
  fi
}

# ===== 显示状态与 banner =====
sb_service_state(){
  systemctl is-active --quiet "${SYSTEMD_SERVICE:-sing-box.service}" && echo -e "${C_GREEN}运行中${C_RESET}" || echo -e "${C_RED}未运行/未安装${C_RESET}"
}
bbr_state(){
  sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr && echo -e "${C_GREEN}已启用 BBR${C_RESET}" || echo -e "${C_RED}未启用 BBR${C_RESET}"
}

banner(){
  clear >/dev/null 2>&1 || true
  hr
  echo -e " ${C_CYAN}🚀 ${SCRIPT_NAME} ${SCRIPT_VERSION} 🚀${C_RESET}"
  echo -e " ${C_CYAN}脚本更新地址:${C_RESET} https://github.com/Alvin9999/Sing-Box-Plus"
  hr
  echo -e "系统加速状态：$(bbr_state)"
  echo -e "Sing-Box 启动状态：$(sb_service_state)"
  hr
  echo -e "  ${C_BLUE}1)${C_RESET} 安装/部署（18 节点）"
  echo -e "  ${C_GREEN}2)${C_RESET} 查看分享链接"
  echo -e "  ${C_GREEN}3)${C_RESET} 重启服务"
  echo -e "  ${C_GREEN}4)${C_RESET} 一键更换所有端口"
  echo -e "  ${C_GREEN}5)${C_RESET} 一键开启 BBR"
  echo -e "  ${C_RED}8)${C_RESET} 卸载"
  echo -e "  ${C_RED}0)${C_RESET} 退出"
  hr
}

# ===== 业务流程 =====
restart_service(){
  systemctl restart "${SYSTEMD_SERVICE}" || die "重启失败"
  systemctl --no-pager status "${SYSTEMD_SERVICE}" | sed -n '1,6p' || true
}

rotate_ports(){
  load_ports || true
  PORT_VLESSR=""; PORT_VLESS_GRPCR=""; PORT_TROJANR=""; PORT_HY2=""; PORT_VMESS_WS=""
  PORT_HY2_OBFS=""; PORT_SS2022=""; PORT_SS=""; PORT_TUIC=""
  PORT_VLESSR_W=""; PORT_VLESS_GRPCR_W=""; PORT_TROJANR_W=""; PORT_HY2_W=""; PORT_VMESS_WS_W=""
  PORT_HY2_OBFS_W=""; PORT_SS2022_W=""; PORT_SS_W=""; PORT_TUIC_W=""
  save_all_ports
  write_config
  restart_service
  info "已更换端口并重启。"
}

uninstall_all(){
  systemctl stop "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true
  systemctl disable "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/${SYSTEMD_SERVICE}"
  systemctl daemon-reload
  rm -rf "$SB_DIR"
  echo -e "${C_GREEN}已卸载并清理完成。${C_RESET}"
  exit 0
}

deploy_native(){
  install_deps
  install_singbox
  write_config
  info "检查配置 ..."
  ENABLE_DEPRECATED_WIREGUARD_OUTBOUND=true "$BIN_PATH" check -c "$CONF_JSON"
  info "写入并启用 systemd 服务 ..."
  write_systemd
  systemctl restart "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true
  open_firewall
  echo; echo -e "${C_BOLD}${C_GREEN}★ 部署完成（18 节点）${C_RESET}"; echo
  # 打印链接并直接退出
  print_links_grouped
  exit 0
}

ensure_installed_or_hint(){
  if [[ ! -f "$CONF_JSON" ]]; then
    warn "尚未安装，请先选择 1) 安装/部署（18 节点）"
    return 1
  fi
  return 0
}

# ===== 菜单 =====
menu(){
  banner
  read -rp "选择: " op || true
  case "${op:-}" in
    1) deploy_native ;;
    2) if ensure_installed_or_hint; then print_links_grouped; exit 0; fi ;;
    3) if ensure_installed_or_hint; then restart_service; fi; read -rp "回车返回..." _ || true; menu ;;
    4) if ensure_installed_or_hint; then rotate_ports; fi; read -rp "回车返回..." _ || true; menu ;;
    5) enable_bbr; read -rp "回车返回..." _ || true; menu ;;
    8) uninstall_all ;; # 直接退出
    0) exit 0 ;;
    *) menu ;;
  esac
}

# ===== 入口 =====
menu
