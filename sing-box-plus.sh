#!/usr/bin/env bash
# -------------------------------------------------------
# Sing-Box Native Manager (Reality + HY2 + VMess WS + SS + SS2022 + TUIC)
# Author: ported from Docker version by Alvin9999; native rewrite with jq-safe JSON
# OS: Debian / Ubuntu / CentOS / RHEL / Rocky / Alma
# Version:
SCRIPT_NAME="Sing-Box Native Manager"
SCRIPT_VERSION="v1.5.0-native (jq-safe)"
# -------------------------------------------------------
set -euo pipefail

########################  颜色  ########################
C_RESET="\033[0m"; C_BOLD="\033[1m"; C_DIM="\033[2m"
C_RED="\033[31m";  C_GREEN="\033[32m"; C_YELLOW="\033[33m"
C_BLUE="\033[34m"; C_CYAN="\033[36m"
: "${CRESET:=$C_RESET}"

hr(){ printf "${C_DIM}──────────────────────────────────────────────────────────${C_RESET}\n"; }
banner(){ clear; echo -e "${C_CYAN}${C_BOLD}$SCRIPT_NAME ${SCRIPT_VERSION}${C_RESET}"; hr; }

########################  输入修复  ########################
READ_OPTS=(-e -r)
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

########################  选项与默认  ########################
SB_DIR=${SB_DIR:-/opt/sing-box}          # 配置/证书/数据目录
DATA_DIR="${SB_DIR}/data"
CERT_DIR="${SB_DIR}/cert"
TOOLS_DIR="${SB_DIR}/tools"
CONF_JSON="${SB_DIR}/config.json"

BIN_PATH=${BIN_PATH:-/usr/local/bin/sing-box}
SYSTEMD_SERVICE=${SYSTEMD_SERVICE:-sing-box.service}

# 协议开关
ENABLE_VLESS_REALITY=${ENABLE_VLESS_REALITY:-true}
ENABLE_VLESS_GRPCR=${ENABLE_VLESS_GRPCR:-true}
ENABLE_TROJAN_REALITY=${ENABLE_TROJAN_REALITY:-true}
ENABLE_HYSTERIA2=${ENABLE_HYSTERIA2:-true}
ENABLE_VMESS_WS=${ENABLE_VMESS_WS:-true}
ENABLE_HY2_OBFS=${ENABLE_HY2_OBFS:-true}
ENABLE_SS2022=${ENABLE_SS2022:-true}
ENABLE_SS=${ENABLE_SS:-true}
ENABLE_TUIC=${ENABLE_TUIC:-true}

# Reality/其他细节
REALITY_SERVER=${REALITY_SERVER:-www.microsoft.com}
REALITY_SERVER_PORT=${REALITY_SERVER_PORT:-443}
GRPC_SERVICE=${GRPC_SERVICE:-grpc}
VMESS_WS_PATH=${VMESS_WS_PATH:-/vm}

PLUS_RAW_URL="https://raw.githubusercontent.com/Alvin9999/Sing-Box-Plus/main/sing-box-plus.sh"
PLUS_LOCAL="${TOOLS_DIR}/sing-box-plus.sh"

########################  工具函数  ########################
info(){ echo -e "${C_GREEN}[信息]${C_RESET} $*"; }
warn(){ echo -e "${C_YELLOW}[警告]${C_RESET} $*"; }
err(){  echo -e "${C_RED}[错误]${C_RESET} $*"; }
need_root(){ [[ $EUID -eq 0 ]] || { err "请以 root 运行：bash $0"; exit 1; }; }
require_cmd(){ command -v "$1" >/dev/null 2>&1 || { err "缺少命令 $1"; exit 1; }; }

urlenc(){ local s="$1" o= c; for((i=0;i<${#s};i++)){ c="${s:i:1}"; case "$c" in [a-zA-Z0-9.~_-])o+="$c";;*)printf -v h '%%%02X' "'$c"; o+="$h";; esac; }; printf '%s' "$o"; }

OS_FAMILY=""; PKG=""
pkg_detect(){
  . /etc/os-release
  case "${ID,,}" in
    debian|ubuntu|linuxmint) OS_FAMILY="debian"; PKG="apt";;
    rhel|centos|rocky|almalinux|ol|fedora)
      if command -v dnf >/dev/null 2>&1; then OS_FAMILY="rhel"; PKG="dnf"; else OS_FAMILY="rhel"; PKG="yum"; fi;;
    *) err "暂不支持的系统: $ID"; exit 1;;
  esac
}
pkg_update(){
  case "$PKG" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true;;
    dnf) dnf makecache -y >/dev/null 2>&1 || true;;
    yum) yum makecache -y >/dev/null 2>&1 || true;;
  esac
}
pkg_install(){
  local pkgs=("$@")
  case "$PKG" in
    apt) apt-get install -y "${pkgs[@]}" >/dev/null 2>&1 || true;;
    dnf) dnf install -y "${pkgs[@]}" >/dev/null 2>&1 || true;;
    yum) yum install -y "${pkgs[@]}" >/dev/null 2>&1 || true;;
  esac
}

ensure_dirs(){ mkdir -p "$SB_DIR" "$DATA_DIR" "$TOOLS_DIR" "$CERT_DIR"; chmod 700 "$SB_DIR"; }

get_ip(){ curl -fsS4 https://ip.gs || curl -fsS4 https://ifconfig.me || echo "YOUR_SERVER_IP"; }

########################  安装 sing-box 二进制  ########################
arch_map(){
  local m; m=$(uname -m)
  case "$m" in
    x86_64|amd64) echo "amd64";;
    aarch64|arm64) echo "arm64";;
    armv7l|armv7) echo "armv7";;
    i386|i686) echo "386";;
    s390x) echo "s390x";;
    *) err "不支持的架构: $m"; exit 1;;
  esac
}
install_prereqs(){
  pkg_update
  if [[ "$OS_FAMILY" == "debian" ]]; then
    pkg_install jq curl openssl iproute2 ca-certificates tar xz-utils
    command -v ufw >/dev/null 2>&1 || pkg_install ufw
    command -v setcap >/dev/null 2>&1 || pkg_install libcap2-bin
  else
    pkg_install jq curl openssl iproute ca-certificates tar xz
    command -v firewall-cmd >/dev/null 2>&1 || pkg_install firewalld
    command -v setcap >/dev/null 2>&1 || pkg_install libcap
  fi
}
fetch_latest_url(){
  local GOARCH="$1"
  local url
  url=$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest \
        | jq -r ".assets[] | select(.name|test(\"linux-${GOARCH}\\\\.(tar\\\\.(xz|gz))$\")) | .browser_download_url" \
        | head -n1 || true)
  printf "%s" "${url:-}"
}
install_singbox(){
  install_prereqs
  if [[ -x "$BIN_PATH" ]]; then
    info "检测到 sing-box：$("$BIN_PATH" version 2>/dev/null || echo '已安装')"
    return 0
  fi
  local GOARCH; GOARCH=$(arch_map)
  local url; url=$(fetch_latest_url "$GOARCH")
  if [[ -z "$url" ]]; then
    err "未能自动获取 sing-box 最新版本下载地址，请稍后重试或手动安装。"
    exit 1
  fi
  info "下载 sing-box (${GOARCH}) ..."
  local tmpdir; tmpdir="$(mktemp -d)"
  local tarfile="${tmpdir}/sb.tar"
  curl -fsSL "$url" -o "$tarfile"
  mkdir -p "${tmpdir}/x"
  if file "$tarfile" | grep -qi xz; then
    tar -xJf "$tarfile" -C "${tmpdir}/x"
  else
    tar -xzf "$tarfile" -C "${tmpdir}/x"
  fi
  local bin; bin="$(find "${tmpdir}/x" -type f -name sing-box -perm -u+x | head -n1 || true)"
  [[ -n "$bin" ]] || { err "解包失败：未找到 sing-box 可执行文件"; exit 1; }
  install -m 0755 "$bin" "$BIN_PATH"
  setcap 'cap_net_bind_service=+ep' "$BIN_PATH" 2>/dev/null || true
  info "已安装：$("$BIN_PATH" version 2>/dev/null || echo 'sing-box')"
  rm -rf "$tmpdir"
}

########################  端口（五位随机且不重复）  ########################
PORTS=()
gen_port(){ while :; do p=$(( ( RANDOM % 55536 ) + 10000 )); [[ $p -le 65535 ]] || continue; [[ ! " ${PORTS[*]} " =~ " $p " ]] && { PORTS+=("$p"); echo "$p"; return; }; done; }
rand_ports_reset(){ PORTS=(); }

########################  保存/加载  ########################
save_env(){ cat > "${SB_DIR}/env.conf" <<EOF
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
  read "${READ_OPTS[@]}" -p "按回车返回菜单..." _ || true
}

########################  防火墙  ########################
_open_ufw(){
  local proto port; for it in "$@"; do proto="${it#*/}"; port="${it%/*}"; ufw allow "${port}/${proto}" >/dev/null 2>&1 || true; done
  ufw reload >/dev/null 2>&1 || true
}
_open_firewalld(){
  systemctl enable --now firewalld >/dev/null 2>&1 || true
  local proto port; for it in "$@"; do proto="${it#*/}"; port="${it%/*}"
    firewall-cmd --permanent --add-port="${port}/${proto}" >/dev/null 2>&1 || true
  done
  firewall-cmd --reload >/dev/null 2>&1 || true
}
_open_iptables(){
  local proto port; for it in "$@"; do proto="${it#*/}"; port="${it%/*}"
    [[ "$proto" == "tcp" ]] && iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$port" -j ACCEPT
    [[ "$proto" == "udp" ]] && iptables -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport "$port" -j ACCEPT
  done
  if [[ "$OS_FAMILY" == "debian" ]]; then
    pkg_install iptables-persistent >/dev/null 2>&1 || true
    command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
  else
    pkg_install iptables-services >/dev/null 2>&1 || true
    service iptables save >/dev/null 2>&1 || true
  fi
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

  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q -E "Status: active|状态： 活跃"; then
    info "检测到 UFW，放行端口..."
    _open_ufw "${rules[@]}"
  elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    info "检测到 Firewalld，放行端口..."
    _open_firewalld "${rules[@]}"
  else
    info "使用 iptables 放行端口..."
    _open_iptables "${rules[@]}"
  fi
}

########################  Systemd  ########################
write_systemd(){
cat > "/etc/systemd/system/${SYSTEMD_SERVICE}" <<EOF
[Unit]
Description=Sing-Box (Native)
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
  systemctl daemon-reload
  systemctl enable "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true
}

########################  生成凭据/端口/证书/配置  ########################
rand_hex8(){ head -c 8 /dev/urandom | xxd -p; }
rand_b64_32(){ openssl rand -base64 32 | tr -d '\n'; }
gen_uuid(){
  if [[ -x "$BIN_PATH" ]]; then "$BIN_PATH" generate uuid 2>/dev/null || true; fi
  command -v uuidgen >/dev/null 2>&1 && uuidgen || cat /proc/sys/kernel/random/uuid
}
gen_reality(){
  require_cmd "$BIN_PATH"
  "$BIN_PATH" generate reality-keypair
}
mk_cert(){
  local crt="${CERT_DIR}/fullchain.pem" key="${CERT_DIR}/key.pem"
  if [[ ! -s "$crt" || ! -s "$key" ]]; then
    info "生成自签证书 ..."
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 3650 -nodes \
      -keyout "$key" -out "$crt" -subj "/CN=$REALITY_SERVER" \
      -addext "subjectAltName=DNS:$REALITY_SERVER" >/dev/null 2>&1
  fi
}

PORT_VLESSR=""; PORT_VLESS_GRPCR=""; PORT_TROJANR=""; PORT_HY2=""; PORT_VMESS_WS=""
PORT_HY2_OBFS=""; PORT_SS2022=""; PORT_SS=""; PORT_TUIC=""

save_all_ports(){
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
}

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

  TUIC_UUID="$UUID"
  TUIC_PWD="$UUID"

  save_creds
}

# ★★★ 安全生成 config.json（用 jq，自动转义） ★★★
write_config(){
  ensure_dirs
  # 如因在 Windows 编辑过文件，先去掉 CRLF 的 \r
  sed -i 's/\r$//' "${SB_DIR}/"*.env 2>/dev/null || true

  load_env || true; load_creds || true; load_ports || true
  ensure_creds
  save_all_ports
  mk_cert
  local CRT="${CERT_DIR}/fullchain.pem" KEY="${CERT_DIR}/key.pem"

  jq -n \
    --arg RS "$REALITY_SERVER" \
    --argjson RSP "${REALITY_SERVER_PORT:-443}" \
    --arg UID "$UUID" \
    --arg RPR "$REALITY_PRIV" \
    --arg RPB "$REALITY_PUB" \
    --arg SID "$REALITY_SID" \
    --arg HY2 "$HY2_PWD" \
    --arg HY22 "$HY2_PWD2" \
    --arg HY2O "$HY2_OBFS_PWD" \
    --arg GRPC "$GRPC_SERVICE" \
    --arg VMWS "$VMESS_WS_PATH" \
    --arg CRT "$CRT" \
    --arg KEY "$KEY" \
    --arg SS2022 "$SS2022_KEY" \
    --arg SSPWD "$SS_PWD" \
    --arg TUICUUID "$TUIC_UUID" \
    --arg TUICPWD "$TUIC_PWD" \
    --argjson P1 "$PORT_VLESSR" \
    --argjson P2 "$PORT_VLESS_GRPCR" \
    --argjson P3 "$PORT_TROJANR" \
    --argjson P4 "$PORT_HY2" \
    --argjson P5 "$PORT_VMESS_WS" \
    --argjson P6 "$PORT_HY2_OBFS" \
    --argjson P7 "$PORT_SS2022" \
    --argjson P8 "$PORT_SS" \
    --argjson P9 "$PORT_TUIC" '
    {
      log:{level:"info", timestamp:true},
      inbounds:[
        {type:"vless", tag:"vless-reality", listen:"0.0.0.0", listen_port:$P1,
          users:[{uuid:$UID, flow:"xtls-rprx-vision"}],
          tls:{enabled:true, server_name:$RS,
            reality:{enabled:true, handshake:{server:$RS, server_port:$RSP},
                     private_key:$RPR, short_id:[$SID]}}},
        {type:"vless", tag:"vless-grpcr", listen:"0.0.0.0", listen_port:$P2,
          users:[{uuid:$UID}],
          tls:{enabled:true, server_name:$RS,
            reality:{enabled:true, handshake:{server:$RS, server_port:$RSP},
                     private_key:$RPR, short_id:[$SID]}},
          transport:{type:"grpc", service_name:$GRPC}},
        {type:"trojan", tag:"trojan-reality", listen:"0.0.0.0", listen_port:$P3,
          users:[{password:$UID}],
          tls:{enabled:true, server_name:$RS,
            reality:{enabled:true, handshake:{server:$RS, server_port:$RSP},
                     private_key:$RPR, short_id:[$SID]}}},
        {type:"hysteria2", tag:"hy2", listen:"0.0.0.0", listen_port:$P4,
          users:[{name:"hy2", password:$HY2}],
          tls:{enabled:true, certificate_path:$CRT, key_path:$KEY}},
        {type:"vmess", tag:"vmess-ws", listen:"0.0.0.0", listen_port:$P5,
          users:[{uuid:$UID}],
          transport:{type:"ws", path:$VMWS}},
        {type:"hysteria2", tag:"hy2-obfs", listen:"0.0.0.0", listen_port:$P6,
          users:[{name:"hy2", password:$HY22}],
          obfs:{type:"salamander", password:$HY2O},
          tls:{enabled:true, certificate_path:$CRT, key_path:$KEY, alpn:["h3"]}},
        {type:"shadowsocks", tag:"ss2022", listen:"0.0.0.0", listen_port:$P7,
          method:"2022-blake3-aes-256-gcm", password:$SS2022},
        {type:"shadowsocks", tag:"ss", listen:"0.0.0.0", listen_port:$P8,
          method:"aes-256-gcm", password:$SSPWD},
        {type:"tuic", tag:"tuic-v5", listen:"0.0.0.0", listen_port:$P9,
          users:[{uuid:$TUICUUID, password:$TUICPWD}],
          congestion_control:"bbr",
          tls:{enabled:true, certificate_path:$CRT, key_path:$KEY, alpn:["h3"]}}
      ],
      outbounds:[{type:"direct"},{type:"block"}]
    }' > "$CONF_JSON"

  save_env
}

########################  分享链接  ########################
print_links(){
  load_env; load_creds; load_ports
  local ip; ip=$(get_ip)
  local links=()

  links+=("vless://${UUID}@${ip}:${PORT_VLESSR}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#vless-reality")
  links+=("vless://${UUID}@${ip}:${PORT_VLESS_GRPCR}?encryption=none&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=grpc&serviceName=${GRPC_SERVICE}#vless-grpc-reality")
  links+=("trojan://${UUID}@${ip}:${PORT_TROJANR}?security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#trojan-reality")

  links+=("hy2://$(urlenc "${HY2_PWD}")@${ip}:${PORT_HY2}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#hysteria2")
  links+=("hy2://$(urlenc "${HY2_PWD2}")@${ip}:${PORT_HY2_OBFS}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}&alpn=h3&obfs=salamander&obfs-password=$(urlenc "${HY2_OBFS_PWD}")&obfsParam=$(urlenc "${HY2_OBFS_PWD}")#hysteria2-obfs")

  local VMESS_JSON; VMESS_JSON=$(cat <<JSON
{"v":"2","ps":"vmess-ws","add":"${ip}","port":"${PORT_VMESS_WS}","id":"${UUID}","aid":"0","net":"ws","type":"none","host":"","path":"${VMESS_WS_PATH}","tls":""}
JSON
)
  links+=("vmess://$(printf "%s" "$VMESS_JSON" | base64 -w 0 2>/dev/null || printf "%s" "$VMESS_JSON" | base64 | tr -d '\n')")

  links+=("tuic://${UUID}:$(urlenc "${UUID}")@${ip}:${PORT_TUIC}?congestion_control=bbr&alpn=h3&insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#tuic-v5")

  echo -e "${C_BLUE}${C_BOLD}分享链接（可直接导入 v2rayN）${C_RESET}"
  hr; for l in "${links[@]}"; do echo "  $l"; done; hr
}

########################  账号参数  ########################
print_manual_params(){
  load_env; load_creds; load_ports
  local ip; ip=$(get_ip)
  echo -e "${C_BLUE}${C_BOLD}账号参数（手动填写用）${C_RESET}"; hr
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
OK="${C_GREEN}✔${C_RESET}"; NO="${C_RED}✘${C_RESET}"
status_bar(){
  local svc_stat bbr_stat
  if systemctl is-active --quiet "${SYSTEMD_SERVICE}" 2>/dev/null; then svc_stat="${OK} 运行中"; else
    if pgrep -x sing-box >/dev/null 2>&1; then svc_stat="${OK} 运行中(非systemd)"; else svc_stat="${NO} 未运行"; fi
  fi
  local cc qd; cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "未知")
  qd=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "未知")
  if [[ "$cc" == "bbr" ]]; then bbr_stat="${OK} 已启用（bbr）"; else bbr_stat="${NO} 未启用（当前：${cc}，队列：${qd}）"; fi
  echo -e "${C_DIM}系统状态：${C_RESET} Sing-Box：${svc_stat}    BBR：${bbr_stat}"
}

########################  升级/清理  ########################
update_binary(){
  info "升级 sing-box 二进制 ..."
  rm -f "$BIN_PATH" 2>/dev/null || true
  install_singbox
  systemctl restart "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true
  echo; echo -e "${C_BOLD}${C_GREEN}★ 执行结果：二进制已更新${C_RESET}"
  read "${READ_OPTS[@]}" -p "按回车返回菜单..." _ || true
}
update_plus_script(){
  ensure_dirs; local tmp; tmp="$(mktemp)"
  if ! curl -fsSL "$PLUS_RAW_URL" -o "$tmp"; then
    echo -e "${C_BOLD}${C_RED}★ 执行结果：获取远程脚本失败${C_RESET}"; rm -f "$tmp"
  else
    if [[ -f "$PLUS_LOCAL" ]] && cmp -s "$PLUS_LOCAL" "$tmp"; then
      echo -e "${C_BOLD}${C_GREEN}★ 执行结果：脚本已是最新版（$PLUS_LOCAL）${C_RESET}"
    else
      install -m 0755 "$tmp" "$PLUS_LOCAL"
      echo -e "${C_BOLD}${C_GREEN}★ 执行结果：脚本已更新（$PLUS_LOCAL）${CRESET}"
    fi
    rm -f "$tmp"
  fi
  echo; read "${READ_OPTS[@]}" -p "按回车返回菜单..." _ || true
}

########################  核心操作（原生）  ########################
deploy_native(){
  install_singbox
  ensure_dirs; write_config
  info "检查配置 ..."
  "$BIN_PATH" check -c "$CONF_JSON"

  info "写入并启用 systemd 服务 ..."
  write_systemd
  systemctl restart "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true

  open_firewall
  echo; echo -e "${C_BOLD}${C_GREEN}★ 执行结果：部署完成（原生）${C_RESET}"; echo
  show_status_block; print_manual_params; print_links
  echo; read "${READ_OPTS[@]}" -p "按回车返回菜单，输入 q 退出: " x || true; [[ "${x:-}" == q ]] && exit 0
}
restart_service(){
  systemctl restart "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true
  echo; echo -e "${C_BOLD}${C_GREEN}★ 执行结果：服务已重启${C_RESET}"
  show_status_block
  echo; read "${READ_OPTS[@]}" -p "按回车返回菜单..." _ || true
}
rotate_ports(){
  load_env; load_creds || { err "未找到凭据，请先部署"; read "${READ_OPTS[@]}" -p "按回车返回菜单..." _ || true; return 1; }
  echo; info "随机更换所有端口 ..."
  PORTS=()
  PORT_VLESSR=$(gen_port); PORT_VLESS_GRPCR=$(gen_port); PORT_TROJANR=$(gen_port); PORT_HY2=$(gen_port); PORT_VMESS_WS=$(gen_port)
  PORT_HY2_OBFS=$(gen_port); PORT_SS2022=$(gen_port); PORT_SS=$(gen_port); PORT_TUIC=$(gen_port)
  save_ports; write_config
  "$BIN_PATH" check -c "$CONF_JSON"
  systemctl restart "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true
  open_firewall
  echo -e "${C_BOLD}${C_GREEN}★ 执行结果：端口已全部更换（五位随机且互不重复）${C_RESET}"
  show_status_block; print_manual_params; print_links
  echo; read "${READ_OPTS[@]}" -p "按回车返回菜单，输入 q 退出: " x || true; [[ "${x:-}" == q ]] && exit 0
}
uninstall_all(){
  read "${READ_OPTS[@]}" -p "确认卸载并删除 ${SB_DIR} ? (y/N): " yn || true
  [[ "${yn,,}" == y ]] || { echo "已取消"; read "${READ_OPTS[@]}" -p "按回车返回菜单..." _ || true; return; }
  systemctl disable "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true
  systemctl stop "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/${SYSTEMD_SERVICE}"
  systemctl daemon-reload || true
  rm -rf "$SB_DIR"
  rm -f "$BIN_PATH"
  echo; echo -e "${C_BOLD}${C_GREEN}★ 执行结果：已卸载完成${C_RESET}"; echo; read "${READ_OPTS[@]}" -p "按回车返回菜单..." _ || true
}

########################  UI  ########################
show_status_block(){
  load_env; load_ports || true
  local ip; ip=$(get_ip)
  echo -e "${C_BLUE}${C_BOLD}运行状态${C_RESET}"; hr
  echo -e "名称\t二进制\t状态" | column -t -s $'\t'
  local st="未运行"; systemctl is-active --quiet "${SYSTEMD_SERVICE}" && st="运行中" || { pgrep -x sing-box >/dev/null && st="运行中(非systemd)"; }
  echo -e "sing-box\t${BIN_PATH}\t${st}" | column -t -s $'\t'
  hr
  echo -e "${C_DIM}配置目录:${C_RESET} $SB_DIR"
  echo -e "${C_DIM}数据目录:${C_RESET} $DATA_DIR"
  echo -e "${C_DIM}服务器 IP:${C_RESET} $ip"
  echo
  echo -e "${C_BLUE}${C_BOLD}已启用协议与端口${C_RESET}"; hr
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

menu(){
  fix_tty; banner
  echo -e "${C_BOLD}${C_BLUE}================  管 理 菜 单  ================${C_RESET}"
  echo -e "  ${C_GREEN}1)${C_RESET} 安装/部署 Sing-Box（原生）"
  echo -e "  ${C_GREEN}2)${C_RESET} 查看状态 & 分享链接"
  echo -e "  ${C_GREEN}3)${C_RESET} 重启服务"
  echo -e "  ${C_GREEN}4)${C_RESET} 升级 Sing-Box 二进制"
  echo -e "  ${C_GREEN}5)${C_RESET} 更新脚本"
  echo -e "  ${C_GREEN}6)${C_RESET} 一键更换所有端口（五位随机且互不重复）"
  echo -e "  ${C_GREEN}7)${C_RESET} 一键开启 BBR 加速"
  echo -e "  ${C_GREEN}8)${C_RESET} 卸载"
  echo -e "  ${C_GREEN}0)${CRESET} 退出"
  echo -e "${C_BOLD}${C_BLUE}===============================================${C_RESET}"
  status_bar
  read "${READ_OPTS[@]}" -p "选择操作（回车退出）: " op || true
  [[ -z "${op:-}" ]] && exit 0
  case "$op" in
    1) deploy_native;;
    2) show_status_block; print_manual_params; print_links; echo; read "${READ_OPTS[@]}" -p "按回车返回菜单，输入 q 退出: " x || true; [[ "${x:-}" == q ]] && exit 0;;
    3) restart_service;;
    4) update_binary;;
    5) update_plus_script;;
    6) rotate_ports;;
    7) enable_bbr;;
    8) uninstall_all;;
    0) exit 0;;
    *) echo "无效选项"; sleep 1;;
  esac
}

########################  主入口  ########################
need_root; pkg_detect; pkg_update; ensure_dirs
while true; do menu; done
