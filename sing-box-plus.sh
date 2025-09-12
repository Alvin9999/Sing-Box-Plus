#!/usr/bin/env bash
# -------------------------------------------------------
# Sing-Box Manager (Native, no Docker) — 9 协议一键部署
# Author: Alvin9999
# OS: Debian / Ubuntu / CentOS / RHEL / Rocky / Alma
# Version:
SCRIPT_NAME="Sing-Box 原生管理脚本"
SCRIPT_VERSION="v1.5.0-native"
# -------------------------------------------------------
set -euo pipefail

########################  颜色 / UI  ########################
C_RESET="\033[0m"; C_BOLD="\033[1m"; C_DIM="\033[2m"
C_RED="\033[31m";  C_GREEN="\033[32m"; C_YELLOW="\033[33m"
C_BLUE="\033[34m"; C_CYAN="\033[36m"
READ_OPTS=(-e -r)
LOG_FILE=${LOG_FILE:-/var/log/sing-box-plus.log}

hr(){ printf "${C_DIM}===============================================${C_RESET}\n"; }
info(){ echo -e "${C_GREEN}[信息]${C_RESET} $*"; }
warn(){ echo -e "${C_YELLOW}[警告]${C_RESET} $*"; }
err(){  echo -e "${C_RED}[错误]${C_RESET} $*"; }

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

########################  目录 / 常量  ########################
SB_ETC=/etc/sing-box
SB_LIB=/var/lib/sing-box
SB_BIN=/usr/local/bin/sing-box
CERT_DIR="$SB_ETC/cert"
TOOLS_DIR=/opt/sing-box/tools
mkdir -p "$SB_ETC" "$SB_LIB" "$CERT_DIR" "$TOOLS_DIR" 2>/dev/null || true
chmod 700 "$SB_ETC"

# 目标协议（保持 9 个类型；如需临时禁用，把 true 改 false）
ENABLE_VLESS_R=true          # 1) VLESS Reality TCP (vision)
ENABLE_VLESS_GRPCR=true      # 2) VLESS Reality gRPC
ENABLE_TROJAN_R=true         # 3) Trojan Reality TCP
ENABLE_HYSTERIA2=true        # 4) Hysteria2 (可含 obfs salamander)
ENABLE_TUIC=true             # 5) TUIC v5 (TLS+H3)
ENABLE_VMESS_WS=true         # 6) VMess WS
ENABLE_SS2022=true           # 7) Shadowsocks 2022 (TCP/UDP)
ENABLE_SHADOWTLS_SS=true     # 8) ShadowTLS v3 -> 本机 SS2022
ENABLE_VLESS_H2R=true        # 9) VLESS Reality HTTP/2 (H2R)

# 其它默认
REALITY_SNI=${REALITY_SNI:-www.microsoft.com}
GRPC_SERVICE=${GRPC_SERVICE:-grpc}
VMESS_WS_PATH=${VMESS_WS_PATH:-/vm}
HY2_OBFS=${HY2_OBFS:-true}
HY2_ALPN=${HY2_ALPN:-h3}
TUIC_ALPN=${TUIC_ALPN:-h3}
SS2022_METHOD="2022-blake3-aes-256-gcm"

########################  工具函数  ########################
need_root(){ [[ $EUID -eq 0 ]] || { err "请用 root 运行"; exit 1; }; }

detect_os_pm(){
  if command -v apt-get >/dev/null 2>&1; then OS_FAMILY=debian; PKG=apt
  elif command -v dnf >/devnull 2>&1; then OS_FAMILY=rhel; PKG=dnf
  elif command -v yum >/dev/null 2>&1; then OS_FAMILY=rhel; PKG=yum
  else OS_FAMILY=unknown; PKG=unknown; fi
}

pkg_update(){
  case "$PKG" in
    apt) export DEBIAN_FRONTEND=noninteractive
         apt-get update -y >/dev/null ;;
    dnf) dnf makecache -y -q >/dev/null || true ;;
    yum) yum makecache -y -q >/dev/null || true ;;
  esac
}
pkg_install(){ case "$PKG" in
  apt) apt-get install -y -qq "$@" >/dev/null ;;
  dnf) dnf install -y -q "$@" >/dev/null ;;
  yum) yum install -y -q "$@" >/dev/null ;;
esac; }

prefer_ipv4_begin(){
  if command -v apt-get >/dev/null 2>&1; then
    echo 'Acquire::ForceIPv4 "true";' >/etc/apt/apt.conf.d/99force-ipv4-sb 2>/dev/null || true
  fi
  export CURL_IPV4="-4"
}
prefer_ipv4_end(){ rm -f /etc/apt/apt.conf.d/99force-ipv4-sb 2>/dev/null || true; unset CURL_IPV4; }

wait_apt_lock(){
  local locks=(/var/lib/dpkg/lock-frontend /var/lib/dpkg/lock \
               /var/cache/apt/archives/lock /var/lib/apt/lists/lock)
  [[ "$PKG" == "apt" ]] || return 0
  echo -ne "${C_GREEN}[信息]${C_RESET} 正在等待系统释放 APT 锁 "
  while fuser "${locks[@]}" >/dev/null 2>&1; do printf "."; sleep 1; done
  echo
}

rand_port(){ shuf -i 10000-65535 -n 1; }
uuid(){ cat /proc/sys/kernel/random/uuid; }
rand_sid(){ hexdump -vn8 -e '8/1 "%02x"' /dev/urandom; }
rand_str(){ tr -dc 'A-Za-z0-9' </dev/urandom | head -c ${1:-24}; }

ensure_unique_ports(){
  local list=("$@") used="" v n
  for n in "${list[@]}"; do
    while :; do
      v="${!n:-}"; [[ -n "$v" ]] || v=$(rand_port)
      if [[ ! "$used" =~ (^|,)"$v"(,|$) ]]; then
        declare -g "$n=$v"; used="${used:+$used,}$v"; break
      fi
      v=
    done
  done
}

open_firewall(){
  # 入参：形如 "tcp:12345" "udp:23456" "both:30000"
  local item proto port
  for item in "$@"; do
    proto=${item%%:*}; port=${item##*:}
    case "$proto" in
      both)
        if command -v ufw >/dev/null 2>&1; then ufw allow "$port" >/dev/null 2>&1 || true
        elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
          firewall-cmd --permanent --add-port="$port/tcp" >/dev/null 2>&1 || true
          firewall-cmd --permanent --add-port="$port/udp" >/dev/null 2>&1 || true
        else
          iptables -I INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
          iptables -I INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || true
        fi
      ;;
      tcp|udp)
        if command -v ufw >/dev/null 2>&1; then ufw allow "$port"/"$proto" >/dev/null 2>&1 || true
        elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
          firewall-cmd --permanent --add-port="$port/$proto" >/dev/null 2>&1 || true
        else
          iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || true
        fi
      ;;
    esac
  done
  # firewalld 需要 reload
  if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
}

urlenc(){
  local s="$1" out="" c i
  local LC_ALL_B=${LC_ALL-}; local LC_CTYPE_B=${LC_CTYPE-}
  export LC_ALL=C LC_CTYPE=C
  for ((i=0; i<${#s}; i++)); do
    c="${s:i:1}"
    case "$c" in [a-zA-Z0-9.~_-]) out+="$c";; *) printf -v out '%s%%%02X' "$out" "'$c";; esac
  done
  [[ -n "${LC_ALL_B-}"  ]] && export LC_ALL="$LC_ALL_B"  || unset LC_ALL
  [[ -n "${LC_CTYPE_B-}" ]] && export LC_CTYPE="$LC_CTYPE_B" || unset LC_CTYPE
  printf '%s' "$out"
}

b64(){ printf '%s' "$1" | base64 -w0; }
pad(){ printf "%-20s" "$1"; }

title(){
  clear
  echo -e "${C_CYAN}${C_BOLD}${SCRIPT_NAME}${C_RESET}  ${C_DIM}${SCRIPT_VERSION}${C_RESET}"
  hr
}

status_bar(){
  local OK="${C_GREEN}✔${C_RESET}" NO="${C_RED}✘${C_RESET}" WAIT="${C_YELLOW}…${C_RESET}"
  local bbr cc qd; cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "未知")
  qd=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "未知")
  [[ "$cc" == "bbr" ]] && bbr="${OK} 已启用（bbr）" || bbr="${NO} 未启用（当前：$cc，队列：$qd）"
  local svc="sing-box" s; s=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
  case "$s" in active) s="${OK} 运行中";; inactive) s="${NO} 已停止";; failed) s="${NO} 启动失败";;
                activating) s="${WAIT} 启动中";; *) s="${NO} 未部署";; esac
  echo -e "${C_DIM}系统状态：${C_RESET} BBR：$bbr    Sing-Box：$s"
}

########################  安装 / 更新 sing-box  ########################
install_base(){
  detect_os_pm
  prefer_ipv4_begin; [[ "$PKG" == "apt" ]] && wait_apt_lock
  pkg_update
  case "$PKG" in
    apt) pkg_install curl jq openssl tar xz-utils iproute2 ca-certificates ufw || true ;;
    dnf) pkg_install curl jq openssl tar xz iproute ca-certificates firewalld || true ;;
    yum) pkg_install curl jq openssl tar xz iproute ca-certificates firewalld || true ;;
  esac
  prefer_ipv4_end
}

install_singbox_bin(){
  mkdir -p "$(dirname -- "$LOG_FILE")" 2>/dev/null || true
  : >"$LOG_FILE" 2>/dev/null || true
  local arch ver api assets url tgz tmpdir
  case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    armv7l) arch=armv7 ;;
    *) arch=amd64 ;;
  esac
  info "获取 sing-box 最新版本 ..."
  prefer_ipv4_begin
  api=$(curl -fsSL ${CURL_IPV4:-} https://api.github.com/repos/SagerNet/sing-box/releases/latest)
  ver=$(printf '%s' "$api" | jq -r '.tag_name' | sed 's/^v//')
  assets=$(printf '%s' "$api" | jq -r '.assets[].browser_download_url')
  url=$(printf '%s\n' "$assets" | grep -E "linux-${arch}\.tar\.gz$" | head -n1 || true)
  prefer_ipv4_end
  if [[ -z "${url:-}" || -z "${ver:-}" ]]; then
    err "获取版本失败，尝试备用下载（可能不是最新）"
    ver="1.9.6"
    url="https://github.com/SagerNet/sing-box/releases/download/v${ver}/sing-box-${ver}-linux-${arch}.tar.gz"
  fi
  info "下载并安装 sing-box v${ver} ..."
  prefer_ipv4_begin
  tgz="/tmp/sing-box-${ver}-linux-${arch}.tar.gz"
  curl -fsSL ${CURL_IPV4:-} -o "$tgz" "$url"
  tmpdir=$(mktemp -d)
  tar -xzf "$tgz" -C "$tmpdir"
  install -m 0755 "$tmpdir/sing-box-${ver}-linux-${arch}/sing-box" "$SB_BIN"
  rm -rf "$tgz" "$tmpdir"
  prefer_ipv4_end
  "$SB_BIN" version || true
}

########################  端口 / 凭据  ########################
randomize_ports(){
  # 9 个端口
  ensure_unique_ports \
    PORT_VLESS_R PORT_VLESS_GRPCR PORT_TROJAN_R PORT_HY2 \
    PORT_TUIC PORT_VMESS_WS PORT_SS2022 PORT_STLS PORT_STLS_SS PORT_VLESS_H2R
  cat > "$SB_ETC/ports.env" <<EOF
PORT_VLESS_R=${PORT_VLESS_R}
PORT_VLESS_GRPCR=${PORT_VLESS_GRPCR}
PORT_TROJAN_R=${PORT_TROJAN_R}
PORT_HY2=${PORT_HY2}
PORT_TUIC=${PORT_TUIC}
PORT_VMESS_WS=${PORT_VMESS_WS}
PORT_SS2022=${PORT_SS2022}
PORT_STLS=${PORT_STLS}
PORT_STLS_SS=${PORT_STLS_SS}
PORT_VLESS_H2R=${PORT_VLESS_H2R}
EOF
}
load_ports(){ [ -f "$SB_ETC/ports.env" ] && source "$SB_ETC/ports.env" || randomize_ports; }

gen_reality_keys(){
  if [ ! -f "$SB_ETC/reality.json" ]; then
    "$SB_BIN" generate reality-keypair > "$SB_ETC/reality.json"
  fi
  REAL_PRIV=$(jq -r '.PrivateKey' "$SB_ETC/reality.json")
  REAL_PUB=$(jq -r '.PublicKey'  "$SB_ETC/reality.json")
  SHORT_ID=${SHORT_ID:-$(rand_sid)}
}

gen_certs(){
  if [ ! -f "$CERT_DIR/fullchain.pem" ] || [ ! -f "$CERT_DIR/key.pem" ]; then
    info "生成自签证书 ..."
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -days 3650 -nodes \
      -keyout "$CERT_DIR/key.pem" \
      -out   "$CERT_DIR/fullchain.pem" \
      -subj "/CN=$REALITY_SNI" \
      -addext "subjectAltName=DNS:$REALITY_SNI" >/dev/null 2>&1
    chmod 600 "$CERT_DIR/key.pem"
  fi
}

########################  写配置（9 入站） ########################
write_config(){
  load_ports; gen_reality_keys; gen_certs

  UUID=${UUID:-$(uuid)}
  HY2_PASS=${HY2_PASS:-$(rand_str 20)}
  OBFS_PASS=${OBFS_PASS:-$(rand_str 16)}
  TUIC_ID=${TUIC_ID:-$(uuid)}; TUIC_PASS="$TUIC_ID"
  SS2022_KEY=${SS2022_KEY:-$(openssl rand -base64 32)}

  # 取出本机 IPv4
  local ip4; ip4=$(curl -fsSL -4 ip.sb 2>/dev/null || hostname -I | awk '{print $1}')

  jq -n \
    --arg en_vless_r        "${ENABLE_VLESS_R}" \
    --arg en_vless_grpcr    "${ENABLE_VLESS_GRPCR}" \
    --arg en_trojan_r       "${ENABLE_TROJAN_R}" \
    --arg en_hy2            "${ENABLE_HYSTERIA2}" \
    --arg en_tuic           "${ENABLE_TUIC}" \
    --arg en_vmess_ws       "${ENABLE_VMESS_WS}" \
    --arg en_ss2022         "${ENABLE_SS2022}" \
    --arg en_shadowtls      "${ENABLE_SHADOWTLS_SS}" \
    --arg en_vless_h2r      "${ENABLE_VLESS_H2R}" \
    --arg uuid              "$UUID" \
    --arg sni               "$REALITY_SNI" \
    --arg priv              "$REAL_PRIV" \
    --arg pub               "$REAL_PUB" \
    --arg sid               "$SHORT_ID" \
    --arg grpc              "$GRPC_SERVICE" \
    --arg ws                "$VMESS_WS_PATH" \
    --arg hy2pwd            "$HY2_PASS" \
    --arg obfspwd           "$OBFS_PASS" \
    --arg hy2obfs           "$HY2_OBFS" \
    --arg tuicid            "$TUIC_ID" \
    --arg tuicpw            "$TUIC_PASS" \
    --arg tuicalpn          "$TUIC_ALPN" \
    --arg hy2alpn           "$HY2_ALPN" \
    --arg ss2022pwd         "$SS2022_KEY" \
    --arg ss2022method      "$SS2022_METHOD" \
    --arg p_vless_r         "${PORT_VLESS_R:-44301}" \
    --arg p_vless_grpcr     "${PORT_VLESS_GRPCR:-44302}" \
    --arg p_trojan_r        "${PORT_TROJAN_R:-44303}" \
    --arg p_hy2             "${PORT_HY2:-44304}" \
    --arg p_tuic            "${PORT_TUIC:-44305}" \
    --arg p_vmess_ws        "${PORT_VMESS_WS:-44306}" \
    --arg p_ss2022          "${PORT_SS2022:-44307}" \
    --arg p_stls            "${PORT_STLS:-44308}" \
    --arg p_stls_ss         "${PORT_STLS_SS:-44309}" \
    --arg p_vless_h2r       "${PORT_VLESS_H2R:-44310}" \
    '
    def reality($tag; $port; $with_flow):
      {
        "type": "vless", "tag": $tag, "listen": "::", "listen_port": ($port|tonumber),
        "users": (if $with_flow then [{"uuid": $uuid, "flow": "xtls-rprx-vision"}] else [{"uuid": $uuid}] end),
        "tls": {
          "enabled": true, "server_name": $sni,
          "reality": {
            "enabled": true,
            "handshake": {"server": $sni, "server_port": 443},
            "private_key": $priv, "short_id": [$sid]
          }
        }
      };

    def vless_h2_reality($port):
      reality("vless-h2r"; $port; false) + { "transport": { "type": "http", "path": "/h2" } };

    def vless_grpc_reality($port; $service):
      reality("vless-grpc-reality"; $port; false)
      + { "transport": { "type": "grpc", "service_name": $service } };

    def trojan_reality($port):
      {
        "type":"trojan","tag":"trojan-reality","listen":"::","listen_port":($port|tonumber),
        "users":[{"password":$uuid}],
        "tls":{"enabled":true,"server_name":$sni,
          "reality":{"enabled":true,"handshake":{"server":$sni,"server_port":443},"private_key":$priv,"short_id":[$sid]}
        }
      };

    def hysteria2($port):
      {
        "type":"hysteria2","tag":"hy2","listen":"::","listen_port":($port|tonumber),
        "users":[{"password":$hy2pwd}],
        "tls":{"enabled":true,"server_name":$sni,"alpn":[$hy2alpn],
               "certificate_path":"/etc/sing-box/cert/fullchain.pem","key_path":"/etc/sing-box/cert/key.pem"}
      } + ( if ($hy2obfs=="true") then { "obfs": { "type":"salamander","password":$obfspwd } } else {} end );

    def tuic($port):
      {
        "type":"tuic","tag":"tuic","listen":"::","listen_port":($port|tonumber),
        "users":[{"uuid":$tuicid,"password":$tuicpw}],
        "congestion_control":"bbr",
        "tls":{"enabled":true,"alpn":[$tuicalpn],
               "certificate_path":"/etc/sing-box/cert/fullchain.pem","key_path":"/etc/sing-box/cert/key.pem"}
      };

    def vmess_ws($port; $path):
      { "type":"vmess","tag":"vmess-ws","listen":"::","listen_port":($port|tonumber),
        "users":[{"uuid":$uuid}],
        "transport":{"type":"ws","path":$path}
      };

    def ss2022($port):
      { "type":"shadowsocks","tag":"ss2022","listen":"::","listen_port":($port|tonumber),
        "method":$ss2022method,"password":$ss2022pwd,"network":"tcp,udp"
      };

    def shadowtls_to_ss($port_stls; $port_ss):
      { "type":"shadowtls","tag":"stls","listen":"::","listen_port":($port_stls|tonumber),
        "version":3,"password":$ss2022pwd,
        "handshake":{"server":$sni,"server_port":443},
        "detour":"ss2022"
      },
      { "type":"shadowsocks","tag":"ss2022","listen":"::","listen_port":($port_ss|tonumber),
        "method":$ss2022method,"password":$ss2022pwd,"network":"tcp,udp"
      };

    .log = {"level":"info"} |
    .inbounds = (
      []
      + (if ($en_vless_r=="true")     then [ reality("vless-reality"; $p_vless_r; true) ] else [] end)
      + (if ($en_vless_grpcr=="true") then [ vless_grpc_reality($p_vless_grpcr; $grpc) ] else [] end)
      + (if ($en_trojan_r=="true")    then [ trojan_reality($p_trojan_r) ] else [] end)
      + (if ($en_hy2=="true")         then [ hysteria2($p_hy2) ] else [] end)
      + (if ($en_tuic=="true")        then [ tuic($p_tuic) ] else [] end)
      + (if ($en_vmess_ws=="true")    then [ vmess_ws($p_vmess_ws; $ws) ] else [] end)
      + (if ($en_ss2022=="true" and ($en_shadowtls!="true")) then [ ss2022($p_ss2022) ] else [] end)
      + (if ($en_shadowtls=="true")   then [ shadowtls_to_ss($p_stls; $p_stls_ss) ] else [] end)
      + (if ($en_vless_h2r=="true")   then [ vless_h2_reality($p_vless_h2r) ] else [] end)
    )
  ' > "$SB_ETC/config.json"

  cat > "$SB_ETC/account.env" <<EOF
IPV4=${ip4}
UUID=${UUID}
REAL_PUB=${REAL_PUB}
SHORT_ID=${SHORT_ID}
HY2_PASS=${HY2_PASS}
OBFS_PASS=${OBFS_PASS}
TUIC_ID=${TUIC_ID}
TUIC_PASS=${TUIC_PASS}
SS2022_KEY=${SS2022_KEY}
EOF
}


########################  systemd 服务  ########################
install_systemd(){
cat > /etc/systemd/system/sing-box.service <<'EOF'
[Unit]
Description=Sing-Box Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box -D /var/lib/sing-box -c /etc/sing-box/config.json
WorkingDirectory=/var/lib/sing-box
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SYS_RESOURCE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
LimitNOFILE=1048576
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now sing-box >/dev/null 2>&1 || true
}

restart_service(){ systemctl restart sing-box; }
service_status(){ systemctl is-active sing-box >/dev/null 2>&1; }

########################  展示参数 / 链接  ########################
show_params(){
  source "$SB_ETC/ports.env"
  source "$SB_ETC/account.env"
  echo -e "${C_BOLD}已启用协议与端口${C_RESET}"; hr
  [[ $ENABLE_VLESS_R == true      ]] && echo "  - VLESS Reality (TCP):      $PORT_VLESS_R"
  [[ $ENABLE_VLESS_H2R == true    ]] && echo "  - VLESS H2 Reality (TCP):   $PORT_VLESS_H2R   路径: /h2"
  [[ $ENABLE_VLESS_GRPCR == true  ]] && echo "  - VLESS gRPC Reality (TCP): $PORT_VLESS_GRPCR  service: $GRPC_SERVICE"
  [[ $ENABLE_TROJAN_R == true     ]] && echo "  - Trojan Reality (TCP):     $PORT_TROJAN_R"
  [[ $ENABLE_HYSTERIA2 == true    ]] && echo "  - Hysteria2 (UDP):          $PORT_HY2"
  [[ $ENABLE_TUIC == true         ]] && echo "  - TUIC v5 (UDP):            $PORT_TUIC"
  [[ $ENABLE_SS2022 == true       ]] && echo "  - Shadowsocks 2022 (TCP/UDP): $PORT_SS2022"
  [[ $ENABLE_SHADOWTLS_SS == true ]] && echo "  - ShadowTLS (TCP):          $PORT_STLS  -> 本机SS: $PORT_STLS_SS"
  [[ $ENABLE_VMESS_WS == true     ]] && echo "  - VMess WS (TCP):           $PORT_VMESS_WS   路径: $VMESS_WS_PATH"
  hr

  # 账号参数（中英对照，便于手填）
  local ip="$IPV4"
  echo -e "${C_BOLD}账号参数（手动填写）${C_RESET}"; hr
  if [[ $ENABLE_VLESS_R == true ]]; then
    echo "📌 节点（VLESS Reality / TCP）"
    pad "  Address (地址)";      echo " $ip"
    pad "  Port (端口)";         echo " $PORT_VLESS_R"
    pad "  UUID (用户ID)";       echo " $UUID"
    pad "  flow (流控)";         echo " xtls-rprx-vision"
    pad "  encryption (加密)";   echo " none"
    pad "  network (传输)";      echo " tcp"
    pad "  TLS";                 echo " reality"
    pad "  SNI (serverName)";    echo " $REALITY_SNI"
    pad "  Fingerprint";         echo " chrome"
    pad "  Public key";          echo " $REAL_PUB"
    pad "  ShortId";             echo " $SHORT_ID"
    hr
  fi
  if [[ $ENABLE_VLESS_GRPCR == true ]]; then
    echo "📌 节点（VLESS Reality / gRPC）"
    pad "  Address";             echo " $ip"
    pad "  Port";                echo " $PORT_VLESS_GRPCR"
    pad "  UUID";                echo " $UUID"
    pad "  network";             echo " grpc"
    pad "  ServiceName";         echo " $GRPC_SERVICE"
    pad "  TLS";                 echo " reality"
    pad "  SNI";                 echo " $REALITY_SNI"
    pad "  Fingerprint";         echo " chrome"
    pad "  Public key";          echo " $REAL_PUB"
    pad "  ShortId";             echo " $SHORT_ID"
    hr
  fi
  if [[ $ENABLE_TROJAN_R == true ]]; then
    echo "📌 节点（Trojan Reality / TCP）"
    pad "  Address";             echo " $ip"
    pad "  Port";                echo " $PORT_TROJAN_R"
    pad "  Password";            echo " $UUID"
    pad "  TLS";                 echo " reality"
    pad "  SNI";                 echo " $REALITY_SNI"
    pad "  Fingerprint";         echo " chrome"
    pad "  Public key";          echo " $REAL_PUB"
    pad "  ShortId";             echo " $SHORT_ID"
    hr
  fi
  if [[ $ENABLE_HYSTERIA2 == true ]]; then
    echo "📌 节点（Hysteria2）"
    pad "  Address";             echo " $ip"
    pad "  Port";                echo " $PORT_HY2"
    pad "  Password";            echo " $HY2_PASS"
    pad "  TLS";                 echo " tls"
    pad "  SNI";                 echo " $REALITY_SNI"
    pad "  ALPN";                echo " $HY2_ALPN"
    if [[ "$HY2_OBFS" == "true" ]]; then
      pad "  Obfs";              echo " salamander"
      pad "  Obfs-Password";     echo " $OBFS_PASS"
    fi
    pad "  AllowInsecure";       echo " true"
    hr
  fi
  if [[ $ENABLE_TUIC == true ]]; then
    echo "📌 节点（TUIC v5）"
    pad "  Address";             echo " $ip"
    pad "  Port";                echo " $PORT_TUIC"
    pad "  UUID";                echo " $TUIC_ID"
    pad "  Password";            echo " $TUIC_PASS"
    pad "  congestion_control";  echo " bbr"
    pad "  ALPN";                echo " $TUIC_ALPN"
    pad "  SNI";                 echo " $REALITY_SNI"
    pad "  AllowInsecure";       echo " true"
    hr
  fi
  if [[ $ENABLE_VMESS_WS == true ]]; then
    echo "📌 节点（VMess / WS）"
    pad "  Address";             echo " $ip"
    pad "  Port";                echo " $PORT_VMESS_WS"
    pad "  UUID";                echo " $UUID"
    pad "  network";             echo " ws"
    pad "  path";                echo " $VMESS_WS_PATH"
    pad "  TLS";                 echo " none"
    hr
  fi
  if [[ $ENABLE_SS2022 == true || $ENABLE_SHADOWTLS_SS == true ]]; then
    echo "📌 节点（Shadowsocks 2022）"
    pad "  Address";             echo " $ip"
    pad "  Port";                echo " ${PORT_SS2022:-$PORT_STLS_SS}"
    pad "  Method";              echo " $SS2022_METHOD"
    pad "  Password";            echo " $SS2022_KEY"
    [[ $ENABLE_SHADOWTLS_SS == true ]] && { pad "  建议通过"; echo " ShadowTLS($PORT_STLS) -> SS(${PORT_STLS_SS})"; }
    hr
  fi
  if [[ $ENABLE_VLESS_H2R == true ]]; then
    echo "📌 节点（VLESS Reality / H2）"
    pad "  Address";             echo " $ip"
    pad "  Port";                echo " $PORT_VLESS_H2R"
    pad "  UUID";                echo " $UUID"
    pad "  network";             echo " http"
    pad "  path";                echo " /h2"
    pad "  TLS";                 echo " reality"
    pad "  SNI";                 echo " $REALITY_SNI"
    pad "  Fingerprint";         echo " chrome"
    pad "  Public key";          echo " $REAL_PUB"
    pad "  ShortId";             echo " $SHORT_ID"
    hr
  fi
}

share_links(){
  source "$SB_ETC/ports.env"
  source "$SB_ETC/account.env"
  local ip="$IPV4"; local sni=$(urlenc "$REALITY_SNI") pbk=$(urlenc "$REAL_PUB") sid=$(urlenc "$SHORT_ID")
  echo -e "${C_BOLD}分享链接（可导入 v2rayN）${C_RESET}"; hr
  [[ $ENABLE_VLESS_R == true ]]       && echo "  vless://$UUID@$ip:$PORT_VLESS_R?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$sni&fp=chrome&pbk=$pbk&sid=$sid&type=tcp#vless-reality"
  [[ $ENABLE_VLESS_GRPCR == true ]]   && echo "  vless://$UUID@$ip:$PORT_VLESS_GRPCR?encryption=none&security=reality&sni=$sni&fp=chrome&pbk=$pbk&sid=$sid&type=grpc&serviceName=$(urlenc "$GRPC_SERVICE")#vless-grpc-reality"
  [[ $ENABLE_TROJAN_R == true ]]      && echo "  trojan://$UUID@$ip:$PORT_TROJAN_R?security=reality&sni=$sni&fp=chrome&pbk=$pbk&sid=$sid&type=tcp#trojan-reality"
  if [[ $ENABLE_HYSTERIA2 == true ]]; then
    local qs="insecure=1&sni=$sni&alpn=$(urlenc "$HY2_ALPN")"
    [[ "$HY2_OBFS" == "true" ]] && qs="$qs&obfs=salamander&obfs-password=$(urlenc "$OBFS_PASS")"
    echo "  hy2://$(urlenc "$HY2_PASS")@$ip:$PORT_HY2?$qs#hysteria2"
  fi
  [[ $ENABLE_TUIC == true ]]         && echo "  tuic://$TUIC_ID:$TUIC_PASS@$ip:$PORT_TUIC?congestion_control=bbr&alpn=$(urlenc "$TUIC_ALPN")&sni=$sni&allow_insecure=1#tuic-v5"
  if [[ $ENABLE_VMESS_WS == true ]]; then
    local vm='{"v":"2","ps":"vmess-ws","add":"'"$ip"'","port":"'"$PORT_VMESS_WS"'","id":"'"$UUID"'","aid":"0","net":"ws","type":"none","host":"","path":"'"$VMESS_WS_PATH"'","tls":""}'
    echo "  vmess://$(b64 "$vm")"
  fi
  if [[ $ENABLE_SS2022 == true ]]; then
    local enc=$(b64 "$SS2022_METHOD:$SS2022_KEY")
    echo "  ss://$enc@$ip:$PORT_SS2022#ss2022"
  fi
  if [[ $ENABLE_SHADOWTLS_SS == true ]]; then
    echo "  shadowtls://$ip:$PORT_STLS?server=${REALITY_SNI}:443  ← 先连此，再连本机SS(${PORT_STLS_SS})"
  fi
  [[ $ENABLE_VLESS_H2R == true ]]    && echo "  vless://$UUID@$ip:$PORT_VLESS_H2R?encryption=none&security=reality&sni=$sni&fp=chrome&pbk=$pbk&sid=$sid&type=http&path=$(urlenc "/h2")#vless-h2r"
}

########################  BBR  ########################
enable_bbr(){
  sysctl -w net.core.default_qdisc=fq >/dev/null
  sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null
  cat >/etc/sysctl.d/99-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  sysctl --system >/dev/null
}

########################  操作封装  ########################
deploy(){
  install_base
  install_singbox_bin
  randomize_ports
  write_config
  install_systemd
  # 开放端口
  local rules=()
  [[ $ENABLE_VLESS_R == true      ]] && rules+=("tcp:${PORT_VLESS_R}")
  [[ $ENABLE_VLESS_H2R == true    ]] && rules+=("tcp:${PORT_VLESS_H2R}")
  [[ $ENABLE_VLESS_GRPCR == true  ]] && rules+=("tcp:${PORT_VLESS_GRPCR}")
  [[ $ENABLE_TROJAN_R == true     ]] && rules+=("tcp:${PORT_TROJAN_R}")
  [[ $ENABLE_HYSTERIA2 == true    ]] && rules+=("udp:${PORT_HY2}")
  [[ $ENABLE_TUIC == true         ]] && rules+=("udp:${PORT_TUIC}")
  [[ $ENABLE_SS2022 == true       ]] && rules+=("both:${PORT_SS2022}")
  [[ $ENABLE_SHADOWTLS_SS == true ]] && rules+=("tcp:${PORT_STLS}" "both:${PORT_STLS_SS}")
  [[ $ENABLE_VMESS_WS == true     ]] && rules+=("tcp:${PORT_VMESS_WS}")
  open_firewall "${rules[@]}"
  info "部署完成！"
  show_status_and_links_then_exit
  exit 0
}

change_ports(){
  randomize_ports
  write_config
  restart_service
  info "端口已更换完成"
}

update_singbox(){
  install_singbox_bin
  restart_service
  info "Sing-Box 已更新并重启"
}

self_update(){
  local url="https://raw.githubusercontent.com/Alvin9999/Sing-Box-Plus/main/sing-box-plus.sh"
  prefer_ipv4_begin
  curl -fsSL ${CURL_IPV4:-} -o "$TOOLS_DIR/sing-box-plus.new" "$url"
  prefer_ipv4_end
  if ! cmp -s "$0" "$TOOLS_DIR/sing-box-plus.new"; then
    mv "$TOOLS_DIR/sing-box-plus.new" "$0"; chmod +x "$0"
    info "脚本已更新，请重新运行。"
  else
    rm -f "$TOOLS_DIR/sing-box-plus.new"
    info "脚本已是最新版。"
  fi
}

uninstall_all(){
  systemctl disable --now sing-box >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/sing-box.service
  systemctl daemon-reload
  rm -rf "$SB_ETC" "$SB_LIB"
  rm -f "$SB_BIN"
  info "已卸载 sing-box 与配置文件"
}

show_status_and_links_then_exit(){
  local ip; ip=$(curl -fsSL -4 ip.sb 2>/dev/null || hostname -I | awk '{print $1}')
  echo; echo -e "${C_BOLD}配置目录: ${C_RESET}$SB_ETC"
  echo -e "${C_BOLD}服务器IP: ${C_RESET}$ip"
  echo
  show_params
  share_links
}

########################  菜单  ########################
menu(){
  while true; do
    fix_tty
    title
    echo -e "${C_BOLD}================  管 理 菜 单  ================${C_RESET}"
    echo -e "  ${C_GREEN}1)${C_RESET} 安装 Sing-Box"
    echo -e "  ${C_GREEN}2)${C_RESET} 查看状态 & 分享链接（然后退出）"
    echo -e "  ${C_GREEN}3)${C_RESET} 重启服务"
    echo -e "  ${C_GREEN}4)${C_RESET} 更新 Sing-Box"
    echo -e "  ${C_GREEN}5)${C_RESET} 更新脚本"
    echo -e "  ${C_GREEN}6)${C_RESET} 一键更换所有端口（五位随机且互不重复）"
    echo -e "  ${C_GREEN}7)${C_RESET} 一键开启 BBR 加速"
    echo -e "  ${C_GREEN}8)${C_RESET} 卸载"
    echo -e "  ${C_GREEN}0)${C_RESET} 退出"
    hr
    status_bar
    echo
    read "${READ_OPTS[@]}" -p "选择操作（回车退出）: " opt || true
    [[ -z "${opt:-}" ]] && exit 0
    case "$opt" in
      1) deploy ;;
      2) show_status_and_links_then_exit; exit 0 ;;
      3) restart_service; info "已重启服务"; read -p "回车返回菜单..." _ ;;
      4) update_singbox; read -p "回车返回菜单..." _ ;;
      5) self_update; read -p "回车返回菜单..." _ ;;
      6) change_ports; read -p "回车返回菜单..." _ ;;
      7) enable_bbr; info "BBR 已启用"; read -p "回车返回菜单..." _ ;;
      8) uninstall_all; read -p "回车返回菜单..." _ ;;
      0) exit 0 ;;
      *) echo -e "${C_YELLOW}无效选项${C_RESET}"; sleep 1 ;;
    esac
  done
}

########################  入口  ########################
need_root
menu
