#!/usr/bin/env bash
# ============================================================
#  Sing-Box-Plus 管理脚本（18 节点：直连 9 + WARP 9）
#  Version: v2.5.1
#  author：Alvin9999
#  Repo: https://github.com/Alvin9999/Sing-Box-Plus
# ============================================================

set -Eeuo pipefail

SBP_VERSION="2.5.1"

# =========================
# 基础路径 / 变量
# =========================
SB_DIR=${SB_DIR:-/opt/sing-box}
CONF_JSON=${CONF_JSON:-$SB_DIR/config.json}
CERT_DIR=${CERT_DIR:-$SB_DIR/cert}
SBP_ROOT=${SBP_ROOT:-/var/lib/sing-box-plus}
SBP_BIN_DIR=${SBP_BIN_DIR:-$SBP_ROOT/bin}
SB_BIN=${SB_BIN:-$SBP_BIN_DIR/sing-box}
CF_BIN=${CF_BIN:-/usr/local/bin/cloudflared}
WGCF_BIN=${WGCF_BIN:-$SBP_BIN_DIR/wgcf}
SYSTEMD_SERVICE=${SYSTEMD_SERVICE:-sing-box.service}

mkdir -p "$SB_DIR" "$CERT_DIR" "$SBP_BIN_DIR"

# ============ 样式 ============
C_RESET="$(printf '\033[0m')" ; C_BOLD="$(printf '\033[1m')"
C_BLUE="$(printf '\033[34m')" ; C_CYAN="$(printf '\033[36m')"
C_DIM="$(printf '\033[2m')"   ; C_RED="$(printf '\033[31m')"
hr(){ printf '%s\n' "------------------------------------------------------------"; }

# ============ 工具函数 ============
safe_source(){ local f="$1"; [[ -s "$f" ]] || return 1; set +u; # shellcheck disable=SC1090
source "$f"; set -u; }

detect_goarch(){ case "$(uname -m)" in x86_64|amd64) echo amd64;; aarch64|arm64) echo arm64;; armv7l|armv7) echo armv7;; i386|i686) echo 386;; *) echo amd64;; esac; }
dl(){ local url="$1" out="$2"; if command -v curl >/dev/null; then curl -fsSL --retry 2 --connect-timeout 8 -o "$out" "$url"; else wget -qO "$out" "$url"; fi; }

b64enc(){ if base64 --help 2>&1 | grep -q -- " -w "; then base64 -w 0; else base64 | tr -d '\n'; fi; }
pad_b64(){ local s="${1:-}"; s="$(printf '%s' "$s" | tr -d '\r\n\" ')"; s="${s%%=*}"; local r=$(( ${#s} % 4 )); ((r==2))&&s="${s}=="; ((r==3))&&s="${s}="; printf '%s' "$s"; }

# URL 编码：优先 python3，否则用 jq，最后简单兜底
urlenc(){
  local s="${1:-}"
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<PY "$s"
import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))
PY
  elif command -v jq >/dev/null 2>&1; then
    printf '%s' "$s" | jq -sRr @uri
  else
    # 仅替换空格 -> %20 的简陋兜底
    printf '%s' "$s" | sed 's/ /%20/g'
  fi
}

get_ip(){
  local ip=""
  ip="$(curl -fsS --max-time 3 https://ip.sb 2>/dev/null || true)"
  [[ -n "$ip" ]] || ip="$(curl -fsS --max-time 3 https://ifconfig.me 2>/dev/null || true)"
  [[ -n "$ip" ]] || ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  echo "${ip:-127.0.0.1}"
}

pause(){ echo; read -rp "按回车返回主菜单..." _; }
sudo_exec(){ if [[ $EUID -ne 0 ]]; then sudo "$0" "$@"; else "$0" "$@"; fi; }

# ============ 文件路径 ============
ENV_FILE="$SB_DIR/env.conf"
CREDS_FILE="$SB_DIR/creds.env"
PORTS_FILE="$SB_DIR/ports.env"
WARP_FILE="$SB_DIR/warp.env"
ARGO_FILE="$SB_DIR/argo.env"

# ============ 环境 / 凭据 / 端口 ============
load_env(){ safe_source "$ENV_FILE" || true; : "${ENABLE_WARP:=true}" "${VMESS_WS_PATH:=/vm}" "${GRPC_SERVICE:=grpc}" ; }
save_env(){ cat >"$ENV_FILE"<<EOF
ENABLE_WARP=${ENABLE_WARP}
VMESS_WS_PATH=${VMESS_WS_PATH}
GRPC_SERVICE=${GRPC_SERVICE}
EOF
}

load_creds(){ safe_source "$CREDS_FILE" || true; }
save_creds(){ cat >"$CREDS_FILE"<<EOF
UUID=${UUID}
REALITY_SERVER=${REALITY_SERVER}
REALITY_SERVER_PORT=${REALITY_SERVER_PORT}
REALITY_PRIV=${REALITY_PRIV}
REALITY_PUB=${REALITY_PUB}
REALITY_SID=${REALITY_SID}
HY2_PWD=${HY2_PWD}
HY2_PWD2=${HY2_PWD2}
HY2_OBFS_PWD=${HY2_OBFS_PWD}
SS2022_KEY=${SS2022_KEY}
SS_PWD=${SS_PWD}
TUIC_UUID=${TUIC_UUID}
TUIC_PWD=${TUIC_PWD}
EOF
}

load_ports(){ safe_source "$PORTS_FILE" || true; }
save_ports(){ cat >"$PORTS_FILE"<<EOF
PORT_VLESSR=${PORT_VLESSR}
PORT_VLESS_GRPCR=${PORT_VLESS_GRPCR}
PORT_TROJANR=${PORT_TROJANR}
PORT_HY2=${PORT_HY2}
PORT_VMESS_WS=${PORT_VMESS_WS}
PORT_HY2_OBFS=${PORT_HY2_OBFS}
PORT_SS2022=${PORT_SS2022}
PORT_SS=${PORT_SS}
PORT_TUIC=${PORT_TUIC}
PORT_VLESSR_W=${PORT_VLESSR_W}
PORT_VLESS_GRPCR_W=${PORT_VLESS_GRPCR_W}
PORT_TROJANR_W=${PORT_TROJANR_W}
PORT_HY2_W=${PORT_HY2_W}
PORT_VMESS_WS_W=${PORT_VMESS_WS_W}
PORT_HY2_OBFS_W=${PORT_HY2_OBFS_W}
PORT_SS2022_W=${PORT_SS2022_W}
PORT_SS_W=${PORT_SS_W}
PORT_TUIC_W=${PORT_TUIC_W}
EOF
}

rand_hex(){ openssl rand -hex 12; }

ensure_creds(){
  load_creds
  : "${UUID:=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)}"
  : "${HY2_PWD:=$(rand_hex)}" ; : "${HY2_PWD2:=$(rand_hex)}" ; : "${HY2_OBFS_PWD:=$(rand_hex)}"
  : "${SS2022_KEY:=$(openssl rand -base64 32)}" ; : "${SS_PWD:=$(rand_hex)}"
  : "${TUIC_UUID:=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)}" ; : "${TUIC_PWD:=$(rand_hex)}"
  : "${REALITY_SERVER:=www.cloudflare.com}" ; : "${REALITY_SERVER_PORT:=443}"
  if [[ -z "${REALITY_PRIV:-}" || -z "${REALITY_PUB:-}" ]]; then
    local j; j="$("$SB_BIN" generate reality-keypair | jq -c '.' 2>/dev/null || true)"
    if [[ -n "$j" ]]; then REALITY_PRIV="$(jq -r '.PrivateKey'<<<"$j")"; REALITY_PUB="$(jq -r '.PublicKey'<<<"$j")"; fi
  fi
  : "${REALITY_SID:=$(echo $(rand_hex) | cut -c1-8)}"
  save_creds
}

ensure_ports(){
  load_ports
  # 直连 9
  : "${PORT_VLESSR:=30001}" ; : "${PORT_VLESS_GRPCR:=30002}" ; : "${PORT_TROJANR:=30003}"
  : "${PORT_HY2:=30004}"     ; : "${PORT_VMESS_WS:=30005}"   ; : "${PORT_HY2_OBFS:=30006}"
  : "${PORT_SS2022:=30007}"  ; : "${PORT_SS:=30008}"         ; : "${PORT_TUIC:=30009}"
  # WARP 9
  : "${PORT_VLESSR_W:=31001}" ; : "${PORT_VLESS_GRPCR_W:=31002}" ; : "${PORT_TROJANR_W:=31003}"
  : "${PORT_HY2_W:=31004}"     ; : "${PORT_VMESS_WS_W:=31005}"   ; : "${PORT_HY2_OBFS_W:=31006}"
  : "${PORT_SS2022_W:=31007}"  ; : "${PORT_SS_W:=31008}"         ; : "${PORT_TUIC_W:=31009}"
  save_ports
}

# ============ 启动引导（安装依赖 / sing-box / 自签证书） ============
ensure_jq(){
  command -v jq >/dev/null 2>&1 && return 0
  local arch out="$SBP_BIN_DIR/jq"; arch="$(detect_goarch)"
  dl "https://github.com/jqlang/jq/releases/latest/download/jq-linux-${arch}" "$out" \
    || { [[ "$arch" = amd64 ]] && dl "https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64" "$out" || true; }
  chmod +x "$out" 2>/dev/null || true
  command -v jq >/dev/null 2>&1
}

sbp_bootstrap(){
  [[ $EUID -eq 0 ]] || { echo "[ERR] 请使用 root 运行或加 sudo"; exit 1; }
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y curl openssl tar unzip ca-certificates uuid-runtime iproute2 >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl openssl tar unzip ca-certificates util-linux iproute >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl openssl tar unzip ca-certificates util-linux iproute >/dev/null 2>&1 || true
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm curl openssl tar unzip ca-certificates util-linux iproute2 >/dev/null 2>&1 || true
  fi
  ensure_jq || { echo "[ERR] 无法获得 jq"; exit 1; }

  # 安装 sing-box 二进制（生成 Reality 密钥 & 运行）
  if [[ ! -x "$SB_BIN" ]]; then
    local a tmp json url pkg ; a="$(detect_goarch)"; tmp="$(mktemp -d)"
    json="$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest)"
    url="$(printf '%s' "$json" | jq -r --arg a "$a" '.assets[] | select(.name|test("linux-" + $a + "\\.(tar\\.(xz|gz)|zip)$")) | .browser_download_url' | head -n1)"
    [[ -n "$url" ]] || { echo "[ERR] 获取 sing-box 发行包失败"; exit 1; }
    pkg="$tmp/pkg"; dl "$url" "$pkg"
    case "$url" in
      *.tar.xz) tar -xJf "$pkg" -C "$tmp" ;;
      *.tar.gz) tar -xzf "$pkg" -C "$tmp" ;;
      *.zip) unzip -q "$pkg" -d "$tmp" ;;
    esac
    local bin; bin="$(find "$tmp" -type f -name 'sing-box' | head -n1)"
    install -m 0755 "$bin" "$SB_BIN"; rm -rf "$tmp"
  fi

  # 自签证书（hy2/tuic/ss2022 用）
  if [[ ! -f "$CERT_DIR/private.key" || ! -f "$CERT_DIR/cert.pem" ]]; then
    openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/private.key" >/dev/null 2>&1
    openssl req -new -x509 -days 36500 -key "$CERT_DIR/private.key" -out "$CERT_DIR/cert.pem" -subj "/CN=www.microsoft.com" >/dev/null 2>&1
  fi
}

# ============ WARP (wgcf) ============
install_wgcf(){
  [[ -x "$WGCF_BIN" ]] && return 0
  local a tmp; a="$(detect_goarch)"; tmp="$(mktemp -d)"
  dl "https://github.com/ViRb3/wgcf/releases/latest/download/wgcf-linux-${a}" "$tmp/wgcf" \
    && install -m 0755 "$tmp/wgcf" "$WGCF_BIN" || { echo "[WARN] 获取 wgcf 失败"; return 1; }
  rm -rf "$tmp"
}

load_warp(){ safe_source "$WARP_FILE" || true; }
save_warp(){ cat >"$WARP_FILE"<<EOF
WARP_PRIVATE_KEY=${WARP_PRIVATE_KEY}
WARP_PEER_PUBLIC_KEY=${WARP_PEER_PUBLIC_KEY}
WARP_ENDPOINT_HOST=${WARP_ENDPOINT_HOST}
WARP_ENDPOINT_PORT=${WARP_ENDPOINT_PORT}
WARP_ADDRESS_V4=${WARP_ADDRESS_V4}
WARP_ADDRESS_V6=${WARP_ADDRESS_V6}
WARP_RESERVED_1=${WARP_RESERVED_1}
WARP_RESERVED_2=${WARP_RESERVED_2}
WARP_RESERVED_3=${WARP_RESERVED_3}
EOF
}

ensure_warp_profile(){
  load_env
  [[ "${ENABLE_WARP}" == "true" ]] || return 0
  load_warp
  if [[ -n "${WARP_PRIVATE_KEY:-}" && -n "${WARP_PEER_PUBLIC_KEY:-}" && -n "${WARP_ENDPOINT_HOST:-}" && -n "${WARP_ENDPOINT_PORT:-}" ]]; then
    WARP_PRIVATE_KEY="$(pad_b64 "$WARP_PRIVATE_KEY")"
    WARP_PEER_PUBLIC_KEY="$(pad_b64 "$WARP_PEER_PUBLIC_KEY")"
    save_warp; return 0
  fi
  install_wgcf || { echo "[WARN] 无法安装 wgcf，禁用 WARP"; ENABLE_WARP=false; save_env; return 0; }
  local wd="$SB_DIR/wgcf"; mkdir -p "$wd"
  [[ -f "$wd/wgcf-account.toml" ]] || "$WGCF_BIN" register --accept-tos --config "$wd/wgcf-account.toml" >/dev/null
  "$WGCF_BIN" generate --config "$wd/wgcf-account.toml" --profile "$wd/wgcf-profile.conf" >/dev/null
  local prof="$wd/wgcf-profile.conf" ep host port ad rs
  WARP_PRIVATE_KEY="$(pad_b64 "$(awk -F'= *' '/^PrivateKey/{gsub(/\r/,"");print $2; exit}' "$prof")")"
  WARP_PEER_PUBLIC_KEY="$(pad_b64 "$(awk -F'= *' '/^PublicKey/{gsub(/\r/,"");print $2; exit}' "$prof")")"
  ep="$(awk -F'= *' '/^Endpoint/{gsub(/\r/,"");print $2; exit}' "$prof"|tr -d '" ')"
  if [[ "$ep" =~ ^\[(.+)\]:(.+)$ ]]; then host="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"; else host="${ep%:*}"; port="${ep##*:}"; fi
  WARP_ENDPOINT_HOST="$host"; WARP_ENDPOINT_PORT="$port"
  ad="$(awk -F'= *' '/^Address/{gsub(/\r/,"");print $2; exit}' "$prof"|tr -d '" ')"
  WARP_ADDRESS_V4="${ad%%,*}"; WARP_ADDRESS_V6="${ad##*,}"
  rs="$(awk -F'= *' '/^Reserved/{gsub(/\r/,"");print $2; exit}' "$prof"|tr -d '" ')"
  WARP_RESERVED_1="${rs%%,*}"; rs="${rs#*,}"; WARP_RESERVED_2="${rs%%,*}"; WARP_RESERVED_3="${rs##*,}"
  : "${WARP_RESERVED_1:=0}" "${WARP_RESERVED_2:=0}" "${WARP_RESERVED_3:=0}"
  save_warp
}

# ============ 写入 sing-box 配置（18 节点） ============
write_config(){
  load_env; load_creds; load_ports; ensure_creds; ensure_ports; ensure_warp_profile
  local CRT="$CERT_DIR/cert.pem" KEY="$CERT_DIR/private.key"
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
  --arg WPRIV "$(pad_b64 "${WARP_PRIVATE_KEY:-}")" --arg WPPUB "$(pad_b64 "${WARP_PEER_PUBLIC_KEY:-}")" \
  --arg WHOST "${WARP_ENDPOINT_HOST:-}" --argjson WPORT "${WARP_ENDPOINT_PORT:-0}" \
  --arg W4 "${WARP_ADDRESS_V4:-}" --arg W6 "${WARP_ADDRESS_V6:-}" \
  --argjson WR1 "${WARP_RESERVED_1:-0}" --argjson WR2 "${WARP_RESERVED_2:-0}" --argjson WR3 "${WARP_RESERVED_3:-0}" \
  '
  def inbound_vless($p):      {type:"vless", listen:"0.0.0.0", listen_port:$p, users:[{uuid:$UID}], tls:{enabled:true, server_name:$RS, reality:{enabled:true, handshake:{server:$RS, server_port:$RSP}, private_key:$RPR, short_id:[$SID]}}};
  def inbound_vless_flow($p): {type:"vless", listen:"0.0.0.0", listen_port:$p, users:[{uuid:$UID, flow:"xtls-rprx-vision"}], tls:{enabled:true, server_name:$RS, reality:{enabled:true, handshake:{server:$RS, server_port:$RSP}, private_key:$RPR, short_id:[$SID]}}};
  def inbound_trojan($p):     {type:"trojan", listen:"0.0.0.0", listen_port:$p, users:[{password:$UID}], tls:{enabled:true, server_name:$RS, reality:{enabled:true, handshake:{server:$RS, server_port:$RSP}, private_key:$RPR, short_id:[$SID]}}};
  def inbound_hy2($p):        {type:"hysteria2", listen:"0.0.0.0", listen_port:$p, users:[{name:"hy2", password:$HY2}], tls:{enabled:true, certificate_path:$CRT, key_path:$KEY}};
  def inbound_vmess_ws($p):   {type:"vmess", listen:"0.0.0.0", listen_port:$p, users:[{uuid:$UID}], transport:{type:"ws", path:$VMWS}};
  def inbound_hy2_obfs($p):   {type:"hysteria2", listen:"0.0.0.0", listen_port:$p, users:[{name:"hy2", password:$HY22}], obfs:{type:"salamander", password:$HY2O}, tls:{enabled:true, certificate_path:$CRT, key_path:$KEY, alpn:["h3"]}};
  def inbound_ss2022($p):     {type:"shadowsocks", listen:"0.0.0.0", listen_port:$p, method:"2022-blake3-aes-256-gcm", password:$SS2022};
  def inbound_ss($p):         {type:"shadowsocks", listen:"0.0.0.0", listen_port:$p, method:"aes-256-gcm", password:$SSPWD};
  def inbound_tuic($p):       {type:"tuic", listen:"0.0.0.0", listen_port:$p, users:[{uuid:$TUICUUID, password:$TUICPWD}], congestion_control:"bbr", tls:{enabled:true, certificate_path:$CRT, key_path:$KEY, alpn:["h3"]}};

  def warp_outbound:
    {type:"wireguard", tag:"warp",
      local_address: ( [ $W4, $W6 ] | map(select(. != "")) ),
      system_interface:false, private_key:$WPRIV,
      peers:[{ server:$WHOST, server_port:$WPORT, public_key:$WPPUB, reserved:[$WR1,$WR2,$WR3], allowed_ips:["0.0.0.0/0","::/0"] }],
      mtu:1280
    };

  {
    log:{level:"info", timestamp:true},
    dns:{ servers:[ {tag:"dns-remote", address:"https://1.1.1.1/dns-query", detour:"direct"}, {address:"tls://dns.google", detour:"direct"} ], strategy:"prefer_ipv4" },
    inbounds:[
      (inbound_vless_flow($P1) + {tag:"vless-reality"}),
      (inbound_vless($P2)      + {tag:"vless-grpcr", transport:{type:"grpc", service_name:$GRPC}}),
      (inbound_trojan($P3)     + {tag:"trojan-reality"}),
      (inbound_hy2($P4)        + {tag:"hy2"}),
      (inbound_vmess_ws($P5)   + {tag:"vmess-ws"}),
      (inbound_hy2_obfs($P6)   + {tag:"hy2-obfs"}),
      (inbound_ss2022($P7)     + {tag:"ss2022"}),
      (inbound_ss($P8)         + {tag:"ss"}),
      (inbound_tuic($P9)       + {tag:"tuic-v5"}),

      (inbound_vless_flow($PW1)+ {tag:"vless-reality-warp"}),
      (inbound_vless($PW2)     + {tag:"vless-grpcr-warp", transport:{type:"grpc", service_name:$GRPC}}),
      (inbound_trojan($PW3)    + {tag:"trojan-reality-warp"}),
      (inbound_hy2($PW4)       + {tag:"hy2-warp"}),
      (inbound_vmess_ws($PW5)  + {tag:"vmess-ws-warp"}),
      (inbound_hy2_obfs($PW6)  + {tag:"hy2-obfs-warp"}),
      (inbound_ss2022($PW7)    + {tag:"ss2022-warp"}),
      (inbound_ss($PW8)        + {tag:"ss-warp"}),
      (inbound_tuic($PW9)      + {tag:"tuic-v5-warp"})
    ],
    outbounds: (
      if $ENABLE_WARP=="true" and ($WPRIV|length)>0 and ($WHOST|length)>0
      then [{type:"direct", tag:"direct"}, {type:"block", tag:"block"}, warp_outbound]
      else [{type:"direct", tag:"direct"}, {type:"block", tag:"block"}] end
    ),
    route: (
      if $ENABLE_WARP=="true" and ($WPRIV|length)>0 and ($WHOST|length)>0
      then { default_domain_resolver:"dns-remote",
             rules:[{ inbound:["vless-reality-warp","vless-grpcr-warp","trojan-reality-warp","hy2-warp","vmess-ws-warp","hy2-obfs-warp","ss2022-warp","ss-warp","tuic-v5-warp"], outbound:"warp" }],
             final:"direct" }
      else { final:"direct" } end
    )
  }' > "$CONF_JSON"
}

# ============ systemd（sing-box） ============
write_systemd_singbox(){
  cat >/etc/systemd/system/$SYSTEMD_SERVICE <<EOF
[Unit]
Description=Sing-Box Service (SBP)
After=network-online.target
Wants=network-online.target

[Service]
Environment=ENABLE_DEPRECATED_WIREGUARD_OUTBOUND=true
ExecStart=$SB_BIN run -c $CONF_JSON
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now "$SYSTEMD_SERVICE"
}

# ============ 防火墙放行 ============
open_firewall(){
  load_ports
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

# ============ Argo Quick Tunnel（临时域名） ============
write_runner(){
cat > "$SB_DIR/sbp-argo-run.sh" <<"EOSH"
#!/usr/bin/env bash
set -Eeuo pipefail
SB_DIR=${SB_DIR:-/opt/sing-box}
CF_BIN=${CF_BIN:-/usr/local/bin/cloudflared}
MODE="${1:-direct}"  # direct / warp

set +u
source "$SB_DIR/ports.env" 2>/dev/null || true
source "$SB_DIR/env.conf"  2>/dev/null || true
set -u

if [[ "$MODE" == "direct" ]]; then TARGET_PORT="${PORT_VMESS_WS:-}"; KEY="ARGO_HOST_DIRECT"; else TARGET_PORT="${PORT_VMESS_WS_W:-}"; KEY="ARGO_HOST_WARP"; fi
[[ -n "${TARGET_PORT:-}" ]] || { echo "[ERR] 未找到目标端口（$MODE）"; exit 1; }

LOG="$SB_DIR/argo-${MODE}.log"; : > "$LOG"

update_env(){
  local host="$1"
  {
    flock -x 9
    set +u; source "$SB_DIR/argo.env" 2>/dev/null || true; set -u
    if [[ "$KEY" == "ARGO_HOST_DIRECT" ]]; then
      ARGO_HOST_DIRECT="$host"; : "${ARGO_HOST_WARP:=}"
    else
      ARGO_HOST_WARP="$host"; : "${ARGO_HOST_DIRECT:=}"
    fi
    {
      echo "ARGO_HOST_DIRECT=${ARGO_HOST_DIRECT:-}"
      echo "ARGO_HOST_WARP=${ARGO_HOST_WARP:-}"
      echo "UPDATED_AT=$(date -u +%FT%TZ)"
    } > "$SB_DIR/argo.env"
  } 9>"$SB_DIR/argo.env.lock"
  echo "[INFO] $KEY=$host 已写入 $SB_DIR/argo.env"
}

stdbuf -oL -eL "$CF_BIN" tunnel --no-autoupdate --protocol h2 \
  --url "http://127.0.0.1:${TARGET_PORT}" 2>&1 | while IFS= read -r line; do
    echo "$line" | tee -a "$LOG" >/dev/null
    if [[ "$line" =~ https://([a-zA-Z0-9.-]+\.trycloudflare\.com) ]]; then
      update_env "${BASH_REMATCH[1]}"
    fi
  done
EOSH
chmod +x "$SB_DIR/sbp-argo-run.sh"
}

write_systemd_argo(){
  cat >/etc/systemd/system/cloudflared-sbp@.service <<'EOF'
[Unit]
Description=Cloudflared Quick Tunnel (SBP %i)
After=network-online.target sing-box.service
Wants=network-online.target

[Service]
Type=simple
Environment=SB_DIR=/opt/sing-box
Environment=CF_BIN=/usr/local/bin/cloudflared
ExecStart=/opt/sing-box/sbp-argo-run.sh %i
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

install_cloudflared(){
  [[ -x "$CF_BIN" ]] && return 0
  local a url tmp ; a="$(detect_goarch)"; tmp="$(mktemp -d)"
  url="$(curl -fsSL https://api.github.com/repos/cloudflare/cloudflared/releases/latest \
        | jq -r --arg a "$a" '.assets[] | select(.name|test("^cloudflared-linux-" + $a + "$")) | .browser_download_url' | head -n1)"
  [[ -n "$url" ]] || { echo "[ERR] 未找到 cloudflared 发行包"; exit 1; }
  dl "$url" "$tmp/cloudflared"; install -m 0755 "$tmp/cloudflared" "$CF_BIN"; rm -rf "$tmp"
}

start_argo(){
  install_cloudflared
  write_runner
  write_systemd_argo
  systemctl enable --now cloudflared-sbp@direct.service
  systemctl enable --now cloudflared-sbp@warp.service
}

wait_argo_hosts(){
  local deadline=$((SECONDS+35))
  while (( SECONDS < deadline )); do
    safe_source "$ARGO_FILE" || true
    [[ -n "${ARGO_HOST_DIRECT:-}" && -n "${ARGO_HOST_WARP:-}" ]] && return 0
    sleep 1
  done
  return 1
}

# ============ 分享链接（18 + 2 Argo） ============
vmess_link(){
  local ps="$1" add="$2" port="$3" id="$4" path="$5"
  local json
  json=$(jq -nc --arg ps "$ps" --arg add "$add" --arg port "$port" \
              --arg id "$id" --arg path "$path" '
  {"v":"2","ps":$ps,"add":$add,"port":$port,"id":$id,"aid":"0","scy":"auto","net":"ws","type":"none","host":$add,"path":$path,"tls":"tls","sni":$add,"alpn":""}')
  printf "vmess://%s" "$(printf "%s" "$json" | b64enc)"
}

print_links(){
  load_env; load_creds; load_ports
  local ip; ip="$(get_ip)"
  local D=() W=()

  # 直连 9
  D+=("vless://${UUID}@${ip}:${PORT_VLESSR}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#vless-reality")
  D+=("vless://${UUID}@${ip}:${PORT_VLESS_GRPCR}?encryption=none&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=grpc&serviceName=${GRPC_SERVICE}#vless-grpc-reality")
  D+=("trojan://${UUID}@${ip}:${PORT_TROJANR}?security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#trojan-reality")
  D+=("hy2://$(urlenc "${HY2_PWD}")@${ip}:${PORT_HY2}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#hysteria2")
  D+=("$(vmess_link 'vmess-ws' "$ip" "${PORT_VMESS_WS}" "$UUID" "$VMESS_WS_PATH")")
  D+=("hy2://$(urlenc "${HY2_PWD2}")@${ip}:${PORT_HY2_OBFS}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}&alpn=h3&obfs=salamander&obfs-password=$(urlenc "${HY2_OBFS_PWD}")#hysteria2-obfs")
  D+=("ss://$(printf "%s" "2022-blake3-aes-256-gcm:${SS2022_KEY}" | b64enc)@${ip}:${PORT_SS2022}#ss2022")
  D+=("ss://$(printf "%s" "aes-256-gcm:${SS_PWD}" | b64enc)@${ip}:${PORT_SS}#ss")
  D+=("tuic://${TUIC_UUID}:$(urlenc "${TUIC_PWD}")@${ip}:${PORT_TUIC}?congestion_control=bbr&alpn=h3&insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#tuic-v5")

  # WARP 9
  W+=("vless://${UUID}@${ip}:${PORT_VLESSR_W}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#vless-reality-warp")
  W+=("vless://${UUID}@${ip}:${PORT_VLESS_GRPCR_W}?encryption=none&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=grpc&serviceName=${GRPC_SERVICE}#vless-grpc-reality-warp")
  W+=("trojan://${UUID}@${ip}:${PORT_TROJANR_W}?security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#trojan-reality-warp")
  W+=("hy2://$(urlenc "${HY2_PWD}")@${ip}:${PORT_HY2_W}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#hysteria2-warp")
  W+=("$(vmess_link 'vmess-ws-warp' "$ip" "${PORT_VMESS_WS_W}" "$UUID" "$VMESS_WS_PATH")")
  W+=("hy2://$(urlenc "${HY2_PWD2}")@${ip}:${PORT_HY2_OBFS_W}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}&alpn=h3&obfs=salamander&obfs-password=$(urlenc "${HY2_OBFS_PWD}")#hysteria2-obfs-warp")
  W+=("ss://$(printf "%s" "2022-blake3-aes-256-gcm:${SS2022_KEY}" | b64enc)@${ip}:${PORT_SS2022_W}#ss2022-warp")
  W+=("ss://$(printf "%s" "aes-256-gcm:${SS_PWD}" | b64enc)@${ip}:${PORT_SS_W}#ss-warp")
  W+=("tuic://${TUIC_UUID}:$(urlenc "${TUIC_PWD}")@${ip}:${PORT_TUIC_W}?congestion_control=bbr&alpn=h3&insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#tuic-v5-warp")

  echo -e "${C_BLUE}${C_BOLD}分享链接 · 合计 20 条（直连9 + WARP9 + Argo2）${C_RESET}"; hr
  echo -e "${C_CYAN}${C_BOLD}【直连 9】${C_RESET}"; for l in "${D[@]}"; do echo "  $l"; done; hr
  echo -e "${C_CYAN}${C_BOLD}【WARP 9】${C_RESET}"; for l in "${W[@]}"; do echo "  $l"; done; hr

  # 追加 Argo 2 条（读取 trycloudflare 域名）
  safe_source "$ARGO_FILE" || true
  if [[ -n "${ARGO_HOST_DIRECT:-}" ]]; then
    echo -e "${C_CYAN}${C_BOLD}【Argo 直连】${C_RESET} Host: ${ARGO_HOST_DIRECT}  Port: 443  Path: ${VMESS_WS_PATH}"
    echo "  $(vmess_link 'vmess-ws-argo'  "$ARGO_HOST_DIRECT"  "443" "$UUID" "$VMESS_WS_PATH")"
  else
    echo -e "${C_DIM}[Argo 直连] 暂无域名，执行：sudo $0 argo-restart${C_RESET}"
  fi
  if [[ -n "${ARGO_HOST_WARP:-}" ]]; then
    echo -e "${C_CYAN}${C_BOLD}【Argo + WARP】${C_RESET} Host: ${ARGO_HOST_WARP}  Port: 443  Path: ${VMESS_WS_PATH}"
    echo "  $(vmess_link 'vmess-ws-argo-warp'  "$ARGO_HOST_WARP"  "443" "$UUID" "$VMESS_WS_PATH")"
  else
    echo -e "${C_DIM}[Argo+WARP] 暂无域名，执行：sudo $0 argo-restart${C_RESET}"
  fi
  hr
}

# ============ 子命令 ============
cmd_install(){
  sbp_bootstrap
  ensure_creds
  ensure_ports
  write_config
  write_systemd_singbox
  open_firewall

  # 安装并启动 Argo 两实例（direct / warp）
  start_argo
  echo "[INFO] 等待 trycloudflare 域名生成..."
  if wait_argo_hosts; then
    echo "[OK] 已捕获到 Argo 域名，写入 $ARGO_FILE"
  else
    echo "[WARN] 暂未捕获到 Argo 域名，可稍后运行：$0 links"
  fi

  echo; print_links
}

cmd_restart(){
  systemctl restart "$SYSTEMD_SERVICE"
  echo "[OK] sing-box 已重启"
}

cmd_status(){
  systemctl --no-pager -l status "$SYSTEMD_SERVICE" || true
  echo; echo "[ENV] $ENV_FILE"; [[ -s "$ENV_FILE" ]] && cat "$ENV_FILE" || echo "(empty)"
  echo; echo "[CREDS] $CREDS_FILE"; [[ -s "$CREDS_FILE" ]] && sed 's/^REALITY_PRIV=.*/REALITY_PRIV=***hidden***/; s/^REALITY_PUB=.*/REALITY_PUB=***hidden***/' "$CREDS_FILE" || echo "(empty)"
  echo; echo "[PORTS] $PORTS_FILE"; [[ -s "$PORTS_FILE" ]] && cat "$PORTS_FILE" || echo "(empty)"
  echo; echo "[ARGO]  $ARGO_FILE"; [[ -s "$ARGO_FILE" ]] && cat "$ARGO_FILE" || echo "(empty)"
}

cmd_links(){ print_links; }

cmd_uninstall(){
  systemctl disable --now "$SYSTEMD_SERVICE" || true
  rm -f /etc/systemd/system/$SYSTEMD_SERVICE
  systemctl daemon-reload

  systemctl disable --now cloudflared-sbp@direct.service || true
  systemctl disable --now cloudflared-sbp@warp.service || true
  rm -f /etc/systemd/system/cloudflared-sbp@.service
  systemctl daemon-reload

  rm -f "$SB_DIR/sbp-argo-run.sh" "$ARGO_FILE" "$SB_DIR/argo.env.lock" "$SB_DIR/argo-direct.log" "$SB_DIR/argo-warp.log"
  echo "[OK] 已卸载 systemd 配置（保留 $SB_DIR 下的 *.env 与 $CONF_JSON）"
}

cmd_argo_install(){
  start_argo
  if wait_argo_hosts; then print_links; else echo "[WARN] 暂未捕获到域名，可稍后运行：$0 links"; fi
}
cmd_argo_restart(){
  systemctl restart cloudflared-sbp@direct.service || true
  systemctl restart cloudflared-sbp@warp.service || true
  echo "[INFO] 已重启 Argo，等待域名更新..."
  if wait_argo_hosts; then print_links; else echo "[WARN] 暂未捕获到域名，可稍后运行：$0 links"; fi
}
cmd_argo_status(){
  systemctl --no-pager -l status cloudflared-sbp@direct.service || true
  echo
  systemctl --no-pager -l status cloudflared-sbp@warp.service || true
  echo
  [[ -s "$ARGO_FILE" ]] && cat "$ARGO_FILE" || echo "(no argo.env)"
}

usage(){
cat <<USAGE
sing-box-plus v${SBP_VERSION}

用法:
  sudo $0 install         # 一键安装/更新（依赖/证书/配置/服务）+ 启动 Argo 两实例
  sudo $0 restart         # 重启 sing-box
  $0   status             # 查看状态 & 当前 env/creds/ports/argo
  $0   links              # 打印 18 + 2 Argo 分享链接
  sudo $0 uninstall       # 卸载 systemd（保留配置文件）

Argo 管理:
  sudo $0 argo-install    # 安装 cloudflared & 写入 systemd & 启动
  sudo $0 argo-restart    # 重启 Argo 两实例，刷新 trycloudflare 域名
  $0   argo-status        # 查看 Argo 状态与当前域名

也可直接运行不带参数进入交互式主菜单：  $0 menu
USAGE
}

# ============ 主菜单 ============
menu(){
  while true; do
    clear
    echo -e "${C_BOLD}sing-box-plus v${SBP_VERSION}${C_RESET}"
    hr
    echo "1) 一键安装/更新（依赖/证书/配置/服务 + Argo）"
    echo "2) 查看分享链接（18 + 2 Argo）"
    echo "3) 查看运行状态（sing-box/env/ports/argo）"
    echo "4) 重启 sing-box"
    echo "5) 安装/启动 Argo（cloudflared 两实例）"
    echo "6) 重启 Argo（刷新临时域名）"
    echo "7) 查看 Argo 状态"
    echo "8) 卸载（移除 systemd，保留配置文件）"
    echo "9) 退出"
    hr
    read -rp "请选择 [1-9]: " ans
    case "$ans" in
      1) sudo_exec install; pause ;;
      2) "$0" links; pause ;;
      3) "$0" status; pause ;;
      4) sudo_exec restart; pause ;;
      5) sudo_exec argo-install; pause ;;
      6) sudo_exec argo-restart; pause ;;
      7) "$0" argo-status; pause ;;
      8) sudo_exec uninstall; pause ;;
      9) clear; exit 0 ;;
      *) echo "无效选择"; sleep 1 ;;
    esac
  done
}

# ============ 入口 ============
case "${1:-menu}" in
  menu)           menu ;;
  install)        cmd_install ;;
  restart)        cmd_restart ;;
  status)         cmd_status ;;
  links)          cmd_links ;;
  uninstall)      cmd_uninstall ;;
  argo-install)   cmd_argo_install ;;
  argo-restart)   cmd_argo_restart ;;
  argo-status)    cmd_argo_status ;;
  *)              menu ;;
esac
