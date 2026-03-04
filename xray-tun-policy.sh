#!/usr/bin/env bash
set -euo pipefail

# xray-tun-policy.sh
# Goal: route ALL local TCP traffic through Xray (redir-in) -> proxy,
#       except SSH (port 22) and local/private nets.
#
# Requires:
#  - Xray inbound "redir-in" listening on 127.0.0.1:${REDIR_PORT} with followRedirect:true
#  - Xray service user must be excluded from marking to avoid loops (auto-detected)

### === Config (override via env) ===
MARK_HEX="${MARK_HEX:-0x1}"          # packets to intercept
XRAY_MARK_HEX="${XRAY_MARK_HEX:-0xff}" # reserved mark to bypass (optional)
REDIR_PORT="${REDIR_PORT:-12345}"    # Xray redir-in port (NOT 11111, that is metrics in your setup)
SSH_PORT="${SSH_PORT:-22}"
EXEMPT_IP="${EXEMPT_IP:-176.193.38.66/32}"

CHAIN_MANGLE="${CHAIN_MANGLE:-XRAY_OUT}"
CHAIN_NAT="${CHAIN_NAT:-XRAY_NAT}"

### === Helpers ===
have() { command -v "$1" >/dev/null 2>&1; }

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: run as root" >&2
    exit 1
  fi
}

detect_xray_user() {
  local u=""
  if have systemctl; then
    # systemctl show prints like "User=nobody"
    u="$(systemctl show -p User xray 2>/dev/null | sed -n 's/^User=//p' | tr -d '\r' || true)"
  fi
  if [[ -z "${u}" ]]; then
    u="nobody"
  fi
  echo "${u}"
}

ensure_chain_mangle() {
  iptables -t mangle -N "${CHAIN_MANGLE}" 2>/dev/null || true
  iptables -t mangle -F "${CHAIN_MANGLE}"
  # Ensure OUTPUT jumps to our chain as rule #1
  iptables -t mangle -D OUTPUT -j "${CHAIN_MANGLE}" 2>/dev/null || true
  iptables -t mangle -I OUTPUT 1 -j "${CHAIN_MANGLE}"
}

ensure_chain_nat() {
  iptables -t nat -N "${CHAIN_NAT}" 2>/dev/null || true
  iptables -t nat -F "${CHAIN_NAT}"
  # Ensure OUTPUT (tcp + mark) jumps to our NAT chain as rule #1
  iptables -t nat -D OUTPUT -p tcp -m mark --mark "${MARK_HEX}" -j "${CHAIN_NAT}" 2>/dev/null || true
  iptables -t nat -I OUTPUT 1 -p tcp -m mark --mark "${MARK_HEX}" -j "${CHAIN_NAT}"
}

apply_rules() {
  local xray_user xray_uid xray_gid
  xray_user="$(detect_xray_user)"

  # Resolve UID/GID (fallback safely if user not found)
  xray_uid="$(id -u "${xray_user}" 2>/dev/null || echo "")"
  xray_gid="$(id -g "${xray_user}" 2>/dev/null || echo "")"

  ensure_chain_mangle
  ensure_chain_nat

  ### --- MANGLE: mark local OUTPUT traffic (except bypasses) ---
  # 1) Exclude Xray process itself (prevents loops)
  if [[ -n "${xray_uid}" ]]; then
    iptables -t mangle -A "${CHAIN_MANGLE}" -m owner --uid-owner "${xray_uid}" -j RETURN
  fi
  if [[ -n "${xray_gid}" ]]; then
    iptables -t mangle -A "${CHAIN_MANGLE}" -m owner --gid-owner "${xray_gid}" -j RETURN 2>/dev/null || true
  fi

  # 2) Bypass already-marked traffic (optional safety)
  iptables -t mangle -A "${CHAIN_MANGLE}" -m mark --mark "${XRAY_MARK_HEX}" -j RETURN

  # 3) Bypass established connections
  iptables -t mangle -A "${CHAIN_MANGLE}" -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN

  # 4) Bypass SSH both directions
  iptables -t mangle -A "${CHAIN_MANGLE}" -p tcp --dport "${SSH_PORT}" -j RETURN
  iptables -t mangle -A "${CHAIN_MANGLE}" -p tcp --sport "${SSH_PORT}" -j RETURN

  # 5) Bypass exempt IP (your allowlist)
  iptables -t mangle -A "${CHAIN_MANGLE}" -s "${EXEMPT_IP}" -j RETURN
  iptables -t mangle -A "${CHAIN_MANGLE}" -d "${EXEMPT_IP}" -j RETURN

  # 6) Bypass local/private networks
  iptables -t mangle -A "${CHAIN_MANGLE}" -d 127.0.0.0/8 -j RETURN
  iptables -t mangle -A "${CHAIN_MANGLE}" -d 10.0.0.0/8 -j RETURN
  iptables -t mangle -A "${CHAIN_MANGLE}" -d 172.16.0.0/12 -j RETURN
  iptables -t mangle -A "${CHAIN_MANGLE}" -d 192.168.0.0/16 -j RETURN
  iptables -t mangle -A "${CHAIN_MANGLE}" -d 172.17.0.0/16 -j RETURN

  # 7) Mark everything else
  iptables -t mangle -A "${CHAIN_MANGLE}" -j MARK --set-xmark "${MARK_HEX}"/0xffffffff

  ### --- NAT: redirect marked TCP to Xray redir-in ---
  # Bypass reserved mark (optional)
  iptables -t nat -A "${CHAIN_NAT}" -m mark --mark "${XRAY_MARK_HEX}" -j RETURN
  # Redirect all marked TCP to redir-in port
  iptables -t nat -A "${CHAIN_NAT}" -p tcp -j REDIRECT --to-ports "${REDIR_PORT}"

  echo "OK: Applied Xray policy routing:"
  echo "  - Mark: ${MARK_HEX} (OUTPUT -> ${CHAIN_MANGLE})"
  echo "  - Redirect marked TCP -> 127.0.0.1:${REDIR_PORT} (OUTPUT -> ${CHAIN_NAT})"
  echo "  - SSH bypass: tcp/${SSH_PORT}"
  echo "  - Xray user bypass: ${xray_user}${xray_uid:+ (uid ${xray_uid})}"
}

### === Main ===
require_root
apply_rules
