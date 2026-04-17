#!/usr/bin/env bash
# go_anon_enhanced.sh
# Enhanced privacy bootstrap: Tor circuit hopping on packet threshold,
# multi-layer VPN chaining (VPN-over-VPN-over-Tor), MAC randomisation,
# DNS-over-HTTPS, I2P, IPFS, dual proxychains, and a nftables kill-switch.
#
# REQUIREMENTS: Run as root on a Debian/Ubuntu-based host.
#
set -euo pipefail
IFS=$'\n\t'

##############################################################
# CONFIGURATION — edit before running
##############################################################

HOST_IFACE="wlan0"          # your physical NIC
VM_NAME="privacy-vm"
VM_USER="vmuser"

# --- Proxychains ---
PROXYCHAINS_HOST_CONF="/etc/proxychains4.conf"
PROXYCHAINS_VM_CONF="/etc/proxychains4_vm.conf"

# --- Tor ---
TORRC_FILE="/etc/tor/torrc"
TOR_CONTROL_PORT=9051
TOR_CONTROL_PASS="your_tor_control_password"   # change this
TOR_SOCKS_PORT=9050

# --- Tor circuit-hop threshold (packets per minute on tun0) ---
# When the packet rate on tun0 exceeds this, a new Tor circuit is requested.
TOR_HOP_PKT_THRESHOLD=5000   # packets/min
TOR_HOP_INTERVAL=30          # seconds between threshold checks

# --- VPN layer 1 (outermost — connects directly to the internet) ---
OVPN1_PATH="/root/vpn1.ovpn"
VPN1_REMOTE_IP="198.51.100.20"
VPN1_REMOTE_PORT="1194"
VPN1_REMOTE_PROTO="udp"
VPN1_TUN="tun0"

# --- VPN layer 2 (runs inside tun0 — VPN-over-VPN) ---
OVPN2_PATH="/root/vpn2.ovpn"
VPN2_REMOTE_IP="198.51.100.21"
VPN2_REMOTE_PORT="443"
VPN2_REMOTE_PROTO="tcp"
VPN2_TUN="tun1"

# --- VPS SOCKS bridge (optional extra hop) ---
VPS_SOCKS_HOST="vps.example.com"
VPS_SOCKS_PORT=1080
VPS_HOST_IP="203.0.113.10"
SSH_KEY_PATH="/root/.ssh/id_rsa"

# --- Tunnel interfaces allowed to egress ---
TUN_IFACES=("tun0" "tun1")

# --- OpenVPN config dir ---
OPENVPN_DIR="/etc/openvpn/clients"

# --- Guest VM credentials for optional guestcontrol copy ---
GUEST_COPY_USER="vboxuser"
GUEST_COPY_PASS=""

# --- DoH provider (Cloudflare used here; swap to any RFC 8484 endpoint) ---
DOH_UPSTREAM="https://1.1.1.1/dns-query"

##############################################################
# Helpers
##############################################################

log()  { echo -e "\n\033[1;32m[+]\033[0m $*"; }
warn() { echo -e "\n\033[1;33m[!]\033[0m $*"; }
err()  { echo -e "\n\033[1;31m[✗]\033[0m $*" >&2; }

confirm_or_exit(){
  read -r -p "Continue? (y/N): " a
  [[ "${a:-}" =~ ^[Yy]$ ]] || { err "Aborted."; exit 1; }
}

require_root(){ [[ $EUID -eq 0 ]] || { err "Must run as root."; exit 1; }; }

##############################################################
# 1) Install prerequisites
##############################################################

install_prereqs(){
  log "Installing packages…"
  apt-get update -qq
  apt-get install -y \
    proxychains4 tor obfs4proxy openvpn \
    wireguard-tools \
    virtualbox virtualbox-ext-pack \
    firejail apparmor apparmor-utils \
    i2p default-jre \
    dnscrypt-proxy \
    macchanger \
    nftables iproute2 \
    jq dnsutils curl wget \
    apt-transport-https gnupg2 ca-certificates \
    iptables-persistent netfilter-persistent \
    nethogs vnstat \
    || true
}

##############################################################
# 2) MAC address randomisation (runs before interface comes up)
##############################################################

setup_mac_randomisation(){
  log "Setting up MAC randomisation on $HOST_IFACE…"

  # systemd-networkd approach: create a .link file
  cat > /etc/systemd/network/10-mac-rand.link <<EOF
[Match]
OriginalName=$HOST_IFACE

[Link]
MACAddressPolicy=random
EOF

  # Also drop a NetworkManager dispatcher script as a fallback
  if command -v nmcli >/dev/null 2>&1; then
    cat > /etc/NetworkManager/dispatcher.d/pre-up.d/01-mac-rand.sh <<'SH'
#!/usr/bin/env bash
# Randomise MAC before each connection
if [[ "$2" == "pre-up" ]]; then
  macchanger -r "$1" 2>/dev/null || true
fi
SH
    chmod 755 /etc/NetworkManager/dispatcher.d/pre-up.d/01-mac-rand.sh
  fi

  log "MAC randomisation configured (takes effect on next interface restart)."
}

##############################################################
# 3) Proxychains (host=strict, VM=random)
##############################################################

configure_two_proxychains(){
  log "Writing host proxychains (strict_chain)…"
  [[ -f "$PROXYCHAINS_HOST_CONF" ]] && cp -v "$PROXYCHAINS_HOST_CONF" "${PROXYCHAINS_HOST_CONF}.bak.$(date +%s)"

  cat > "$PROXYCHAINS_HOST_CONF" <<EOF
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
# Layer 1: Tor SOCKS
socks5  127.0.0.1 ${TOR_SOCKS_PORT}
# Layer 2: VPS SOCKS (uncomment when vps-socks.service is running)
#socks5  127.0.0.1 ${VPS_SOCKS_PORT}
EOF

  log "Writing VM proxychains template (random_chain)…"
  cat > "$PROXYCHAINS_VM_CONF" <<EOF
random_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5  127.0.0.1 ${TOR_SOCKS_PORT}
#socks5  127.0.0.1 ${VPS_SOCKS_PORT}
#socks5  10.11.12.13 1080
#socks5  54.55.56.57 1080
EOF
}

attempt_copy_vm_config_to_guest(){
  if ! command -v VBoxManage >/dev/null 2>&1; then
    warn "VBoxManage not found; copy VM config manually."; return 0
  fi
  VBoxManage list runningvms | grep -q "\"${VM_NAME}\"" || { warn "VM not running; skip copy."; return 0; }
  if [[ -n "${GUEST_COPY_PASS}" ]]; then
    VBoxManage guestcontrol "$VM_NAME" copyto "$PROXYCHAINS_VM_CONF" /tmp/proxychains4.conf \
      --username "$GUEST_COPY_USER" --password "$GUEST_COPY_PASS" || { err "guestcontrol copy failed"; return 1; }
    VBoxManage guestcontrol "$VM_NAME" run \
      --username "$GUEST_COPY_USER" --password "$GUEST_COPY_PASS" --wait-stdout \
      -- /bin/sh -c "sudo mv /tmp/proxychains4.conf /etc/proxychains4.conf && sudo chmod 644 /etc/proxychains4.conf"
  else
    warn "No guest creds; copy $PROXYCHAINS_VM_CONF into the VM manually."
  fi
}

##############################################################
# 4) Tor + obfs4 with ControlPort for circuit hopping
##############################################################

configure_tor_obfs4(){
  log "Configuring Tor + obfs4 (with ControlPort)…"
  [[ -f "$TORRC_FILE" ]] && cp -v "$TORRC_FILE" "${TORRC_FILE}.bak.$(date +%s)"

  # Hash the control password
  local hashed_pass
  hashed_pass="$(tor --hash-password "${TOR_CONTROL_PASS}" 2>/dev/null | tail -1)"

  cat >> "$TORRC_FILE" <<EOF

# --- added by go_anon_enhanced ---
SocksPort 127.0.0.1:${TOR_SOCKS_PORT}
DNSPort  127.0.0.1:5353
ControlPort 127.0.0.1:${TOR_CONTROL_PORT}
HashedControlPassword ${hashed_pass}
ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
Log notice file /var/log/tor/notices.log

# Use bridges if direct Tor is blocked (fill in your bridge lines below):
#UseBridges 1
#Bridge obfs4 <ip>:<port> <fingerprint> cert=<cert> iat-mode=0
EOF

  systemctl enable tor || true
  systemctl restart tor
}

##############################################################
# 5) Tor circuit hopper (packet-threshold daemon)
#    Monitors tun0 packet rate; sends NEWNYM when threshold exceeded.
##############################################################

install_tor_hopper(){
  log "Installing Tor circuit-hopper daemon…"

  cat > /usr/local/sbin/tor_hopper.sh <<HOPPER
#!/usr/bin/env bash
# tor_hopper.sh — sends NEWNYM signal when packet rate exceeds threshold
set -euo pipefail

IFACE="${VPN1_TUN}"
THRESHOLD=${TOR_HOP_PKT_THRESHOLD}
INTERVAL=${TOR_HOP_INTERVAL}
CTRL_HOST="127.0.0.1"
CTRL_PORT="${TOR_CONTROL_PORT}"
CTRL_PASS="${TOR_CONTROL_PASS}"

log(){ echo "[tor_hopper] \$(date '+%F %T') \$*"; }

send_newnym(){
  (
    echo -e "AUTHENTICATE \\"${CTRL_PASS}\\"\r\nSIGNAL NEWNYM\r\nQUIT" \
    | nc -q1 "\$CTRL_HOST" "\$CTRL_PORT" >/dev/null 2>&1
  ) && log "NEWNYM sent — new Tor circuit established." \
    || log "WARN: NEWNYM failed (Tor ControlPort not reachable?)"
}

prev_rx=0; prev_tx=0

while true; do
  # Read current packet counters from /proc/net/dev
  read -r rx tx < <(
    awk -v iface="\$IFACE:" '
      \$1 == iface { print \$3, \$11 }
    ' /proc/net/dev
  ) 2>/dev/null || { sleep "\$INTERVAL"; continue; }

  if [[ \$prev_rx -gt 0 ]]; then
    delta_rx=$(( (rx - prev_rx) * 60 / INTERVAL ))
    delta_tx=$(( (tx - prev_tx) * 60 / INTERVAL ))
    total_pps=$(( delta_rx + delta_tx ))
    log "Packet rate on \$IFACE: \${total_pps} pkt/min (threshold \${THRESHOLD})"
    if [[ \$total_pps -gt \$THRESHOLD ]]; then
      log "Threshold exceeded! Requesting new Tor circuit…"
      send_newnym
      # Back-off: wait extra interval before next hop to avoid rapid cycling
      sleep "\$INTERVAL"
    fi
  fi

  prev_rx=\$rx; prev_tx=\$tx
  sleep "\$INTERVAL"
done
HOPPER

  chmod 755 /usr/local/sbin/tor_hopper.sh

  cat > /etc/systemd/system/tor-hopper.service <<SVC
[Unit]
Description=Tor Circuit Hopper (packet-threshold trigger)
After=tor.service network-online.target
Requires=tor.service

[Service]
Type=simple
ExecStart=/usr/local/sbin/tor_hopper.sh
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVC

  systemctl daemon-reload
  systemctl enable tor-hopper.service
  log "tor-hopper.service enabled (starts after next boot or: systemctl start tor-hopper)."
}

##############################################################
# 6) Multi-layer VPN chaining
#    Layer 1: VPN1 connects over raw internet → tun0
#    Layer 2: VPN2 routes *through* tun0 (VPN-over-VPN)   → tun1
#    Optional Layer 3: Tor SOCKS (already on 9050)
#    Applications: proxychains4 → tun1 → tun0 → internet
#    Stack: App → ProxyChains(Tor) → tun1(VPN2) → tun0(VPN1) → Internet
##############################################################

setup_multilayer_vpn(){
  log "Configuring multi-layer VPN chain (VPN1 → VPN2 → Tor)…"

  mkdir -p "$OPENVPN_DIR"; chmod 700 "$OPENVPN_DIR"

  # ---- VPN Layer 1 systemd unit ----
  if [[ -f "$OVPN1_PATH" ]]; then
    cp -v "$OVPN1_PATH" "$OPENVPN_DIR/vpn1.ovpn"
  else
    warn "VPN1 config not found at $OVPN1_PATH — add it before starting vpn1.service"
  fi

  cat > /etc/systemd/system/vpn1.service <<SVC
[Unit]
Description=VPN Layer 1 (outermost — raw internet)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/sbin/openvpn --config ${OPENVPN_DIR}/vpn1.ovpn --dev ${VPN1_TUN}
Restart=on-failure
RestartSec=15

[Install]
WantedBy=multi-user.target
SVC

  # ---- VPN Layer 2 systemd unit ----
  # Routes VPN2 traffic via tun0 so VPN2 traffic rides inside VPN1.
  # This is achieved by adding a static route for VPN2_REMOTE_IP via the
  # *physical* gateway before VPN2 connects, then letting VPN2 use the
  # default route inside tun0.
  if [[ -f "$OVPN2_PATH" ]]; then
    cp -v "$OVPN2_PATH" "$OPENVPN_DIR/vpn2.ovpn"
  else
    warn "VPN2 config not found at $OVPN2_PATH — add it before starting vpn2.service"
  fi

  cat > /etc/systemd/system/vpn2.service <<SVC
[Unit]
Description=VPN Layer 2 (rides inside tun0 — VPN-over-VPN)
After=vpn1.service
Requires=vpn1.service

[Service]
Type=simple
# Bind OpenVPN traffic to tun0 so it exits through VPN1
ExecStartPre=/bin/bash -c 'ip route add ${VPN2_REMOTE_IP} via \$(ip route show default dev ${VPN1_TUN} | awk "/default/{print \$3}") dev ${VPN1_TUN} || true'
ExecStart=/usr/sbin/openvpn --config ${OPENVPN_DIR}/vpn2.ovpn --dev ${VPN2_TUN} --route-nopull
ExecStopPost=/bin/bash -c 'ip route del ${VPN2_REMOTE_IP} 2>/dev/null || true'
Restart=on-failure
RestartSec=15

[Install]
WantedBy=multi-user.target
SVC

  systemctl daemon-reload
  log "VPN units created. Start order: vpn1 → vpn2."
  log "Enable: systemctl enable --now vpn1.service && sleep 10 && systemctl enable --now vpn2.service"

  # ---- Optional WireGuard layer (alternative to OpenVPN layer 2) ----
  log "WireGuard alternative layer 2 setup note:"
  cat <<'WG'
  To use WireGuard as the inner VPN layer instead of OpenVPN:
  1. Put your .conf in /etc/wireguard/wg0.conf
  2. Add:  Table = off   (so wg doesn't replace the routing table)
  3. Add a PostUp rule:  ip route add <wg-server-ip> via <tun0-gw> dev tun0
  4. systemctl enable --now wg-quick@wg0
WG
}

##############################################################
# 7) VirtualBox isolation
##############################################################

configure_virtualbox_vm(){
  command -v VBoxManage >/dev/null 2>&1 || { err "VBoxManage missing"; return 1; }
  VBoxManage list vms | grep -q "\"${VM_NAME}\"" || { err "VM $VM_NAME not found"; return 1; }

  log "Hardening VirtualBox VM $VM_NAME…"
  VBoxManage modifyvm "$VM_NAME" --clipboard-mode disabled
  VBoxManage modifyvm "$VM_NAME" --drag-and-drop disabled
  VBoxManage modifyvm "$VM_NAME" --usb off || true
  VBoxManage modifyvm "$VM_NAME" --audio none || true
  VBoxManage modifyvm "$VM_NAME" --vram 16

  local NATNET="privacy-natnet"
  VBoxManage natnetwork list | grep -q "$NATNET" || \
    VBoxManage natnetwork add --netname "$NATNET" --network "10.200.200.0/24" --enable --dhcp on

  VBoxManage modifyvm "$VM_NAME" --nic1 natnetwork --nat-network1 "$NATNET"
}

##############################################################
# 8) DNS-over-HTTPS via dnscrypt-proxy
##############################################################

setup_doh(){
  log "Configuring dnscrypt-proxy (DoH) to prevent DNS leaks…"

  cat > /etc/dnscrypt-proxy/dnscrypt-proxy.toml <<'DOH'
listen_addresses = ['127.0.0.53:53']
server_names = ['cloudflare', 'cloudflare-ipv6', 'quad9-dnscrypt-ip4-filter-pri']
doh_servers = true
dnscrypt_servers = true
require_dnssec = true
require_nolog = true
require_nofilter = false

[sources]
  [sources.public-resolvers]
  urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md']
  cache_file = '/var/cache/dnscrypt-proxy/public-resolvers.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  refresh_delay = 72
DOH

  systemctl enable dnscrypt-proxy || true
  systemctl restart dnscrypt-proxy || true

  # Point systemd-resolved at dnscrypt-proxy
  mkdir -p /etc/systemd/resolved.conf.d
  cat > /etc/systemd/resolved.conf.d/doh.conf <<'RESOLV'
[Resolve]
DNS=127.0.0.53
DNSStubListener=no
RESOLV
  systemctl restart systemd-resolved || true

  log "DoH active: all DNS now routed through dnscrypt-proxy."
}

##############################################################
# 9) Disable host leakers
##############################################################

disable_host_leaks(){
  log "Masking host leak services…"
  for svc in snapd apport gnome-online-accounts.service whoopsie.service avahi-daemon.service cups.service; do
    systemctl list-unit-files | grep -q "$svc" && \
      { systemctl stop "$svc" 2>/dev/null || true; systemctl mask "$svc" 2>/dev/null || true; }
  done
  pkill -f "clipit|copyq|parcellite|xclipboard" 2>/dev/null || true

  # Disable IPv6 to reduce leak surface (Tor is IPv4 only)
  log "Disabling IPv6 on $HOST_IFACE…"
  sysctl -w net.ipv6.conf.all.disable_ipv6=1
  sysctl -w net.ipv6.conf.default.disable_ipv6=1
  sysctl -w net.ipv6.conf."${HOST_IFACE}".disable_ipv6=1

  grep -q "disable_ipv6" /etc/sysctl.d/99-privacy.conf 2>/dev/null || cat >> /etc/sysctl.d/99-privacy.conf <<'SYSCTL'
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
SYSCTL
}

##############################################################
# 10) Firefox hardening
##############################################################

configure_firefox_profile(){
  local PROFILE_DIR="$HOME/.mozilla/firefox/privacy-profile"
  mkdir -p "$PROFILE_DIR"

  cat > "$PROFILE_DIR/user.js" <<'EOF'
user_pref("media.peerconnection.enabled", false);      // kill WebRTC
user_pref("network.dns.disablePrefetch", true);
user_pref("network.http.speculative-parallel-limit", 0);
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.fingerprintingProtection", true);
user_pref("dom.battery.enabled", false);
user_pref("geo.enabled", false);
user_pref("browser.safebrowsing.enabled", false);
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.send_pings", false);
user_pref("network.cookie.cookieBehavior", 1);
user_pref("privacy.firstparty.isolate", true);
user_pref("privacy.trackingprotection.enabled", true);
user_pref("media.navigator.enabled", false);
user_pref("network.proxy.socks", "127.0.0.1");
user_pref("network.proxy.socks_port", 9050);
user_pref("network.proxy.socks_version", 5);
user_pref("network.proxy.socks_remote_dns", true);
user_pref("network.proxy.type", 1);
user_pref("dom.event.clipboardevents.enabled", false);
user_pref("browser.cache.disk.enable", false);
user_pref("browser.cache.memory.enable", false);
EOF
  log "Firefox profile written to $PROFILE_DIR"
}

##############################################################
# 11) I2P + IPFS
##############################################################

install_i2p_ipfs(){
  apt-get install -y i2p || true

  if ! command -v ipfs >/dev/null 2>&1; then
    local tag
    tag="$(curl -s https://api.github.com/repos/ipfs/go-ipfs/releases/latest | jq -r .tag_name || true)"
    if [[ -n "${tag:-}" ]]; then
      local url="https://dist.ipfs.io/go-ipfs/${tag}/go-ipfs_${tag#v}_linux-amd64.tar.gz"
      wget -q -O /tmp/go-ipfs.tgz "$url" \
        && tar -C /tmp -xzf /tmp/go-ipfs.tgz \
        && /tmp/go-ipfs/install.sh || true
      ipfs init || true
    fi
  fi
}

##############################################################
# 12) VPS SOCKS tunnel (optional 4th hop)
##############################################################

add_vps_socks_entry(){
  log "Creating vps-socks.service (SSH dynamic SOCKS on localhost:${VPS_SOCKS_PORT})…"
  cat > /etc/systemd/system/vps-socks.service <<EOF
[Unit]
Description=Persistent SSH dynamic SOCKS tunnel to VPS
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/ssh -o StrictHostKeyChecking=no \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=60 \
  -N -D ${VPS_SOCKS_PORT} \
  -i ${SSH_KEY_PATH} root@${VPS_SOCKS_HOST}
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  log "Enable when ready: systemctl enable --now vps-socks.service"
}

##############################################################
# 13) nftables kill-switch
#     Allows: loopback, DHCP, VPN1 server, VPN2-via-tun0,
#             SSH to VPS, tun0/tun1 egress.
#     Drops: everything else (including raw clearnet).
##############################################################

enable_killswitch(){
  log "Applying nftables kill-switch…"

  local tun_list
  tun_list="${TUN_IFACES[*]}"   # e.g. "tun0 tun1"

  nft -f - <<NFT
flush ruleset

table inet filter {

  set tun_ifaces { type ifname; elements = { ${tun_list// /, } } }

  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
    udp dport 68 accept   # DHCP replies
  }

  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
  }

  chain output {
    type filter hook output priority 0; policy drop;
    ct state established,related accept
    oif lo accept

    # DHCP discovery
    udp sport 68 udp dport 67 accept

    # Allow VPN1 server (bootstrap the tunnel)
    ip daddr ${VPN1_REMOTE_IP} ${VPN1_REMOTE_PROTO} dport ${VPN1_REMOTE_PORT} accept

    # Allow VPN2 server (traffic routes through tun0 anyway, but keep explicit)
    ip daddr ${VPN2_REMOTE_IP} ${VPN2_REMOTE_PROTO} dport ${VPN2_REMOTE_PORT} accept

    # Allow SSH to VPS for SOCKS bridge
    ip daddr ${VPS_HOST_IP} tcp dport 22 accept

    # Allow traffic out via VPN tunnels — everything else is dropped
    oifname @tun_ifaces accept

    # Allow Tor bootstrap (Tor uses a guard node on port 9001/9030)
    tcp dport { 9001, 9030 } accept
  }
}
NFT

  # Persist rules across reboots
  nft list ruleset > /etc/nftables.conf
  systemctl enable nftables || true
  log "Kill-switch active. Check: nft list ruleset"
}

disable_killswitch(){
  log "Disabling kill-switch (accept-all)…"
  nft flush ruleset 2>/dev/null || true
  nft add table inet filter
  nft add chain inet filter input  '{ type filter hook input  priority 0; policy accept; }'
  nft add chain inet filter forward '{ type filter hook forward priority 0; policy accept; }'
  nft add chain inet filter output '{ type filter hook output priority 0; policy accept; }'
  log "Kill-switch disabled."
}

##############################################################
# 14) Leak test helpers
##############################################################

leak_tests(){
  log "Leak test commands (run these manually after tunnels are up):"
  cat <<'TESTS'

# 1. Check public IP (should show VPN2/Tor exit, NOT your real IP):
   curl -s https://ifconfig.me

# 2. Check via proxychains (strict Tor chain):
   proxychains4 curl -s https://ifconfig.me

# 3. DNS leak check (should show DoH resolver, not ISP):
   dig +short @127.0.0.53 whoami.akamai.net

# 4. WebRTC check (browser-based):
   open https://browserleaks.com/webrtc

# 5. Full IP/DNS leak panel:
   open https://ipleak.net

# 6. Tor circuit info:
   echo -e 'AUTHENTICATE "your_tor_control_password"\r\nGETINFO circuit-status\r\nQUIT' \
     | nc 127.0.0.1 9051

# 7. Monitor VPN/Tor traffic in real time:
   nethogs tun0
TESTS
}

##############################################################
# 15) Main
##############################################################

main(){
  require_root

  log "=== GoAnon Enhanced Privacy Bootstrap ==="
  log "Stack: App → ProxyChains(Tor) → tun1(VPN2) → tun0(VPN1) → Internet"
  log "Extra: MAC randomisation, DoH, circuit hopping, kill-switch firewall."
  warn "Review configuration variables at the top of this script before continuing."
  confirm_or_exit

  install_prereqs
  setup_mac_randomisation
  configure_two_proxychains
  attempt_copy_vm_config_to_guest
  configure_tor_obfs4
  install_tor_hopper
  setup_multilayer_vpn
  configure_virtualbox_vm || warn "VirtualBox config skipped (VM may not exist yet)."
  setup_doh
  disable_host_leaks
  configure_firefox_profile
  install_i2p_ipfs
  add_vps_socks_entry
  enable_killswitch

  log "=== Bootstrap complete ==="
  log "Suggested startup order:"
  cat <<'ORDER'
  1.  systemctl start vpn1.service          # Outer VPN (tun0)
  2.  sleep 10 && systemctl start vpn2.service  # Inner VPN (tun1, routes through tun0)
  3.  systemctl start tor.service           # Tor (routes through tun1 → tun0)
  4.  systemctl start tor-hopper.service    # Automatic circuit hopping
  5.  systemctl start vps-socks.service     # Optional 4th hop (SSH SOCKS)
  6.  proxychains4 <your application>       # App traffic: Tor → tun1 → tun0 → internet
ORDER

  leak_tests
}

##############################################################
# Entry point
##############################################################

case "${1:-}" in
  --enable-ks)   enable_killswitch;  exit 0 ;;
  --disable-ks)  disable_killswitch; exit 0 ;;
  --hop-now)
    log "Requesting manual Tor circuit hop…"
    echo -e "AUTHENTICATE \"${TOR_CONTROL_PASS}\"\r\nSIGNAL NEWNYM\r\nQUIT" \
      | nc -q1 127.0.0.1 "${TOR_CONTROL_PORT}"
    exit 0
    ;;
  --leak-test)   leak_tests; exit 0 ;;
  *)             main "$@" ;;
esac
