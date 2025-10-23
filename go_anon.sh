#!/usr/bin/env bash
# privacy_stack_bootstrap.sh
# Host+VM privacy bootstrap with dual proxychains (host=strict, VM=random),
# Tor+obfs4, VPN placeholders, VirtualBox isolation, I2P+IPFS, and a kill-switch firewall.
set -euo pipefail
IFS=$'\n\t'

########################
# Basic configuration
########################
HOST_IFACE="wlan0"                 # adjust if different
VM_NAME="privacy-vm"
VM_USER="vmuser"

# Proxychains configs
PROXYCHAINS_HOST_CONF="/etc/proxychains4.conf"       # host (strict_chain)
PROXYCHAINS_VM_CONF="/etc/proxychains4_vm.conf"      # VM template (random_chain)

# Tor/I2P/IPFS
TORRC_FILE="/etc/tor/torrc"
I2P_SERVICE="/etc/default/i2p"
IPFS_DIR="/opt/ipfs"

# VPN & VPS (placeholders; fill real values!)
OPENVPN_DIR="/etc/openvpn/clients"
OVPN1_PATH="/root/openvpn1.ovpn"    # supply file
OVPN2_PATH="/root/openvpn2.ovpn"    # supply file
VPS_SOCKS_HOST="vps.example.com"    # supply hostname
VPS_SOCKS_PORT=1080
SSH_KEY_PATH="/root/.ssh/id_rsa"

# Recommended to hardcode the **IP** for rules (avoid DNS during lock-down)
VPS_HOST_IP="203.0.113.10"          # TODO: set to your VPS public IP

# (Optional) allow contacting your VPN servers while kill-switch is active
VPN1_REMOTE_IP="198.51.100.20"      # TODO set or leave blank to skip allow
VPN1_REMOTE_PORT="1194"             # common OpenVPN UDP
VPN1_REMOTE_PROTO="udp"             # udp|tcp

VPN2_REMOTE_IP="198.51.100.21"      # TODO set or leave blank to skip allow
VPN2_REMOTE_PORT="443"
VPN2_REMOTE_PROTO="tcp"

# Tunnel interfaces that are allowed to egress
TUN_IFACES=("tun0" "tun1")

# VBox guestcontrol copy (optional)
GUEST_COPY_USER="vboxuser"
GUEST_COPY_PASS=""

DOUBLE_NAT_NOTE=$'\n# Host uses strict chain; VM uses random chain (double-NAT / multi-hop permutations).\n'

########################
# Helpers
########################
log(){ echo -e "\n[+] $*"; }
err(){ echo -e "\n[!] $*" >&2; }
confirm_or_exit(){ read -r -p "Continue? (y/N): " a; [[ "${a:-}" =~ ^[Yy]$ ]] || { err "Aborted."; exit 1; }; }

########################
# 1) Packages
########################
install_prereqs(){
  log "Installing base packages…"
  apt update
  apt install -y proxychains4 tor obfs4proxy openvpn virtualbox virtualbox-ext-pack firejail \
    i2p default-jre jq dnsutils curl wget apt-transport-https gnupg2 ca-certificates nftables || true
}

########################
# 2) Proxychains (host strict, VM random)
########################
configure_two_proxychains(){
  log "Writing host proxychains (strict_chain)…"
  [[ -f "$PROXYCHAINS_HOST_CONF" ]] && cp -v "$PROXYCHAINS_HOST_CONF" "${PROXYCHAINS_HOST_CONF}.bak.$(date +%s)"
  cat > "$PROXYCHAINS_HOST_CONF" <<EOF
strict_chain
proxy_dns
$DOUBLE_NAT_NOTE
[ProxyList]
socks5  127.0.0.1 9050
#socks5  ${VPS_SOCKS_HOST} ${VPS_SOCKS_PORT}
#socks5  10.11.12.13 1080
EOF

  log "Writing VM proxychains template (random_chain)…"
  cat > "$PROXYCHAINS_VM_CONF" <<EOF
random_chain
proxy_dns
$DOUBLE_NAT_NOTE
[ProxyList]
socks5  127.0.0.1 9050
#socks5  ${VPS_SOCKS_HOST} ${VPS_SOCKS_PORT}
#socks5  10.11.12.13 1080
#socks5  54.55.56.57 1080
EOF
}

attempt_copy_vm_config_to_guest(){
  if ! command -v VBoxManage >/dev/null 2>&1; then
    log "VBoxManage not found; manual copy of VM config required (inside guest to /etc/proxychains4.conf)."
    return 0
  fi
  if ! VBoxManage list runningvms | grep -q "\"${VM_NAME}\""; then
    log "VM not running; skip guestcontrol copy."
    return 0
  fi
  if [[ -n "$GUEST_COPY_PASS" ]]; then
    log "Attempting guestcontrol copy of VM proxychains config…"
    VBoxManage guestcontrol "$VM_NAME" copyto "$PROXYCHAINS_VM_CONF" /tmp/proxychains4.conf \
      --username "$GUEST_COPY_USER" --password "$GUEST_COPY_PASS" || { err "guestcontrol copy failed"; return 1; }
    VBoxManage guestcontrol "$VM_NAME" run --username "$GUEST_COPY_USER" --password "$GUEST_COPY_PASS" \
      --wait-stdout -- "/bin/sh" "-c" "sudo mv /tmp/proxychains4.conf /etc/proxychains4.conf && sudo chmod 644 /etc/proxychains4.conf"
    log "VM proxychains updated."
  else
    log "No guest creds; copy $PROXYCHAINS_VM_CONF into the VM manually."
  fi
}

########################
# 3) Tor + obfs4
########################
configure_tor_obfs4(){
  log "Configuring Tor + obfs4…"
  [[ -f "$TORRC_FILE" ]] && cp -v "$TORRC_FILE" "${TORRC_FILE}.bak.$(date +%s)"
  cat >> "$TORRC_FILE" <<'EOF'

# --- added by privacy bootstrap ---
SocksPort 127.0.0.1:9050
DNSPort   127.0.0.1:5353
ClientTransportPlugin obfs4 /usr/bin/obfs4proxy
Log notice file /var/log/tor/notices.log
EOF
  systemctl enable tor || true
  systemctl restart tor
}

########################
# 4) OpenVPN placeholders
########################
setup_openvpn_clients(){
  log "Preparing OpenVPN client folder…"
  mkdir -p "$OPENVPN_DIR"; chmod 700 "$OPENVPN_DIR"
  [[ -f "$OVPN1_PATH" ]] && cp -v "$OVPN1_PATH" "$OPENVPN_DIR/client1.ovpn" || log "Add your VPN1 .ovpn at $OVPN1_PATH"
  [[ -f "$OVPN2_PATH" ]] && cp -v "$OVPN2_PATH" "$OPENVPN_DIR/client2.ovpn" || log "Add your VPN2 .ovpn at $OVPN2_PATH"
}

########################
# 5) VirtualBox isolation
########################
configure_virtualbox_vm(){
  if ! command -v VBoxManage >/dev/null 2>&1; then err "VBoxManage missing"; return 1; fi
  VBoxManage list vms | grep -q "\"${VM_NAME}\"" || { err "VM $VM_NAME not found"; return 1; }

  log "Disabling clipboard & drag-and-drop, enforcing NAT network…"
  VBoxManage controlvm "$VM_NAME" setclipboardmode disabled || true
  VBoxManage controlvm "$VM_NAME" setdraganddrop disabled || true

  VBoxManage modifyvm "$VM_NAME" --nic1 nat
  NATNET_NAME="privacy-natnet"
  VBoxManage natnetwork list | grep -q "$NATNET_NAME" || \
    VBoxManage natnetwork add --netname "$NATNET_NAME" --network "10.200.200.0/24" --enable --dhcp on
  VBoxManage modifyvm "$VM_NAME" --nic1 natnetwork --nat-network1 "$NATNET_NAME"
}

########################
# 6) Disable common host 'leakers'
########################
disable_host_leaks(){
  log "Masking some host services (review first)…"
  systemctl is-active --quiet snapd && { systemctl stop snapd || true; systemctl mask snapd || true; }
  systemctl list-unit-files | grep -q apport && { systemctl stop apport || true; systemctl mask apport || true; }
  for svc in gnome-online-accounts.service whoopsie.service; do
    systemctl list-unit-files | grep -q "$svc" && { systemctl stop "$svc" || true; systemctl mask "$svc" || true; }
  done
  pkill -f "clipit|copyq|parcellite|xclipboard" || true
}

########################
# 7) Firefox hardening (profile)
########################
configure_firefox_profile(){
  PROFILE_DIR="$HOME/.mozilla/firefox/privacy-profile"
  mkdir -p "$PROFILE_DIR"
  cat > "$PROFILE_DIR/user.js" <<'EOF'
user_pref("media.peerconnection.enabled", false);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.http.speculative-parallel-limit", 0);
user_pref("privacy.resistFingerprinting", true);
user_pref("dom.battery.enabled", false);
user_pref("geo.enabled", false);
user_pref("browser.safebrowsing.enabled", false);
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.send_pings", false);
user_pref("network.cookie.cookieBehavior", 1);
user_pref("privacy.firstparty.isolate", true);
user_pref("privacy.trackingprotection.enabled", true);
user_pref("media.navigator.enabled", false);
EOF
  log "Profile at $PROFILE_DIR (use Firejail or run via proxychains inside VM)."
}

########################
# 8) I2P + IPFS (basic)
########################
install_i2p_ipfs(){
  apt install -y i2p || true
  if ! command -v ipfs >/dev/null 2>&1; then
    IPFS_TAG="$(curl -s https://api.github.com/repos/ipfs/go-ipfs/releases/latest | jq -r .tag_name || true)"
    if [[ -n "${IPFS_TAG:-}" ]]; then
      URL="https://dist.ipfs.io/go-ipfs/${IPFS_TAG}/go-ipfs_${IPFS_TAG#v}_linux-amd64.tar.gz"
      wget -q -O /tmp/go-ipfs.tgz "$URL" && tar -C /tmp -xzf /tmp/go-ipfs.tgz && /tmp/go-ipfs/install.sh || true
      ipfs init || true
    fi
  fi
}

########################
# 9) VPS SOCKS tunnel (systemd)
########################
add_vps_socks_entry(){
  cat > /etc/systemd/system/vps-socks.service <<EOF
[Unit]
Description=Persistent SSH dynamic socks tunnel to VPS
After=network-online.target
[Service]
Type=simple
User=root
ExecStart=/usr/bin/ssh -o ExitOnForwardFailure=yes -o ServerAliveInterval=60 -N -D ${VPS_SOCKS_PORT} -i ${SSH_KEY_PATH} root@${VPS_SOCKS_HOST}
Restart=on-failure
RestartSec=10
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  log "Edit SSH key/host, then enable: systemctl enable --now vps-socks.service"
}

############################################################
# 10) Kill-switch firewall (nftables preferred, iptables fallback)
############################################################
# Policy:
#  - Allow loopback, established/related
#  - Allow DHCP client (so you can get an IP)
#  - Allow SSH to your VPS (to build the SOCKS hop)
#  - (Optional) Allow contacting VPN servers (fill IP/port/proto)
#  - Allow all traffic **out via tun0/tun1** (VPN tunnels)
#  - Drop everything else egress
setup_killswitch_nft(){
  if ! command -v nft >/dev/null 2>&1; then
    err "nftables not found; will try iptables fallback."
    return 1
  fi

  log "Writing nftables kill-switch rules to /etc/nftables.conf …"
  cat > /etc/nftables.conf <<NFT
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  sets {
    tun_ifaces { type ifname; elements = { ${TUN_IFACES[*]} } }
  }

  chains {
    input {
      type filter hook input priority 0;
      policy drop;
      ct state established,related accept
      iif lo accept
      # DHCP server replies to client
      udp dport 68 accept
    }

    forward {
      type filter hook forward priority 0;
      policy drop;
      ct state established,related accept
    }

    output {
      type filter hook output priority 0;
      policy drop;

      ct state established,related accept
      oif lo accept

      # DHCP client -> server (obtain lease)
      udp sport 68 dport 67 accept

      # Allow building the SOCKS tunnel to your VPS
      ip daddr ${VPS_HOST_IP} tcp dport 22 accept

      # Optional: allow contacting VPN servers (fill IPs above)
      $( [[ -n "${VPN1_REMOTE_IP}" ]] && echo "ip daddr ${VPN1_REMOTE_IP} ${VPN1_REMOTE_PROTO} dport ${VPN1_REMOTE_PORT} accept" )
      $( [[ -n "${VPN2_REMOTE_IP}" ]] && echo "ip daddr ${VPN2_REMOTE_IP} ${VPN2_REMOTE_PROTO} dport ${VPN2_REMOTE_PORT} accept" )

      # Allow any traffic that leaves via VPN tunnels (tun0/tun1)
      oifname @tun_ifaces accept
    }
  }
}
NFT

  systemctl enable nftables || true
  systemctl restart nftables
  log "nftables kill-switch active. Use 'nft list ruleset' to inspect."
  return 0
}

disable_killswitch_nft(){
  if command -v nft >/dev/null 2>&1; then
    log "Disabling nftables kill-switch (setting accept-all fallback)…"
    cat > /etc/nftables.conf <<'NFT'
flush ruleset
table inet filter {
  chain input { type filter hook input priority 0; policy accept; }
  chain forward{ type filter hook forward priority 0; policy accept; }
  chain output { type filter hook output priority 0; policy accept; }
}
NFT
    systemctl restart nftables || true
  fi
}

setup_killswitch_iptables(){
  log "Applying iptables kill-switch (legacy fallback)…"
  iptables -F; iptables -X
  ip6tables -F; ip6tables -X

  # Default DROP
  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT DROP

  # Established/related
  iptables -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  # Loopback
  iptables -A INPUT  -i lo -j ACCEPT
  iptables -A OUTPUT -o lo -j ACCEPT

  # DHCP
  iptables -A INPUT  -p udp --dport 68 -j ACCEPT
  iptables -A OUTPUT -p udp --sport 68 --dport 67 -j ACCEPT

  # SSH to VPS
  iptables -A OUTPUT -p tcp -d "$VPS_HOST_IP" --dport 22 -j ACCEPT

  # Optional: VPN servers
  [[ -n "${VPN1_REMOTE_IP}" ]] && iptables -A OUTPUT -p "$VPN1_REMOTE_PROTO" -d "$VPN1_REMOTE_IP" --dport "$VPN1_REMOTE_PORT" -j ACCEPT
  [[ -n "${VPN2_REMOTE_IP}" ]] && iptables -A OUTPUT -p "$VPN2_REMOTE_PROTO" -d "$VPN2_REMOTE_IP" --dport "$VPN2_REMOTE_PORT" -j ACCEPT

  # Allow via tun ifaces
  for ti in "${TUN_IFACES[@]}"; do
    iptables -A OUTPUT -o "$ti" -j ACCEPT
    iptables -A INPUT  -i "$ti" -j ACCEPT
  done

  log "iptables kill-switch applied. To clear: iptables -F; iptables -P INPUT ACCEPT; iptables -P OUTPUT ACCEPT; iptables -P FORWARD ACCEPT"
}

enable_killswitch(){
  # Try nft first; fallback to iptables
  setup_killswitch_nft || setup_killswitch_iptables
  log "Kill-switch enabled. Remember: until tunnels are up, only allowed flows (VPS SSH, optional VPN servers, DHCP) will work."
}

disable_killswitch(){
  if command -v nft >/dev/null 2>&1; then
    disable_killswitch_nft
  else
    iptables -F
    iptables -P INPUT ACCEPT; iptables -P OUTPUT ACCEPT; iptables -P FORWARD ACCEPT
    ip6tables -F
    ip6tables -P INPUT ACCEPT; ip6tables -P OUTPUT ACCEPT; ip6tables -P FORWARD ACCEPT
  fi
  log "Kill-switch disabled (all ACCEPT)."
}

########################
# 11) Leak tests
########################
leak_tests(){
  cat <<'TEST'

# Public IP (direct):
curl -s https://ifconfig.me || curl -s https://ipinfo.io/ip

# Public IP via host proxychains (sequential):
proxychains4 curl -s https://ifconfig.me

# DNS (direct vs proxied):
dig +short @resolver1.opendns.com myip.opendns.com
proxychains4 dig +short @resolver1.opendns.com myip.opendns.com

# In VM, use its proxychains (/etc/proxychains4.conf):
proxychains4 curl -s https://ifconfig.me
TEST
}

########################
# 12) Main
########################
main(){
  log "This will configure dual proxychains, Tor/obfs4, VPN placeholders, VBox isolation, I2P/IPFS, and a kill-switch firewall."
  confirm_or_exit

  install_prereqs
  configure_two_proxychains
  attempt_copy_vm_config_to_guest
  configure_tor_obfs4
  setup_openvpn_clients
  configure_virtualbox_vm
  disable_host_leaks
  configure_firefox_profile
  install_i2p_ipfs
  add_vps_socks_entry

  log ">>> Enabling kill-switch now… (edit VPS_HOST_IP/VPN*_REMOTE_* first if needed)"
  enable_killswitch

  log "Bootstrap complete. Use these helpers:"
  echo "  # Disable kill-switch temporarily:  $(basename "$0") --disable-ks"
  echo "  # Re-enable kill-switch:            $(basename "$0") --enable-ks"
  leak_tests
}

# Support simple toggles without re-running everything
case "${1:-}" in
  --enable-ks)   enable_killswitch; exit 0 ;;
  --disable-ks)  disable_killswitch; exit 0 ;;
  *)             main "$@";;
esac
