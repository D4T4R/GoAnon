# 🛡️ GoAnon

A layered **privacy bootstrap & boilerplate** for Linux hosts with a **Virtual Machine Setup**.

This script automates:

- Dual **proxychains** configs  
  - Host → `strict_chain` (sequential)  
  - VM → `random_chain` (multi-hop randomized)
- **Tor + obfs4** configuration  
- Two-level **OpenVPN** placeholders  
- **VPS SOCKS** tunnel via systemd (`ssh -D`)  
- **VirtualBox** isolation (NAT, no clipboard or drag-drop)  
- **Firefox** hardened profile (anti-fingerprinting)  
- **I2P** + **IPFS** installation  
- **Kill-switch firewall** (nftables preferred, iptables fallback)

> ⚠️ This project enhances privacy but does **not** guarantee complete anonymity.  
> Always audit, customize, and test before real-world use.

---

## 🚀 Quick Start

```bash
# 1. Save the script
curl -sS -o privacy_stack_bootstrap.sh https://example.com/privacy_stack_bootstrap.sh
chmod +x privacy_stack_bootstrap.sh

# 2. Edit required variables
nano privacy_stack_bootstrap.sh
# - VPS_SOCKS_HOST, VPS_HOST_IP, SSH_KEY_PATH
# - OVPN1_PATH, OVPN2_PATH
# - VM_NAME (existing VirtualBox VM)
# - Optional: VPN1/2 IP, PORT, PROTO for kill-switch allowlist

# 3. Execute
sudo ./privacy_stack_bootstrap.sh

# 4. Toggle kill-switch manually
sudo ./privacy_stack_bootstrap.sh --disable-ks
sudo ./privacy_stack_bootstrap.sh --enable-ks
